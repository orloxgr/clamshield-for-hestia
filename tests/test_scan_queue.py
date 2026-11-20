"""Queue reasons follow real worker gates without changing jobs or services."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.scan_queue import ScanQueue
from clamshield.scan_status import ScanStatus
from clamshield.settings import Settings
from clamshield.store import Store


HEALTHY={'clamshield-worker.service':{'LoadState':'loaded','ActiveState':'inactive'},
         'clamshield-worker.timer':{'LoadState':'loaded','ActiveState':'active'}}


class ScanQueueTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.settings=Settings(state=Path(folder.name)/'state');self.settings.prepare()
        self.store=Store(self.settings.database);self.queue=ScanQueue(self.settings,self.store)
        self.context=dict(actor='alice',owner='alice',identity='alice-generation',admin=False)
        self.hestia=Mock();self.hestia.authorize.return_value=self.context
        probe=patch.object(ScanQueue,'units',return_value=HEALTHY);self.units=probe.start();self.addCleanup(probe.stop)

    def job(self,key,owner='alice',source='manual',status='queued',created=100):
        context=self.context|dict(owner=owner,identity=owner+'-generation')
        site=dict(owner=owner,identity=context['identity'],domain=key+'.test',root='/private/fixture-root')
        job=self.store.enqueue(context,site,source=source)
        with self.store.connection() as db:db.execute('UPDATE jobs SET status=?,created=? WHERE id=?',(status,created,job))
        return self.store.job(context,job)

    def locked(self):
        fd=os.open(self.settings.state/'worker.lock',os.O_CREAT|os.O_RDWR,0o600)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.addCleanup(os.close,fd)
        return fd

    def test_fifo_position_is_global_and_independent_of_search_scope_and_kind(self):
        first=self.job('foreign',owner='bob',source='signature-update',created=1)
        second=self.job('integrity',source='wordpress-integrity',created=2)
        third=self.job('manual',created=3)
        page=ScanStatus(self.store,self.hestia,self.settings).list(self.context,search='manual')
        self.assertEqual(1,page['total']);self.assertEqual(3,page['jobs'][0]['queue']['position'])
        self.assertNotIn('foreign',json.dumps(page));self.assertNotIn(first['id'],json.dumps(page))
        self.queue.describe([second]);self.assertEqual(2,second['queue']['position'])
        with self.store.connection() as db:self.assertEqual(3,db.execute("SELECT count(*) FROM jobs WHERE status='queued'").fetchone()[0])

    def test_stale_lock_filename_is_free_and_missing_lock_is_not_created(self):
        path=self.settings.state/'worker.lock';self.assertFalse(self.queue.lock_busy());self.assertFalse(path.exists())
        path.write_bytes(b'');path.chmod(0o600);self.assertFalse(self.queue.lock_busy())
        job=self.job('sample',created=995)
        with patch('clamshield.scan_queue.time.time',return_value=1000):self.queue.describe([job])
        self.assertEqual('waiting',job['queue']['code']);self.assertEqual(5,job['queue']['wait_seconds'])

    def test_active_oneshot_worker_is_not_misreported_as_starting_or_failed(self):
        self.job('foreign',owner='bob',source='signature-update',status='running')
        self.locked();job=self.job('sample')
        self.units.return_value=HEALTHY|{'clamshield-worker.service':{'LoadState':'loaded','ActiveState':'activating','SubState':'start'}}
        self.queue.describe([job],admin=True)
        self.assertEqual('scan-running',job['queue']['code']);self.assertIn('automatic scan after signature updates: bob / foreign.test',job['queue']['message'])
        self.queue.describe([job],admin=False)
        self.assertEqual('Waiting for another scan to finish.',job['queue']['message']);self.assertNotIn('bob',json.dumps(job['queue']))

    def test_abandoned_running_record_without_held_lock_is_recovery_not_live_work(self):
        self.job('old',owner='bob',status='running');job=self.job('sample')
        self.queue.describe([job]);self.assertEqual('recovery',job['queue']['code'])

    def test_held_lock_without_running_scan_does_not_invent_an_active_job(self):
        self.locked();job=self.job('sample');self.queue.describe([job])
        self.assertEqual('scanner-busy',job['queue']['code'])

    def test_pending_activation_journals_and_service_controls_explain_exact_worker_gates(self):
        job=self.job('sample')
        for filename,code in [('signature-activation.json','signature-activation'),('resources-activation.json','resource-activation'),('website-engine-activation.json','engine-activation')]:
            with self.subTest(filename=filename):
                path=self.settings.state/filename;path.write_text('{}')
                self.queue.describe([job],admin=True);self.assertEqual(code,job['queue']['code']);self.assertEqual('history',job['queue']['action'])
                self.queue.describe([job],admin=False);self.assertIsNone(job['queue']['action']);path.unlink()
        self.store.enqueue_task(self.context,'website-engine-start',{})
        self.queue.describe([job],admin=True);self.assertEqual('engine-control',job['queue']['code'])

    def test_missing_masked_failed_and_stopped_services_never_claim_normal_waiting(self):
        job=self.job('sample')
        for fields,unit,code in [({'LoadState':'not-found'},'service','unavailable'),({'LoadState':'masked'},'timer','unavailable'),({'ActiveState':'failed'},'service','worker-failed'),({'ActiveState':'inactive'},'timer','timer-stopped')]:
            with self.subTest(fields=fields):
                name='clamshield-worker.'+unit;self.units.return_value=HEALTHY|{name:HEALTHY[name]|fields}
                self.queue.describe([job]);self.assertEqual(code,job['queue']['code'])

    def test_delayed_unclaimed_jobs_and_unknown_probes_are_explicit_and_nonmutating(self):
        job=self.job('sample',created=900)
        with patch('clamshield.scan_queue.time.time',return_value=1000):self.queue.describe([job])
        self.assertEqual('delayed',job['queue']['code']);self.assertEqual(100,job['queue']['wait_seconds'])
        self.units.return_value={};self.queue.describe([job]);self.assertEqual('unknown',job['queue']['code'])
        self.units.return_value=HEALTHY|{'clamshield-worker.service':{'ActiveState':'activating'}}
        self.queue.describe([job]);self.assertEqual('starting',job['queue']['code'])
        self.assertEqual('queued',self.store.job(self.context,job['id'])['status'])

    def test_unsafe_lock_is_not_followed_or_reported_as_healthy(self):
        target=self.settings.state/'private';target.write_text('private')
        (self.settings.state/'worker.lock').symlink_to(target)
        self.assertIsNone(self.queue.lock_busy());job=self.job('sample');self.queue.describe([job])
        self.assertEqual('unknown',job['queue']['code']);self.assertEqual('private',target.read_text())

    def test_terminal_jobs_do_not_probe_units_or_locks(self):
        job=self.job('sample',status='completed')
        with patch.object(self.queue,'lock_busy') as lock:self.queue.describe([job])
        self.units.assert_not_called();lock.assert_not_called();self.assertNotIn('queue',job)


class ScanQueueUnitProbe(unittest.TestCase):
    def test_read_only_probe_is_bounded_and_parses_only_the_two_owned_units(self):
        output='Id=clamshield-worker.service\nLoadState=loaded\nActiveState=activating\nSubState=start\n\nId=clamshield-worker.timer\nLoadState=loaded\nActiveState=active\n\nId=foreign.service\nActiveState=active\n'
        with patch('clamshield.scan_queue.subprocess.run',return_value=Mock(stdout=output,returncode=0)) as run:
            value=ScanQueue.units()
        self.assertEqual({'clamshield-worker.service','clamshield-worker.timer'},set(value))
        args,kwargs=run.call_args;self.assertEqual(['/usr/bin/systemctl','show','--no-pager'],args[0][:3]);self.assertEqual(2,kwargs['timeout'])
        for error in (OSError(),subprocess.TimeoutExpired('fixture',2)):
            with patch('clamshield.scan_queue.subprocess.run',side_effect=error):self.assertEqual({},ScanQueue.units())
