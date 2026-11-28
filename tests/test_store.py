from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import sqlite3
import time
import unittest
from unittest.mock import patch

from clamshield.errors import AccessDenied, Conflict
from clamshield.store import Store,SCHEMA,database_deadline


class ScopedStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.sqlite3')
        self.alice = dict(actor='alice', owner='alice', identity='alice-generation-1')
        self.bob = dict(actor='bob', owner='bob', identity='bob-generation-1')
        self.site = dict(owner='alice', identity='alice-generation-1', domain='alice.test', root='/srv/alice')

    def test_independent_connections_enforce_durable_wal_commits(self):
        for immediate in (False, True):
            with self.store.connection(immediate) as db:
                self.assertEqual('wal', db.execute('PRAGMA journal_mode').fetchone()[0])
                self.assertEqual(2, db.execute('PRAGMA synchronous').fetchone()[0])

    def test_request_deadline_bounds_real_sqlite_write_contention_and_resets(self):
        with self.store.connection(True):
            started=time.monotonic()
            with database_deadline(started+.08),self.assertRaises(sqlite3.OperationalError):
                with self.store.connection(True):self.fail('Concurrent write lock unexpectedly acquired')
            self.assertLess(time.monotonic()-started,1)
        with self.store.connection() as db:
            self.assertEqual(20000,db.execute('PRAGMA busy_timeout').fetchone()[0])
            self.assertEqual(2,db.execute('PRAGMA synchronous').fetchone()[0])

    def test_expired_request_does_not_open_database_and_nested_budget_cannot_extend(self):
        with database_deadline(time.monotonic()-1),patch('clamshield.store.sqlite3.connect') as connect:
            with self.assertRaisesRegex(sqlite3.OperationalError,'time budget'):
                with self.store.connection():pass
            connect.assert_not_called()
        with database_deadline(time.monotonic()+2):
            with database_deadline(time.monotonic()+20),self.store.connection() as db:
                self.assertLessEqual(db.execute('PRAGMA busy_timeout').fetchone()[0],2000)
        with self.store.connection() as db:self.assertEqual(20000,db.execute('PRAGMA busy_timeout').fetchone()[0])

    def test_request_deadline_does_not_leak_to_other_workers_or_after_error(self):
        def timeout():
            with self.store.connection() as db:return db.execute('PRAGMA busy_timeout').fetchone()[0]
        with ThreadPoolExecutor(max_workers=1) as pool:
            self.assertEqual(20000,pool.submit(timeout).result())
            with self.assertRaises(RuntimeError):
                with database_deadline(time.monotonic()-1):
                    self.assertEqual(20000,pool.submit(timeout).result())
                    raise RuntimeError('request failed')
        self.assertEqual(20000,timeout())

    def test_account_and_recreated_account_cannot_read_or_cancel_old_job(self):
        job = self.store.enqueue(self.alice, self.site)
        for context in (self.bob, self.alice | {'identity': 'alice-generation-2'}):
            self.assertEqual([], self.store.list_jobs(context))
            with self.assertRaises(AccessDenied):
                self.store.cancel(context, job)
            with self.assertRaises(AccessDenied):
                self.store.job(context, job)

    def test_only_one_worker_claims_each_job(self):
        ids = {self.store.enqueue(self.alice, self.site) for _ in range(20)}
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda i: self.store.claim('worker-' + str(i)), range(25)))
        claimed = [row['id'] for row in rows if row]
        self.assertEqual(ids, set(claimed))
        self.assertEqual(len(ids), len(claimed))

    def test_active_integrity_reuse_binds_root_target_source_and_native_generation(self):
        first=self.store.enqueue(self.alice,self.site,source='wordpress-integrity',reuse_active=True)
        self.assertEqual(first,self.store.enqueue(self.alice,self.site,source='wordpress-integrity',reuse_active=True))
        variants=[(self.alice,self.site,'blog','wordpress-integrity'),
            (self.alice,self.site,'','manual'),
            (self.alice,self.site|{'root':'/srv/replacement'},'','wordpress-integrity'),
            (self.alice|{'identity':'recreated'},self.site|{'identity':'recreated'},'','wordpress-integrity')]
        ids={first}
        for context,site,target,source in variants:
            job=self.store.enqueue(context,site,target,source=source,reuse_active=True)
            self.assertNotIn(job,ids);ids.add(job)

    def test_cancellation_is_terminal_for_queued_job(self):
        job = self.store.enqueue(self.alice, self.site)
        self.store.cancel(self.alice, job)
        self.assertIsNone(self.store.claim('worker'))
        self.assertEqual('cancelled', self.store.job(self.alice, job)['status'])
        with self.assertRaises(Conflict):
            self.store.cancel(self.alice, job)

    def test_audit_and_findings_are_scoped(self):
        job_id = self.store.enqueue(self.alice, self.site)
        job = self.store.claim('worker')
        self.store.add_finding(job, 'bad.php', {'sha256': 'abc'},
            dict(engine='yara', signature='Webshell', provider='local'))
        self.assertEqual(1, len(self.store.list_findings(self.alice)))
        self.assertEqual([], self.store.list_findings(self.bob))
        self.assertEqual([], self.store.history(self.bob))
        self.assertEqual(job_id, job['id'])

    def test_update_keeps_scan_evidence_and_queues_exact_scoped_fresh_scan_once(self):
        original=self.store.enqueue(self.alice,self.site,'uploads',source='manual',generation='old')
        job=self.store.claim('interrupted-worker')
        counters=dict(seen=8,scanned=7,infected=1,errors=0)
        self.store.progress(original,counters)
        self.store.add_finding(job,'uploads/bad.php',{'sha256':'abc'},dict(engine='yara',signature='Test',provider='local'))
        self.store.file_result(original,'uploads/bad.php','infected',{'fixture':True})
        self.assertEqual(dict(interrupted=1,requeued=1),self.store.interrupt_for_update())
        old=self.store.job(self.alice,original)
        self.assertEqual('failed',old['status']);self.assertEqual(counters,old['counters'])
        self.assertIn('coverage is incomplete',old['error'])
        replacements=[row for row in self.store.list_jobs(self.alice) if row['id']!=original]
        self.assertEqual(1,len(replacements));new=replacements[0]
        for field in ('owner','identity','actor','domain','root','target','source'):
            self.assertEqual(old[field],new[field])
        self.assertEqual('queued',new['status']);self.assertEqual({},new['counters'])
        self.assertEqual('unknown',new['generation'])
        self.assertEqual(1,len(self.store.list_findings(self.alice)))
        with self.store.connection() as db:
            self.assertEqual(1,db.execute('SELECT count(*) FROM file_results WHERE job_id=?',(original,)).fetchone()[0])
        self.assertEqual(dict(interrupted=0,requeued=0),self.store.interrupt_for_update())
        self.assertEqual(2,len(self.store.list_jobs(self.alice)))
        for foreign in (self.bob,self.alice|{'identity':'recreated'}):
            self.assertEqual([],self.store.list_jobs(foreign));self.assertEqual([],self.store.history(foreign))
        self.assertEqual(new['id'],self.store.claim('new-worker')['id'])

    def test_update_never_replays_mutations_cancelled_work_or_unclaimed_jobs(self):
        repair=self.store.enqueue(self.alice,self.site,source='repair-preview')
        self.store.claim('worker')
        cancelled=self.store.enqueue(self.alice,self.site)
        self.store.claim('other-worker');self.store.cancel(self.alice,cancelled)
        queued=self.store.enqueue(self.alice,self.site)
        self.assertEqual(dict(interrupted=2,requeued=0),self.store.interrupt_for_update())
        self.assertEqual('failed',self.store.job(self.alice,repair)['status'])
        self.assertEqual('cancelled',self.store.job(self.alice,cancelled)['status'])
        self.assertEqual('queued',self.store.job(self.alice,queued)['status'])
        self.assertEqual(3,len(self.store.list_jobs(self.alice)))

    def test_update_interruption_and_replacement_roll_back_together(self):
        original=self.store.enqueue(self.alice,self.site);self.store.claim('worker')
        with patch.object(self.store,'audit',side_effect=RuntimeError('Simulated interruption')):
            with self.assertRaises(RuntimeError):self.store.interrupt_for_update()
        self.assertEqual('running',self.store.job(self.alice,original)['status'])
        self.assertEqual(1,len(self.store.list_jobs(self.alice)))

    def test_service_control_yield_preserves_evidence_and_requeues_scoped_full_scan_once(self):
        original=self.store.enqueue(self.alice,self.site,'uploads',source='manual',generation='old')
        job=self.store.claim('worker');counters=dict(seen=8,scanned=7,infected=1,errors=1)
        self.store.add_finding(job,'uploads/bad.php',{'sha256':'abc'},dict(engine='yara',signature='Fixture',provider='local'))
        self.store.file_result(original,'uploads/bad.php','error',{'fixture':True})
        self.store.enqueue_task(self.bob,'website-engine-start',{})
        self.assertFalse(self.store.yield_for_website_control(job|{'worker':'foreign'},counters))
        self.assertTrue(self.store.yield_for_website_control(job,counters))
        self.assertFalse(self.store.yield_for_website_control(job,counters))
        old=self.store.job(self.alice,original);self.assertEqual('partial',old['status']);self.assertEqual(counters,old['counters'])
        new=next(row for row in self.store.list_jobs(self.alice) if row['id']!=original)
        for key in ('owner','identity','actor','root','domain','target','source'):self.assertEqual(old[key],new[key])
        self.assertEqual('queued',new['status']);self.assertEqual('unknown',new['generation']);self.assertEqual({},new['counters'])
        self.assertEqual(1,len(self.store.list_findings(self.alice)));self.assertEqual([],self.store.list_jobs(self.bob))
        with self.store.connection() as db:self.assertEqual(1,db.execute('SELECT count(*) FROM file_results WHERE job_id=?',(original,)).fetchone()[0])

    def test_service_yield_requeue_is_atomic_and_never_replays_repair_or_cancelled_work(self):
        original=self.store.enqueue(self.alice,self.site);job=self.store.claim('worker')
        self.store.enqueue_task(self.bob,'website-engine-stop',{})
        with patch.object(self.store,'audit',side_effect=RuntimeError('Interrupted transaction')):
            with self.assertRaises(RuntimeError):self.store.yield_for_website_control(job,{'seen':1})
        self.assertEqual('running',self.store.job(self.alice,original)['status']);self.assertEqual(1,len(self.store.list_jobs(self.alice)))
        self.store.cancel(self.alice,original);self.assertFalse(self.store.yield_for_website_control(job,{}))
        repair=self.store.enqueue(self.alice,self.site,source='repair-preview');repair_job=self.store.claim('repair-worker')
        self.assertEqual(repair,repair_job['id']);self.assertFalse(self.store.yield_for_website_control(repair_job,{}))

    def test_service_tasks_have_priority_and_report_actual_phase_and_blocking_work(self):
        update=self.store.enqueue_task(self.alice,'signatures-update',{})
        control=self.store.enqueue_task(self.alice,'website-engine-start',{})
        task=self.store.claim_task('maintenance',prioritize_website=True);self.assertEqual(control,task['id'])
        self.store.task_progress(task,'waiting-scan')
        status=self.store.website_engine_status(self.alice);self.assertEqual('waiting-scan',status['latest']['phase']);self.assertTrue(status['pending'])
        self.store.finish_task(task,{'verified':True});running=self.store.claim_task('maintenance',prioritize_website=True)
        self.assertEqual(update,running['id']);self.store.enqueue_task(self.alice,'website-engine-start',{})
        status=self.store.website_engine_status(self.alice);self.assertEqual('queued',status['latest']['status']);self.assertEqual('signatures-update',status['blocking_action'])

    def test_dashboard_totals_include_rows_beyond_preview_limits_and_isolate_account_generation(self):
        old = self.store.enqueue(self.alice, self.site)
        with self.store.connection() as db:
            db.execute('UPDATE jobs SET created=0 WHERE id=?',(old,))
            for n in range(201):
                db.execute("INSERT INTO jobs(id,owner,identity,domain,root,target,source,actor,created,generation,status) VALUES(?,?,?,?,?,'','manual',?,?,'test','completed')",
                           ('recent-'+str(n),*self.store.scope(self.alice),'alice.test','/srv/alice','alice',n+1))
            for n in range(501):
                db.execute("INSERT INTO findings(id,job_id,owner,identity,domain,path,fingerprint,engine,signature,provider,severity,created,status) VALUES(?,?,?,?,?,'sample','{}','yara','Test','local','review',?,?)",
                           ('f-'+str(n),old,*self.store.scope(self.alice),'alice.test',n,'open' if n<500 else 'resolved'))
            for n in range(302):
                db.execute("INSERT INTO operations(id,finding_id,owner,identity,actor,kind,status,created,metadata) VALUES(?,?,?,?,?,'quarantine',?,?, '{}')",
                           ('q-'+str(n),'f-0',*self.store.scope(self.alice),'alice','quarantined' if n<301 else 'restored',n))
        self.assertEqual(500,len(self.store.list_findings(self.alice)))
        self.assertEqual(499,sum(v['status']=='open' for v in self.store.list_findings(self.alice)))
        self.assertFalse(any(v['status']=='queued' for v in self.store.list_jobs(self.alice)))
        self.assertEqual(dict(open_findings=500,active_scans=1,quarantined=301),self.store.dashboard_counts(self.alice))
        for other in (self.bob,self.alice|{'identity':'recreated'}):
            self.assertEqual(dict(open_findings=0,active_scans=0,quarantined=0),self.store.dashboard_counts(other))

    def test_system_audit_is_visible_to_native_admin_context_only_and_keeps_tenant_generation_scope(self):
        self.store.audit(dict(actor='clamshield-maintenance',owner='@admin',identity=''),'mail.refresh_rebased','server',{'fixture':True})
        self.store.audit(self.alice,'owner.event','old-account',{})
        self.assertEqual(['owner.event'],[r['action'] for r in self.store.history(self.alice)])
        self.assertEqual([],self.store.history(self.alice|{'identity':'recreated-account'}))
        self.assertEqual([],self.store.history(self.bob))
        actions={r['action'] for r in self.store.history(self.bob|{'admin':True})}
        self.assertEqual({'mail.refresh_rebased'},actions)

    def test_rule_provenance_is_a_scoped_snapshot_of_the_actual_detection(self):
        self.store.enqueue(self.alice,self.site);job=self.store.claim('worker')
        detection=dict(engine='yara',signature='local:Rule',provider='local',rule_id='local:Rule',
                       source_version='1',license='MIT',rule_sha256='a'*64)
        finding_id=self.store.add_finding(job,'bad.php',{'sha256':'abc'},detection)
        detection['source_version']='changed later'
        self.assertEqual('1',self.store.finding(self.alice,finding_id)['detail']['source_version'])
        with self.assertRaises(AccessDenied):self.store.finding(self.bob,finding_id)

    def test_concurrent_legacy_database_migration_preserves_existing_findings(self):
        path=Path(self.temp.name)/'legacy.sqlite3'
        with sqlite3.connect(path) as db:
            db.executescript(SCHEMA.replace(", detail TEXT NOT NULL DEFAULT '{}'",''))
            db.execute("INSERT INTO jobs(id,owner,identity,domain,root,target,source,actor,created,generation) VALUES('j','alice','alice-generation-1','alice.test','/srv/alice','','manual','alice',1,'old')")
            db.execute("INSERT INTO findings(id,job_id,owner,identity,domain,path,fingerprint,engine,signature,provider,severity,created) VALUES('f','j','alice','alice-generation-1','alice.test','old.php','{}','yara','Old','yara','review',1)")
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _:Store(path),range(4)))
        self.assertEqual({},Store(path).finding(self.alice,'f')['detail'])
        self.assertEqual('Old',Store(path).finding(self.alice,'f')['signature'])

    def test_unsafe_initialization_lock_cannot_redirect_or_share_state(self):
        import os
        path=Path(self.temp.name)/'new.sqlite3';lock=path.with_name(path.name+'.init.lock')
        target=Path(self.temp.name)/'untouched';target.write_bytes(b'keep')
        lock.symlink_to(target)
        with self.assertRaises((OSError,AccessDenied)):Store(path)
        self.assertEqual(b'keep',target.read_bytes());lock.unlink()
        os.link(target,lock)
        with self.assertRaises(AccessDenied):Store(path)
        lock.unlink();lock.write_bytes(b'');lock.chmod(0o666)
        with self.assertRaises(AccessDenied):Store(path)
