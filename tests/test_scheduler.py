from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.paths import attributes
from clamshield.scheduler import DEFAULTS, Scheduler, schedule_slot, validate_policy
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.providers import Providers


class CalendarSchedules(unittest.TestCase):
    def test_fall_dst_repeated_hour_has_one_calendar_slot(self):
        policy = validate_policy({'frequency': 'daily', 'time': '03:15', 'timezone': 'Europe/Athens'})
        first = datetime(2026,10,25,0,30,tzinfo=timezone.utc)
        second = datetime(2026,10,25,1,30,tzinfo=timezone.utc)
        self.assertEqual(schedule_slot(policy, first), schedule_slot(policy, second))

    def test_monthday_31_runs_on_last_day_of_short_month(self):
        policy = validate_policy({'frequency':'monthly','time':'02:00','monthday':31})
        self.assertEqual('monthly:2026-02-28', schedule_slot(policy,datetime(2026,2,28,3,tzinfo=timezone.utc)))


class Monitoring(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'site';self.root.mkdir()
        self.settings=Settings(state=Path(self.temp.name)/'state')
        self.store=Store(self.settings.database)
        self.context=dict(actor='alice',owner='alice',identity='generation')
        self.site=dict(owner='alice',identity='generation',domain='site.test',root=str(self.root),suspended=False)
        self.scheduler=Scheduler(self.settings,self.store,Mock())

    def test_enabled_schedule_runs_once_and_replay_is_idempotent(self):
        before=datetime(2026,11,18,1,tzinfo=timezone.utc)
        self.scheduler.save(self.context,self.site,{'frequency':'daily'},before)
        due=datetime(2026,11,18,3,tzinfo=timezone.utc)
        ids=self.scheduler.site(self.context,self.site,'rules',due)
        self.assertEqual(1,len(ids))
        self.assertEqual([],self.scheduler.site(self.context,self.site,'rules',due))
        # Simulate a crash after job creation and before last_slot update, after
        # the job itself has already completed.
        with self.store.connection() as db:
            db.execute("UPDATE jobs SET status='completed',finished=1")
            db.execute("UPDATE policies SET last_slot='daily:2026-11-17'")
        self.scheduler.site(self.context,self.site,'rules',due)
        self.assertEqual(1,len(self.store.list_jobs(self.context)))

    def test_only_changed_files_are_queued_after_baseline_scan(self):
        clean=self.root/'clean.php';clean.write_text('clean')
        changed=self.root/'changed.php';changed.write_text('before')
        self.scheduler.save(self.context,self.site,{'watch':True})
        job_id=self.store.enqueue(self.context,self.site,generation='unconfigured')
        job=self.store.claim('test')
        for path in (clean,changed):
            self.store.observed(job,path.name,attributes(path.stat())|{'sha256':'fixture'})
        self.store.finish(job,'completed',{})
        changed.write_text('after modification')
        ids=self.scheduler.site(self.context,self.site,'unconfigured',datetime.now(timezone.utc))
        self.assertEqual(1,len(ids))
        self.assertEqual('changed.php',self.store.job(self.context,ids[0])['target'])

    def test_integrity_job_cannot_replace_or_suppress_malware_baseline(self):
        self.scheduler.save(self.context,self.site,{'watch':True})
        integrity=self.store.enqueue(self.context,self.site,source='wordpress-integrity',generation='new')
        pending=self.scheduler.site(self.context,self.site,'new',datetime.now(timezone.utc))
        self.assertEqual(1,len(pending))
        self.assertEqual('watch-initial',self.store.job(self.context,pending[0])['source'])
        with self.store.connection() as db:
            db.execute("UPDATE jobs SET status='completed',finished=100 WHERE id=?",(integrity,))
            db.execute("DELETE FROM jobs WHERE id=?",(pending[0],))
        pending=self.scheduler.site(self.context,self.site,'new',datetime.now(timezone.utc))
        self.assertEqual('watch-initial',self.store.job(self.context,pending[0])['source'])

    def test_recreated_account_does_not_inherit_old_policy(self):
        self.scheduler.save(self.context,self.site,{'watch':True})
        new_context=self.context|{'identity':'replacement'}
        self.assertFalse(self.scheduler.policy(new_context,self.site)['watch'])

    def test_new_rule_generation_queues_full_recheck_without_file_changes(self):
        job_id=self.store.enqueue(self.context,self.site,generation='old-rules')
        job=self.store.claim('test');self.store.finish(job,'completed',{})
        with patch('clamshield.rules.download',side_effect=AssertionError('Scans must not download rules')),patch('clamshield.signatures.Signatures.update',side_effect=AssertionError('Scans must not update signatures')):
            ids=self.scheduler.site(self.context,self.site,'new-rules',datetime.now(timezone.utc))
        self.assertEqual(1,len(ids))
        job=self.store.job(self.context,ids[0])
        self.assertEqual('signature-update',job['source'])
        self.assertEqual('',job['target'])

    def test_provider_timer_uses_provider_intervals_and_server_cooldowns_instead_of_an_hourly_constant(self):
        providers=Providers(self.settings);providers.save({'official':{'interval_minutes':180}})
        instant=datetime.now(timezone.utc);anchor=instant.timestamp()-7200
        providers.status('official',last_attempt=anchor,last_success=anchor)
        self.scheduler.hestia.inventory.return_value=[{'owner':'admin','identity':'admin-generation','role':'admin','suspended':False,'sites':[]}]
        with patch('clamshield.scheduler.Health'):
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            providers.save({'official':{'interval_minutes':60}})
            providers.status('official',retry_after=instant.timestamp()+3600)
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            providers.status('official',retry_after=None)
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(1,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])

    def baseline(self):
        self.store.enqueue(self.context,self.site,generation='old-rules')
        job=self.store.claim('test');self.store.finish(job,'completed',{})
        return job

    def tick_site(self,generation='new-rules'):
        return self.scheduler.site(self.context,self.site,generation,datetime.now(timezone.utc))

    def test_cancelled_recheck_stays_cancelled_and_watch_initial_cannot_replace_it(self):
        self.baseline();self.scheduler.save(self.context,self.site,{'watch':True})
        job=self.tick_site()[0];self.store.cancel(self.context,job)
        for _ in range(3):self.assertEqual([],self.tick_site())
        self.assertEqual('cancelled',self.store.job(self.context,job)['status'])
        with self.store.connection() as db:self.assertEqual('old-rules',db.execute("SELECT generation FROM jobs WHERE status='completed'").fetchone()[0])
        newer=self.tick_site('newer-rules');self.assertEqual(1,len(newer))
        self.store.cancel(self.context,newer[0])
        manual=self.store.enqueue(self.context,self.site,generation='new-rules')
        self.assertEqual('queued',self.store.job(self.context,manual)['status'])

    def test_running_cancel_remains_effective_after_worker_finishes(self):
        self.baseline();job_id=self.tick_site()[0];job=self.store.claim('test')
        self.store.cancel(self.context,job_id);self.assertEqual([],self.tick_site())
        self.store.finish(job,'cancelled',{'seen':3,'scanned':2})
        self.assertEqual([],self.tick_site())
        self.assertEqual(2,self.store.job(self.context,job_id)['counters']['scanned'])

    def test_cancelled_initial_watch_stays_cancelled_for_same_generation(self):
        self.scheduler.save(self.context,self.site,{'watch':True})
        job=self.tick_site()[0];self.assertEqual('watch-initial',self.store.job(self.context,job)['source'])
        self.store.cancel(self.context,job);self.assertEqual([],self.tick_site())
        self.assertEqual(1,len(self.tick_site('newer-rules')))

    def test_cancelled_full_recheck_keeps_individual_changed_file_monitoring(self):
        path=self.root/'changed.php';path.write_text('before')
        job=self.baseline();self.store.observed(job,path.name,attributes(path.stat())|{'sha256':'fixture'})
        self.scheduler.save(self.context,self.site,{'watch':True})
        full=self.tick_site()[0];self.store.cancel(self.context,full);self.assertEqual([],self.tick_site())
        path.write_text('changed contents')
        queued=self.tick_site();self.assertEqual(1,len(queued))
        changed=self.store.job(self.context,queued[0]);self.assertEqual(('watch','changed.php'),(changed['source'],changed['target']))

    def test_cancel_intent_is_bound_to_native_identity_root_and_generation(self):
        job=self.store.enqueue(self.context,self.site,source='signature-update',generation='rules')
        self.store.cancel(self.context,job)
        self.assertIsNone(self.store.enqueue(self.context,self.site,source='watch-initial',generation='rules'))
        for context,site in [(self.context,self.site|{'root':str(self.root/'replacement')}),(self.context|{'identity':'replacement'},self.site|{'identity':'replacement'})]:
            self.assertIsNotNone(self.store.enqueue(context,site,source='signature-update',generation='rules'))

    def test_auto_admission_is_atomic_and_cancelling_legacy_twins_keeps_manual_work(self):
        job=self.store.enqueue(self.context,self.site,source='signature-update',generation='rules')
        self.assertIsNone(self.store.enqueue(self.context,self.site,source='watch-initial',generation='rules'))
        twin=self.store.enqueue(self.context,self.site,source='manual',generation='rules')
        manual=self.store.enqueue(self.context,self.site,source='manual',generation='rules')
        with self.store.connection(True) as db:db.execute("UPDATE jobs SET source='watch-initial' WHERE id=?",(twin,))
        self.store.cancel(self.context,job)
        self.assertEqual('cancelled',self.store.job(self.context,twin)['status'])
        self.assertEqual('queued',self.store.job(self.context,manual)['status'])

    def test_cancelled_update_replacement_binds_the_current_generation(self):
        from clamshield.generations import current
        job=self.store.enqueue(self.context,self.site,source='signature-update')
        self.store.cancel(self.context,job)
        self.assertEqual(current(self.settings),self.store.job(self.context,job)['generation'])
        self.assertIsNone(self.store.enqueue(self.context,self.site,source='watch-initial',generation=current(self.settings)))

    def test_yara_timer_uses_saved_interval_cooldown_installed_profile_and_deduplicates_work(self):
        from clamshield.rule_updates import RuleUpdates
        Providers(self.settings).save({'automatic':False})
        updates=RuleUpdates(self.settings);instant=datetime.now(timezone.utc)
        updates.save({'interval_minutes':180});updates.record(last_attempt=instant.timestamp()-7200)
        self.scheduler.hestia.inventory.return_value=[{'owner':'admin','identity':'admin-generation','role':'admin','suspended':False,'sites':[]}]
        payload={'profile':'extended','release':None,'automatic':True,'revision':'fixture'}
        with patch('clamshield.scheduler.Health'),patch('clamshield.rule_manager.RuleManager') as manager:
            manager.return_value.automatic_update.return_value=payload
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            updates.save({'interval_minutes':60});updates.record(retry_after=instant.timestamp()+3600)
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            updates.record(retry_after=None)
            manager.return_value.automatic_update.return_value=None
            self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            manager.return_value.automatic_update.return_value=payload
            self.scheduler.tick(instant);self.scheduler.tick(instant)
            with self.store.connection() as db:self.assertEqual(1,db.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0])
            task=self.store.claim_task('test');self.assertEqual(payload,task['payload'])
            self.assertEqual(('admin','admin-generation'),(task['owner'],task['identity']))
