from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from clamshield.paths import attributes
from clamshield.scheduler import DEFAULTS, Scheduler, schedule_slot, validate_policy
from clamshield.settings import Settings
from clamshield.store import Store


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
        ids=self.scheduler.site(self.context,self.site,'new-rules',datetime.now(timezone.utc))
        self.assertEqual(1,len(ids))
        job=self.store.job(self.context,ids[0])
        self.assertEqual('signature-update',job['source'])
        self.assertEqual('',job['target'])
