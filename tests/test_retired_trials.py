import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.application import Application
from clamshield.errors import AccessDenied
from clamshield.notification_preferences import NotificationPreferences
from clamshield.scheduler import Scheduler
from clamshield.settings import Settings
from clamshield.store import Store, encode
from clamshield.website_permissions import DEFAULTS, WebsitePermissions
from clamshield.worker import Worker


class RemovedTrialScans(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        base=Path(folder.name);self.root=base/'site';self.root.mkdir()
        self.settings=Settings(state=base/'state');self.settings.prepare()
        self.store=Store(self.settings.database)
        self.context=dict(actor='alice',owner='alice',identity='native-generation',admin=False)
        self.site=dict(owner='alice',identity='native-generation',domain='site.test',root=str(self.root),suspended=False)
        self.hestia=Mock();self.hestia.authorize.return_value=self.context;self.hestia.sites.return_value=[self.site]

    def test_old_endpoints_are_unsupported_for_users_and_administrators(self):
        app=Application(self.settings,self.store,self.hestia)
        for admin in (False,True):
            self.hestia.authorize.return_value=self.context|dict(admin=admin)
            for action in ('rules-trial','rules-trial-report','rules-trial-status'):
                with self.subTest(admin=admin,action=action),self.assertRaisesRegex(AccessDenied,'Unsupported operation'):
                    app.dispatch(dict(actor='alice',action=action,domain='site.test'))
        self.assertEqual([],self.store.list_jobs(self.context))

    def test_upgrade_cancels_only_pending_legacy_trials_once_and_preserves_history(self):
        queued=self.store.enqueue(self.context,self.site,source='yara-trial')
        running=self.store.enqueue(self.context,self.site,source='yara-trial')
        completed=self.store.enqueue(self.context,self.site,source='yara-trial')
        ordinary=self.store.enqueue(self.context,self.site,source='manual')
        with self.store.connection(True) as db:
            db.execute("UPDATE jobs SET status='running',counters=? WHERE id=?",(encode({'scanned':17,'errors':1}),running))
            db.execute("UPDATE jobs SET status='completed',counters=? WHERE id=?",(encode({'scanned':42}),completed))
            db.execute('CREATE TABLE rule_trials(job_id TEXT PRIMARY KEY,result TEXT)')
            db.execute('INSERT INTO rule_trials VALUES(?,?)',(completed,'historical evidence'))
        for _ in range(2):Store(self.settings.database)
        for job_id in (queued,running):
            job=self.store.job(self.context,job_id)
            self.assertEqual('cancelled',job['status']);self.assertTrue(job['cancel_requested'])
            self.assertIn('removed',job['error'])
        self.assertEqual({'scanned':17,'errors':1},self.store.job(self.context,running)['counters'])
        self.assertEqual('completed',self.store.job(self.context,completed)['status'])
        self.assertEqual('queued',self.store.job(self.context,ordinary)['status'])
        with self.store.connection() as db:
            self.assertEqual(1,db.execute("SELECT COUNT(*) FROM audit WHERE action='installation.trials_retired'").fetchone()[0])
            self.assertEqual('historical evidence',db.execute('SELECT result FROM rule_trials').fetchone()[0])
        self.assertEqual({'interrupted':0,'requeued':0},self.store.interrupt_for_update())

    def test_late_legacy_job_is_cancelled_before_any_engine_or_filesystem_scan(self):
        job_id=self.store.enqueue(self.context,self.site,source='yara-trial')
        job=self.store.claim('fixture');engine=Mock()
        with patch('clamshield.worker.walk',side_effect=AssertionError('No filesystem scan is allowed')):
            Worker(self.settings,self.store,self.hestia,[engine]).run(job)
        engine.scan.assert_not_called();self.hestia.authorize.assert_not_called()
        self.assertEqual('cancelled',self.store.job(self.context,job_id)['status'])
        self.assertEqual([],self.store.list_findings(self.context))

    def test_legacy_permissions_keep_all_current_choices_without_exposing_retired_permission(self):
        expected=DEFAULTS|{'quarantine':False,'scan':False}
        with self.store.connection(True) as db:
            db.execute('INSERT INTO website_permissions VALUES(?,?,?,?,?)',
                ('alice','native-generation',encode(expected|{'rule_trials':True}),1,'old-revision'))
        permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        result=permissions.get(self.context)
        self.assertEqual(expected,result['permissions']);self.assertNotIn('rule_trials',result['labels'])
        with self.store.connection(True) as db:
            db.execute('UPDATE website_permissions SET settings=?',(encode(expected|{'rule_trials':'invalid'}),))
        with self.assertRaises(AccessDenied):permissions.get(self.context)

    def test_notification_preferences_filter_retired_category_and_remain_saveable(self):
        with self.store.connection(True) as db:
            db.execute('''INSERT INTO notification_preferences(actor,identity,bell,categories,starts_after,revision,updated)
                VALUES(?,?,0,?,0,'old-revision',1)''',('alice','native-generation',json.dumps(['detections','trials'])))
        prefs=NotificationPreferences(self.settings,self.store,self.hestia)
        current=prefs.get(self.context)
        self.assertEqual(['detections'],current['settings']['categories']);self.assertNotIn('trials',current['categories'])
        saved=prefs.save(self.context,dict(bell=False,categories=['detections']),current['settings']['revision'])
        self.assertEqual(['detections'],saved['settings']['categories'])

    def test_historical_trial_does_not_count_as_a_clean_website_baseline(self):
        job_id=self.store.enqueue(self.context,self.site,source='yara-trial',generation='fixture')
        with self.store.connection(True) as db:db.execute("UPDATE jobs SET status='completed',finished=1 WHERE id=?",(job_id,))
        scheduler=Scheduler(self.settings,self.store,self.hestia)
        scheduler.save(self.context,self.site,{'watch':True})
        from datetime import datetime,timezone
        queued=scheduler.site(self.context,self.site,'fixture',datetime.now(timezone.utc))
        self.assertEqual(1,len(queued));self.assertEqual('watch-initial',self.store.job(self.context,queued[0])['source'])
