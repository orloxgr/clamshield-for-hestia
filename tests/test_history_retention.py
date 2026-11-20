import fcntl
import json
import os
import time
import unittest
from unittest.mock import patch

import test_mail_custody as fixtures
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.history_retention import HistoryRetention, DEFAULTS, validate
from clamshield.store import encode


class HistoryRetentionTests(unittest.TestCase):
    setUp = fixtures.MailCustodyTests.setUp
    request_for = fixtures.MailCustodyTests.request_for
    items = fixtures.MailCustodyTests.items
    capture = fixtures.MailCustodyTests.capture
    delivery = fixtures.MailCustodyTests.delivery
    blob = fixtures.MailCustodyTests.blob

    def history(self):return HistoryRetention(self.settings,self.store,self.native)

    def save(self, context=None, **periods):
        context = context or self.alice
        return self.history().save(context, DEFAULTS | periods, self.history().get(context)['revision'])

    def job(self, context=None, count=2, *, source='manual', dedup=None):
        context = context or self.alice
        site = dict(owner=context['owner'],identity=context['identity'],domain=context['owner']+'.test',root='/tmp/fixture')
        job = self.store.enqueue(context,site,source=source,dedup_key=dedup)
        with self.store.connection(True) as db:
            db.execute("UPDATE jobs SET status='completed',finished=?,counters=? WHERE id=?",(time.time()-3*86400,encode({'scanned':count}),job))
            for i in range(count):db.execute('INSERT INTO file_results VALUES(NULL,?,?,?,?)',(job,str(i),'clean','{}'))
        return job,site

    def decision(self, context=None, *, outcome='accepted', exim_id='history-fixture'):
        context = context or self.alice
        import uuid
        key=uuid.uuid4().hex
        with self.store.connection(True) as db:
            db.execute('INSERT INTO mail_decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(key,*self.store.scope(context),context['owner']+'.test','inbox','inbox@'+context['owner']+'.test',exim_id,'sender@test',time.time()-3*86400,'a'*64,'tag','spam',encode({'smtp_outcome':outcome})))
        return key

    def test_default_keeps_data_preview_is_nonmutating_and_revision_changes(self):
        job,_=self.job();self.decision()
        before=self.history().get(self.alice)
        self.assertEqual(DEFAULTS,before['policy']);self.assertEqual(0,sum(before['preview'].values()))
        preview=self.history().get(self.alice,dict(scan_days=1,mail_days=1,event_days=1))
        self.assertEqual(1,preview['preview']['scan_reports']);self.assertEqual(2,preview['preview']['scan_file_rows'])
        self.assertEqual(1,preview['preview']['mail_decisions'])
        self.assertEqual(2,self.store.job(self.alice,job)['counters']['scanned'])
        saved=self.save(scan_days=1)
        self.assertNotEqual(saved['revision'],before['revision'])
        with self.assertRaises(Conflict):self.history().save(self.alice,DEFAULTS,before['revision'])

    def test_bounded_report_pruning_keeps_summary_and_scheduler_dedup(self):
        job,site=self.job(count=503,dedup='fixture-slot');self.save(scan_days=1)
        first=self.history().once();self.assertEqual(500,first['scan_file_rows']);self.assertEqual(0,first['scan_reports'])
        current=self.store.job(self.alice,job)
        self.assertTrue(current['counters']['history_expired']);self.assertTrue(current['counters']['history_prune_pending'])
        self.assertEqual(503,current['counters']['scanned'])
        self.assertEqual(job,self.store.enqueue(self.alice,site,dedup_key='fixture-slot'))
        second=self.history().once();self.assertEqual(3,second['scan_file_rows']);self.assertEqual(1,second['scan_reports'])
        self.assertEqual(0,self.history().once().get('scan_file_rows',0))

    def test_findings_and_recheck_references_keep_all_report_rows(self):
        finding_job,_=self.job();recheck,_=self.job();self.save(scan_days=1)
        with self.store.connection(True) as db:
            db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('finding',finding_job,*self.store.scope(self.alice),'alice.test','index.php','{}','clamav','Fixture','local','high',time.time(),'open','{}'))
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)',('operation','finding',*self.store.scope(self.alice),'alice','quarantine','restored',time.time(),encode({'recheck_job':recheck}),None))
        self.assertEqual(0,self.history().once()['scan_file_rows'])
        with self.store.connection() as db:self.assertEqual(4,db.execute('SELECT COUNT(*) FROM file_results').fetchone()[0])

    def test_queued_running_and_unfinished_automatic_discovery_keep_details(self):
        job,_=self.job();self.save(scan_days=1)
        with self.store.connection(True) as db:db.execute('INSERT INTO remediation_scans VALUES(?,0,0)',(job,))
        self.assertEqual(0,self.history().once()['scan_file_rows'])
        with self.store.connection(True) as db:db.execute('UPDATE remediation_scans SET finished=1');db.execute("UPDATE jobs SET status='running' WHERE id=?",(job,))
        self.assertEqual(0,self.history().once()['scan_file_rows'])

    def test_unconfirmed_mail_and_active_custody_are_protected(self):
        staged=self.capture();protected=self.decision(exim_id=self.request.message_id);unknown=self.decision(outcome=None,exim_id='unknown')
        eligible=self.decision(exim_id='settled');self.save(mail_days=1)
        self.assertEqual(1,self.history().once()['mail_decisions'])
        with self.store.connection() as db:
            ids={row['id'] for row in db.execute('SELECT id FROM mail_decisions')}
        self.assertEqual({protected,unknown},ids)
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_account_isolation_revocation_and_actor_recreation_preserve_data(self):
        alice,_=self.job();bob,_=self.job(self.bob);self.save(scan_days=1)
        admin=self.native.authorize('admin','alice')
        self.history().permission(admin,False,self.history().get(admin)['revision'])
        with self.assertRaises(AccessDenied):self.save(scan_days=1)
        self.assertEqual(1,self.history().once()['history_blocked'])
        self.history().permission(admin,True,self.history().get(admin)['revision'])
        self.assertEqual(1,self.history().once()['history_blocked'])
        self.save(scan_days=1);self.ids['alice']='new-generation'
        self.assertEqual(1,self.history().once()['history_blocked'])
        with self.assertRaises(AccessDenied):self.history().get(self.alice)
        self.assertEqual(DEFAULTS,self.history().get(self.native.authorize('alice'))['policy'])
        with self.store.connection() as db:self.assertEqual(4,db.execute('SELECT COUNT(*) FROM file_results').fetchone()[0])

    def test_admin_policy_is_independent_of_tenant_delegation(self):
        self.job();admin=self.native.authorize('admin','alice')
        self.history().permission(admin,False,self.history().get(admin)['revision'])
        self.save(admin,scan_days=1)
        self.assertEqual(2,self.history().once()['scan_file_rows'])

    def test_old_events_protect_references_and_unread_notifications(self):
        job,_=self.job();self.save(event_days=1)
        self.store.audit(self.alice,'fixture.unbound','unbound',{})
        self.store.notify('alice',self.ids['alice'],'fixture','unbound',{},'read')
        self.store.notify('alice',self.ids['alice'],'fixture','unread',{},'unread')
        with self.store.connection(True) as db:
            db.execute('UPDATE audit SET created=?',(time.time()-3*86400,))
            db.execute('UPDATE notifications SET created=?',(time.time()-3*86400,))
            db.execute("UPDATE notifications SET read_at=? WHERE dedup_key='read'",(time.time(),))
        result=self.history().once()
        self.assertEqual(2,result['audit_events']);self.assertEqual(1,result['read_notifications'])
        with self.store.connection() as db:
            self.assertTrue(db.execute('SELECT 1 FROM audit WHERE subject=?',(job,)).fetchone())
            self.assertEqual(1,db.execute('SELECT COUNT(*) FROM notifications').fetchone()[0])

    def test_transaction_interruption_rolls_back_rows_markers_and_audit(self):
        job,_=self.job();self.save(scan_days=1)
        audit=self.store.audit
        def stop(context,action,*args,**kwargs):
            if action=='history.pruned':raise fixtures.Interrupted()
            return audit(context,action,*args,**kwargs)
        with patch.object(self.store,'audit',side_effect=stop),self.assertRaises(fixtures.Interrupted):self.history().once()
        self.assertNotIn('history_expired',self.store.job(self.alice,job)['counters'])
        with self.store.connection() as db:self.assertEqual(2,db.execute('SELECT COUNT(*) FROM file_results').fetchone()[0])
        self.assertEqual(2,self.history().once()['scan_file_rows'])

    def test_reset_stops_pruning_and_invalid_periods_fail_closed(self):
        self.job();saved=self.save(scan_days=1)
        self.history().save(self.alice,None,saved['revision'],reset=True)
        self.assertEqual(0,self.history().once()['history_accounts'])
        for value in ({},DEFAULTS|{'scan_days':True},DEFAULTS|{'mail_days':-1},DEFAULTS|{'event_days':3651}):
            with self.assertRaises(ClamShieldError):validate(value)
        with self.assertRaises(AccessDenied):self.history().permission(self.alice,False,self.history().get(self.alice)['revision'])

    def test_recovery_lock_contention_and_native_deadline_are_preserved(self):
        self.job();self.save(scan_days=1);deadline=time.monotonic()+100;self.native.deadline=deadline
        with self.custody.locked():self.assertEqual({'history_busy':True},self.history().once())
        self.assertEqual(deadline,self.native.deadline)

    def test_report_read_racing_with_prune_never_reports_empty_clean_details(self):
        from clamshield.wordpress import WordPress
        from clamshield.rule_trials import RuleTrials
        for source,reporter in (('wordpress-integrity',WordPress),('yara-trial',RuleTrials)):
            job,_=self.job(source=source);self.save(scan_days=1)
            original=self.store.job(self.alice,job)
            self.history().once()
            with patch.object(self.store,'job',return_value=original),self.assertRaisesRegex(AccessDenied,'history expired'):
                reporter(self.settings,self.store,self.native).report(self.alice,job)

    def test_partial_summary_remains_partial_after_expiring_detail(self):
        job,_=self.job();self.save(scan_days=1)
        with self.store.connection(True) as db:
            db.execute("UPDATE jobs SET status='partial',counters=? WHERE id=?",(encode({'scanned':2,'errors':3,'skipped':1}),job))
        self.assertEqual(2,self.history().once()['scan_file_rows'])
        result=self.store.job(self.alice,job)
        self.assertEqual('partial',result['status']);self.assertEqual(3,result['counters']['errors']);self.assertEqual(1,result['counters']['skipped'])

    def test_dedup_recheck_edges_survive_interruption_before_parent_metadata_save(self):
        original,_=self.job();plan,_=self.job();child,_=self.job(dedup=plan+':apply');restored,_=self.job(dedup='restore-operation:restore')
        with self.store.connection(True) as db:
            db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('finding',original,*self.store.scope(self.alice),'alice.test','index.php','{}','clamav','Fixture','local','high',time.time(),'open','{}'))
            db.execute('INSERT INTO repair_plans VALUES(?,?,?,?,?,?,?,?,?)',(plan,'finding',*self.store.scope(self.alice),'alice','applying',time.time(),'{}',None))
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)',('restore-operation','finding',*self.store.scope(self.alice),'alice','quarantine','restoring',time.time(),'{}',None))
        self.save(scan_days=1)
        self.assertEqual(0,self.history().once()['scan_file_rows'])
        with self.store.connection() as db:self.assertEqual(8,db.execute('SELECT COUNT(*) FROM file_results').fetchone()[0])
