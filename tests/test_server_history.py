import hashlib
import json
import os
import time
import unittest
import uuid
from unittest.mock import Mock,patch

import test_mail_custody as fixtures
from clamshield.errors import AccessDenied,ClamShieldError,Conflict
from clamshield.server_history import ServerHistory,DEFAULTS,ANCHORS,validate
from clamshield.store import encode


class ServerHistoryTests(unittest.TestCase):
    setUp=fixtures.MailCustodyTests.setUp
    request_for=fixtures.MailCustodyTests.request_for

    def server(self):return ServerHistory(self.settings,self.store,self.native)
    def admin(self):return self.native.authorize('admin')
    def save(self,**periods):
        context=self.admin()
        return self.server().save(context,DEFAULTS|periods,self.server().get(context)['revision'])
    def task(self,action='fixture-action',age=3,status='completed'):
        key=uuid.uuid4().hex
        with self.store.connection(True) as db:
            db.execute('INSERT INTO maintenance VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(key,'admin',self.ids['admin'],'admin',action,encode({'private':'inert-fixture'}),time.time()-age*86400,time.time()-age*86400,time.time()-age*86400,status,'fixture-worker',encode({'generation':'fixture-generation','detail':['large','inert']}),'failure details' if status=='failed' else None))
        return key
    def row(self,key):
        with self.store.connection() as db:return dict(db.execute('SELECT * FROM maintenance WHERE id=?',(key,)).fetchone())

    def test_admin_only_scope_validation_and_nonmutating_default_preview(self):
        self.assertEqual(DEFAULTS,self.server().get(self.admin())['policy'])
        self.assertFalse(self.server().once()['server_history_configured'])
        for method in (lambda:self.server().get(self.alice),lambda:self.server().save(self.alice,DEFAULTS,'default'),lambda:self.server().save(self.alice,None,'default',reset=True)):
            with self.assertRaises(AccessDenied):method()
        for value in ({},DEFAULTS|{'event_days':True},DEFAULTS|{'maintenance_days':-1},DEFAULTS|{'event_days':3651}):
            with self.assertRaises(ClamShieldError):validate(value)

    def test_preview_revision_and_reset_leave_policy_disabled_by_default(self):
        before=self.server().get(self.admin());self.task(age=4);self.task(age=3)
        preview=self.server().get(self.admin(),DEFAULTS|{'maintenance_days':1})
        self.assertEqual(1,preview['preview']['maintenance_details'])
        self.assertEqual(before['revision'],self.server().get(self.admin())['revision'])
        saved=self.save(maintenance_days=1)
        with self.assertRaises(Conflict):self.server().save(self.admin(),DEFAULTS,before['revision'])
        reset=self.server().save(self.admin(),None,saved['revision'],reset=True)
        self.assertEqual(DEFAULTS,reset['policy']);self.assertFalse(self.server().once()['server_history_configured'])

    def test_compaction_keeps_latest_status_identity_hash_receipts_and_no_resubmit(self):
        older=self.task(age=4,status='failed');latest=self.task(age=3,status='failed');before=self.row(older)
        self.save(maintenance_days=1);result=self.server().once();self.assertEqual(1,result['maintenance_details'])
        after=self.row(older);receipt=json.loads(after['result'])
        for key in ('id','owner','identity','actor','action','created','started','finished','status','worker'):self.assertEqual(before[key],after[key])
        self.assertEqual('{}',after['payload']);self.assertEqual('failed',after['status'])
        self.assertEqual(hashlib.sha256(before['payload'].encode()).hexdigest(),receipt['payload_sha256'])
        self.assertEqual(hashlib.sha256(before['result'].encode()).hexdigest(),receipt['result_sha256'])
        self.assertEqual('Detailed maintenance history expired',after['error'])
        self.assertNotIn('history_expired',json.loads(self.row(latest)['result']))
        self.assertEqual(0,self.server().once()['maintenance_details']);self.assertIsNone(self.store.claim_task('fixture-worker'))

    def test_server_events_only_and_permanent_recovery_anchors(self):
        contexts=[dict(actor='fixture',owner='@admin',identity=''),self.alice]
        for context in contexts:self.store.audit(context,'fixture.event','unbound',{})
        for anchor in ANCHORS:self.store.audit(contexts[0],anchor,'catalog-or-refresh',{})
        with self.store.connection(True) as db:db.execute('UPDATE audit SET created=?',(time.time()-3*86400,))
        self.save(event_days=1);self.assertEqual(1,self.server().once()['server_events'])
        with self.store.connection() as db:
            self.assertEqual(2,db.execute('SELECT COUNT(*) FROM audit WHERE action IN (?,?)',ANCHORS).fetchone()[0])
            self.assertEqual(1,db.execute("SELECT COUNT(*) FROM audit WHERE owner='alice'").fetchone()[0])

    def test_unread_and_referenced_notices_remain(self):
        task=self.task();context=dict(actor='fixture',owner='@admin',identity='')
        for subject,key,read in (('unbound','eligible',True),('unbound','unread',False),(task,'referenced',True)):
            self.store.notify('@admin','','fixture',subject,{},key)
            with self.store.connection(True) as db:db.execute('UPDATE notifications SET created=?,read_at=? WHERE dedup_key=?',(time.time()-3*86400,time.time() if read else None,key))
        self.save(event_days=1);self.assertEqual(1,self.server().once()['read_server_notifications'])
        with self.store.connection() as db:self.assertEqual({'unread','referenced'},{row[0] for row in db.execute('SELECT dedup_key FROM notifications')})

    def test_queued_and_running_tasks_defer_pruning(self):
        first=self.task(age=4);self.task(age=3);queued=self.task(status='queued');self.save(maintenance_days=1)
        for state in ('queued','running'):
            with self.store.connection(True) as db:db.execute('UPDATE maintenance SET status=? WHERE id=?',(state,queued))
            self.assertIn('server_history_deferred',self.server().once())
            self.assertEqual(0,self.server().get(self.admin(),DEFAULTS|{'maintenance_days':1})['preview']['maintenance_details'])
            self.assertNotIn('history_expired',json.loads(self.row(first)['result']))

    def test_pending_or_symlinked_journal_defers_without_reading_it(self):
        first=self.task(age=4);self.task(age=3);self.save(maintenance_days=1)
        journal=self.settings.state/'signature-activation.json';journal.symlink_to('/nonexistent/foreign')
        self.assertIn('server_history_deferred',self.server().once());journal.unlink()
        journal.write_text('untrusted invalid fixture')
        self.assertIn('server_history_deferred',self.server().once())
        self.assertNotIn('history_expired',json.loads(self.row(first)['result']))

    def test_live_maintenance_lock_is_nonblocking_and_preserves_deadline(self):
        self.task(age=4);self.task(age=3);self.save(maintenance_days=1)
        deadline=time.monotonic()+100;self.native.deadline=deadline
        with self.server().maintenance_lock():self.assertEqual({'server_history_busy':True},self.server().once())
        self.assertEqual(deadline,self.native.deadline)

    def test_recreated_or_demoted_authorizing_admin_does_not_inherit_policy(self):
        first=self.task(age=4);self.task(age=3);self.save(maintenance_days=1)
        self.ids['admin']='recreated-admin'
        self.assertTrue(self.server().once()['server_history_blocked'])
        self.assertNotIn('history_expired',json.loads(self.row(first)['result']))
        self.save(maintenance_days=1)
        with patch.object(self.native,'authorize',return_value=self.alice):self.assertTrue(self.server().once()['server_history_blocked'])

    def test_referenced_maintenance_payload_is_not_compacted(self):
        first=self.task(age=4);self.task(age=3);self.save(maintenance_days=1)
        with self.store.connection(True) as db:
            db.execute("INSERT INTO jobs(id,owner,identity,domain,root,target,source,actor,created,counters,generation) VALUES(?,?,?,?,?,?,?,?,?,?,?)",('job',*self.store.scope(self.alice),'alice.test','/fixture','','fixture','alice',time.time(),encode({'task_id':first}),'fixture'))
        self.assertEqual(0,self.server().once()['maintenance_details'])

    def test_pruning_and_receipts_roll_back_as_one_transaction_on_interruption(self):
        first=self.task(age=4);self.task(age=3);before=self.row(first);self.save(maintenance_days=1)
        audit=self.store.audit
        def stop(context,action,*args,**kwargs):
            if action=='history.server_pruned':raise fixtures.Interrupted()
            return audit(context,action,*args,**kwargs)
        with patch.object(self.store,'audit',side_effect=stop),self.assertRaises(fixtures.Interrupted):self.server().once()
        self.assertEqual(before,self.row(first));self.assertEqual(1,self.server().once()['maintenance_details'])

    def test_task_and_event_batches_are_bounded(self):
        for age in range(3,105):self.task(age=age)
        self.save(maintenance_days=1)
        self.assertEqual(100,self.server().once()['maintenance_details'])
        self.assertEqual(1,self.server().once()['maintenance_details'])
