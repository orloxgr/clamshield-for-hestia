import json
import time
import unittest
from unittest.mock import patch

import test_mail_custody as fixtures
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.mail_policy import PERMISSIONS
from clamshield.mail_retention import MailRetention
from clamshield.store import encode


class MailRetentionTests(unittest.TestCase):
    request_for = fixtures.MailCustodyTests.request_for
    items = fixtures.MailCustodyTests.items
    capture = fixtures.MailCustodyTests.capture
    blob = fixtures.MailCustodyTests.blob
    delivery = fixtures.MailCustodyTests.delivery

    def setUp(self):
        fixtures.MailCustodyTests.setUp(self)
        self.retention = MailRetention(self.settings, self.store, self.native)
        self.now = time.time()+2*86400

    def save(self, context, period, mailbox='', inherit=False):
        domain = context['owner']+'.test'
        before = self.retention.get(context, domain, mailbox)
        return self.retention.save(context, domain, mailbox, {'inherit':True} if inherit else {'days':period}, before['revision'])

    def permission(self, owner, **changes):
        context = self.native.authorize('admin', owner)
        return self.policies.save_permissions(context, dict.fromkeys(PERMISSIONS,True)|changes)

    def test_default_keeps_originals_and_preview_never_changes_policy_or_custody(self):
        staged = self.capture()
        result = self.retention.get(self.alice, 'alice.test', proposed={'days':1}, now=self.now)
        self.assertEqual(0, result['effective_days']); self.assertEqual(1, result['summary']['due'])
        self.assertEqual(1, result['summary']['eligible'])
        self.assertEqual(0, self.retention.once(now=self.now)['mail_expired'])
        self.assertEqual(fixtures.MESSAGE, self.blob(staged['transaction_id']).read_bytes())
        self.assertIsNone(self.custody.list(self.alice)['messages'][0]['expiry_at'])
        with self.store.connection() as db:
            self.assertEqual(0, db.execute('SELECT COUNT(*) FROM mail_retention_policies').fetchone()[0])
            self.assertEqual(0, db.execute('SELECT COUNT(*) FROM mail_expiry_actions').fetchone()[0])

    def test_expiry_preserves_shared_body_then_removes_last_copy_and_keeps_history(self):
        staged = self.capture(); self.save(self.alice, 1)
        self.assertIsNotNone(self.custody.list(self.alice)['messages'][0]['expiry_at'])
        self.assertEqual(1, self.retention.once(now=self.now)['mail_expired'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())
        self.assertEqual('expired', self.retention.history(self.alice)['actions'][0]['status'])
        self.assertEqual([], self.retention.history(self.bob)['actions'])
        self.save(self.bob, 1)
        self.assertEqual(1, self.retention.once(now=self.now)['mail_expired'])
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual(0, self.retention.once(now=self.now)['mail_expired'])
        with self.store.connection() as db:
            self.assertEqual(2, db.execute("SELECT COUNT(*) FROM audit WHERE action='mail.expired'").fetchone()[0])
            self.assertEqual(1, db.execute('SELECT COUNT(*) FROM mail_transactions').fetchone()[0])

    def test_mailbox_override_zero_and_return_to_domain_inheritance(self):
        staged = self.capture(); self.save(self.alice, 1); own = self.save(self.alice, 0, 'inbox')
        self.assertFalse(own['inherited']); self.assertEqual(0, own['effective_days'])
        self.assertEqual(0, self.retention.once(now=self.now)['mail_expired'])
        inherited = self.save(self.alice, 0, 'inbox', inherit=True)
        self.assertTrue(inherited['inherited']); self.assertEqual(1, inherited['effective_days'])
        self.assertEqual(1, self.retention.once(now=self.now)['mail_expired'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_stale_revision_and_browser_authority_fields_cannot_change_policy(self):
        before = self.retention.get(self.alice, 'alice.test', 'inbox')
        self.save(self.alice, 2)
        with self.assertRaises(Conflict):self.retention.save(self.alice, 'alice.test', 'inbox', {'days':1}, before['revision'])
        for value in ({'days':True}, {'days':-1}, {'days':3651}, {'days':1.0}, {'days':1,'actor':'admin'}, {'inherit':1}, []):
            with self.subTest(value=value), self.assertRaises(ClamShieldError):
                self.retention.save(self.alice, 'alice.test', '', value, self.retention.get(self.alice,'alice.test')['revision'])
        with self.assertRaises(AccessDenied):self.retention.get(self.alice, 'bob.test')
        with self.assertRaises(AccessDenied):self.retention.get(self.alice, None)

    def test_delete_permission_is_independent_and_revocation_holds_existing_expiry(self):
        staged = self.capture(); self.permission('alice', manage_policy=False)
        self.save(self.alice, 1)
        self.permission('alice', delete=False, manage_policy=True)
        self.assertFalse(self.retention.get(self.alice,'alice.test')['can_manage'])
        with self.assertRaises(AccessDenied):self.save(self.alice, 0)
        self.assertEqual(1, self.retention.once(now=self.now)['mail_expiry_blocked'])
        self.assertEqual(fixtures.MESSAGE, self.blob(staged['transaction_id']).read_bytes())
        self.assertEqual(0, self.retention.once(now=self.now+1)['mail_expiry_considered'])
        self.permission('alice', delete=True)
        self.retention.retry(self.alice,self.delivery(self.alice))
        self.assertEqual(1, self.retention.once(now=self.now+2)['mail_expired'])

    def test_admin_authority_survives_tenant_permission_restriction_but_not_actor_recreation(self):
        staged = self.capture(); admin = self.native.authorize('admin','alice')
        self.permission('alice', delete=False); self.save(admin,1)
        self.ids['admin']='replacement-admin'
        self.assertEqual(1,self.retention.once(now=self.now)['mail_expiry_blocked'])
        self.assertEqual(fixtures.MESSAGE,self.blob(staged['transaction_id']).read_bytes())
        current_admin=self.native.authorize('admin','alice'); self.save(current_admin,1)
        self.retention.retry(current_admin,self.delivery(self.alice))
        self.assertEqual(1,self.retention.once(now=self.now+1)['mail_expired'])

    def test_unconfirmed_source_is_held_and_fair_batch_reaches_another_due_recipient(self):
        first=self.capture();self.save(self.alice,1);self.save(self.bob,1)
        with self.store.connection() as db:
            db.execute('INSERT INTO mail_acceptance VALUES(?,?,?,?,?,?,?)',(first['transaction_id'],self.request.message_id,1,1,'uncertain','{}',None))
        second_request=self.request_for(recipients=('inbox@alice.test',))
        second=self.custody.stage(second_request,self.items(second_request,actions=('quarantine',)))
        self.custody.commit(second['transaction_id'])
        with self.store.connection() as db:db.execute('UPDATE mail_recipients SET created=created+1 WHERE transaction_id=?',(second['transaction_id'],))
        for _ in range(3):self.retention.once(now=self.now,limit=1)
        with self.store.connection() as db:
            self.assertEqual('deleted',db.execute('SELECT status FROM mail_recipients WHERE transaction_id=?',(second['transaction_id'],)).fetchone()[0])
        self.assertEqual(fixtures.MESSAGE,self.blob(first['transaction_id']).read_bytes())
        self.assertFalse(self.blob(second['transaction_id']).exists())

    def test_release_and_uncertain_delivery_are_excluded(self):
        staged=self.capture();self.save(self.alice,1);self.save(self.bob,1)
        with self.store.connection() as db:
            db.execute("UPDATE mail_recipients SET status=CASE owner WHEN 'alice' THEN 'release_queued' ELSE 'delivery_uncertain' END")
        self.assertEqual(0,self.retention.once(now=self.now)['mail_expiry_considered'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_interrupted_last_body_unlink_recovers_one_expiry_with_retained_proof(self):
        self.request=self.request_for(recipients=('inbox@alice.test',));staged=self.capture(actions=('quarantine',));self.save(self.alice,1)
        with patch.object(MailRetention,'finish',side_effect=fixtures.Interrupted):
            with self.assertRaises(fixtures.Interrupted):self.retention.once(now=self.now)
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual('deleting',self.retention.history(self.alice)['actions'][0]['status'])
        self.assertEqual(1,self.custody.recover()['mail_recovered'])
        self.assertEqual('expired',self.retention.history(self.alice)['actions'][0]['status'])
        self.assertEqual(0,self.custody.recover()['mail_recovered'])

    def test_changed_body_and_foreign_or_revoked_retry_preserve_bytes(self):
        staged=self.capture();self.save(self.alice,1)
        blob=self.blob(staged['transaction_id']);blob.chmod(0o600);blob.write_bytes(b'changed');blob.chmod(0o400)
        self.assertEqual(1,self.retention.once(now=self.now)['mail_expiry_blocked'])
        self.assertEqual(b'changed',blob.read_bytes())
        with self.assertRaises(AccessDenied):self.retention.retry(self.bob,self.delivery(self.alice))
        self.permission('alice',delete=False)
        with self.assertRaises(AccessDenied):self.retention.retry(self.alice,self.delivery(self.alice))

    def test_corrupted_committed_expiry_recipe_is_rejected_before_unlink(self):
        staged=self.capture();self.save(self.alice,1)
        with patch.object(self.retention.custody,'_finish_delete',side_effect=fixtures.Interrupted):
            with self.assertRaises(fixtures.Interrupted):self.retention.once(now=self.now)
        with self.store.connection() as db:
            row=db.execute("SELECT recipient_id,metadata FROM mail_expiry_actions WHERE status='deleting'").fetchone()
            metadata=json.loads(row['metadata']);metadata['sha256']='0'*64
            db.execute('UPDATE mail_expiry_actions SET metadata=? WHERE recipient_id=?',(encode(metadata),row['recipient_id']))
        self.assertEqual(1,self.custody.recover()['mail_recovery_failed'])
        self.assertEqual(fixtures.MESSAGE,self.blob(staged['transaction_id']).read_bytes())

    def test_account_recreation_cannot_inherit_expiry_authority_or_history(self):
        staged=self.capture();self.save(self.alice,1);self.ids['alice']='new-alice'
        replacement=self.native.authorize('alice')
        self.assertEqual(1,self.retention.once(now=self.now)['mail_expiry_blocked'])
        self.assertEqual([],self.retention.history(replacement)['actions'])
        self.assertEqual(0,self.retention.get(replacement,'alice.test')['effective_days'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_policy_disabled_after_discovery_stops_before_durable_deletion(self):
        staged=self.capture();self.save(self.alice,1);original=self.retention.authority
        def disabled(selected):
            context=original(selected);self.save(self.alice,0);return context
        with patch.object(self.retention,'authority',side_effect=disabled):
            result=self.retention.once(now=self.now)
        self.assertEqual(0,result['mail_expired']);self.assertEqual(0,result['mail_expiry_blocked'])
        self.assertEqual([],self.retention.history(self.alice)['actions'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_expiry_respects_caller_deadline_and_restores_it_without_discarding_mail(self):
        staged=self.capture();self.save(self.alice,1)
        previous=time.monotonic()-1;self.native.deadline=previous;native_call=self.native.call
        def limited(*args):self.native.remaining();return native_call(*args)
        self.native.call=limited
        self.assertEqual(1,self.retention.once(now=self.now)['mail_expiry_blocked'])
        self.assertEqual(previous,self.native.deadline)
        self.assertEqual(fixtures.MESSAGE,self.blob(staged['transaction_id']).read_bytes())

    def test_release_after_discovery_is_not_misreported_as_blocked_expiry(self):
        staged=self.capture();self.save(self.alice,1);original=self.retention.authority
        def release(selected):
            context=original(selected);self.custody.queue_release(self.alice,self.delivery(self.alice),'Own release');return context
        with patch.object(self.retention,'authority',side_effect=release):result=self.retention.once(now=self.now)
        self.assertEqual(0,result['mail_expired']);self.assertEqual(0,result['mail_expiry_blocked'])
        self.assertEqual([],self.retention.history(self.alice)['actions'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())
