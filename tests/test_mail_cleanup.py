import os
import unittest
from unittest.mock import patch

import test_mail_custody as fixtures
import test_mail_delivery as delivery_fixtures
from clamshield.mail_cleanup import MailCleanup
from clamshield.mail_delivery import MailDelivery


class MailCleanupTests(unittest.TestCase):
    setUp = fixtures.MailCustodyTests.setUp
    request_for = fixtures.MailCustodyTests.request_for
    items = fixtures.MailCustodyTests.items
    capture = fixtures.MailCustodyTests.capture
    delivery = fixtures.MailCustodyTests.delivery
    blob = fixtures.MailCustodyTests.blob
    worker = delivery_fixtures.MailDeliveryTests.worker

    def cleanable(self, actions=('tag', 'deliver')):
        staged = self.capture(actions=actions)
        worker, native = self.worker()
        result = worker.once()
        native.observe.return_value = {'state': 'delivered', 'native_id': 'native-fixture'}
        self.assertEqual('delivered', worker.reconcile(result['attempt']))
        return staged, worker, native, result['attempt']

    def cleanup(self):
        return MailCleanup(self.settings, self.store, self.native)

    def sendcopy(self, attempt):
        return self.settings.state / 'mail-custody' / (attempt + '.delivery')

    def entry(self, kind, subject):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM mail_body_cleanup WHERE kind=? AND subject=?', (kind, subject)).fetchone()
        return dict(row) if row else None

    def test_confirmed_delivery_purges_private_bodies_but_keeps_native_proof(self):
        staged, worker, native, attempt = self.cleanable()
        with self.store.connection() as db:
            before = dict(db.execute('SELECT * FROM mail_delivery_attempts WHERE id=?', (attempt,)).fetchone())
        result = worker.recover()
        self.assertEqual(2, result['mail_bodies_purged'])
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertFalse(self.sendcopy(attempt).exists())
        with self.store.connection() as db:
            after = dict(db.execute('SELECT * FROM mail_delivery_attempts WHERE id=?', (attempt,)).fetchone())
        self.assertEqual(before, after)
        self.assertEqual('delivered', self.custody.list(self.alice)['messages'][0]['status'])
        self.assertEqual('purged', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual(0, worker.once()['mail_bodies_purged'])
        self.assertEqual(1, native.submit.call_count)

    def test_quarantined_other_recipient_retains_shared_source_not_finished_send_copy(self):
        staged, worker, native, attempt = self.cleanable(('tag', 'quarantine'))
        self.assertEqual(1, worker.recover()['mail_bodies_purged'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())
        self.assertFalse(self.sendcopy(attempt).exists())
        self.assertIsNone(self.entry('source', staged['transaction_id']))
        self.assertTrue(self.custody.preview(self.bob, self.delivery(self.bob))['available'])
        self.custody.delete(self.bob, self.delivery(self.bob))
        self.assertFalse(self.blob(staged['transaction_id']).exists())

    def test_queued_failed_and_unknown_native_outcomes_never_purge(self):
        for state in ('native_queued', 'unknown', 'native_failed'):
            self.request = self.request_for()
            staged = self.capture(actions=('tag', 'deliver'))
            worker, native = self.worker()
            native.observe.return_value = {'state': state, 'native_id': None if state == 'unknown' else 'native-fixture'}
            result = worker.once()
            self.assertEqual(0, result['mail_bodies_purged'])
            self.assertTrue(self.blob(staged['transaction_id']).exists())
            self.assertTrue(self.sendcopy(result['attempt']).exists())
            self.assertIsNone(self.entry('delivery', result['attempt']))

    def test_interruption_after_unlink_recovers_both_journals_without_resend(self):
        staged, worker, native, attempt = self.cleanable()
        original = os.unlink
        for subject, kind in ((staged['transaction_id'], 'source'), (attempt, 'delivery')):
            def interrupt(name, *args, **kwargs):
                original(name, *args, **kwargs)
                raise fixtures.Interrupted()
            with patch('clamshield.mail_cleanup.os.unlink', side_effect=interrupt):
                with self.assertRaises(fixtures.Interrupted):
                    self.cleanup().once()
            self.assertEqual('deleting', self.entry(kind, subject)['status'])
        self.assertEqual(1, worker.recover()['mail_bodies_purged'])
        self.assertEqual('purged', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual('purged', self.entry('delivery', attempt)['status'])
        self.assertEqual(1, native.submit.call_count)

    def test_interruption_after_validation_keeps_exact_bytes_until_recovery(self):
        staged, worker, native, attempt = self.cleanable()
        cleanup = self.cleanup(); validate = cleanup._validate
        def interrupt(root, name, metadata):
            if self.entry('source', staged['transaction_id'])['status'] == 'deleting':
                raise fixtures.Interrupted()
            return validate(root, name, metadata)
        with patch.object(cleanup, '_validate', side_effect=interrupt):
            with self.assertRaises(fixtures.Interrupted): cleanup.once()
        self.assertTrue(self.blob(staged['transaction_id']).exists())
        self.assertEqual('deleting', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual(2, worker.recover()['mail_bodies_purged'])

    def test_missing_before_validated_journal_is_blocked_not_success(self):
        staged, worker, native, attempt = self.cleanable()
        self.blob(staged['transaction_id']).unlink()
        self.assertEqual(1, worker.recover()['mail_body_cleanup_blocked'])
        self.assertEqual('blocked', self.entry('source', staged['transaction_id'])['status'])
        with self.store.connection() as db:
            self.assertEqual('committed', self.custody.transaction(staged['transaction_id'], db)['status'])

    def test_changed_inode_and_bytes_are_retained_and_not_automatically_retried(self):
        staged, worker, native, attempt = self.cleanable()
        body = self.blob(staged['transaction_id']); data = body.read_bytes()
        body.rename(body.with_suffix('.saved')); body.write_bytes(data); body.chmod(0o400)
        sendcopy = self.sendcopy(attempt); sendcopy.chmod(0o600)
        sendcopy.write_bytes(sendcopy.read_bytes() + b'changed'); sendcopy.chmod(0o400)
        self.assertEqual(2, worker.recover()['mail_body_cleanup_blocked'])
        self.assertTrue(body.exists()); self.assertTrue(sendcopy.exists())
        self.assertEqual('blocked', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual(0, self.cleanup().once()['mail_bodies_purged'])

    def test_symlinks_and_hardlinks_are_retained(self):
        staged, worker, native, attempt = self.cleanable()
        body = self.blob(staged['transaction_id']); saved = body.with_suffix('.saved')
        body.rename(saved); body.symlink_to(saved)
        sendcopy = self.sendcopy(attempt); os.link(sendcopy, sendcopy.with_suffix('.link'))
        self.assertEqual(2, worker.recover()['mail_body_cleanup_blocked'])
        self.assertTrue(body.is_symlink()); self.assertTrue(saved.exists()); self.assertTrue(sendcopy.exists())

    def test_cleanup_warning_is_scoped_to_the_current_native_owner_generation(self):
        staged, worker, native, attempt = self.cleanable()
        self.blob(staged['transaction_id']).unlink(); self.sendcopy(attempt).unlink()
        worker.recover()
        self.assertEqual(2, self.policies.list(self.alice)['cleanup_blocked'])
        self.assertEqual(0, self.policies.list(self.bob)['cleanup_blocked'])
        self.ids['alice'] = 'recreated-owner'
        with self.assertRaises(fixtures.AccessDenied): self.policies.list(self.alice)
        self.assertEqual(0, self.policies.list(self.native.authorize('alice'))['cleanup_blocked'])

    def test_changed_file_after_durable_delete_intent_is_not_unlinked(self):
        staged, worker, native, attempt = self.cleanable()
        cleanup = self.cleanup(); validate = cleanup._validate
        def interrupt(root, name, metadata):
            if self.entry('source', staged['transaction_id'])['status'] == 'deleting':
                raise fixtures.Interrupted()
            return validate(root, name, metadata)
        with patch.object(cleanup, '_validate', side_effect=interrupt):
            with self.assertRaises(fixtures.Interrupted): cleanup.once()
        body = self.blob(staged['transaction_id']); body.rename(body.with_suffix('.saved'))
        body.write_bytes(b'unrelated replacement'); body.chmod(0o400)
        self.assertEqual(1, worker.recover()['mail_body_cleanup_blocked'])
        self.assertEqual(b'unrelated replacement', body.read_bytes())
        self.assertEqual('blocked', self.entry('source', staged['transaction_id'])['status'])

    def test_audit_transaction_interruption_finishes_only_recorded_unlink(self):
        staged, worker, native, attempt = self.cleanable()
        audit = self.store.audit
        def interrupt(context, action, *args, **kwargs):
            if action == 'mail.body_purged': raise fixtures.Interrupted()
            return audit(context, action, *args, **kwargs)
        with patch.object(self.store, 'audit', side_effect=interrupt):
            with self.assertRaises(fixtures.Interrupted): self.cleanup().once()
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual('deleting', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual(2, MailDelivery(self.settings, self.store, self.native, native).recover()['mail_bodies_purged'])
