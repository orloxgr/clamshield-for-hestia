import json
import os
import unittest
from unittest.mock import Mock, patch

import test_mail_custody as fixtures
import test_mail_cleanup as cleanup_fixtures
import test_mail_delivery as delivery_fixtures
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.mail_acceptance import MailAcceptance
from clamshield.mail_bridge import process_start
from clamshield.mail_cleanup import MailCleanup
from clamshield.mail_review import MailReview
from dataclasses import replace


class MailReviewTests(unittest.TestCase):
    setUp = fixtures.MailCustodyTests.setUp
    request_for = fixtures.MailCustodyTests.request_for
    items = fixtures.MailCustodyTests.items
    capture = fixtures.MailCustodyTests.capture
    delivery = fixtures.MailCustodyTests.delivery
    blob = fixtures.MailCustodyTests.blob
    worker = delivery_fixtures.MailDeliveryTests.worker
    cleanable = cleanup_fixtures.MailCleanupTests.cleanable
    cleanup = cleanup_fixtures.MailCleanupTests.cleanup
    sendcopy = cleanup_fixtures.MailCleanupTests.sendcopy
    entry = cleanup_fixtures.MailCleanupTests.entry

    def review(self):return MailReview(self.settings, self.store, self.native)

    def armed(self):
        request = replace(self.request, peer_pid=os.getpid(), peer_start=process_start(os.getpid()))
        staged = self.custody.stage(request, self.items(request))
        native = Mock(); native.checkpoint.return_value = {'device': 1, 'inode': 2, 'offset': 0}
        native.observe_acceptance.return_value = {'state': 'unknown'}
        acceptance = MailAcceptance(self.settings, self.store, self.native, native)
        acceptance.arm(staged, request)
        return staged, acceptance, native

    def test_unknown_source_recheck_never_submits_or_discards_and_proof_can_resolve(self):
        staged, acceptance, native = self.armed(); recipient = self.delivery(self.alice)
        with patch('clamshield.mail_review.MailAcceptance', return_value=acceptance), patch('clamshield.mail_delivery.NativeExim.submit') as submit:
            self.assertEqual('uncertain', self.review().recheck(self.alice, recipient, 'source')['state'])
            self.assertTrue(self.blob(staged['transaction_id']).exists())
            with self.assertRaises(Conflict):self.custody.queue_release(self.alice, recipient, 'Reviewed')
            native.observe_acceptance.return_value = {'state': 'accepted', 'native_id': self.request.message_id}
            self.assertEqual('accepted', self.review().recheck(self.alice, recipient, 'source')['state'])
            self.assertEqual('accepted', self.review().recheck(self.alice, recipient, 'source')['state'])
            submit.assert_not_called()
        self.assertEqual(0, self.review().list(self.alice)['total'])
        self.assertTrue(self.custody.preview(self.alice, recipient)['available'])

    def test_source_rejection_resolves_only_using_native_proof(self):
        staged, acceptance, native = self.armed()
        native.observe_acceptance.return_value = {'state': 'rejected', 'native_id': self.request.message_id}
        with patch('clamshield.mail_review.MailAcceptance', return_value=acceptance):
            self.assertEqual('rejected', self.review().recheck(self.alice, self.delivery(self.alice), 'source')['state'])
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual(0, self.review().list(self.alice)['total'])

    def test_delivery_recheck_only_observes_same_attempt_and_never_submits_again(self):
        staged = self.capture(actions=('tag', 'deliver')); worker, native = self.worker()
        native.observe.return_value = {'state': 'unknown', 'native_id': None}
        result = worker.once(); recipient = self.delivery(self.alice)
        self.assertEqual('delivery', self.review().list(self.alice)['items'][0]['stage'])
        with patch('clamshield.mail_review.MailDelivery', return_value=worker):
            self.assertEqual('uncertain', self.review().recheck(self.alice, recipient, 'delivery')['state'])
            native.observe.return_value = {'state': 'delivered', 'native_id': 'native-fixture'}
            self.assertEqual('delivered', self.review().recheck(self.alice, recipient, 'delivery')['state'])
        self.assertEqual(1, native.submit.call_count)
        self.assertTrue(self.blob(staged['transaction_id']).exists())
        self.assertEqual(0, self.review().list(self.alice)['total'])

    def test_scope_account_recreation_and_invalid_search_do_not_expose_or_act(self):
        staged, acceptance, native = self.armed(); alice_id = self.delivery(self.alice)
        self.assertEqual(1, self.review().list(self.alice)['total'])
        self.assertEqual(1, self.review().list(self.bob)['total'])
        self.assertEqual('inbox@bob.test', self.review().list(self.bob)['items'][0]['recipient'])
        with self.assertRaises(AccessDenied):self.review().recheck(self.bob, alice_id, 'source')
        with self.assertRaises(ClamShieldError):self.review().list(self.alice, search='x'*301)
        with self.assertRaises(ClamShieldError):self.review().list(self.alice, offset=True)
        self.ids['alice'] = 'recreated'
        with self.assertRaises(AccessDenied):self.review().list(self.alice)
        fresh = self.native.authorize('alice')
        self.assertEqual(0, self.review().list(fresh)['total'])
        with self.assertRaises(AccessDenied):self.review().recheck(fresh, alice_id, 'source')

    def test_cleanup_retry_restores_exact_validated_copy_after_transient_failure(self):
        staged, worker, native, attempt = self.cleanable(); recipient = self.delivery(self.alice)
        real_unlink = os.unlink
        def deny_source(name, *args, **kwargs):
            if name.endswith('.eml'):raise PermissionError('fixture transient unlink refusal')
            return real_unlink(name, *args, **kwargs)
        with patch('clamshield.mail_cleanup.os.unlink', side_effect=deny_source):self.cleanup().once()
        self.assertEqual('deleting', json.loads(self.entry('source', staged['transaction_id'])['metadata'])['resume_status'])
        self.assertEqual(['source_cleanup'], [r['stage'] for r in self.review().list(self.alice)['items']])
        self.assertEqual('purged', self.review().recheck(self.alice, recipient, 'source_cleanup')['state'])
        self.assertFalse(self.blob(staged['transaction_id']).exists()); self.assertEqual(1, native.submit.call_count)

    def test_cleanup_missing_before_validation_is_never_adopted_as_deletion(self):
        staged, worker, native, attempt = self.cleanable(); self.blob(staged['transaction_id']).unlink()
        self.cleanup().once(); recipient = self.delivery(self.alice)
        self.assertEqual('blocked', self.review().recheck(self.alice, recipient, 'source_cleanup')['state'])
        self.assertEqual('validating', json.loads(self.entry('source', staged['transaction_id'])['metadata'])['resume_status'])
        self.assertEqual(1, self.review().list(self.alice)['total'])

    def test_cleanup_replacement_inode_and_cross_tenant_retry_are_denied(self):
        staged, worker, native, attempt = self.cleanable(); body = self.blob(staged['transaction_id'])
        body.rename(body.with_suffix('.saved')); body.write_bytes(b'unrelated'); body.chmod(0o400)
        self.cleanup().once(); recipient = self.delivery(self.alice)
        with self.assertRaises(AccessDenied):self.review().recheck(self.bob, recipient, 'source_cleanup')
        self.assertEqual('blocked', self.review().recheck(self.alice, recipient, 'source_cleanup')['state'])
        self.assertEqual(b'unrelated', body.read_bytes())

    def test_cleanup_interrupted_unlink_then_blocked_retains_durable_phase(self):
        staged, worker, native, attempt = self.cleanable(); recipient = self.delivery(self.alice)
        real_unlink = os.unlink
        def unlinked_error(name, *args, **kwargs):
            real_unlink(name, *args, **kwargs)
            if name.endswith('.eml'):raise OSError('post-unlink filesystem error')
        with patch('clamshield.mail_cleanup.os.unlink', side_effect=unlinked_error):self.cleanup().once()
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual('blocked', self.entry('source', staged['transaction_id'])['status'])
        self.assertEqual('purged', self.review().recheck(self.alice, recipient, 'source_cleanup')['state'])
        self.assertEqual(1, native.submit.call_count)

    def test_concurrent_recovery_busy_has_no_side_effect(self):
        staged, acceptance, native = self.armed()
        with acceptance.locked(), self.assertRaisesRegex(Conflict, 'recovery is active'):
            self.review().recheck(self.alice, self.delivery(self.alice), 'source')
        native.observe_acceptance.assert_not_called()
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_invalid_stage_and_absent_attempt_never_construct_native_delivery(self):
        self.capture(); recipient = self.delivery(self.alice)
        with self.assertRaises(ClamShieldError):self.review().recheck(self.alice, recipient, 'resend')
        with self.assertRaises(Conflict):self.review().recheck(self.alice, recipient, 'delivery')
        with self.assertRaises(Conflict):self.review().recheck(self.alice, recipient, 'delivery_cleanup')
