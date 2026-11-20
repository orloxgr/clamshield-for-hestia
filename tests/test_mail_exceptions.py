import hashlib
import time
import unittest

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.mail_policy import PERMISSIONS, evaluate
import test_mail_policy as policies
import test_mail_custody as custody


class ScopedExceptionChanges(unittest.TestCase):
    setUp = policies.MailPolicyTests.setUp
    call = policies.MailPolicyTests.call

    def entry(self, **changes):
        return dict(engine='clamav', signature='Fixture.Signature', sha256='a'*64,
            expires=time.time()+3600, reason='Reviewed inert false positive') | changes

    def add(self, mailbox='', entry=None, **options):
        return self.mail.change_exception(self.context, 'alice.test', mailbox, 'add', entry or self.entry(), **options)

    def test_exception_permission_is_independent_from_policy_editing(self):
        admin = self.native.authorize('admin', 'alice')
        self.mail.save_permissions(admin, PERMISSIONS | dict(manage_policy=False))
        self.assertEqual(1, len(self.add()['exception_entries']))
        with self.assertRaises(AccessDenied): self.mail.save(self.context, 'alice.test', '', dict(enabled=True))
        self.mail.save_permissions(admin, PERMISSIONS | dict(manage_exceptions=False))
        with self.assertRaises(AccessDenied): self.add()
        self.mail.change_exception(admin, 'alice.test', '', 'add', self.entry())

    def test_mailbox_edit_copies_inherited_exceptions_without_changing_other_mailboxes(self):
        first = self.entry(); self.add(entry=first)
        self.mail.save(self.context, 'alice.test', 'first', dict(spam_threshold=8))
        changed = self.add('first', self.entry(signature='Second.Signature'))
        self.assertEqual(2, len(changed['exception_entries']))
        self.assertEqual(8, changed['overrides']['spam_threshold'])
        self.assertEqual([first], self.mail.get(self.context, 'alice.test', 'second')['effective']['exceptions'])
        restored = self.mail.change_exception(self.context, 'alice.test', 'first', 'inherit', revision=changed['revision'])
        self.assertNotIn('exceptions', restored['overrides'])
        self.assertEqual(8, restored['overrides']['spam_threshold'])

    def test_remove_inherited_entry_excludes_only_this_mailbox(self):
        value = self.add(); entry_id = value['exception_entries'][0]['id']
        selected = self.mail.get(self.context, 'alice.test', 'first')
        result = self.mail.change_exception(self.context, 'alice.test', 'first', 'remove',
            entry_id=entry_id, revision=selected['revision'])
        self.assertEqual([], result['effective']['exceptions'])
        self.assertEqual(1, len(self.mail.get(self.context, 'alice.test')['effective']['exceptions']))

    def test_stale_policy_editor_cannot_overwrite_new_exception_or_parent_change(self):
        old = self.mail.get(self.context, 'alice.test', 'first')
        self.add('first')
        for reset in (False, True):
            with self.assertRaises(Conflict):
                self.mail.save(self.context, 'alice.test', 'first', {}, reset=reset, revision=old['revision'])
        selected = self.mail.get(self.context, 'alice.test', 'first')
        self.mail.save(self.context, 'alice.test', '', dict(spam_threshold=7))
        with self.assertRaises(Conflict):
            self.mail.change_exception(self.context, 'alice.test', 'first', 'inherit', revision=selected['revision'])
        self.assertEqual(1, len(self.mail.get(self.context, 'alice.test', 'first')['exception_entries']))

    def test_atomic_add_merges_other_entries_and_renewal_does_not_duplicate(self):
        self.add(); self.add(entry=self.entry(signature='Other'))
        renewed = self.add(entry=self.entry(reason='Renewed review'))
        self.assertEqual(2, len(renewed['exception_entries']))
        self.assertEqual('Renewed review', renewed['effective']['exceptions'][-1]['reason'])

    def test_exception_limit_refuses_new_entry_atomically_but_allows_renewal(self):
        entries = [self.entry(signature='Rule.'+str(index)) for index in range(100)]
        self.mail.save(self.context, 'alice.test', '', dict(exceptions=entries))
        with self.assertRaises(ClamShieldError): self.add()
        self.assertEqual(entries, self.mail.get(self.context, 'alice.test')['effective']['exceptions'])
        self.assertEqual(100, len(self.add(entry=self.entry(signature='Rule.0'))['exception_entries']))

    def test_invalid_expiry_signature_and_scope_are_rejected(self):
        for entry in (self.entry(expires=1), self.entry(sha256='*'), self.entry(reason=''), self.entry(engine='spamassassin')):
            with self.assertRaises(ClamShieldError): self.add(entry=entry)
        with self.assertRaises(AccessDenied): self.mail.change_exception(self.context, 'bob.test', '', 'add', self.entry())
        with self.assertRaises(ClamShieldError): self.mail.change_exception(self.context, 'alice.test', '', 'inherit')
        with self.assertRaises(Conflict): self.mail.change_exception(self.context, 'alice.test', '', 'remove', entry_id='untrusted-id')

    def test_exception_removal_restores_detection_and_never_suppresses_different_bytes(self):
        self.mail.save(self.context, 'alice.test', '', dict(enabled=True))
        value = self.add()
        def verdict(digest):
            return evaluate(self.mail.get(self.context, 'alice.test')['effective'], policies.scan('malware'), sender='', sha256=digest)
        self.assertEqual('excepted', verdict('a'*64)['classification'])
        self.assertEqual('reject', verdict('b'*64)['action'])
        self.mail.change_exception(self.context, 'alice.test', '', 'remove', entry_id=value['exception_entries'][0]['id'])
        self.assertEqual('reject', verdict('a'*64)['action'])

    def test_root_api_cannot_select_another_owner_and_recreated_account_has_no_exceptions(self):
        app = Application(self.settings, self.store, self.native)
        app.dispatch(dict(actor='alice', action='mail-exception-add', domain='alice.test', policy=self.entry()))
        with self.assertRaises(AccessDenied):
            app.dispatch(dict(actor='alice', owner='bob', action='mail-exception-add', domain='bob.test', policy=self.entry()))
        self.ids['alice'] = 'replacement'
        with self.assertRaises(AccessDenied): self.add()
        new = self.native.authorize('alice')
        self.assertEqual([], self.mail.get(new, 'alice.test')['exception_entries'])


class QuarantineFalsePositives(unittest.TestCase):
    setUp = custody.MailCustodyTests.setUp
    request_for = custody.MailCustodyTests.request_for
    items = custody.MailCustodyTests.items
    capture = custody.MailCustodyTests.capture
    blob = custody.MailCustodyTests.blob
    delivery = custody.MailCustodyTests.delivery

    def value(self, **changes):
        return dict(engine='clamav', signature='Harmless.Fixture', expires=time.time()+3600,
            reason='Reviewed exact quarantine content') | changes

    def test_server_derives_mailbox_and_hash_and_keeps_message_quarantined(self):
        staged = self.capture(); delivery = self.delivery(self.alice)
        before = self.custody.preview(self.alice, delivery)
        result = self.custody.add_exception(self.alice, delivery, self.value())
        self.assertEqual('inbox', result['mailbox'])
        self.assertEqual(hashlib.sha256(custody.MESSAGE).hexdigest(), result['effective']['exceptions'][0]['sha256'])
        self.assertEqual(before, self.custody.preview(self.alice, delivery))
        self.assertEqual(custody.MESSAGE, self.blob(staged['transaction_id']).read_bytes())
        self.assertEqual([], self.policies.get(self.bob, 'bob.test', 'inbox')['effective']['exceptions'])
        event = next(e for e in self.store.history(self.alice) if e['action']=='mail.exception_add')
        self.assertEqual(delivery, event['detail']['source_delivery'])

    def test_forged_signature_hash_recipient_and_owner_are_rejected(self):
        self.capture(); delivery = self.delivery(self.alice)
        with self.assertRaises(AccessDenied): self.custody.add_exception(self.bob, delivery, self.value())
        with self.assertRaises(AccessDenied): self.custody.add_exception(self.alice, delivery, self.value(signature='Not.Detected'))
        for field in ('sha256', 'mailbox', 'recipient'):
            with self.assertRaises(ClamShieldError): self.custody.add_exception(self.alice, delivery, self.value(**{field:'forged'}))

    def test_prepared_uncertain_and_deleted_sources_cannot_create_exceptions(self):
        staged = self.custody.stage(self.request, self.items()); delivery = self.delivery(self.alice)
        with self.assertRaises(Conflict): self.custody.add_exception(self.alice, delivery, self.value())
        self.custody.commit(staged['transaction_id'])
        with self.store.connection() as db:
            db.execute('INSERT INTO mail_acceptance VALUES(?,?,?,?,?,?,?)',
                (staged['transaction_id'], self.request.message_id, 1, 1, 'uncertain', '{}', None))
        with self.assertRaises(Conflict): self.custody.add_exception(self.alice, delivery, self.value())
        with self.store.connection() as db: db.execute('DELETE FROM mail_acceptance')
        self.custody.delete(self.alice, delivery)
        with self.assertRaises(Conflict): self.custody.add_exception(self.alice, delivery, self.value())

    def test_tampered_private_original_and_replaced_account_cannot_create_exception(self):
        staged = self.capture(); delivery = self.delivery(self.alice)
        blob = self.blob(staged['transaction_id']); blob.chmod(0o600)
        blob.write_bytes(b'changed'); blob.chmod(0o400)
        with self.assertRaises(Conflict): self.custody.add_exception(self.alice, delivery, self.value())
        self.ids['alice'] = 'recreated'
        with self.assertRaises(AccessDenied): self.custody.add_exception(self.alice, delivery, self.value())

    def test_exception_permission_does_not_grant_release_and_api_has_no_internal_verdict(self):
        self.capture(); delivery = self.delivery(self.alice)
        admin = self.native.authorize('admin', 'alice')
        self.policies.save_permissions(admin, PERMISSIONS | dict(manage_policy=False, release=False))
        app = Application(self.settings,self.store,self.native)
        value = app.dispatch(dict(actor='alice', action='mail-quarantine-exception', delivery_id=delivery, policy=self.value()))
        self.assertEqual(1, len(value['exception_entries']))
        with self.assertRaises(AccessDenied): self.custody.queue_release(self.alice, delivery, 'Review')
        self.policies.save_permissions(admin, PERMISSIONS | dict(manage_exceptions=False))
        with self.assertRaises(AccessDenied): self.custody.add_exception(self.alice, delivery, self.value())
