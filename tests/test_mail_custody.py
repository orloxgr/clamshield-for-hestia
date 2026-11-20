from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.hestia import Hestia
from clamshield.mail_bridge import MailRequest, SEALS
from clamshield.mail_custody import MailCustody, safe_preview
from clamshield.mail_inventory import resolve
from clamshield.mail_policy import MailPolicies, PERMISSIONS
from clamshield.settings import Settings
from clamshield.store import Store


MESSAGE = (b'From: Visible Sender <sender@remote.test>\nTo: visible@remote.test\n'
           b'Bcc: secret-envelope@other.test\nSubject: Harmless quarantine fixture\n'
           b'MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary="fixture"\n\n'
           b'--fixture\nContent-Type: text/plain; charset=utf-8\n\nHarmless plain body\n'
           b'--fixture\nContent-Type: text/html\n\n<script>never execute</script><img src="https://invalid.test/pixel">\n'
           b'--fixture--\n')


class Interrupted(BaseException):
    pass


class MailCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name) / 'state'); self.settings.prepare()
        self.store = Store(self.settings.database)
        self.ids = {'alice': 'alice-generation', 'bob': 'bob-generation', 'admin': 'admin-generation'}
        self.native = Hestia(); self.native.identity = lambda owner: self.ids[owner]
        def call(command, *args):
            if command == 'v-list-user':
                return {args[0]: {'ROLE': 'admin' if args[0] == 'admin' else 'user', 'SUSPENDED': 'no'}}
            if command == 'v-list-mail-domains':
                return {args[0] + '.test': {}}
            if command == 'v-list-mail-accounts':
                return {'inbox': {}}
            raise AssertionError(command)
        self.native.call = Mock(side_effect=call)
        self.custody = MailCustody(self.settings, self.store, self.native)
        self.policies = MailPolicies(self.store, self.native)
        self.alice, self.bob = self.native.authorize('alice'), self.native.authorize('bob')
        for owner in ('alice','bob'):self.policies.save_permissions(self.native.authorize('admin',owner),dict.fromkeys(PERMISSIONS,True))
        # Start custody/retention scenarios with an empty activity history;
        # the explicit fixture grants are pre-existing administrator setup.
        with self.store.connection() as db:db.execute("DELETE FROM audit WHERE action='mail.permissions_saved'")
        self.fds = []; self.addCleanup(lambda: [os.close(fd) for fd in self.fds])
        self.request = self.request_for()

    def request_for(self, content=MESSAGE, recipients=('inbox@alice.test', 'inbox@bob.test'), sealed=True):
        fd = os.memfd_create('custody-test', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        self.fds.append(fd); os.write(fd, content)
        if sealed:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        return MailRequest('native-' + uuid.uuid4().hex, 'envelope@remote.test', '192.0.2.5', '', 'esmtp', recipients, 1, fd)

    def items(self, request=None, actions=('quarantine', 'quarantine')):
        request = request or self.request; result = []
        for recipient, action in zip(request.recipients, actions):
            decision = {'action': action, 'classification': 'malware' if action == 'quarantine' else 'spam',
                        'scan_complete': True, 'detections': [{'engine': 'clamav', 'signature': 'Harmless.Fixture'}]}
            if action in ('deliver', 'reject', 'defer'):
                result.append({'decision': decision}); continue
            owner = recipient.rsplit('@', 1)[1].split('.')[0]
            context = self.native.authorize(owner)
            result.append({'context': context, 'target': resolve(self.policies.targets(context), recipient), 'decision': decision})
        return result

    def capture(self, actions=('quarantine', 'quarantine')):
        staged = self.custody.stage(self.request, self.items(actions=actions))
        self.custody.commit(staged['transaction_id'])
        return staged

    def blob(self, transaction_id):
        return self.settings.state / 'mail-custody' / (transaction_id + '.eml')

    def delivery(self, context):
        return self.custody.list(context)['messages'][0]['id']

    def test_capture_is_private_and_prepared_does_not_mean_accepted(self):
        position = os.lseek(self.request.fd, 0, os.SEEK_CUR)
        staged = self.custody.stage(self.request, self.items())
        blob = self.blob(staged['transaction_id'])
        self.assertEqual(MESSAGE, blob.read_bytes()); self.assertEqual(0o400, blob.stat().st_mode & 0o777)
        self.assertEqual(0o700, blob.parent.stat().st_mode & 0o777)
        self.assertEqual(position, os.lseek(self.request.fd, 0, os.SEEK_CUR))
        row = self.custody.list(self.alice)['messages'][0]; self.assertEqual('prepared', row['status'])
        with self.assertRaises(Conflict):
            self.custody.preview(self.alice, row['id'])
        self.custody.commit(staged['transaction_id'])
        preview = self.custody.preview(self.alice, row['id'])
        self.assertEqual('quarantined', preview['status']); self.assertEqual(hashlib.sha256(MESSAGE).hexdigest(), preview['sha256'])
        self.assertEqual('plain-text', preview['format']); self.assertIn('Harmless plain body', preview['text'])
        self.assertNotIn('<script>', preview['text']); self.assertNotIn('Bcc', preview['headers'])
        self.assertNotIn('inbox@bob.test', str(preview)); self.assertNotIn('secret-envelope', str(preview))
        self.assertNotIn('transaction_id', self.custody.list(self.alice)['messages'][0])

    def test_shared_blob_queries_and_deletion_remain_recipient_scoped(self):
        staged = self.capture(); alice_id, bob_id = self.delivery(self.alice), self.delivery(self.bob)
        self.assertEqual(1, self.custody.list(self.alice, 'Harmless quarantine')['total'])
        self.assertEqual(1, self.custody.list(self.alice, 'envelope@remote.test')['total'])
        self.assertEqual(0, self.custody.list(self.alice, 'inbox@bob.test')['total'])
        self.assertEqual(0, self.custody.list(self.alice, '%')['total'])
        with self.assertRaises(AccessDenied): self.custody.preview(self.alice, bob_id)
        with self.assertRaises(AccessDenied): self.custody.delete(self.bob, alice_id)
        self.custody.delete(self.alice, alice_id)
        self.assertTrue(self.blob(staged['transaction_id']).is_file())
        self.assertEqual(0, self.custody.list(self.alice)['total'])
        self.assertTrue(self.custody.preview(self.bob, bob_id)['available'])
        self.custody.delete(self.bob, bob_id)
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        with self.assertRaises(Conflict): self.custody.preview(self.bob, bob_id)

    def test_unconfirmed_source_cannot_release_delete_or_lose_custody(self):
        staged = self.capture(); delivery_id = self.delivery(self.alice)
        with self.store.connection() as db:
            db.execute('INSERT INTO mail_acceptance VALUES(?,?,?,?,?,?,?)',
                       (staged['transaction_id'], self.request.message_id, 1, 1, 'armed', '{}', None))
        for status in ('armed', 'response_sent', 'uncertain', 'proven', 'rejected', 'unknown-future-state'):
            with self.subTest(status=status):
                with self.store.connection() as db:
                    db.execute('UPDATE mail_acceptance SET status=?', (status,))
                with self.assertRaises(Conflict):self.custody.queue_release(self.alice, delivery_id, 'reviewed')
                with self.assertRaises(Conflict):self.custody.delete(self.alice, delivery_id)
                self.assertEqual('quarantined', self.custody.list(self.alice)['messages'][0]['status'])
                self.assertEqual(MESSAGE, self.blob(staged['transaction_id']).read_bytes())
        with self.store.connection() as db:db.execute("UPDATE mail_acceptance SET status='accepted'")
        self.custody.delete(self.alice, delivery_id)
        self.assertEqual(MESSAGE, self.blob(staged['transaction_id']).read_bytes())

    def test_old_pending_delete_recovery_preserves_an_unconfirmed_source(self):
        staged = self.capture(); delivery_id = self.delivery(self.alice)
        with self.store.connection() as db:
            db.execute('INSERT INTO mail_acceptance VALUES(?,?,?,?,?,?,?)',
                       (staged['transaction_id'], self.request.message_id, 1, 1, 'uncertain', '{}', None))
            db.execute("UPDATE mail_recipients SET status='deleting' WHERE id=?", (delivery_id,))
        result = self.custody.recover()
        self.assertEqual(1, result['mail_recovery_failed'])
        self.assertEqual(MESSAGE, self.blob(staged['transaction_id']).read_bytes())
        with self.store.connection() as db:
            self.assertEqual('deleting', db.execute('SELECT status FROM mail_recipients WHERE id=?', (delivery_id,)).fetchone()[0])
            self.assertIn('acceptance', db.execute('SELECT error FROM mail_recipients WHERE id=?', (delivery_id,)).fetchone()[0])
            db.execute("UPDATE mail_acceptance SET status='accepted'")
        self.assertEqual(1, self.custody.recover()['mail_recovered'])
        self.assertEqual(MESSAGE, self.blob(staged['transaction_id']).read_bytes())

    def test_replaying_same_native_reference_is_idempotent_but_content_or_selection_changes_fail(self):
        items = self.items(); first = self.custody.stage(self.request, items)
        self.assertEqual(first, self.custody.stage(self.request, items))
        self.custody.commit(first['transaction_id']); self.custody.commit(first['transaction_id'])
        self.assertEqual(1, self.custody.list(self.alice)['total'])
        different = self.request_for(content=MESSAGE + b'changed')
        with self.assertRaises(Conflict): self.custody.stage(replace(different, message_id=self.request.message_id), self.items(different))
        items[0]['decision']['action'] = 'junk'
        with self.assertRaises(Conflict): self.custody.stage(self.request, items)

    def test_reject_defer_incomplete_and_unsealed_transactions_never_capture(self):
        for actions in (('quarantine', 'reject'), ('quarantine', 'defer'), ('deliver', 'deliver')):
            with self.assertRaises(Conflict): self.custody.stage(self.request, self.items(actions=actions))
        items = self.items(); items[0]['decision']['scan_complete'] = False
        with self.assertRaises(Conflict): self.custody.stage(self.request, items)
        request = self.request_for(sealed=False)
        with self.assertRaises(ClamShieldError): self.custody.stage(request, self.items(request))
        with self.store.connection() as db:
            self.assertEqual(0, db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])

    def test_finished_private_copy_recovers_to_prepared_without_delivery_or_acceptance(self):
        with patch('clamshield.mail_custody.rename_noreplace', side_effect=Interrupted):
            with self.assertRaises(Interrupted): self.custody.stage(self.request, self.items())
        report = self.custody.recover(); self.assertEqual(1, report['mail_recovered'])
        self.assertEqual('prepared', self.custody.list(self.alice)['messages'][0]['status'])
        self.assertEqual(0, self.custody.recover()['mail_recovered'])
        with self.assertRaises(Conflict): self.custody.queue_release(self.alice, self.delivery(self.alice), 'reviewed')

    def test_interruption_after_publish_recovers_same_bytes_without_auto_commit(self):
        with patch.object(self.custody, '_prepared', side_effect=Interrupted):
            with self.assertRaises(Interrupted): self.custody.stage(self.request, self.items())
        self.assertEqual(1, self.custody.recover()['mail_recovered'])
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM mail_transactions').fetchone()
            self.assertEqual('prepared', row['status']); self.assertEqual(MESSAGE, self.blob(row['id']).read_bytes())

    def test_unaccepted_capture_can_abort_with_interruption_recovery_but_accepted_mail_cannot(self):
        staged = self.custody.stage(self.request, self.items())
        with patch.object(self.custody, '_finish_abort', side_effect=Interrupted):
            with self.assertRaises(Interrupted): self.custody.abort(staged['transaction_id'])
        self.assertEqual(1, self.custody.recover()['mail_recovered'])
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual(0, self.custody.list(self.alice)['total'])
        with self.assertRaises(Conflict): self.custody.commit(staged['transaction_id'])
        self.request = self.request_for(); committed = self.capture()
        with self.assertRaises(Conflict): self.custody.abort(committed['transaction_id'])

    def test_partial_write_failure_is_never_promoted_or_accepted(self):
        with patch('clamshield.mail_custody.os.write', side_effect=OSError('storage failure')):
            with self.assertRaises(OSError): self.custody.stage(self.request, self.items())
        self.assertEqual(1, self.custody.recover()['mail_recovery_failed'])
        self.assertEqual('capture_failed', self.custody.list(self.alice)['messages'][0]['status'])
        with self.assertRaises(Conflict): self.custody.preview(self.alice, self.delivery(self.alice))

    def test_last_deletion_recovers_after_unlink_before_database_commit(self):
        request = self.request_for(recipients=('inbox@alice.test',)); self.request = request
        staged = self.capture(actions=('quarantine',)); delivery = self.delivery(self.alice)
        original = self.store.audit
        def interrupt(context, action, *args, **kwargs):
            if action == 'mail.deleted': raise Interrupted()
            return original(context, action, *args, **kwargs)
        with patch.object(self.store, 'audit', side_effect=interrupt):
            with self.assertRaises(Interrupted): self.custody.delete(self.alice, delivery)
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual('deleting', self.custody.list(self.alice)['messages'][0]['status'])
        self.assertEqual(1, self.custody.recover()['mail_recovered'])
        self.assertEqual(0, self.custody.list(self.alice)['total'])

    def test_explicit_delete_can_resume_its_existing_verified_deletion_journal(self):
        self.request=self.request_for(recipients=('inbox@alice.test',));staged=self.capture(actions=('quarantine',));delivery=self.delivery(self.alice)
        audit=self.store.audit
        def interrupt(context,action,*args,**kwargs):
            if action=='mail.deleted':raise Interrupted()
            return audit(context,action,*args,**kwargs)
        with patch.object(self.store,'audit',side_effect=interrupt),self.assertRaises(Interrupted):self.custody.delete(self.alice,delivery)
        self.assertFalse(self.blob(staged['transaction_id']).exists());self.custody.delete(self.alice,delivery)
        self.assertEqual(0,self.custody.list(self.alice)['total'])

    def test_changed_inodes_hardlinks_symlinks_and_bytes_cannot_be_previewed_or_deleted(self):
        staged = self.capture(); delivery = self.delivery(self.alice); blob = self.blob(staged['transaction_id'])
        old = blob.with_suffix('.saved'); os.rename(blob, old)
        blob.write_bytes(MESSAGE); blob.chmod(0o400)
        with self.assertRaises(Conflict): self.custody.preview(self.alice, delivery)
        blob.unlink(); os.rename(old, blob)
        link = blob.with_suffix('.link'); os.link(blob, link)
        with self.assertRaises(Conflict): self.custody.preview(self.alice, delivery)
        link.unlink()
        os.rename(blob, old); blob.symlink_to(old)
        with self.assertRaises(OSError): self.custody.preview(self.alice, delivery)
        blob.unlink(); os.rename(old, blob)
        blob.chmod(0o600); blob.write_bytes(MESSAGE + b'changed'); blob.chmod(0o400)
        with self.assertRaises(Conflict): self.custody.delete(self.alice, delivery)
        self.assertEqual(0, self.custody.recover()['mail_recovery_failed'])
        self.assertTrue(blob.exists())

    def test_changed_shared_blob_prevents_interrupted_recipient_deletion_from_finalizing(self):
        staged = self.capture(); delivery = self.delivery(self.alice)
        with patch.object(self.custody, '_finish_delete', side_effect=Interrupted):
            with self.assertRaises(Interrupted): self.custody.delete(self.alice, delivery)
        blob = self.blob(staged['transaction_id']); blob.chmod(0o600)
        blob.write_bytes(MESSAGE + b'changed'); blob.chmod(0o400)
        self.assertEqual(1, self.custody.recover()['mail_recovery_failed'])
        self.assertEqual('deleting', self.custody.list(self.alice)['messages'][0]['status'])
        self.assertTrue(blob.exists())

    def test_permissions_and_native_generation_changes_guard_preview_release_delete(self):
        self.capture(); delivery = self.delivery(self.alice)
        admin = self.native.authorize('admin', 'alice')
        self.policies.save_permissions(admin, dict.fromkeys(PERMISSIONS,True) | {'release': False, 'delete': False})
        with self.assertRaises(AccessDenied): self.custody.queue_release(self.alice, delivery, 'reviewed')
        with self.assertRaises(AccessDenied): self.custody.queue_release(self.alice | {'admin': True}, delivery, 'forged role')
        with self.assertRaises(AccessDenied): self.custody.delete(self.alice, delivery)
        self.assertTrue(self.custody.preview(self.alice, delivery)['available'])
        self.custody.queue_release(admin, delivery, 'Administrator-reviewed fixture')
        self.assertEqual('release_queued', self.custody.list(self.alice)['messages'][0]['status'])
        self.ids['alice'] = 'new-generation'
        with self.assertRaises(AccessDenied): self.custody.preview(self.alice, delivery)
        new = self.native.authorize('alice'); self.assertEqual(0, self.custody.list(new)['total'])
        with self.assertRaises(AccessDenied): self.custody.preview(new, delivery)

    def test_release_destination_is_immutable_and_changed_native_target_denies_commit(self):
        staged = self.custody.stage(self.request, self.items())
        self.ids['alice'] = 'new-generation'
        with self.assertRaises(AccessDenied): self.custody.commit(staged['transaction_id'])
        with self.store.connection() as db:
            self.assertEqual({'prepared'}, {r['status'] for r in db.execute('SELECT status FROM mail_recipients')})

    def revoke_global_before_commit(self,operation):
        staged=self.capture();delivery=self.delivery(self.alice)
        self.policies.save_permissions(self.native.authorize('admin','alice'),None,reset=True)
        admin=self.native.authorize('admin')
        def defaults(grants):
            value=self.policies.server(admin)
            self.policies.save_server(admin,dict(defaults={},permissions=grants),value['revision'])
        defaults(dict(PERMISSIONS,release=True,delete=True))
        original=self.custody.policies.permissions;revoked=False
        def revoke(context,db=None):
            nonlocal revoked
            value=original(context,db)
            if db is None and not revoked:
                revoked=True;defaults(dict(PERMISSIONS))
            return value
        with patch.object(self.custody.policies,'permissions',side_effect=revoke):
            with self.assertRaises(AccessDenied):
                if operation=='release':self.custody.queue_release(self.alice,delivery,'Reviewed fixture')
                else:self.custody.delete(self.alice,delivery)
        self.assertTrue(revoked)
        self.assertEqual('quarantined',self.custody.list(self.alice)['messages'][0]['status'])
        self.assertTrue(self.blob(staged['transaction_id']).exists())

    def test_global_release_permission_revoked_before_commit_keeps_email_quarantined(self):
        self.revoke_global_before_commit('release')

    def test_global_delete_permission_revoked_before_commit_keeps_original_bytes(self):
        self.revoke_global_before_commit('delete')

    def test_plaintext_preview_skips_html_named_attachments_and_caps_input(self):
        html = safe_preview(b'Content-Type: text/html\n\n<script>no</script>', 48)
        self.assertEqual('', html['text'])
        attachment = safe_preview(b'Content-Type: text/plain; name="file.txt"\n\nAttachment bytes', 60)
        self.assertEqual('', attachment['text'])
        text = b'Subject: ' + b'x' * 2000 + b'\n\n' + b'y' * 200000
        result = safe_preview(text, len(text) + 1000)
        self.assertEqual(1000, len(result['headers']['Subject'])); self.assertEqual(128 * 1024, len(result['text']))
        self.assertTrue(result['truncated']); self.assertEqual('plain-text', result['format'])
