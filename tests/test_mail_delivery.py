import hashlib
import fcntl
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

import test_mail_custody as fixtures
from clamshield.errors import AccessDenied, Conflict
from clamshield.mail_delivery import MailDelivery, NativeExim, PROTOCOL, payload, matches_reinjection
from clamshield.mail_bridge import process_start


class NativeEvidenceTests(unittest.TestCase):
    def test_selected_delivery_tags_subject_by_classification_and_preserves_mime(self):
        original=b'Subject: =?UTF-8?B?VGVzdA==?=\r\n\tfolded\r\nContent-Type: application/octet-stream\r\n\r\n\x00body\xff\r\n'
        for category,label in [('malware','MALWARE'),('phishing','PHISHING'),('spam','SPAM'),('blocked-sender','BLOCKED SENDER')]:
            result=payload(original,'a'*32,'tag',classification=category)
            self.assertIn(('Subject: *** '+label+' *** =?UTF-8?B?VGVzdA==?=\n\tfolded').encode(),result)
            self.assertEqual(original.split(b'\r\n\r\n',1)[1],result.split(b'\n\n',1)[1])
            again=payload(result,'b'*32,'tag',classification=category)
            self.assertEqual(1,again.count(('*** '+label+' ***').encode()))
        self.assertIn(b'Subject: *** MALWARE ***\n',payload(b'From: a@test\n\nBody','a'*32,'tag',classification='malware'))

    def test_reinjection_preserves_existing_headers_and_only_allows_native_fixups(self):
        expected=b'From: sender@test\nSubject: Original\n\nBody\r\n'
        received=b'Received: native trace\n\tfolded\n'+expected.replace(b'\n\n',b'\nDate: Thu, 19 Nov 2026 05:00:00 +0000\nMessage-Id: <native@test>\n\n')
        self.assertTrue(matches_reinjection(expected,received))
        for changed in (received.replace(b'Original',b'Changed'),received+b'modified',
                        received.replace(b'\n\n',b'\nX-New: unapproved\n\n'),
                        received.replace(b'\n\n',b'\nDate: duplicate\n\n'),
                        received.removeprefix(b'Received: native trace\n\tfolded\n')):
            self.assertFalse(matches_reinjection(expected,changed))
        existing=b'Message-Id: <original@test>\n'+expected
        self.assertFalse(matches_reinjection(existing,b'Received: native\n'+existing.replace(b'original@test',b'other@test')))

    def test_status_headers_are_replaced_without_changing_binary_mime_body(self):
        original=(b'From: sender@example.test\r\nX-Spam-Status: forged\r\n\tforged continuation\r\n'
                  b'X-ClamShield-Forged: yes\r\nContent-Type: application/octet-stream\r\n\r\n\x00binary\r\nbytes\xff')
        prepared=payload(original,'a'*32,'junk')
        self.assertNotIn(b'forged',prepared)
        self.assertIn(b'X-Spam-Status: Yes\n',prepared)
        self.assertTrue(prepared.endswith(b'\x00binary\r\nbytes\xff'))
        self.assertIn(b'X-Spam-Status: No\n',payload(original,'a'*32,'junk',released=True))

    def test_native_acceptance_requires_root_protocol_and_unique_native_id(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'mainlog';log.write_bytes(b'')
            native=NativeExim(log=log);checkpoint=native.checkpoint()
            # Sender-visible headers/text cannot act as a native acceptance record.
            log.write_text('2026-11-19 05:10:00 native-one <= sender@test U=alice P='+PROTOCOL+'a'*32+' S=10\n')
            self.assertEqual('unknown',native.observe('a'*32,checkpoint)['state'])
            with log.open('a') as stream:
                stream.write('2026-11-19 05:10:00 fake-one <= "evil U=root P='+PROTOCOL+'a'*32+' S=10 "@test U=alice P=local S=10\n')
            self.assertEqual('unknown',native.observe('a'*32,checkpoint)['state'])
            with log.open('a') as stream:
                stream.write('2026-11-19 05:10:01 native-two <= sender@test U=root P='+PROTOCOL+'a'*32+' S=10\n')
            self.assertEqual({'state':'native_queued','native_id':'native-two'},native.observe('a'*32,checkpoint))
            with log.open('a') as stream:
                stream.write('2026-11-19 05:10:02 native-two => inbox@test R=localuser T=local_delivery\n2026-11-19 05:10:03 native-two Completed\n')
            self.assertEqual('delivered',native.observe('a'*32,checkpoint)['state'])
            with log.open('a') as stream:
                stream.write('2026-11-19 05:10:04 native-three <= sender@test U=root P='+PROTOCOL+'a'*32+' S=10\n')
            with self.assertRaises(Conflict):native.observe('a'*32,checkpoint)

    def test_rotation_can_reconcile_but_truncation_and_unsafe_logs_cannot(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'mainlog';log.write_bytes(b'old\n');native=NativeExim(log=log);checkpoint=native.checkpoint()
            with log.open('a') as stream:stream.write('2026-11-19 05:10:01 native-two <= sender@test U=root P='+PROTOCOL+'a'*32+' S=10\n')
            log.rename(log.with_name('mainlog.1'))
            log.write_text('2026-11-19 05:10:02 native-two => inbox@test R=localuser T=local_delivery\n2026-11-19 05:10:03 native-two Completed\n')
            self.assertEqual('delivered',native.observe('a'*32,checkpoint)['state'])
            checkpoint=native.checkpoint();log.write_bytes(b'')
            with self.assertRaises(Conflict):native.observe('a'*32,checkpoint)
            log.chmod(0o666)
            with self.assertRaises(AccessDenied):native.checkpoint()

    def test_persisted_native_acceptance_survives_acceptance_log_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'mainlog';log.write_bytes(b'');native=NativeExim(log=log);checkpoint=native.checkpoint()
            log.write_text('2026-11-19 05:10:02 native-two => inbox@test R=localuser T=local_delivery\n2026-11-19 05:10:03 native-two Completed\n')
            self.assertEqual('delivered',native.observe('a'*32,checkpoint,native_id='native-two')['state'])


class MailDeliveryTests(unittest.TestCase):
    setUp=fixtures.MailCustodyTests.setUp
    request_for=fixtures.MailCustodyTests.request_for
    items=fixtures.MailCustodyTests.items
    capture=fixtures.MailCustodyTests.capture
    delivery=fixtures.MailCustodyTests.delivery
    blob=fixtures.MailCustodyTests.blob

    def worker(self):
        native=Mock()
        native.checkpoint.return_value={'device':1,'inode':2,'offset':0}
        native.observe.return_value={'state':'native_queued','native_id':'native-fixture'}
        native.submit.side_effect=lambda attempt,sender,recipient,data,spawned:spawned(os.getpid())
        return MailDelivery(self.settings,self.store,self.native,native),native

    def test_prepared_or_unreleased_capture_never_enters_native_delivery(self):
        worker,native=self.worker()
        self.custody.stage(self.request,self.items())
        self.assertIsNone(worker.once()['attempt']);native.submit.assert_not_called()
        with self.store.connection() as db:transaction=db.execute('SELECT id FROM mail_transactions').fetchone()['id']
        self.custody.commit(transaction)
        self.assertIsNone(worker.once()['attempt']);native.submit.assert_not_called()

    def test_release_targets_only_stored_recipient_and_native_queue_is_not_delivery(self):
        self.capture();delivery_id=self.delivery(self.alice)
        self.custody.queue_release(self.alice,delivery_id,'False positive verified')
        worker,native=self.worker();result=worker.once()
        self.assertEqual('native_queued',result['state'])
        args=native.submit.call_args.args
        self.assertEqual('inbox@alice.test',args[2]);self.assertIn(b'X-ClamShield-Status: Released',args[3])
        row=self.custody.list(self.alice)['messages'][0];self.assertEqual('native_queued',row['status'])
        self.assertEqual('quarantined',self.custody.list(self.bob)['messages'][0]['status'])
        worker.once();self.assertEqual(1,native.submit.call_count)
        native.observe.return_value={'state':'delivered','native_id':'native-fixture'}
        worker.once();self.assertEqual('delivered',self.custody.list(self.alice)['messages'][0]['status'])

    def test_ambiguous_acceptance_never_resubmits_even_after_worker_restart(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker()
        native.observe.return_value={'state':'unknown','native_id':None}
        first=worker.once();self.assertEqual('uncertain',first['state'])
        for _ in range(3):MailDelivery(self.settings,self.store,self.native,native).once()
        self.assertEqual(1,native.submit.call_count)
        native.observe.return_value={'state':'native_queued','native_id':'native-later'}
        worker.once();self.assertEqual('native_queued',self.custody.list(self.alice)['messages'][0]['status'])
        with self.assertRaises(Conflict):worker.submit(first['attempt'])

    def test_refresh_gate_between_preparation_and_submission_retains_same_attempt_for_resume(self):
        captured=self.capture(actions=('junk','deliver'));worker,native=self.worker()
        body=self.blob(captured['transaction_id']);attempt=worker.prepare();before=body.read_bytes()
        with patch('clamshield.mail_runtime.may_deliver',side_effect=[True,False,False]):
            held=worker.once()
        self.assertEqual('prepared',held['state']);self.assertEqual(attempt,held['attempt'])
        native.submit.assert_not_called();self.assertEqual(before,body.read_bytes())
        result=worker.once()
        self.assertEqual(attempt,result['attempt']);self.assertEqual('native_queued',result['state'])
        self.assertEqual(1,native.submit.call_count)

    def test_controller_gate_waits_for_submitting_journal_but_never_locks_native_callback(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker();attempt=worker.prepare()
        entered=threading.Event();release=threading.Event();errors=[];callback_free=[]
        original=worker._data
        def paused_data(*args):
            entered.set()
            if not release.wait(5):raise RuntimeError('Test validation pause timed out')
            return original(*args)
        def submit(*args):
            fd=os.open(self.settings.state/'mail-runtime-submit.lock',os.O_RDWR)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);callback_free.append(True)
            finally:os.close(fd)
            args[-1](os.getpid())
        native.submit.side_effect=submit
        def run():
            try:worker.submit(attempt)
            except BaseException as exc:errors.append(exc)
        with patch.object(worker,'_data',side_effect=paused_data):
            thread=threading.Thread(target=run);thread.start()
            try:
                self.assertTrue(entered.wait(5))
                fd=os.open(self.settings.state/'mail-runtime-submit.lock',os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
            finally:release.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertEqual([],errors)
        self.assertEqual([True],callback_free);self.assertEqual(1,native.submit.call_count)
        with self.store.connection() as db:row=db.execute('SELECT status FROM mail_delivery_attempts WHERE id=?',(attempt,)).fetchone()
        self.assertEqual('native_queued',row['status'])

    def test_interruption_after_native_acceptance_reconciles_without_resend(self):
        self.capture(actions=('tag','deliver'));worker,native=self.worker()
        native.submit.side_effect=fixtures.Interrupted
        with self.assertRaises(fixtures.Interrupted):worker.once()
        native.submit.side_effect=None
        result=worker.once();self.assertIsNone(result['attempt']);self.assertEqual(1,native.submit.call_count)
        self.assertEqual('native_queued',self.custody.list(self.alice)['messages'][0]['status'])

    def test_interrupted_prepare_recovers_exact_bytes_without_submitting(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker()
        with patch.object(worker,'_prepared',side_effect=fixtures.Interrupted):
            with self.assertRaises(fixtures.Interrupted):worker.once()
        native.submit.assert_not_called()
        result=worker.recover();self.assertEqual(1,result['mail_delivery_prepared_recovered']);native.submit.assert_not_called()
        result=worker.once();self.assertEqual('native_queued',result['state']);self.assertEqual(1,native.submit.call_count)

    def test_changed_send_copy_and_recreated_owner_never_submit(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker()
        attempt=worker.prepare();copy=self.settings.state/'mail-custody'/(attempt+'.delivery')
        copy.chmod(0o600);copy.write_bytes(b'changed')
        with self.assertRaises(Conflict):worker.submit(attempt)
        native.submit.assert_not_called()
        self.ids['alice']='recreated-generation'
        with self.assertRaises(AccessDenied):worker.submit(attempt)
        native.submit.assert_not_called()

    def test_changed_native_reference_stays_uncertain_and_does_not_resend(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker();worker.once()
        native.observe.return_value={'state':'delivered','native_id':'other-native-reference'}
        worker.once();self.assertEqual(1,native.submit.call_count)
        self.assertEqual('delivery_uncertain',self.custody.list(self.alice)['messages'][0]['status'])

    def test_revoked_release_permission_is_rechecked_before_submission(self):
        self.capture();self.custody.queue_release(self.alice,self.delivery(self.alice),'Verified false positive')
        worker,native=self.worker();attempt=worker.prepare()
        from clamshield.mail_policy import PERMISSIONS
        admin=self.native.authorize('admin','alice')
        self.policies.save_permissions(admin,dict(dict.fromkeys(PERMISSIONS,True),release=False))
        with self.assertRaises(AccessDenied):worker.submit(attempt)
        native.submit.assert_not_called()

    def test_damaged_preparation_is_retained_for_review_without_native_submission(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker()
        with patch.object(worker,'_prepared',side_effect=fixtures.Interrupted):
            with self.assertRaises(fixtures.Interrupted):worker.once()
        with self.store.connection() as db:attempt=db.execute('SELECT id FROM mail_delivery_attempts').fetchone()['id']
        copy=self.settings.state/'mail-custody'/(attempt+'.delivery');copy.chmod(0o600);copy.write_bytes(b'changed')
        self.assertEqual(1,worker.recover()['mail_delivery_preparation_failed'])
        native.submit.assert_not_called();self.assertTrue(copy.exists())

    def test_missing_logs_do_not_erase_persisted_native_acceptance(self):
        self.capture(actions=('junk','deliver'));worker,native=self.worker();worker.once()
        native.observe.side_effect=FileNotFoundError
        worker.recover();self.assertEqual('native_queued',self.custody.list(self.alice)['messages'][0]['status'])
        self.assertEqual(1,native.submit.call_count)

    def reinjection(self):
        self.capture(actions=('tag','deliver'));worker,native=self.worker();attempt=worker.prepare()
        with self.store.connection(True) as db:
            row=worker._row(attempt,db);meta=dict(row['metadata'],pid=os.getpid(),pid_start=process_start(os.getpid()))
            from clamshield.store import encode
            db.execute("UPDATE mail_delivery_attempts SET status='submitting',metadata=? WHERE id=?",(encode(meta),attempt))
        data=(self.settings.state/'mail-custody'/(attempt+'.delivery')).read_bytes()
        request=self.request_for(content=b'Received: native root process\n'+data,recipients=('inbox@alice.test',))
        return worker,attempt,replace(request,protocol=PROTOCOL+attempt,flags=0,remote_ip='',peer_pid=os.getpid(),peer_start=process_start(os.getpid()))

    def test_exact_native_process_content_and_envelope_get_only_one_reinjection(self):
        worker,attempt,request=self.reinjection()
        self.assertTrue(worker.authorize_reinjection(request)['authorized'])
        with self.assertRaises(AccessDenied):worker.authorize_reinjection(request)
        with self.store.connection() as db:
            self.assertEqual(request.message_id,worker._row(attempt,db)['metadata']['reinjection_id'])

    def test_headers_alone_never_supply_reinjection_authority(self):
        worker,attempt,request=self.reinjection()
        self.assertIsNone(worker.authorize_reinjection(replace(request,protocol='esmtp')))
        with self.store.connection() as db:self.assertNotIn('reinjection_id',worker._row(attempt,db)['metadata'])

    def test_wrong_process_birth_sender_recipient_and_smtp_cannot_reinject(self):
        worker,attempt,request=self.reinjection()
        changes=[dict(peer_pid=None),dict(peer_pid=os.getpid()+10000),dict(peer_start=request.peer_start+1),
                 dict(flags=1),dict(remote_ip='127.0.0.1'),dict(sender='changed@test'),
                 dict(recipients=('inbox@bob.test',)),dict(recipients=('inbox@alice.test','inbox@bob.test'))]
        for fields in changes:
            with self.subTest(fields=fields),self.assertRaises(AccessDenied):
                worker.authorize_reinjection(replace(request,**fields))
        with self.store.connection() as db:self.assertNotIn('reinjection_id',worker._row(attempt,db)['metadata'])

    def test_changed_native_body_and_recreated_account_cannot_reinject(self):
        worker,attempt,request=self.reinjection()
        changed=self.request_for(content=os.pread(request.fd,100000,0)+b'changed',recipients=request.recipients)
        with self.assertRaises(Conflict):worker.authorize_reinjection(replace(request,fd=changed.fd))
        self.ids['alice']='recreated-generation'
        with self.assertRaises(AccessDenied):worker.authorize_reinjection(request)
