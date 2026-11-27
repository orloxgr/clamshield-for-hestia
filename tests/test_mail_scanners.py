import fcntl
import json
from email.message import EmailMessage
from email.policy import SMTP
import os
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread
import time
import unittest

from clamshield.errors import EngineError, ClamShieldError
from clamshield.mail_bridge import SEALS
from clamshield.mail_policy import evaluate, DEFAULTS
from clamshield.mail_scanners import MailClamAV, MailScanner, SpamAssassin, readable_snapshot, mime_payloads


def spam_response(score='5.6', symbols=b'GTUBE,TEST', extra=b'', length=None):
    return (b'SPAMD/1.5 0 EX_OK\r\nSpam: True ; ' + score.encode() + b' / 5\r\nContent-length: ' +
            str(len(symbols) if length is None else length).encode() + b'\r\n' + extra + b'\r\n' + symbols)


def contribution_response(score=5.6, **changes):
    detail = dict(version=1, complete=1, score=score, threshold=5, engine_version='4.0.2', reporter_sha256='b'*64,
                  rules_version='123456', rules=[dict(name='GTUBE',score=score,hits=1,description='Test rule')])
    detail.update(changes)
    body = ('CLAMSHIELD/1 ' + 'a'*64 + '\n' + json.dumps(detail) + '\n\n').encode('ascii')
    return spam_response(str(score), symbols=body)


class MailReportTests(unittest.TestCase):
    def test_dns_metadata_is_bounded_and_never_accepts_private_query_labels(self):
        observation=dict(zone='sa-trusted.bondedsender.org',state='blocked')
        self.assertEqual([observation],SpamAssassin.parse(contribution_response(dns_observations=[observation]),require_details=True)['dns_observations'])
        for malformed in ([observation,observation],[dict(observation,query='private key')],
                          [dict(observation,zone='private-key.'+observation['zone'])],[dict(observation,state='available')]):
            with self.assertRaises(EngineError):SpamAssassin.parse(contribution_response(dns_observations=malformed),require_details=True)

    def test_contributions_are_actual_bounded_and_reconcile_with_the_reported_score(self):
        detail = SpamAssassin.parse(contribution_response(2.395), require_details=True)
        self.assertEqual(2.395, detail['rules'][0]['score'])
        self.assertEqual('a'*64, detail['revision'])
        self.assertEqual('4.0.2', detail['engine_version'])
        for response in (spam_response(), contribution_response(complete=0),
                         contribution_response(rules=[]), contribution_response(score=float('nan')),
                         contribution_response(rules=[dict(name='GTUBE',score=5.6,hits=True,description='Test')]),
                         contribution_response().replace(b'Spam: True ; 5.6', b'Spam: True ; 8.6')):
            with self.subTest(response=response[:100]), self.assertRaises(EngineError):
                SpamAssassin.parse(response, require_details=True)

    def test_spam_report_rejects_nonfinite_failed_and_truncated_scores(self):
        self.assertEqual(['GTUBE', 'TEST'], SpamAssassin.parse(spam_response())['symbols'])
        for response in [spam_response('1e9999'), spam_response('nan'), spam_response(length=90),
                         spam_response(extra=b'Spam: False ; 0 / 5\r\n'),
                         spam_response(symbols=b'ONE\r\nFORGED'), spam_response().replace(b'0 EX_OK', b'75 EX_TEMPFAIL'),
                         spam_response().replace(b'\r\n\r\n', b'\n\n'), spam_response()[:-1]]:
            with self.subTest(response=response), self.assertRaises(EngineError):
                SpamAssassin.parse(response)

    def test_allmatch_does_not_hide_later_malware_or_failed_coverage(self):
        prefix = b'/scan/msg: '
        result = MailClamAV.parse(prefix+b'Spam.Test.UNOFFICIAL FOUND\0'+prefix+b'Malware.Test FOUND\0', '/scan/msg')
        self.assertEqual(['Spam.Test.UNOFFICIAL', 'Malware.Test'], result)
        for response in [prefix+b'Spam.Test FOUND\0'+prefix+b'failed ERROR\0',
                         prefix+b'Spam.Test FOUND\0'+prefix+b'Heuristics.Limits.Exceeded.MaxFiles FOUND\0',
                         prefix+b'Heuristics.Encrypted.Zip FOUND\0', prefix+b'Malware.Test FOUND',
                         b'/wrong/path: OK\0', prefix+b'OK\0'+prefix+b'Spam.Test FOUND\0',
                         (prefix+b'Spam.Test FOUND\0')*1001]:
            with self.subTest(response=response[:180]), self.assertRaises(EngineError):
                MailClamAV.parse(response, '/scan/msg')
        self.assertEqual([], MailClamAV.parse(prefix+b'OK\0', '/scan/msg'))


@unittest.skipUnless(sys.platform == 'linux', 'Linux immutable snapshots and credentials')
class MailScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o710)
        self.fd = os.memfd_create('test-mail', os.MFD_ALLOW_SEALING)
        os.write(self.fd, b'From: harmless@example.test\r\nX-Spam-Status: forged-clean\r\n\r\nHarmless test message\r\n')
        fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, SEALS)
        self.addCleanup(os.close, self.fd)

    def test_private_copy_preserves_descriptor_offset_and_cleans_up_on_failure(self):
        os.lseek(self.fd, 17, os.SEEK_SET)
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            with readable_snapshot(self.fd, self.root, os.getgid()) as name:
                path = Path(name)
                self.assertEqual(0o440, path.stat().st_mode & 0o777)
                self.assertEqual(os.pread(self.fd, 1000, 0), path.read_bytes())
                raise RuntimeError('test failure')
        self.assertEqual(17, os.lseek(self.fd, 0, os.SEEK_CUR))
        self.assertEqual([], list(self.root.iterdir()))

    def test_readable_copy_rejects_writable_listable_symlink_and_replaced_content(self):
        for mode in (0o770, 0o750, 0o711):
            self.root.chmod(mode)
            with self.assertRaises(EngineError), readable_snapshot(self.fd, self.root, os.getgid()):
                pass
        self.root.chmod(0o710)
        alias = self.root/'alias'; alias.symlink_to(self.root)
        with self.assertRaises(EngineError), readable_snapshot(self.fd, alias, os.getgid()):
            pass
        alias.unlink()
        with self.assertRaises(EngineError):
            with readable_snapshot(self.fd, self.root, os.getgid()) as name:
                Path(name).chmod(0o640)
                Path(name).write_bytes(b'changed')
        self.assertEqual([], list(self.root.iterdir()))

    def exchange(self, response, expected_uid=None, trickle=False):
        path = self.root/'spamd.sock'
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(path)); listener.listen(1)
        received = bytearray()
        def serve():
            try:
                with listener, listener.accept()[0] as peer:
                    while block := peer.recv(65536):
                        received.extend(block)
                    if trickle:
                        for byte in response:
                            time.sleep(.03)
                            peer.sendall(bytes([byte]))
                    else:
                        peer.sendall(response)
            except (BrokenPipeError, ConnectionResetError):
                pass
        thread = Thread(target=serve); thread.start()
        try:
            result = SpamAssassin(path, expected_uid=os.getuid() if expected_uid is None else expected_uid,
                                 timeout=.12 if trickle else 2).scan(self.fd)
            payload = os.pread(self.fd, 10000, 0)
            self.assertEqual(('REPORT SPAMC/1.5\r\nContent-length: '+str(len(payload))+'\r\n\r\n').encode()+payload, received)
            return result
        finally:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            path.unlink()

    def test_spamd_sends_exact_snapshot_without_forged_score_or_user_preference(self):
        self.assertEqual(5.6, self.exchange(contribution_response())['score'])

    def test_spamd_rejects_untrusted_peer_and_absolute_deadline(self):
        with self.assertRaises(EngineError):
            self.exchange(spam_response(), expected_uid=os.getuid()+1000)
        started = time.monotonic()
        with self.assertRaises(EngineError):
            self.exchange(spam_response(), trickle=True)
        self.assertLess(time.monotonic()-started, 1)

    def test_combined_report_never_treats_engine_failure_as_clean(self):
        class Clam:
            def scan(self, fd, **kwargs): return ['Spam.Test', 'New.Unknown.Test']
        class Spam:
            def scan(self, fd, **kwargs): return {'score': 1.5, 'threshold': 5, 'symbols': ['TEST']}
        scanner = MailScanner(Clam(), Spam(), resolve_signature=lambda n: {'category': 'spam'} if n=='Spam.Test' else {})
        report = scanner.scan(self.fd)
        self.assertTrue(report['complete'])
        self.assertEqual(['spam', 'malware'], [hit['category'] for hit in report['detections']])
        policy = dict(DEFAULTS, enabled=True)
        self.assertEqual('reject', evaluate(policy, report, sender='sender@example.test', sha256=report['sha256'])['action'])
        class Broken:
            def scan(self, fd, **kwargs): raise EngineError('failed')
        for scanner in (MailScanner(Broken(), Spam()), MailScanner(Clam(), Broken())):
            report = scanner.scan(self.fd)
            self.assertFalse(report['complete'])
            decision = evaluate(policy, report, sender='', sha256=report['sha256'])
            self.assertEqual('reject' if report['detections'] else 'deliver', decision['action'])
            self.assertFalse(decision['scan_complete'])

    def test_verified_dns_observations_survive_the_mail_policy_snapshot_without_points(self):
        observation=dict(zone='sa-trusted.bondedsender.org',state='blocked')
        detail=SpamAssassin.parse(contribution_response(2.395,dns_observations=[observation]),require_details=True)
        class Clam:
            def scan(self,fd,**kwargs):return []
        class Spam:
            def scan(self,fd,**kwargs):return detail
        report=MailScanner(Clam(),Spam()).scan(self.fd)
        self.assertTrue(report['complete'])
        decision=evaluate(DEFAULTS|dict(enabled=True),report,sender='',sha256=report['sha256'])
        self.assertEqual('deliver',decision['action']);self.assertEqual(2.395,decision['spam_score'])
        self.assertEqual([observation],decision['spamassassin']['dns_observations'])

    def test_unsealed_input_is_never_submitted(self):
        fd = os.memfd_create('unsealed-mail')
        try:
            os.write(fd, b'not sealed')
            with self.assertRaises(ClamShieldError):
                SpamAssassin('/absent', expected_uid=os.getuid()).scan(fd)
        finally:
            os.close(fd)

    def mime_fd(self, data):
        fd = os.memfd_create('mime-test', os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, fd)
        os.write(fd, data); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        return fd

    def test_mime_decodes_binary_attachment_without_creating_its_filename(self):
        message = EmailMessage(); message.set_content('harmless body')
        message.add_attachment(b'YARA_DECODED_INERT_PATTERN', maintype='application', subtype='octet-stream',
                               filename='../../must-not-exist', cte='base64')
        data = message.as_bytes(policy=SMTP)
        self.assertNotIn(b'YARA_DECODED_INERT_PATTERN', data)
        fd = self.mime_fd(data)
        self.assertEqual([b'harmless body\r\n', b'YARA_DECODED_INERT_PATTERN'], list(mime_payloads(fd)))
        self.assertEqual([], list(self.root.iterdir()))

    def test_mime_limits_and_bad_encoding_fail_without_partial_clean_verdict(self):
        message = EmailMessage(); message.set_content('body')
        message.add_attachment(b'attachment', maintype='application', subtype='octet-stream')
        fd = self.mime_fd(message.as_bytes(policy=SMTP))
        for options in ({'max_parts':2}, {'max_depth':0}, {'max_decoded':5}):
            with self.subTest(options=options), self.assertRaises(EngineError):
                list(mime_payloads(fd, **options))
        for data in (b'Content-Transfer-Encoding: base64\r\n\r\n%%%bad%%%',
                     b'Content-Transfer-Encoding: quoted-printable\r\n\r\nbad=xx',
                     b'Content-Transfer-Encoding: x-unsupported\r\n\r\nopaque',
                     b'Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: binary\r\n\r\nYQ==',
                     b'Content-Type: multipart/mixed; boundary=missing\r\n\r\nnot-a-multipart-body'):
            with self.subTest(data=data), self.assertRaises(EngineError):
                list(mime_payloads(self.mime_fd(data)))

    def test_shared_mail_deadline_keeps_native_delivery_and_marks_check_incomplete(self):
        class LateClam:
            def scan(self, fd, **kwargs): time.sleep(.04); return []
        class Spam:
            def scan(self, fd, **kwargs): return {'score': 0, 'threshold': 5, 'symbols': []}
        result = MailScanner(LateClam(), Spam(), timeout=.01).scan(self.fd)
        self.assertFalse(result['complete'])
        verdict=evaluate(dict(DEFAULTS, enabled=True), result, sender='', sha256=result['sha256'])
        self.assertEqual('deliver',verdict['action']);self.assertEqual('incomplete',verdict['classification'])
