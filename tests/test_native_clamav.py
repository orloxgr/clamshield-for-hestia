import os
from contextlib import contextmanager
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import Mock

from clamshield.errors import EngineError,EncryptedContent
from clamshield.native_clamav import NativeClamAV,configuration


@unittest.skipUnless(sys.platform=='linux','Linux immutable snapshots and peer credentials')
class NativeClamAVTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.base.chmod(0o710)
        self.input=self.base/'input';self.input.write_bytes(b'ignored spam then genuine malware')

    def scan(self,records,*,admission=None):
        endpoint=self.base/'socket';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(endpoint));server.listen(1);self.addCleanup(server.close)
        errors=[]
        def run():
            try:
                connection,_=server.accept()
                with connection:
                    request=b''
                    while not request.endswith(bytes([0])):request+=connection.recv(4096)
                    self.assertTrue(request.startswith(b'zALLMATCHSCAN '))
                    path=os.fsdecode(request[len(b'zALLMATCHSCAN '):-1])
                    self.assertEqual(self.input.read_bytes(),Path(path).read_bytes())
                    self.assertEqual(0o440,Path(path).stat().st_mode&0o777)
                    response=b''.join(os.fsencode(path)+b': '+line+bytes([0]) for line in records)
                    # Exercise collecting replies past the first match/frame.
                    for part in (response[:9],response[9:]):connection.sendall(part)
            except Exception as exc:errors.append(exc)
        thread=Thread(target=run,daemon=True);thread.start()
        client=NativeClamAV(endpoint,self.base,expected_uid=os.geteuid(),group=os.getgid(),admission=admission)
        try:return client.scan(self.input)
        finally:
            thread.join(3);self.assertFalse(thread.is_alive());self.assertEqual([],errors)
            self.assertEqual([],list(self.base.glob('message-*.eml')))

    def test_all_matches_survive_first_irrelevant_detection(self):
        hits=self.scan([b'Spam.Ignored.UNOFFICIAL FOUND',b'Malware.Selected.UNOFFICIAL FOUND'])
        self.assertEqual(['Spam.Ignored.UNOFFICIAL','Malware.Selected.UNOFFICIAL'],[hit['signature'] for hit in hits])

    def test_late_failure_is_not_partial_success(self):
        with self.assertRaises(EngineError):self.scan([b'Spam.Ignored.UNOFFICIAL FOUND',b'failed ERROR'])

    def test_admission_is_cleared_only_after_a_complete_native_response(self):
        reservation=Mock()
        @contextmanager
        def reserve(purpose,deadline):
            self.assertEqual('website',purpose);self.assertGreater(deadline,0)
            yield reservation
        admission=Mock();admission.reserve=reserve
        self.scan([b'Malware.Selected FOUND'],admission=admission)
        reservation.started.assert_called_once();reservation.complete.assert_called_once()
        (self.base/'socket').unlink();reservation.reset_mock()
        with self.assertRaises(EngineError):self.scan([b'Malware.Selected FOUND',b'failed ERROR'],admission=admission)
        reservation.started.assert_called_once();reservation.complete.assert_not_called()

    def test_encrypted_content_is_explicit_incomplete_coverage(self):
        with self.assertRaises(EncryptedContent):self.scan([b'Heuristics.Encrypted.Zip FOUND'])

    def test_clean_and_extended_detection_reports(self):
        self.assertEqual([],self.scan([b'OK']))
        (self.base/'socket').unlink()
        hits=self.scan([b'Malware.Selected (0123456789abcdef0123456789abcdef:33) FOUND'])
        self.assertEqual('Malware.Selected',hits[0]['signature'])

    def test_capture_limit_applies_before_daemon_connection(self):
        client=NativeClamAV(self.base/'absent',self.base,expected_uid=os.geteuid(),group=os.getgid(),maximum=3)
        with self.assertRaisesRegex(EngineError,'file limit'):client.scan(self.input)

    def test_config_discovery_preserves_multiple_exclusions_but_rejects_ambiguous_socket(self):
        path=self.base/'clamd.conf'
        text='LocalSocket /run/clamav/clamd.ctl\nDatabaseDirectory /var/lib/clamav\nExcludePath one\nExcludePath two\n'
        path.write_text(text);path.chmod(0o600)
        self.assertEqual('/var/lib/clamav',configuration(path)['DatabaseDirectory'])
        path.write_text(text+'LocalSocket /tmp/wrong\n')
        with self.assertRaisesRegex(EngineError,'duplicate'):configuration(path)
        path.write_text(text+'AllowAllMatchScan false\n')
        with self.assertRaisesRegex(EngineError,'all-match'):configuration(path)
