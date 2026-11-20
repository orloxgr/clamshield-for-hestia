import os
from pathlib import Path
import socket
import struct
import tempfile
from threading import Thread
import unittest

from clamshield.engines import ClamAV, Yara
from clamshield.errors import EngineError, EncryptedContent


class ClamProtocol(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.file = self.base / 'sample'
        self.file.write_bytes(b'fixture contents')

    def exchange(self, verdict):
        path = self.base / 'clamd.sock'
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(path)); server.listen(1)
        received = bytearray()
        def receive():
            with server, server.accept()[0] as client:
                prefix = b''
                while not prefix.endswith(b'\0'):
                    prefix += client.recv(1)
                self.assertEqual(b'zINSTREAM\0', prefix)
                while True:
                    header = b''
                    while len(header) < 4:
                        header += client.recv(4 - len(header))
                    length = struct.unpack('!I', header)[0]
                    if not length:
                        break
                    while length:
                        chunk = client.recv(length)
                        received.extend(chunk); length -= len(chunk)
                client.sendall(verdict)
        thread = Thread(target=receive)
        thread.start()
        try:
            return ClamAV(path).scan(self.file)
        finally:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(self.file.read_bytes(), received)

    def test_stream_is_complete_and_detection_is_parsed(self):
        result = self.exchange(b'stream: SecuriteInfo.Test.UNOFFICIAL FOUND\0')
        self.assertEqual('securiteinfo', result[0]['provider'])

    def test_error_does_not_become_clean(self):
        with self.assertRaises(EngineError):
            self.exchange(b'stream: scan failed ERROR\0')

    def test_limit_detection_is_incomplete_coverage(self):
        with self.assertRaises(EngineError):
            self.exchange(b'stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0')

    def test_encrypted_archives_and_documents_are_incomplete_not_malware(self):
        for kind in ('Zip','RAR','PDF'):
            with self.subTest(kind=kind):
                (self.base/'clamd.sock').unlink(missing_ok=True)
                with self.assertRaises(EncryptedContent):
                    self.exchange(('stream: Heuristics.Encrypted.'+kind+' FOUND\0').encode())

    def test_unofficial_signature_cannot_spoof_an_internal_coverage_heuristic(self):
        for signature in ('Heuristics.Encrypted.Zip.UNOFFICIAL','Heuristics.Limits.Exceeded.MaxScanSize.UNOFFICIAL'):
            with self.subTest(signature=signature):
                (self.base/'clamd.sock').unlink(missing_ok=True)
                result=self.exchange(('stream: '+signature+' FOUND\0').encode())
                self.assertEqual(signature,result[0]['signature']);self.assertEqual('unofficial',result[0]['provider'])


@unittest.skipUnless(Path('/usr/bin/yara').is_file(), 'Ubuntu YARA integration')
class UbuntuYara(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / 'rules.yar'
        self.rules.write_text('rule ClamShield_Fixture { strings: $s="CLAMSHIELD_TEST_PAYLOAD" condition: $s }')
        self.file = self.root / 'sample.php'

    def test_installed_engine_reads_private_files_via_readonly_descriptors(self):
        self.file.write_text('<?php /* CLAMSHIELD_TEST_PAYLOAD */ ?>')
        self.file.chmod(0o600)
        self.rules.chmod(0o600)
        self.root.chmod(0o700)
        matches = Yara('/usr/bin/yara', self.rules).scan(self.file)
        self.assertEqual(['ClamShield_Fixture'], [item['signature'] for item in matches])

    def test_clean_file_returns_no_matches(self):
        self.file.write_text('<?php echo "Hello"; ?>')
        self.assertEqual([], Yara('/usr/bin/yara', self.rules).scan(self.file))

    def test_invalid_rules_are_an_error(self):
        self.file.write_text('clean')
        self.rules.write_text('invalid yara')
        with self.assertRaises(EngineError):
            Yara('/usr/bin/yara', self.rules).scan(self.file)
