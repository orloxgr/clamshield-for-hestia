import fcntl
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import AccessDenied,EngineError
from clamshield.mail_bridge import SEALS,validate_snapshot
from clamshield.native_gate import NativeGate,baseline,capture
from clamshield.native_service import policy_hook_configured


def origin(name):
    extra=name=='Spam.Selected.UNOFFICIAL'
    return dict(provider='local' if extra else 'clamav',source_id='lab.ndb' if extra else 'official-databases',
                source_version='fixture',category='spam' if extra else 'malware',
                attribution='exact-database-name' if extra else 'official-engine-name')


@unittest.skipUnless(sys.platform=='linux','Native Unix credentials and sealed snapshots')
class NativeGateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o750)
        self.message=self.root/'A1b2C3-D4e5F6-G7';self.message.mkdir(mode=0o750)
        self.path=self.message/(self.message.name+'.eml');self.path.write_bytes(b'Harmless native mail fixture')
        self.path.chmod(0o640)
        self.client=Mock(maximum=1000)
        self.client.version.return_value='ClamAV 1.5.4/fixture'
        self.client.scan_snapshot.return_value=['Spam.Selected.UNOFFICIAL','Eicar-Test-Signature']
        self.gate=NativeGate(self.client,origin,exim_uid=os.geteuid(),root=self.root,timeout=.3)

    def exchange(self,command,*,uid=None):
        server,client=socket.socketpair();self.addCleanup(client.close)
        if uid is not None:
            wrapped=Mock(wraps=server)
            wrapped.getsockopt.return_value=struct.pack('3i',os.getpid(),uid,os.getgid())
        else:wrapped=server
        errors=[]
        def run():
            try:
                with server:self.gate.handle(wrapped)
            except Exception as exc:errors.append(exc)
        thread=Thread(target=run);thread.start()
        result=b''
        try:
            client.sendall(command)
            while block:=client.recv(4096):result+=block
        except (BrokenPipeError,ConnectionResetError):
            result+=b'CONNECTION REJECTED ERROR'
        thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual([],errors)
        return result

    def test_real_exim_line_protocol_scans_sealed_bytes_and_keeps_later_official_hit(self):
        def scan(fd,**_kw):
            self.assertEqual(self.path.read_bytes(),os.pread(fd,1000,0))
            self.assertEqual(SEALS,fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS)
            return ['Spam.Selected.UNOFFICIAL','Eicar-Test-Signature']
        self.client.scan_snapshot.side_effect=scan
        reply=self.exchange(b'SCAN '+os.fsencode(self.path)+b'\n')
        self.assertEqual(os.fsencode(self.path)+b': Eicar-Test-Signature FOUND\n',reply)

    def test_active_policy_hook_decides_official_malware_using_authenticated_envelope(self):
        self.gate.delegate=True
        self.assertEqual(os.fsencode(self.path)+b': OK\n',self.exchange(b'SCAN '+os.fsencode(self.path)+b'\n'))
        self.client.scan_snapshot.assert_not_called()
        self.assertIn(b'ERROR',self.exchange(b'SCAN /etc/shadow\n'))

    def test_policy_delegation_uses_attached_owned_hook_not_broker_heartbeat(self):
        from clamshield.mail_integration import MACRO_TEXT
        import hashlib
        macro=self.root/'macros';macro.write_text(MACRO_TEXT);macro.chmod(0o644)
        library=self.root/'local_scan.so';library.write_bytes(b'owned-test-library');library.chmod(0o644)
        current=dict(phase='active',adapter=dict(library_sha256=hashlib.sha256(library.read_bytes()).hexdigest()))
        with patch('clamshield.mail_runtime.state',return_value=current), \
                patch('clamshield.mail_integration.MACRO',macro),patch('clamshield.mail_integration.LIBRARY',library):
            self.assertTrue(policy_hook_configured(None))
            current['phase']='starting';self.assertTrue(policy_hook_configured(None))
            current['phase']='disabled';self.assertFalse(policy_hook_configured(None))
            current['phase']='active';library.write_bytes(b'foreign');self.assertFalse(policy_hook_configured(None))

    def test_proven_supplemental_only_is_left_for_later_policy_but_unknown_stays_actionable(self):
        self.assertEqual([],baseline(['Spam.Selected.UNOFFICIAL'],origin))
        self.assertEqual(['Unknown.UNOFFICIAL'],baseline(['Unknown.UNOFFICIAL'],origin))
        native=lambda _name:dict(provider='native',source_id='prior-native.ndb',source_version='fixture',category='malware',
                                 attribution='exact-database-name')
        self.assertEqual(['Native.Existing.UNOFFICIAL'],baseline(['Native.Existing.UNOFFICIAL'],native))
        self.client.scan_snapshot.return_value=['Spam.Selected.UNOFFICIAL']
        self.assertTrue(self.exchange(b'zSCAN '+os.fsencode(self.path)+b'\0').endswith(b': OK\0'))

    def test_engine_and_capture_errors_never_return_clean(self):
        self.client.scan_snapshot.side_effect=EngineError('failed')
        self.assertIn(b'ERROR',self.exchange(b'SCAN '+os.fsencode(self.path)+b'\n'))
        self.client.scan_snapshot.reset_mock()
        self.assertIn(b'ERROR',self.exchange(b'SCAN /etc/shadow\n'))
        self.client.scan_snapshot.assert_not_called()

    def test_wrong_uid_and_unsupported_or_oversized_commands_do_not_scan(self):
        for command,uid in ((b'PING\n',os.geteuid()+10000),(b'RELOAD\n',None),(b'x'*4098,None)):
            with self.subTest(command=command[:10]):
                self.assertIn(b'ERROR',self.exchange(command,uid=uid))
        self.client.scan_snapshot.assert_not_called()
        self.assertEqual(b'PONG\0',self.exchange(b'zPING\0'))
        self.client.version.side_effect=EngineError('Native daemon stopped')
        self.assertIn(b'ERROR',self.exchange(b'PING\n'))

    def test_capture_rejects_symlinks_hardlinks_and_special_files(self):
        self.path.unlink();self.path.symlink_to('/etc/hosts')
        with self.assertRaises(OSError),capture(str(self.path),self.root,os.geteuid(),1000):pass
        self.path.unlink();other=self.root/'other';other.write_bytes(b'bytes');os.link(other,self.path)
        with self.assertRaises(AccessDenied),capture(str(self.path),self.root,os.geteuid(),1000):pass
        self.path.unlink();os.mkfifo(self.path)
        with self.assertRaises(AccessDenied),capture(str(self.path),self.root,os.geteuid(),1000):pass

    def test_capture_detects_concurrent_content_replacement_and_size_limits(self):
        original=os.read
        def changed(fd,size):
            result=original(fd,size)
            if result:self.path.write_bytes(b'Changed native file')
            return result
        with patch('clamshield.native_gate.os.read',side_effect=changed),self.assertRaises(EngineError), \
                capture(str(self.path),self.root,os.geteuid(),1000):pass
        with self.assertRaises(AccessDenied),capture(str(self.path),self.root,os.geteuid(),3):pass

    def test_capture_is_a_sealed_descriptor_and_does_not_follow_message_directory(self):
        with capture(str(self.path),self.root,os.geteuid(),1000) as fd:
            self.assertEqual(self.path.stat().st_size,validate_snapshot(fd).st_size)
        self.path.unlink();self.message.rmdir();self.message.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError),capture(str(self.path),self.root,os.geteuid(),1000):pass
