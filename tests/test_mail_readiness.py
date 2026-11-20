import fcntl
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

from clamshield.mail_bridge import SEALS
from clamshield.mail_readiness import ask,serve,REQUEST


@unittest.skipUnless(os.geteuid()==0,'Kernel root peer authentication requires the Linux root lab')
class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'control.sock'
        self.patcher=patch('clamshield.mail_readiness.SOCKET',self.path);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.stop=threading.Event();self.thread=None
        self.addCleanup(self.close)

    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(5);self.assertFalse(self.thread.is_alive())

    def start(self,scanner):
        factory=Mock(return_value=scanner);self.thread=serve(self.stop,factory);return factory

    def test_fixed_sealed_probe_returns_no_detection_or_diagnostic_content(self):
        def scan(fd):
            self.assertEqual(SEALS,fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS)
            body=os.pread(fd,4096,0)
            self.assertIn(b'Inert readiness message.',body)
            self.assertNotIn(b'caller-selected',body)
            return dict(complete=True,errors=[],detections=[{'private':'secret-body'}],raw='secret-diagnostics')
        factory=self.start(Mock(scan=scan))
        self.assertEqual(0o600,self.path.stat().st_mode&0o777)
        self.assertEqual(dict(complete=True,errors=[]),ask())
        factory.assert_called_once_with()

    def test_wrong_or_extended_command_never_runs_scanner(self):
        factory=self.start(Mock())
        for command in (b'/etc/shadow',REQUEST+b'caller-selected'):
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(2);peer.connect(str(self.path));peer.sendall(command)
                self.assertEqual(b'',peer.recv(4096))
        factory.assert_not_called()

    def test_scanner_errors_and_exceptions_are_bounded_fixed_codes(self):
        scanner=Mock();scanner.scan.side_effect=[dict(complete=False,errors=['private error '+('x'*10000)]),RuntimeError('secret-exception')]
        self.start(scanner)
        self.assertEqual(dict(complete=False,errors=['ScannerNotReady']),ask())
        self.assertEqual(dict(complete=False,errors=['ReadinessFailed']),ask())

    def test_kernel_peer_uid_rejects_unprivileged_client_even_if_socket_permissions_are_relaxed(self):
        factory=self.start(Mock());self.path.parent.chmod(0o755);self.path.chmod(0o666)
        code="""import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); s.settimeout(2); s.connect(sys.argv[1])
try:
    s.sendall(b'CSREADY01'); result=s.recv(4096)
except (BrokenPipeError,ConnectionResetError): result=b''
print(repr(result))
"""
        result=subprocess.run(['/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups','/usr/bin/python3','-c',code,str(self.path)],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b"b''",result.stdout.strip());factory.assert_not_called()
