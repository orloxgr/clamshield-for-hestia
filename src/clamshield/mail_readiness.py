"""Root-only fixed-command probe; no caller-selected message, path or target."""
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading

from .errors import EngineError
from .mail_bridge import SEALS

SOCKET=Path('/run/clamshield-mail/control.sock')
REQUEST=b'CSREADY01'


def ask(timeout=30):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(timeout);peer.connect(str(SOCKET))
        _pid,uid,_gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise EngineError('Mail readiness endpoint is not owned by root')
        peer.sendall(REQUEST);payload=peer.recv(4097)
    if len(payload)>4096:raise EngineError('Mail readiness response exceeds its limit')
    value=json.loads(payload)
    if (not isinstance(value,dict) or set(value)!={'complete','errors'} or type(value.get('complete')) is not bool or
            not isinstance(value.get('errors'),list) or any(error not in ('ScannerNotReady','ReadinessFailed') for error in value['errors']) or len(value['errors'])>1):
        raise EngineError('Invalid mail readiness response')
    return value


def serve(stop,factory):
    if SOCKET.exists() or SOCKET.is_symlink():
        info=SOCKET.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0:raise EngineError('Untrusted readiness socket path')
        SOCKET.unlink()
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    listener.bind(str(SOCKET));SOCKET.chmod(0o600);listener.listen(2);listener.settimeout(.5)
    def loop():
        try:
            while not stop.is_set():
                try:peer,_=listener.accept()
                except socket.timeout:continue
                with peer:
                    peer.settimeout(2)
                    try:
                        _pid,uid,_gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                        if uid!=0 or peer.recv(17)!=REQUEST:continue
                        fd=os.memfd_create('clamshield-fixed-readiness',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
                        try:
                            os.write(fd,b'From: control@invalid.test\r\nTo: control@invalid.test\r\nSubject: ClamShield readiness\r\n\r\nInert readiness message.\r\n')
                            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
                            result=factory().scan(fd)
                        finally:os.close(fd)
                        # Even root callers need only readiness, never scanner
                        # diagnostics, detections or message-derived content.
                        response=dict(complete=result.get('complete') is True,errors=['ScannerNotReady'] if result.get('errors') else [])
                        peer.sendall(json.dumps(response).encode())
                    except Exception:
                        try:peer.sendall(b'{"complete":false,"errors":["ReadinessFailed"]}')
                        except OSError:pass
        finally:listener.close();SOCKET.unlink(missing_ok=True)
    thread=threading.Thread(target=loop,daemon=True);thread.start();return thread
