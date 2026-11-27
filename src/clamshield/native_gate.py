"""Native Exim's baseline antivirus protocol, backed by the shared native daemon.

The later policy hook handles selected supplemental signatures. This first gate
retains official/unknown detections and ignores only proven supplemental names.
No service/configuration is changed by importing or constructing this handler.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

from .errors import AccessDenied, ClamShieldError, EngineError
from .mail_bridge import SEALS
from .signature_catalog import validate_origin


def fingerprint(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


@contextmanager
def capture(path,root,uid,maximum):
    """Open Exim's precise scan file through held directories; never follow links."""
    root=Path(root)
    if root.resolve(strict=True)!=root:raise AccessDenied('Native scan root is not canonical')
    match=re.fullmatch(re.escape(str(root))+r'/([A-Za-z0-9-]{6,64})/\1\.eml',path)
    if not match:raise AccessDenied('Native antivirus accepts only Exim scan snapshots')
    handles=[]
    try:
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);handles.append(parent)
        parent_info=os.fstat(parent)
        if parent_info.st_uid not in (0,uid) or parent_info.st_mode&0o022:
            raise AccessDenied('Untrusted native scan directory')
        folder=os.open(match[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);handles.append(folder)
        info=os.fstat(folder)
        if info.st_uid not in (0,uid) or info.st_mode&0o022:
            raise AccessDenied('Untrusted native message directory')
        source=os.open(match[1]+'.eml',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder);handles.append(source)
        before=os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0,uid) or before.st_nlink!=1 or
                before.st_mode&0o022 or before.st_size>maximum):
            raise AccessDenied('Untrusted or oversized native message snapshot')
        target=os.memfd_create('clamshield-native-exim',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC);handles.append(target)
        total=0
        while block:=os.read(source,min(65536,maximum+1-total)):
            total+=len(block)
            if total>maximum:raise EngineError('Native message grew beyond its scan limit')
            view=memoryview(block)
            while view:
                written=os.write(target,view)
                if not written:raise EngineError('Native message snapshot could not be captured')
                view=view[written:]
        if (total!=before.st_size or fingerprint(os.fstat(source))!=fingerprint(before) or
                fingerprint(os.stat(match[1]+'.eml',dir_fd=folder,follow_symlinks=False))!=fingerprint(before)):
            raise EngineError('Native message changed during capture')
        fcntl.fcntl(target,fcntl.F_ADD_SEALS,SEALS)
        yield target
    finally:
        for handle in reversed(handles):os.close(handle)


def baseline(names,resolver):
    """Never let an excluded first match hide an official or unattributed hit."""
    retained=[]
    for name in names:
        if not isinstance(name,str) or not re.fullmatch(r'[^\x00-\x1f\x7f]{1,512}',name):
            raise EngineError('Invalid native antivirus signature')
        origin=validate_origin(resolver(name))
        if name.endswith('.UNOFFICIAL') and origin.get('attribution') in ('exact-database-name','ambiguous-name'):
            continue
        retained.append(name)
    return retained


class NativeGate:
    def __init__(self,client,resolver,*,exim_uid,root='/var/spool/exim4/scan',timeout=25):
        self.client,self.resolver=client,resolver
        self.exim_uid,self.root,self.timeout=exim_uid,Path(root),timeout

    def handle(self,connection):
        deadline=time.monotonic()+self.timeout
        path=None;terminator=b'\n';status='control';error=None
        try:
            _pid,uid,_gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid not in (0,self.exim_uid):raise AccessDenied('Native antivirus peer is not Exim')
            request=bytearray()
            while len(request)<=4096:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise EngineError('Native antivirus request timed out')
                connection.settimeout(remaining)
                byte=connection.recv(1)
                if not byte:raise EngineError('Incomplete native antivirus request')
                request.extend(byte)
                if len(request)==1 and byte==b'z':terminator=b'\0'
                if byte==terminator:break
            else:raise EngineError('Native antivirus request is too long')
            command=bytes(request[:-1])
            if command[:1] in (b'z',b'n'):command=command[1:]
            if command==b'PING':
                reply=b'PONG'
            elif command in (b'VERSION',b'VERSIONCOMMANDS'):
                reply=self.client.version().encode('ascii')
                if command==b'VERSIONCOMMANDS':reply+=b'| COMMANDS: SCAN PING VERSION VERSIONCOMMANDS'
            else:
                if not command.startswith(b'SCAN '):raise EngineError('Unsupported native antivirus command')
                path=command[5:].decode('ascii')
                with capture(path,self.root,self.exim_uid,self.client.maximum) as source:
                    hits=self.client.scan_snapshot(source,deadline=deadline)
                names=baseline(hits,self.resolver)
                status='infected' if names else 'clean'
                reply=os.fsencode(path)+b': '+(names[0].encode('utf-8')+b' FOUND' if names else b'OK')
        except Exception as exc:
            # Never translate protocol, capture, provenance or engine failure to OK.
            reply=b'ClamShield native antivirus check failed ERROR'
            status='error';error=type(exc).__name__
        try:
            connection.settimeout(max(.01,deadline-time.monotonic()))
            connection.sendall(reply+terminator)
        except OSError:pass
        return dict(status=status,error=error)
