"""Discover the distro daemon and submit complete all-match scan requests.

No service/configuration writes occur here. Installation owns any later native
integration; clients must not guess that a missing socket is a clean verdict.
"""
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import subprocess
import time

from .errors import EngineError, EncryptedContent, CoverageUnavailable
from .engines import sealed_file
from .mail_scanners import MailClamAV, readable_snapshot, _connect, _read


CONFIG=Path('/etc/clamav/clamd.conf')
UNIT='clamav-daemon.service'


def configuration(path=CONFIG):
    path=Path(path)
    info=path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
            info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>128*1024):
        raise EngineError('Native ClamAV configuration is not trusted')
    values={}
    for raw in path.read_text().splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):continue
        key,separator,value=line.partition(' ')
        if not separator:
            parts=line.split(None,1)
            if len(parts)!=2:continue
            key,value=parts
        if key in values and key in ('LocalSocket','DatabaseDirectory','User','AllowAllMatchScan'):
            raise EngineError('Native ClamAV configuration has duplicate '+key)
        values[key]=value.strip()
    for key in ('LocalSocket','DatabaseDirectory'):
        value=values.get(key,'')
        if not value.startswith('/') or any(ord(c)<32 for c in value):
            raise EngineError('Native ClamAV requires a local '+key)
    if values.get('AllowAllMatchScan','yes').lower() not in ('yes','true','1'):
        raise EngineError('Native ClamAV must permit all-match scans')
    return values


class NativeClamAV:
    """One bounded request per captured file; the distro daemon stays resident."""
    name='clamav'

    def __init__(self,endpoint,directory,*,expected_uid,group,timeout=45,maximum=50*1024**2):
        self.socket_path=str(endpoint);self.directory=Path(directory)
        self.expected_uid=expected_uid;self.group=group;self.timeout=timeout;self.maximum=maximum

    @classmethod
    def discover(cls,directory,*,path=CONFIG,timeout=45,maximum=50*1024**2):
        values=configuration(path);identity=pwd.getpwnam(values.get('User','clamav'))
        endpoint=Path(values['LocalSocket']);info=endpoint.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=identity.pw_uid:
            raise EngineError('Native ClamAV socket is not owned by its service account')
        # Distro socket activation preserves PID 1/root as SO_PEERCRED even
        # after clamd accepts the inherited descriptor and drops privileges.
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
            probe.settimeout(2);probe.connect(str(endpoint))
            peer_pid,peer_uid,_=struct.unpack('3i',probe.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if peer_uid!=identity.pw_uid:
            if (peer_pid,peer_uid)!=(1,0):raise EngineError('Native ClamAV socket peer is unexpected')
            pid=subprocess.check_output(['/usr/bin/systemctl','show',UNIT,'--property=MainPID','--value'],timeout=3).decode().strip()
            if not pid.isdigit() or int(pid)<2:raise EngineError('Native ClamAV service is not running')
            if not os.path.samefile('/proc/'+pid+'/exe','/usr/sbin/clamd'):
                raise EngineError('Native ClamAV service executable is unexpected')
            if not any(line.endswith(':/system.slice/'+UNIT) for line in Path('/proc/'+pid+'/cgroup').read_text().splitlines()):
                raise EngineError('Native ClamAV process is outside its package service')
        client=cls(endpoint,directory,expected_uid=peer_uid,group=identity.pw_gid,timeout=timeout,maximum=maximum)
        with _connect(endpoint,peer_uid,time.monotonic()+2) as connection:
            connection.sendall(b'zVERSIONCOMMANDS\0')
            reply=_read(connection,time.monotonic()+2)
        if b'ALLMATCHSCAN' not in reply:raise EngineError('Native ClamAV lacks all-match protocol support')
        return client

    def scan(self,path):
        with sealed_file(path,self.maximum) as source:
            size=os.fstat(source).st_size
            if size>self.maximum:raise CoverageUnavailable('Native ClamAV input exceeds the selected file limit')
            if size==0:return []
            deadline=time.monotonic()+self.timeout
            try:
                with readable_snapshot(source,self.directory,self.group) as name:
                    with _connect(self.socket_path,self.expected_uid,deadline) as connection:
                        connection.sendall(b'zALLMATCHSCAN '+os.fsencode(name)+b'\0')
                        response=_read(connection,deadline)
                    # Preserve the website distinction between encryption and
                    # ordinary engine failure; neither is clean coverage.
                    if b': Heuristics.Encrypted' in response:
                        raise EncryptedContent('Native ClamAV encountered encrypted content')
                    names=MailClamAV.parse(response,name)
            except OSError as exc:raise EngineError('Native ClamAV is unavailable or timed out') from exc
        return [dict(engine='clamav',signature=name,provider='unclassified') for name in names]
