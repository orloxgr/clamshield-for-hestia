"""Native spamd fallback for mail skipped by Hestia's early warning ACL.

Only the fixed loopback endpoint is used. Before sending message bytes, bind the
accepted TCP socket to a process in the native spamd systemd control group.
"""
from contextlib import contextmanager
import ipaddress
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import time

from .errors import EngineError
from .mail_bridge import process_start,validate_snapshot
from .mail_scanners import _remaining,_read


def endpoint(value):
    address,port=value.split(':')
    raw=bytes.fromhex(address)
    if len(raw) not in (4,16):raise ValueError('Invalid kernel TCP address')
    ip=ipaddress.ip_address(b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4)))
    if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped:ip=ip.ipv4_mapped
    return str(ip),int(port,16)


def native_group(deadline):
    for unit in ('spamd.service','spamassassin.service'):
        result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=MainPID,ControlGroup'],
            capture_output=True,text=True,timeout=min(2,_remaining(deadline)))
        if result.returncode or len(result.stdout)>4096:continue
        fields=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if (re.fullmatch(r'[1-9][0-9]{0,9}',fields.get('MainPID','')) and
                fields.get('ControlGroup') in ('/system.slice/spamd.service','/system.slice/spamassassin.service')):
            pid=int(fields['MainPID']);return fields['ControlGroup'],pid,process_start(pid)
    raise EngineError('Native SpamAssassin service is not active')


def server_inode(connection):
    local,remote=connection.getpeername(),connection.getsockname()
    for name in ('tcp','tcp6'):
        with open('/proc/net/'+name) as stream:data=stream.read(4*1024**2+1)
        if len(data)>4*1024**2:raise EngineError('Native TCP inventory exceeded its limit')
        for line in data.splitlines()[1:]:
            fields=line.split()
            if len(fields)>9 and fields[3]=='01' and endpoint(fields[1])==local and endpoint(fields[2])==remote:
                if re.fullmatch(r'[1-9][0-9]{0,19}',fields[9]):return fields[9]
    return None


def accepted_peer(connection,group,deadline):
    # The native listener can exist before spamd has finished creating its
    # accepting workers. Observe this one connection, bounded by the caller's
    # deadline; no message bytes are sent until its peer is authenticated.
    until=min(deadline,time.monotonic()+5)
    while time.monotonic()<until:
        inode=server_inode(connection)
        text=(Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs').read_text()
        pids=text.split()
        if len(text)>16384 or len(pids)>256:raise EngineError('Native spamd process inventory exceeded its limit')
        if inode:
            for value in pids:
                if not re.fullmatch(r'[1-9][0-9]{0,9}',value):raise EngineError('Invalid native spamd process')
                pid=int(value)
                try:
                    birth=process_start(pid);directory=Path('/proc')/value
                    if '0::'+group not in (directory/'cgroup').read_text().splitlines():continue
                    handles=list((directory/'fd').iterdir())
                    if len(handles)>4096:raise EngineError('Native spamd descriptor inventory exceeded its limit')
                    if any(os.readlink(path)=='socket:['+inode+']' for path in handles):
                        if process_start(pid)==birth:return dict(pid=pid,birth=birth)
                except (FileNotFoundError,ProcessLookupError):continue
        time.sleep(.01)
    raise EngineError('Native SpamAssassin TCP peer is not in the verified native service')


@contextmanager
def connect(deadline):
    from .native_spam import verify_endpoint
    verify_endpoint()
    group,pid,birth=native_group(deadline)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection:
        connection.settimeout(_remaining(deadline));connection.connect(('127.0.0.1',783))
        peer=accepted_peer(connection,group,deadline)
        if process_start(pid)!=birth:raise EngineError('Native SpamAssassin restarted before scanning')
        yield connection,peer


class NativeSpamAssassin:
    def scan(self,fd,*,deadline):
        info=validate_snapshot(fd)
        try:
            with connect(deadline) as (connection,peer):
                connection.sendall(('REPORT SPAMC/1.2\r\nUser: debian-spamd\r\nContent-length: '+str(info.st_size)+'\r\n\r\n').encode())
                offset=0
                while offset<info.st_size:
                    connection.settimeout(_remaining(deadline));block=os.pread(fd,min(65536,info.st_size-offset),offset)
                    if not block:raise EngineError('Native spam snapshot is incomplete')
                    connection.sendall(block);offset+=len(block)
                connection.shutdown(socket.SHUT_WR);response=_read(connection,deadline)
                if process_start(peer['pid'])!=peer['birth']:raise EngineError('Native spamd process changed during scanning')
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            raise EngineError('Native SpamAssassin is unavailable') from exc
        return self.parse(response)

    @staticmethod
    def parse(response):
        try:
            head,separator,body=response.partition(b'\r\n\r\n')
            lines=head.decode('ascii').split('\r\n')
            if not separator or len(head)>16384 or not re.fullmatch(r'SPAMD/1\.[0-5] 0 EX_OK',lines[0]):raise ValueError()
            headers={}
            for line in lines[1:]:
                key,colon,value=line.partition(':');key=key.lower()
                if not colon or key in headers:raise ValueError()
                headers[key]=value.strip()
            if 'content-length' in headers:
                if not re.fullmatch(r'[0-9]{1,6}',headers['content-length']) or int(headers['content-length'])!=len(body):raise ValueError()
                first,_,report=body.partition(b'\n')
                match=re.fullmatch(rb'([-+0-9.eE]+)/([-+0-9.eE]+)\r?',first)
            else:
                # Current native spamd responds to REPORT/1.2 with Spam: and
                # closes the connection. This is Exim's own fallback format.
                match=re.fullmatch(rb'(?:True|False) ; ([-+0-9.eE]+) / ([-+0-9.eE]+)',headers.get('spam','').encode())
                report=body
            if not match:raise ValueError()
            score,threshold=map(float,match.groups())
            if any(not math.isfinite(value) or abs(value)>1e6 for value in (score,threshold)):raise ValueError()
            # Match Exim's native integer calculation, including its .001 bias.
            metric=int((score+.001)*10)/10
            text=report.decode('utf-8')
            if any(ord(char)<32 and char not in '\n\r\t' for char in text):raise ValueError()
            return dict(score=metric,engine_score=score,required_score=threshold,report=text,source='native-spamd-report')
        except (ValueError,UnicodeError,IndexError) as exc:
            raise EngineError('Native SpamAssassin returned an invalid report') from exc
