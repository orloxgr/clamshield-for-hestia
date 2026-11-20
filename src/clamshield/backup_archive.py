"""Bounded tar readers: no filesystem extraction, execution or implicit links."""
import hashlib
import tarfile

from .errors import ClamShieldError, Conflict
from .paths import relative_path

BLOCK=512
MAX_METADATA=65536


def exact(stream, size):
    output=bytearray()
    while len(output)<size:
        value=stream.read(min(65536,size-len(output)))
        if not value:raise Conflict('Backup archive is truncated')
        output.extend(value)
    return bytes(output)


class Member:
    def __init__(self, stream, size):
        self.stream,self.remaining=stream,size
        self.sha256=hashlib.sha256()

    def read(self, size=-1):
        if size is None or size<0:size=self.remaining
        if size>1024**2:raise Conflict('Backup parser read exceeds its limit')
        value=self.stream.read(min(size,self.remaining))
        if not value and self.remaining:raise Conflict('Backup member is truncated')
        self.remaining-=len(value);self.sha256.update(value)
        return value

    def finish(self, seek=False):
        if seek and self.remaining:
            self.stream.seek(self.remaining,1);self.remaining=0
        while self.remaining:self.read(min(65536,self.remaining))


class Budget:
    def __init__(self, stream, maximum):
        self.stream,self.remaining=stream,maximum

    def read(self, size):
        if size<0 or size>1024**2 or size>self.remaining:raise Conflict('Expanded backup exceeds its read limit')
        value=self.stream.read(size);self.remaining-=len(value)
        return value


def pax(data):
    result={}
    while data:
        try:
            length=int(data.split(b' ',1)[0])
            if not 0<length<=len(data) or data[length-1:length]!=b'\n':raise ValueError()
            record=data[:length].split(b' ',1)[1][:-1]
            key,value=record.decode('utf-8').split('=',1)
            if key in result or key.startswith('GNU.sparse'):raise ValueError()
            result[key]=value;data=data[length:]
        except (ValueError,IndexError,UnicodeError) as exc:raise Conflict('Backup PAX metadata is invalid') from exc
    return result


def visit(stream, handler, *, seek_skips=False, physical_size=None, entries=100000):
    """Visit canonical members, consuming every header to reject ambiguity."""
    seen=set();pending={};names=0;ended=False
    for _ in range(entries):
        block=exact(stream,BLOCK)
        if block==b'\0'*BLOCK:
            if exact(stream,BLOCK)!=b'\0'*BLOCK:raise Conflict('Backup end marker is invalid')
            ended=True;break
        try:info=tarfile.TarInfo.frombuf(block,'utf-8','strict')
        except (tarfile.TarError,ValueError,UnicodeError) as exc:raise Conflict('Backup tar header is invalid') from exc
        if info.size<0:raise Conflict('Backup member size is invalid')
        if info.type==tarfile.GNUTYPE_SPARSE:raise Conflict('Sparse backup members are unsupported')
        if physical_size is not None and stream.tell()+info.size>physical_size:raise Conflict('Backup member exceeds the archive')
        member=Member(stream,info.size)
        if info.type in (tarfile.GNUTYPE_LONGNAME,tarfile.XHDTYPE,tarfile.XGLTYPE):
            if info.size>MAX_METADATA:raise Conflict('Backup extended metadata exceeds its limit')
            data=exact(member,info.size)
            if info.type==tarfile.GNUTYPE_LONGNAME:
                if pending:raise Conflict('Ambiguous backup name metadata')
                try:pending={'path':data.rstrip(b'\0').decode('utf-8')}
                except UnicodeError as exc:raise Conflict('Invalid backup name encoding') from exc
            elif info.type==tarfile.XHDTYPE:
                if pending:raise Conflict('Ambiguous backup PAX metadata')
                pending=pax(data)
            elif set(pax(data))&{'path','size','linkpath'}:
                raise Conflict('Global backup path overrides are unsupported')
        else:
            info.name=pending.get('path',info.name)
            if 'size' in pending:
                try:size=int(pending['size'])
                except ValueError as exc:raise Conflict('Invalid PAX size') from exc
                if size!=info.size:raise Conflict('Conflicting backup member sizes')
            pending={}
            name=info.name[2:] if info.name.startswith('./') else info.name
            name=name.rstrip('/') if info.isdir() else name
            if name in ('','.'):name=''
            try:canonical=relative_path(name)
            except ClamShieldError as exc:raise Conflict('Backup contains an unsafe path') from exc
            if canonical!=name or (not name and not info.isdir()) or name in seen or len(name)>4096:
                raise Conflict('Backup contains duplicate or ambiguous paths')
            names+=len(name)
            if names>16*1024**2:raise Conflict('Backup path catalog exceeds its limit')
            seen.add(name);info.name=name
            handled=handler(info,member)
            member.finish(seek=seek_skips and not handled)
        padding=(-info.size)%BLOCK
        if padding:exact(stream,padding)
    if not ended or pending:raise Conflict('Backup entry limit or incomplete metadata')
    # Check checksums/frames and reject concatenated tar payloads after the end.
    while value:=stream.read(65536):
        if any(value):raise Conflict('Backup has trailing non-tar data')
