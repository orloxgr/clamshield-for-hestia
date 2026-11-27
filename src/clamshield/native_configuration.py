"""Own specific native clamd conffile directives with reversible crash journals.

Hestia files and package units are never edited here. Unrelated administrator
settings, comments, permissions and later changes survive restoration.
"""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .atomic import sync_directory,write_json
from .errors import Conflict,EngineError
from .native_clamav import CONFIG

FIELDS={'LocalSocket','DatabaseDirectory','AllowAllMatchScan','MaxThreads','MaxQueue',
        'MaxFileSize','StreamMaxLength','MaxScanSize','AlertExceedsMax','AlertEncrypted',
        'ScanMail','ScanArchive','HeuristicScanPrecedence','OfficialDatabaseOnly','MaxScanTime','LocalSocketMode'}


def digest(text):return hashlib.sha256(text.encode('utf-8',errors='surrogateescape')).hexdigest()


def directives(text):
    result={}
    for index,line in enumerate(text.splitlines(keepends=True)):
        match=re.match(r'^\s*([A-Za-z][A-Za-z0-9]*)\s+(.*?)\s*$',line)
        if not match or match[1] not in FIELDS:continue
        if match[1] in result:raise Conflict('Duplicate native ClamAV directive: '+match[1])
        result[match[1]]=dict(index=index,value=match[2],line=line)
    return result


def replace(text,replacements):
    found=directives(text);lines=text.splitlines(keepends=True)
    for key,line in replacements.items():
        if key in found:lines[found[key]['index']]=line or ''
        elif line:
            if lines and not lines[-1].endswith('\n'):lines[-1]+='\n'
            lines.append(line)
    return ''.join(lines)


class NativeConfiguration:
    def __init__(self,settings,*,path=CONFIG):
        self.settings,self.path=settings,Path(path)
        self.receipt=settings.state/'native-clamav-fields.json'
        self.journal=settings.state/'native-clamav-edit.json'

    @staticmethod
    def trusted(path,maximum):
        info=path.lstat()
        if (path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
                info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>maximum):
            raise Conflict('Untrusted native ClamAV configuration storage')
        return info

    def snapshot(self):
        info=self.trusted(self.path,128*1024)
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            if (before.st_dev,before.st_ino)!=(info.st_dev,info.st_ino):
                raise Conflict('Native ClamAV configuration was replaced')
            with os.fdopen(os.dup(fd),'rb') as source:raw=source.read(128*1024+1)
            text=raw.decode('utf-8',errors='surrogateescape')
            attributes={name:base64.b64encode(os.getxattr(fd,name)).decode() for name in os.listxattr(fd)}
            if sum(len(name)+len(value) for name,value in attributes.items())>32768:
                raise Conflict('Native ClamAV extended attributes exceed the capture limit')
            after=os.fstat(fd)
            if ((after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(before.st_size,before.st_mtime_ns,before.st_ctime_ns) or
                    len(raw)>128*1024):
                raise Conflict('Native ClamAV configuration changed during capture')
            directives(text)
            return dict(text=text,mode=stat.S_IMODE(before.st_mode),gid=before.st_gid,attributes=attributes)
        finally:os.close(fd)

    def read(self,path):
        if not path.exists() and not path.is_symlink():return None
        self.trusted(path,512*1024)
        value=json.loads(path.read_text())
        if value.get('version')!=1 or value.get('path')!=str(self.path):
            raise Conflict('Native ClamAV ownership record differs from this configuration')
        return value

    @contextmanager
    def locked(self):
        self.settings.prepare()
        path=self.settings.state/'native-clamav-edit.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            self.trusted(path,1024)
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:os.close(fd)

    def publish(self,before,after):
        current=self.snapshot()
        if current!=before:raise Conflict('Native ClamAV settings changed before publication')
        fd,name=tempfile.mkstemp(prefix='.clamshield-clamd-',dir=self.path.parent)
        try:
            os.fchown(fd,0,before['gid']);os.fchmod(fd,before['mode'])
            for key in os.listxattr(fd):
                if key not in before['attributes']:os.removexattr(fd,key)
            for key,value in before['attributes'].items():os.setxattr(fd,key,base64.b64decode(value,validate=True))
            with os.fdopen(fd,'wb') as target:
                fd=None;target.write(after.encode('utf-8',errors='surrogateescape'));target.flush();os.fsync(target.fileno())
            if self.snapshot()!=before:raise Conflict('Native ClamAV settings changed before publication')
            os.replace(name,self.path);sync_directory(self.path.parent)
        finally:
            if fd is not None:os.close(fd)
            Path(name).unlink(missing_ok=True)

    def recover_locked(self):
        journal=self.read(self.journal)
        if journal is None:return False
        current=self.snapshot();before=journal['before'];target=journal['target']
        if any(current[key]!=before[key] for key in ('mode','gid','attributes')):
            raise Conflict('Native ClamAV permissions changed during configuration recovery')
        if current['text']==before['text']:
            if current['text']!=target:self.publish(current,target)
        elif current['text']!=target:
            raise Conflict('Native ClamAV settings changed during configuration recovery')
        receipt=journal['receipt']
        if receipt is None:self.receipt.unlink(missing_ok=True)
        else:write_json(self.receipt,receipt)
        sync_directory(self.settings.state)
        self.journal.unlink();sync_directory(self.settings.state)
        return True

    def recover(self):
        with self.locked():return self.recover_locked()

    def transaction(self,before,target,receipt):
        write_json(self.journal,dict(version=1,path=str(self.path),before=before,target=target,receipt=receipt))
        self.recover_locked()

    def configure(self,values):
        if (not isinstance(values,dict) or not values or set(values)-FIELDS or
                any(not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,4096}',value) for value in values.values())):
            raise EngineError('Invalid owned native ClamAV directives')
        for key,value in values.items():
            if key in ('LocalSocket','DatabaseDirectory'):
                if not value.startswith('/') or any(part in ('.','..','') for part in value[1:].split('/')):
                    raise EngineError('Native ClamAV integration requires canonical absolute paths')
            elif key in ('MaxThreads','MaxQueue'):
                if not value.isdecimal() or not 1<=int(value)<=1024:
                    raise EngineError('Invalid native ClamAV concurrency limit')
            elif key=='MaxScanTime':
                if not value.isdecimal() or not 1<=int(value)<=120000:
                    raise EngineError('Invalid native ClamAV evaluation time limit')
            elif key=='LocalSocketMode':
                if not re.fullmatch(r'[0-7]{3,4}',value):raise EngineError('Invalid native ClamAV socket mode')
            elif key in ('MaxFileSize','StreamMaxLength','MaxScanSize'):
                match=re.fullmatch(r'([0-9]{1,10})([KMG]?)',value)
                if not match or not 0<=int(match[1])*{'':1,'K':1024,'M':1024**2,'G':1024**3}[match[2]]<=2**31-1:
                    raise EngineError('Invalid native ClamAV size limit')
            elif value.lower() not in ('yes','no','true','false','1','0'):
                raise EngineError('Invalid native ClamAV boolean directive')
        with self.locked():
            self.recover_locked();before=self.snapshot();found=directives(before['text'])
            receipt=self.read(self.receipt) or dict(version=1,path=str(self.path),original=before['text'],fields={})
            replacements={}
            for key,value in values.items():
                current=found.get(key)
                owned=receipt['fields'].get(key)
                if owned and (current is None or current['value']!=owned['after']):
                    raise Conflict('Administrator changed owned native ClamAV directive: '+key)
                if current is not None and current['value']==value:continue
                if owned is None:owned=dict(before=current['line'] if current else None)
                receipt['fields'][key]=dict(owned,after=value)
                replacements[key]=key+' '+value+'\n'
            if not replacements:return False
            target=replace(before['text'],replacements);receipt['target_sha256']=digest(target)
            self.transaction(before,target,receipt)
            return True

    def restore(self):
        with self.locked():
            self.recover_locked();receipt=self.read(self.receipt)
            if receipt is None:return dict(restored=[],preserved=[])
            before=self.snapshot();found=directives(before['text']);replacements={};preserved=[]
            for key,owned in receipt['fields'].items():
                if key not in FIELDS:raise Conflict('Unexpected owned native ClamAV directive')
                current=found.get(key)
                if current is not None and current['value']==owned['after']:replacements[key]=owned['before']
                else:preserved.append(key)
            target=receipt['original'] if digest(before['text'])==receipt['target_sha256'] else replace(before['text'],replacements)
            self.transaction(before,target,None)
            return dict(restored=sorted(replacements),preserved=sorted(preserved))
