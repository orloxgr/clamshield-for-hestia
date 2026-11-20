"""Owner/generation-bound native Hestia backup selection and member snapshots."""
from contextlib import contextmanager
from datetime import datetime
import gzip
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

from .backup_archive import Budget, exact, visit
from .errors import AccessDenied, ClamShieldError, Conflict
from .paths import attributes, directory, file_handle, relative_path
from .quarantine import Quarantine


def birth(path, *, fd=None):
    result=subprocess.run(['/usr/bin/stat','--dereference','--format=%w','--',str(path)],
        capture_output=True,text=True,timeout=10,pass_fds=() if fd is None else (fd,))
    match=re.fullmatch(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.(\d{1,9}) ([+-]\d{4})\n?',result.stdout)
    if result.returncode or not match:raise Conflict('Stable backup/account birth identity is unavailable')
    value=datetime.strptime(match[1]+' '+match[3],'%Y-%m-%d %H:%M:%S %z')
    return int(value.timestamp())*10**9+int(match[2].ljust(9,'0'))


class NativeBackups:
    def __init__(self, settings, store, hestia):
        self.settings,self.store,self.hestia=settings,store,hestia

    def path(self, key, default):
        with file_handle(self.settings.hestia/'conf','hestia.conf') as (fd,info):
            if info.st_uid!=0 or info.st_mode&0o022 or info.st_size>1024**2:raise AccessDenied('Native system configuration is not protected')
            with os.fdopen(os.dup(fd),'rb') as stream:data=exact(stream,info.st_size).decode('utf-8')
        declarations=re.findall(r'^'+key+r'=(.*)$',data,re.M)
        if not declarations:return Path(default)
        if len(declarations)!=1:raise Conflict('Ambiguous native backup location')
        value=declarations[0]
        if len(value)>=2 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
        target=Path(value)
        if not value or not target.is_absolute() or '..' in target.parts or '\0' in value:
            raise Conflict('Native backup location is unsupported')
        return target

    def records(self, context, finding):
        Quarantine(self.settings,self.store,self.hestia).validate_site(context,finding)
        conf=self.settings.hestia/'data/users'/context['owner']/'backup.conf'
        if conf.is_symlink():raise Conflict('Native backup metadata is not protected')
        if not conf.exists():return {}
        rows=self.hestia.call('v-list-user-backups',context['owner'],'json')
        Quarantine(self.settings,self.store,self.hestia).validate_site(context,finding)
        if len(rows)>1000:raise Conflict('Native backup catalog exceeds its limit')
        return {name:row for name,row in rows.items() if isinstance(row,dict) and finding['domain'] in row.get('WEB','').split(',')}

    def validate_name(self, owner, name):
        if not isinstance(name,str) or not re.fullmatch(re.escape(owner)+r'\.\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d\.tar',name):
            raise AccessDenied('Invalid native backup selection')

    @contextmanager
    def opened(self, context, name):
        self.validate_name(context['owner'],name)
        base=self.path('BACKUP','/backup')
        with directory(base) as anchor:
            info=os.fstat(anchor)
            if info.st_uid!=0 or info.st_mode&0o022:raise AccessDenied('Native backup directory is not protected')
            fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=anchor)
            try:
                info=os.fstat(fd)
                account=pwd.getpwnam(context['owner']);panel=pwd.getpwnam('hestiaweb')
                owned=info.st_uid==0 or (info.st_uid in (account.pw_uid,panel.pw_uid) and info.st_gid==account.pw_gid)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not owned:
                    raise AccessDenied('Native backup is not a single owned regular file')
                account_born=birth(self.settings.hestia/'data/users'/context['owner'])
                archive_born=birth('/proc/self/fd/'+str(fd),fd=fd)
                if archive_born<account_born:raise AccessDenied('Backup belongs to an earlier account generation')
                yield fd,attributes(info)|{'born_ns':archive_born}
            finally:os.close(fd)

    def catalog(self, context, finding):
        output=[]
        for name,row in sorted(self.records(context,finding).items(),reverse=True):
            self.validate_name(context['owner'],name)
            entry=dict(name=name,date=row.get('DATE',''),available=False)
            if 'local' not in row.get('TYPE','').split(','):entry['error']='Backup is not stored locally'
            else:
                try:
                    with self.opened(context,name) as (_,info):entry.update(available=True,bytes=info['size'])
                except (OSError,ClamShieldError):entry['error']='Local archive is unavailable or its ownership/generation cannot be verified'
            output.append(entry)
        Quarantine(self.settings,self.store,self.hestia).validate_site(context,finding)
        return {'backups':output}

    def selection(self, context, finding, name):
        rows=self.records(context,finding)
        self.validate_name(context['owner'],name)
        if name not in rows or 'local' not in rows[name].get('TYPE','').split(','):
            raise AccessDenied('Local backup is unavailable for this website')
        domain_base=self.path('HOMEDIR','/home')/context['owner']/'web'/finding['domain']
        try:prefix=Path(finding['root']).relative_to(domain_base).as_posix()
        except ValueError as exc:raise Conflict('This custom document root is outside the native domain backup layout') from exc
        member=relative_path('/'.join(v for v in (prefix if prefix!='.' else '',finding['path']) if v),allow_root=False)
        with self.opened(context,name) as (_,info):pass
        Quarantine(self.settings,self.store,self.hestia).validate_site(context,finding)
        return dict(kind='hestia-backup',name=name,archive_fingerprint=info,member=member)

    def replacement(self, context, finding, source):
        current=self.selection(context,finding,source['name'])
        if current!=source:raise Conflict('Native backup or document-root mapping changed; prepare a new preview')
        content=None;compression=None;compressed_sha=None
        prefix='web/'+finding['domain']+'/domain_data.tar.'
        def outer(info, member):
            nonlocal content,compression,compressed_sha
            if info.name not in (prefix+'gz',prefix+'zst'):return False
            if content is not None or not info.isreg() or info.size>2*1024**3:raise Conflict('Native domain archive is ambiguous or exceeds its limit')
            compression=info.name.rsplit('.',1)[1]
            decoder_errors=(OSError,EOFError,ValueError)
            if compression=='gz':decoded=gzip.GzipFile(fileobj=member,mode='rb')
            else:
                try:from compression.zstd import ZstdFile,ZstdError
                except ImportError as exc:raise Conflict('Ubuntu Python Zstandard support is unavailable') from exc
                decoded=ZstdFile(member,mode='rb')
                decoder_errors=(*decoder_errors,ZstdError)
            selected=[]
            def inner(entry, data):
                if entry.name!=source['member']:return False
                if not entry.isreg() or entry.size>self.settings.max_file_bytes:raise Conflict('Backup replacement is not a bounded regular file')
                selected.append(exact(data,entry.size));return True
            try:
                with decoded:visit(Budget(decoded,1024**3),inner)
            except decoder_errors as exc:raise Conflict('Compressed native backup failed validation') from exc
            member.finish();compressed_sha=member.sha256.hexdigest()
            if len(selected)!=1:raise Conflict('This file is absent from the selected native backup')
            content=selected[0];return True
        with self.opened(context,source['name']) as (fd,before):
            if before!=source['archive_fingerprint']:raise Conflict('Native backup changed before its contents were read')
            with os.fdopen(os.dup(fd),'rb') as stream:visit(stream,outer,seek_skips=True,physical_size=before['size'])
            if attributes(os.fstat(fd))!={k:v for k,v in before.items() if k!='born_ns'}:
                raise Conflict('Native backup changed while the replacement was read')
        if content is None:raise Conflict('This website has no readable domain archive in the selected backup')
        Quarantine(self.settings,self.store,self.hestia).validate_site(context,finding)
        return content,dict(kind='hestia-backup',source=source['name'],member=source['member'],
            sha256=hashlib.sha256(content).hexdigest(),size=len(content),archive_fingerprint=before,
            compressed_member_sha256=compressed_sha,compression=compression,authenticity='account-backup',
            warning='This account backup may contain old or infected code. Successful scanning does not prove application compatibility or backup authenticity.')
