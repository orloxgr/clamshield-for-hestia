"""Reversible native spam-rejection delegation using supported Hestia commands.

This controller never writes a native template or mail.conf. Every native API
attempt has durable intent before execution; failed/uncertain attempts require
review rather than an automatic retry. Account and domain directory generations
bind receipts so uninstall cannot change a recreated tenant/domain.
"""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import grp
import stat

from .atomic import write_json
from .errors import AccessDenied,Conflict,EngineError
from .hestia import account_name
from .mail_adapter import bounded,trusted
from .mail_inventory import domain_name
from .mail_runtime import read,fingerprint
from .paths import attributes,directory

HOME=Path('/home')
EXTENSION='add-mail-domain.sh'
EXTENSION_TEXT='#!/bin/sh\n# Managed by clamshield: native mail policy delegation\nexec /usr/local/hestia/bin/v-clamshield mail-domain-added "$@"\n'


def key(owner,identity,domain,generation):
    return hashlib.sha256((owner+'\0'+identity+'\0'+domain+'\0'+generation).encode()).hexdigest()


@contextmanager
def native_directory(hestia,owner,identity,domain):
    owner=account_name(owner);domain=domain_name(domain)
    if hestia.identity(owner)!=identity:raise AccessDenied('Native mail account changed')
    mail_uid=pwd.getpwnam('Debian-exim').pw_uid;mail_gid=grp.getgrnam('mail').gr_gid
    tenant=pwd.getpwnam(owner)
    if tenant.pw_uid in (0,mail_uid) or mail_gid in os.getgrouplist(owner,tenant.pw_gid):
        raise AccessDenied('Native mail directory is writable by the hosting account')
    path=HOME/owner/'conf/mail'/domain
    # All ancestors are root-owned and cannot be renamed by the tenant. The
    # native mail leaf belongs to the distro mail service, not the hosting user.
    with directory('/') as initial:
        fd=os.dup(initial)
        try:
            for index,part in enumerate(path.parts[1:]):
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child;info=os.fstat(fd)
                leaf=index==len(path.parts[1:])-1
                if ((not leaf and (info.st_uid!=0 or info.st_mode&0o022)) or
                        (leaf and (info.st_uid not in (0,mail_uid) or info.st_gid!=mail_gid or info.st_mode&0o007!=1))):
                    raise AccessDenied('Native mail directory ownership is not supported')
            birth,_=hestia.birth(fd)
            generation=hashlib.sha256(f'{info.st_dev}:{info.st_ino}:{birth}'.encode()).hexdigest()
            yield fd,generation
            with directory(path) as live:
                actual=os.fstat(live)
                if (actual.st_dev,actual.st_ino)!=(info.st_dev,info.st_ino):
                    raise AccessDenied('Native mail domain changed during delegation')
            if hestia.identity(owner)!=identity:raise AccessDenied('Native mail account changed during delegation')
        finally:os.close(fd)


def flag(fd):
    try:handle=os.open('reject_spam',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    except FileNotFoundError:return None
    try:
        info=os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>4096 or info.st_mode&0o003 or
                info.st_uid not in (0,pwd.getpwnam('Debian-exim').pw_uid) or info.st_gid not in (0,grp.getgrnam('mail').gr_gid)):
            raise AccessDenied('Native rejection flag is not a private regular file')
        data=os.read(handle,4097)
        if len(data)>4096 or attributes(os.fstat(handle))!=attributes(info):
            raise Conflict('Native rejection flag changed during inspection')
        live=os.stat('reject_spam',dir_fd=fd,follow_symlinks=False)
        if attributes(live)!=attributes(info):raise Conflict('Native rejection flag was replaced')
        return dict(content=base64.b64encode(data).decode(),attributes=attributes(info))
    finally:os.close(handle)


class NativeRejection:
    def __init__(self,settings,hestia):
        self.settings,self.hestia=settings,hestia
        self.path=settings.state/'native-rejection.json'
        self.extension=settings.state/'native-rejection-extension.json'

    def ready(self):
        from .mail_integration import MailIntegration,runtime_hook_ready
        from .mail_service import transport_active
        if not runtime_hook_ready() or not transport_active():raise Conflict('Verify the active mail policy hook before delegating native rejection')
        MailIntegration(self.settings,None,self.hestia).guard()

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'native-rejection.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            trusted(path)
            if stat.S_IMODE(os.fstat(fd).st_mode)!=0o600:raise EngineError('Native rejection lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def ledger(self):
        value=read(self.path)
        if value is None:return dict(owner='clamshield',schema=1,entries={})
        if (not isinstance(value,dict) or set(value)!={'owner','schema','entries'} or value['owner']!='clamshield' or
                value['schema']!=1 or not isinstance(value['entries'],dict) or len(value['entries'])>100000):
            raise EngineError('Invalid native rejection ledger')
        for ident,row in value['entries'].items():
            if (not isinstance(row,dict) or row.get('state') not in ('remove_pending','restore_pending','active','restored','retired','review') or
                    ident!=key(account_name(row['owner']),row['identity'],domain_name(row['domain']),row.get('domain_identity','')) or
                    len(row.get('domain_identity',''))!=64 or not isinstance(row.get('original'),dict)):
                raise EngineError('Invalid native rejection receipt')
            data=base64.b64decode(row['original']['content'],validate=True)
            if len(data)>4096:raise EngineError('Oversized native rejection receipt')
        return value

    def native_row(self,owner,identity,domain):
        if self.hestia.identity(owner)!=identity:raise AccessDenied('Native mail account changed')
        row=self.hestia.call('v-list-mail-domains',owner,'json').get(domain)
        if not row:raise AccessDenied('Native mail domain is unavailable')
        return row

    def command(self,owner,identity,domain,enabled):
        # Dedicated fixed mutation entry; the inventory allowlist stays read-only.
        self.native_row(owner,identity,domain)
        script=self.hestia.root/'bin'/('v-add-mail-domain-reject' if enabled else 'v-delete-mail-domain-reject')
        trusted(script)
        result=bounded([str(script),owner,domain],timeout=self.hestia.remaining(10),check=False)
        if result.returncode:raise EngineError('Native spam rejection change failed; review required')
        self.native_row(owner,identity,domain)

    def suppress(self,owner,identity,domain):
        owner=account_name(owner);domain=domain_name(domain)
        self.ready()
        with self.locked():
            value=self.ledger()
            with native_directory(self.hestia,owner,identity,domain) as (fd,generation):
                ident=key(owner,identity,domain,generation);previous=value['entries'].get(ident)
                native=self.native_row(owner,identity,domain);before=flag(fd)
                if previous and previous['state']=='restored':previous=None
                if previous:
                    if previous['state']=='active' and before is None and native.get('REJECT')!='yes':return False
                    # A reappeared flag is an administrator change, not permission
                    # to repeatedly suppress the native administrator's choice.
                    if previous['state']=='active':
                        previous['state']='review';write_json(self.path,value)
                    raise Conflict('Native rejection delegation requires review')
                if before is None and native.get('REJECT')!='yes':return False
                if before is None or native.get('REJECT')!='yes':raise Conflict('Native rejection flag and inventory disagree')
                row=dict(owner=owner,identity=identity,domain=domain,domain_identity=generation,
                         original=before,state='remove_pending')
                value['entries'][ident]=row;write_json(self.path,value)
                try:
                    self.command(owner,identity,domain,False)
                    if flag(fd) is not None or self.native_row(owner,identity,domain).get('REJECT')=='yes':
                        raise Conflict('Native rejection removal was not confirmed')
                    row['state']='active';write_json(self.path,value)
                except Exception:
                    row['state']='review';write_json(self.path,value);raise
                return True

    def delegated(self,rows):
        # Read-only broker path: no API mutations and no automatic retry.
        result=set();value=self.ledger()
        for native in rows:
            if not any(row['state']=='active' and all(row[name]==native[name] for name in ('owner','identity','domain')) for row in value['entries'].values()):continue
            with native_directory(self.hestia,native['owner'],native['identity'],native['domain']) as (fd,generation):
                row=value['entries'].get(key(native['owner'],native['identity'],native['domain'],generation))
                if row and row['state']=='active' and not native['native_reject_spam'] and flag(fd) is None:
                    result.add((native['owner'],native['identity'],native['domain']))
        return result

    def activate(self,store):
        from .mail_inventory import inventory
        from .mail_policy import MailPolicies
        self.ready();policies=MailPolicies(store,self.hestia);selected=[]
        # Finish the authoritative, generation-bound inventory and policy read
        # before making the first native change. Mailbox overrides may leave
        # unmanaged siblings; their original rejection is applied by the broker.
        for row in inventory(self.hestia):
            if row['suspended']:continue
            context=self.hestia.authorize(row['owner'])
            if context['identity']!=row['identity']:raise AccessDenied('Native mail account changed before delegation')
            mailboxes=['']+[mailbox['name'] for mailbox in row['mailboxes'] if not mailbox['suspended']]
            if any(policies.get(context,row['domain'],mailbox)['effective']['enabled'] for mailbox in mailboxes):
                selected.append(row)
        self.install_extension();changed=0
        for row in selected:changed+=self.suppress(row['owner'],row['identity'],row['domain'])
        return dict(delegated_domains=changed)

    def domain_added(self,store,owner,domain):
        from .mail_inventory import domains
        from .mail_policy import MailPolicies
        from .mail_runtime import state
        # A stale, already executing hook may finish after disable removed it.
        current=state(self.settings)
        if current is None or current['phase']!='active':return dict(delegated=False)
        self.ready();owner=account_name(owner);domain=domain_name(domain)
        context=self.hestia.authorize(owner);rows=domains(self.hestia,owner,domain)
        if len(rows)!=1 or rows[0]['identity']!=context['identity']:raise AccessDenied('Native new mail domain changed')
        policies=MailPolicies(store,self.hestia)
        mailboxes=['']+[mailbox['name'] for mailbox in rows[0]['mailboxes'] if not mailbox['suspended']]
        if not any(policies.get(context,domain,mailbox)['effective']['enabled'] for mailbox in mailboxes):return dict(delegated=False)
        return dict(delegated=self.suppress(owner,context['identity'],domain))

    def install_extension(self):
        with self.locked():
            folder=self.hestia.root/'data/extensions';trusted(folder.parent,directory=True)
            if not folder.exists():folder.mkdir(mode=0o755)
            trusted(folder,directory=True);path=folder/EXTENSION;saved=read(self.extension)
            if saved:
                if (saved.get('owner')!='clamshield' or saved.get('state')!='active' or
                        saved.get('fingerprint')!=fingerprint(path) or path.read_text()!=EXTENSION_TEXT):
                    raise Conflict('Native mail extension changed or needs recovery')
                return
            if path.exists() or path.is_symlink():raise Conflict('The native add-mail-domain extension belongs to another application')
            saved=dict(owner='clamshield',state='creating');write_json(self.extension,saved)
            with directory(folder) as fd:
                handle=os.open(EXTENSION,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=fd)
                try:
                    data=EXTENSION_TEXT.encode()
                    if os.write(handle,data)!=len(data):raise EngineError('Native mail extension publication was incomplete')
                    os.fchmod(handle,0o755);os.fsync(handle)
                    saved['fingerprint']={name:getattr(os.fstat(handle),name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_mode','st_nlink')}
                finally:os.close(handle)
                os.fsync(fd)
            if fingerprint(path)!=saved['fingerprint']:raise Conflict('Native mail extension changed during publication')
            saved['state']='active';write_json(self.extension,saved)

    def remove_extension(self):
        with self.locked():
            saved=read(self.extension)
            if saved is None:return
            if saved.get('owner')!='clamshield' or saved.get('state')!='active':raise Conflict('Native mail extension needs recovery')
            folder=self.hestia.root/'data/extensions';path=folder/EXTENSION
            if path.exists() or path.is_symlink():
                try:owned=fingerprint(path)==saved['fingerprint'] and path.read_text()==EXTENSION_TEXT
                except (OSError,EngineError):owned=False
                if owned:
                    trusted(folder,directory=True)
                    with directory(folder) as fd:
                        if attributes(os.stat(EXTENSION,dir_fd=fd,follow_symlinks=False))!=attributes(path.lstat()):
                            raise Conflict('Native mail extension changed before removal')
                        if fingerprint(path)!=saved['fingerprint']:raise Conflict('Native mail extension changed before removal')
                        os.unlink(EXTENSION,dir_fd=fd);os.fsync(fd)
            self.extension.unlink()
            from .atomic import sync_directory
            sync_directory(self.settings.state)

    def restore(self):
        with self.locked():
            value=self.ledger();restored=0
            for row in value['entries'].values():
                if row['state'] in ('restored','retired'):continue
                if row['state']!='active':raise Conflict('Native rejection has an uncertain operation; inspect before retrying')
                owner,identity,domain=(row[name] for name in ('owner','identity','domain'))
                # Absent/recreated native objects cannot inherit old receipts.
                try:current=self.hestia.identity(owner)
                except (KeyError,FileNotFoundError,AccessDenied):current=None
                if current!=identity:
                    row['state']='retired';write_json(self.path,value);continue
                if domain not in self.hestia.call('v-list-mail-domains',owner,'json'):
                    row['state']='retired';write_json(self.path,value);continue
                with native_directory(self.hestia,owner,identity,domain) as (fd,generation):
                    if generation!=row['domain_identity']:
                        row['state']='retired';write_json(self.path,value);continue
                    if flag(fd) is not None or self.native_row(owner,identity,domain).get('REJECT')=='yes':
                        row['state']='retired';write_json(self.path,value);continue
                    row['state']='restore_pending';write_json(self.path,value)
                    try:
                        self.command(owner,identity,domain,True)
                        created=flag(fd)
                        if created is None or self.native_row(owner,identity,domain).get('REJECT')!='yes':
                            raise Conflict('Native rejection restoration was not confirmed')
                        # Restore only the just-created bound native flag, never
                        # the entire mail.conf or any other administrator data.
                        handle=os.open('reject_spam',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                        try:
                            if attributes(os.fstat(handle))!=created['attributes']:raise Conflict('Native restored flag changed')
                            attrs=row['original']['attributes'];data=base64.b64decode(row['original']['content'],validate=True)
                            os.ftruncate(handle,0)
                            if os.write(handle,data)!=len(data):raise EngineError('Native rejection flag restoration was incomplete')
                            os.fchown(handle,attrs['uid'],attrs['gid']);os.fchmod(handle,attrs['mode']);os.fsync(handle)
                            held=attributes(os.fstat(handle))
                            if attributes(os.stat('reject_spam',dir_fd=fd,follow_symlinks=False))!=held:
                                raise Conflict('Native restored flag was replaced')
                        finally:os.close(handle)
                        os.fsync(fd);row['state']='restored';write_json(self.path,value);restored+=1
                    except Exception:
                        row['state']='review';write_json(self.path,value);raise
            return dict(restored=restored)
