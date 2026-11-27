"""Reversible Spamhaus error-reply exclusions through supported Hestia APIs.

Native templates/ACLs are never edited. Durable intent precedes every API call;
failed or interrupted calls require review, never automatic retry. Receipts and
native DNSBL files can contain provider query keys and remain root-private.
"""
from contextlib import contextmanager
from collections import Counter
import base64
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import stat

from .atomic import write_json,sync_directory
from .errors import Conflict,EngineError
from .mail_adapter import bounded,trusted
from .mail_runtime import read

# Spamhaus reserves the complete /24 for operational errors, including disabled
# or illegally used DQS keys (250/251). Hestia's supported API accepts literal
# IPv4 exclusions, not CIDR syntax; enumerate that bounded network explicitly.
LEGACY_ERRORS=('127.255.255.252','127.255.255.254','127.255.255.255')
ERRORS=tuple('127.255.255.'+str(value) for value in range(256))
MAX_ENTRY=8192
ENTRY=re.compile(r'[A-Za-z0-9.-]+(?:!=[0-9.,]+)?\Z')
FIELDS=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_mode','st_nlink')


def stamp(info):return {name:getattr(info,name) for name in FIELDS}


def entries(content):
    lines=content.decode('utf-8',errors='surrogateescape').splitlines()
    result=[line.strip() for line in lines if line.strip() and not line.lstrip().startswith('#')]
    if len(result)>128 or any(len(line)>MAX_ENTRY or not ENTRY.fullmatch(line) for line in result):
        raise EngineError('Native DNSBL configuration is not supported')
    if len(result)!=len({line.lower() for line in result}):raise Conflict('Duplicate native DNSBL entries need review')
    try:
        for line in result:
            if '!=' in line:
                for address in line.partition('!=')[2].split(','):ipaddress.IPv4Address(address)
    except ValueError as exc:raise EngineError('Native DNSBL return-code filter is invalid') from exc
    return result


def replacement(entry,*,errors=ERRORS):
    zone,separator,excluded=entry.partition('!=')
    lower=zone.lower()
    if not (lower in {'zen.spamhaus.org','sbl.spamhaus.org','xbl.spamhaus.org','pbl.spamhaus.org'} or
            re.fullmatch(r'[a-z0-9-]+\.(?:zen|sbl|xbl|pbl)\.dq\.spamhaus\.net',lower)):
        return entry
    existing=excluded.split(',') if separator else []
    if set(errors)<=set(existing):return entry
    return zone+'!='+','.join(existing+[value for value in errors if value not in existing])


class NativeDnsbl:
    def __init__(self,settings,hestia,*,native=Path('/etc/exim4/dnsbl.conf')):
        self.settings,self.hestia,self.native=settings,hestia,Path(native)
        self.path=settings.state/'native-dnsbl.json'

    @property
    def custom(self):return self.hestia.root/'conf/dnsbl.conf'

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'native-dnsbl.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            trusted(path)
            if stat.S_IMODE(os.fstat(fd).st_mode)!=0o600:raise EngineError('Native DNSBL lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def ledger(self):
        value=read(self.path)
        if value is None:return None
        if (set(value)!={'owner','schema','state','rows','before','after'} or value['owner']!='clamshield' or value['schema']!=1 or
                value['state'] not in ('applying','active','restoring','restored','review') or
                not isinstance(value['rows'],list) or len(value['rows'])>128):raise EngineError('Invalid native DNSBL receipt')
        for row in value['rows']:
            if (not isinstance(row,dict) or set(row) not in ({'original','replacement','state'},{'original','replacement','state','previous_replacement'}) or
                    row['state'] not in ('pending','adding','removing','active','restoring','restored','retired') or
                    not all(isinstance(row[name],str) and ENTRY.fullmatch(row[name]) and len(row[name])<=MAX_ENTRY for name in ('original','replacement')) or
                    row['replacement'] not in (replacement(row['original']),replacement(row['original'],errors=LEGACY_ERRORS)) or row['original']==row['replacement']):
                raise EngineError('Invalid native DNSBL entry receipt')
            if 'previous_replacement' in row and (row['previous_replacement']!=replacement(row['original'],errors=LEGACY_ERRORS) or
                    row['replacement']!=replacement(row['original']) or row['previous_replacement']==row['replacement'] or
                    value['state'] not in ('applying','review') or row['state'] not in ('adding','removing')):
                raise EngineError('Invalid native DNSBL safety upgrade receipt')
        if len({row['original'] for row in value['rows']})!=len(value['rows']):raise EngineError('Duplicate native DNSBL receipts')
        for files in (value['before'],value['after']):
            if not isinstance(files,dict) or set(files)!={'native','custom'}:raise EngineError('Invalid native DNSBL file receipt')
            for saved in files.values():
                if saved is None:continue
                if (not isinstance(saved,dict) or set(saved)!={'content','stamp'} or not isinstance(saved['stamp'],dict) or
                        set(saved['stamp'])!=set(FIELDS) or any(type(n) is not int or n<0 for n in saved['stamp'].values()) or
                        saved['stamp']['st_uid']!=0 or saved['stamp']['st_nlink']!=1 or
                        not stat.S_ISREG(saved['stamp']['st_mode']) or saved['stamp']['st_mode']&0o022):
                    raise EngineError('Invalid native DNSBL file attributes')
                data=base64.b64decode(saved['content'],validate=True)
                if len(data)>65536:raise EngineError('Native DNSBL receipt exceeds limit')
                entries(data)
        return value

    @contextmanager
    def parents(self):
        held=[]
        try:
            for path in (self.native.parent,self.custom.parent):
                for parent in reversed((path,*path.parents)):trusted(parent,directory=True)
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);info=os.fstat(fd)
                held.append((path,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            yield lambda:self.check_parents(held)
        finally:
            for _,fd,_ in held:os.close(fd)

    @staticmethod
    def check_parents(held):
        for path,fd,wanted in held:
            trusted(path,directory=True);info=path.lstat();opened=os.fstat(fd)
            if any((value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode)!=wanted for value in (info,opened)):
                raise Conflict('Native DNSBL directory changed')

    @staticmethod
    def snapshot(path):
        try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:return None
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>65536:
                raise EngineError('Native DNSBL file is not trusted')
            content=os.read(fd,65537)
            if stamp(info)!=stamp(os.fstat(fd)) or stamp(info)!=stamp(path.lstat()) or len(content)!=info.st_size:
                raise Conflict('Native DNSBL file changed while reading')
            entries(content)
            return dict(content=base64.b64encode(content).decode(),stamp=stamp(info))
        finally:os.close(fd)

    def files(self):
        result=dict(native=self.snapshot(self.native),custom=self.snapshot(self.custom))
        if result['native'] is None:raise EngineError('Native DNSBL file is missing')
        if result['custom'] is not None and self.lines(result,'native')!=self.lines(result,'custom'):
            raise Conflict('Native DNSBL source and active settings disagree')
        return result

    @staticmethod
    def lines(files,name='native'):return entries(base64.b64decode(files[name]['content'],validate=True)) if files[name] else []

    def command(self,add,entry):
        script=self.hestia.root/'bin'/('v-add-sys-mail-dnsbl' if add else 'v-delete-sys-mail-dnsbl')
        trusted(script)
        result=bounded([str(script),entry,'no'],timeout=10,check=False)
        if result.returncode:raise EngineError('Native DNSBL change failed; review required')

    def operation(self,value,add,entry,check_parents):
        check_parents();before=self.files()
        if before!=value['after']:raise Conflict('Native DNSBL settings changed concurrently')
        lines=self.lines(before)
        # Hestia uses an unescaped BRE in grep/sed. Never let its dots match an
        # unrelated administrator entry, including during uninstall restoration.
        if any(re.fullmatch(entry,line) and line!=entry for line in lines):
            raise Conflict('Native DNSBL command would match another entry')
        if (entry in lines)==add:raise Conflict('Native DNSBL entry changed before API call')
        self.command(add,entry);check_parents();after=self.files()
        # The supported API copies into the existing native file and appends
        # an existing custom source. Neither operation may bless a replaced
        # leaf or changed ownership/permissions as our own output.
        bound=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')
        for name in ('native','custom') if add else ('native',):
            if before[name] is not None and after[name] is not None and any(before[name]['stamp'][key]!=after[name]['stamp'][key] for key in bound):
                raise Conflict('Native DNSBL file was replaced during API execution')
        expected=Counter(lines);expected[entry]+=1 if add else -1
        if Counter(self.lines(after))!=+expected:raise Conflict('Native DNSBL change was not confirmed')
        value['after']=after;write_json(self.path,value)

    @staticmethod
    def collisions(rows,lines):
        for row in rows:
            for entry in (row['original'],row['replacement']):
                if any(re.fullmatch(entry,line) and entry!=line for line in lines):
                    raise Conflict('Native DNSBL command would match another entry')

    def protect(self):
        with self.locked(),self.parents() as check_parents:
            value=self.ledger()
            if value and value['state'] not in ('active','restored'):raise Conflict('Native DNSBL change needs review; no automatic retry')
            files=self.files();lines=self.lines(files)
            if value and value['state']=='active':
                outdated=[row for row in value['rows'] if row['state']=='active' and replacement(row['original'])!=row['replacement']]
                if outdated and files==value['after'] and all(row['state']=='active' and row['replacement'] in lines and row['original'] not in lines for row in value['rows']):
                    # Extend only our byte-exact prior output. Do not upgrade
                    # through an administrator edit or reset their selections.
                    # The original before-receipt remains the uninstall target.
                    updates=[dict(original=row['replacement'],replacement=replacement(row['original'])) for row in outdated]
                    self.collisions(updates,lines)
                    value['state']='applying';write_json(self.path,value)
                    try:
                        for row in outdated:
                            row['previous_replacement']=row['replacement'];row['replacement']=replacement(row['original'])
                            row['state']='adding';write_json(self.path,value)
                            self.operation(value,True,row['replacement'],check_parents)
                            row['state']='removing';write_json(self.path,value)
                            self.operation(value,False,row['previous_replacement'],check_parents)
                            del row['previous_replacement'];row['state']='active';write_json(self.path,value)
                        value['state']='active';write_json(self.path,value)
                    except Exception:
                        value['state']='review';write_json(self.path,value);raise
                    lines=self.lines(value['after'])
                # Later administrator decisions are preserved, never re-applied
                # on every maintenance tick or code update.
                review=any(row['state']=='active' and (row['replacement'] not in lines or row['original'] in lines) for row in value['rows']) or any(replacement(line)!=line for line in lines)
                return dict(protected_entries=sum(row['state']=='active' and row['replacement'] in lines and row['original'] not in lines for row in value['rows']),review_required=review)
            rows=[dict(original=line,replacement=replacement(line),state='pending') for line in lines if replacement(line)!=line]
            if not rows:return dict(protected_entries=0,unchanged=True)
            self.collisions(rows,lines)
            source=base64.b64decode((files['custom'] or files['native'])['content'],validate=True)
            if not source.endswith(b'\n') or any(row['original'].encode('ascii') not in source.split(b'\n') for row in rows):
                raise Conflict('Native DNSBL formatting requires review before the supported API can change it')
            value=dict(owner='clamshield',schema=1,state='applying',rows=rows,before=files,after=files);write_json(self.path,value)
            try:
                for row in rows:
                    row['state']='adding';write_json(self.path,value);self.operation(value,True,row['replacement'],check_parents)
                    row['state']='removing';write_json(self.path,value);self.operation(value,False,row['original'],check_parents)
                    row['state']='active';write_json(self.path,value)
                value['state']='active';write_json(self.path,value)
            except Exception:
                value['state']='review';write_json(self.path,value);raise
            return dict(protected_entries=len(rows))

    def restore_exact(self,value,check_parents):
        # Only when the complete pre-restore configuration still matched our
        # last owned output. API calls above restored the entries first. Restore
        # original formatting/metadata without replacing a concurrently edited
        # file, and remove only a custom file created by those owned API calls.
        check_parents()
        for name,path in (('native',self.native),('custom',self.custom)):
            current=self.snapshot(path)
            if current!=value['after'][name]:raise Conflict('Native DNSBL file changed during restoration')
            original=value['before'][name]
            if original is None:
                if current is not None:path.unlink();sync_directory(path.parent)
                continue
            if current is None and name=='native':raise Conflict('Native DNSBL source disappeared during restoration')
            fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT|os.O_EXCL if current is None else 0),0o600)
            try:
                if current is not None and stamp(os.fstat(fd))!=current['stamp']:raise Conflict('Native DNSBL restored file changed')
                data=base64.b64decode(original['content'],validate=True);os.ftruncate(fd,0)
                view=memoryview(data)
                while view:
                    count=os.write(fd,view)
                    if not count:raise EngineError('Native DNSBL restoration was incomplete')
                    view=view[count:]
                attributes=original['stamp'];os.fchown(fd,attributes['st_uid'],attributes['st_gid']);os.fchmod(fd,stat.S_IMODE(attributes['st_mode']));os.fsync(fd)
                if stamp(os.fstat(fd))!=stamp(path.lstat()):raise Conflict('Native DNSBL restored file was replaced')
            finally:os.close(fd)
        check_parents();value['after']=self.files()

    def restore(self):
        with self.locked():
            value=self.ledger()
            if value is None or value['state']=='restored':return dict(restored_entries=0)
            if value['state']!='active':raise Conflict('Native DNSBL operation is uncertain; review before restoration')
            with self.parents() as check_parents:
                current=self.files();exact=current==value['after'];value['after']=current
                value['state']='restoring';write_json(self.path,value);count=0
                try:
                    for row in value['rows']:
                        if row['state']!='active':continue
                        lines=self.lines(value['after']);zone=row['original'].partition('!=')[0].lower()
                        if row['replacement'] not in lines:
                            row['state']='retired';exact=False;write_json(self.path,value);continue
                        administrator_choice=row['original'] in lines or any(line.partition('!=')[0].lower()==zone and line!=row['replacement'] for line in lines)
                        self.collisions([row],lines)
                        row['state']='restoring';write_json(self.path,value)
                        if not administrator_choice:self.operation(value,True,row['original'],check_parents)
                        else:exact=False
                        self.operation(value,False,row['replacement'],check_parents)
                        row['state']='restored';write_json(self.path,value);count+=1
                    if exact:self.restore_exact(value,check_parents)
                    value['state']='restored';write_json(self.path,value)
                except Exception:
                    value['state']='review';write_json(self.path,value);raise
                return dict(restored_entries=count)

    def status(self):
        value=self.ledger()
        if value is None:return dict(state='not-recorded',protected_entries=0)
        if value['state']!='active':return dict(state=value['state'],review_required=value['state']!='restored')
        with self.parents():lines=self.lines(self.files())
        count=sum(row['state']=='active' and row['replacement'] in lines and row['original'] not in lines for row in value['rows'])
        return dict(state='active',protected_entries=count,review_required=any(replacement(line)!=line for line in lines) or count!=len(value['rows']))
