"""Owned native spamd score include, exact ownership and one-shot service changes."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time

from .atomic import write,write_json,sync_directory
from .errors import Conflict,EngineError
from .mail_adapter import trusted,bounded
from .mail_bridge import process_start,SEALS
from .mail_runtime import read,fingerprint
from .spamassassin import INFRASTRUCTURE_RULES,infrastructure_rule

CONFIG=Path('/etc/spamassassin/zz-clamshield-native-safety.cf')
PLUGIN=Path('/etc/spamassassin/clamshield-native-safety.pm')
SOURCE=Path(__file__).resolve().parents[2]/'tools/native-spam-safety.pm'
HELPER=Path(__file__).resolve().parents[2]/'tools/native-spam-config.pl'
MARKER='# Managed by clamshield: native SpamAssassin DNS safety\n'


def render(names,plugin,digest):
    if not names or len(names)>256 or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}',name) for name in names):
        raise EngineError('Native administrative rule catalog is invalid')
    if re.search(r'\s',str(plugin)) or not re.fullmatch(r'[a-f0-9]{64}',digest):raise EngineError('Native safety binding is invalid')
    return MARKER+'loadplugin ClamShield::NativeSafety '+str(plugin)+'\n'+''.join('score '+name+' 0\n' for name in sorted(set(names)))+(
        'header CLAMSHIELD_NATIVE_SAFE_'+digest[:16]+" eval:check_native_scores('"+digest+"')\n"
        'describe CLAMSHIELD_NATIVE_SAFE_'+digest[:16]+' Native administrative score configuration verified\n'
        'score CLAMSHIELD_NATIVE_SAFE_'+digest[:16]+' 0.001\n')


class NativeSpamSafety:
    def __init__(self,settings,*,config=CONFIG,plugin=PLUGIN,source=SOURCE):
        self.settings,self.config,self.plugin,self.source=settings,Path(config),Path(plugin),Path(source)
        self.path=settings.state/'native-spam-safety.json'

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'native-spam-safety.lock'
        fd=os.open(path,os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
        try:
            trusted(path);fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def snapshot(self,path):
        if not path.exists() and not path.is_symlink():return None
        for parent in reversed(path.parents):trusted(parent,directory=True)
        trusted(path);before=fingerprint(path)
        if before['st_size']>65536:raise EngineError('Native safety file exceeds its limit')
        data=path.read_bytes()
        if fingerprint(path)!=before:raise Conflict('Native safety file changed while inspected')
        return dict(sha256=hashlib.sha256(data).hexdigest(),fingerprint=before)

    def files(self):return {str(path):self.snapshot(path) for path in (self.config,self.plugin)}

    def receipt(self):
        value=read(self.path)
        if value is None:return None
        if (not isinstance(value,dict) or value.get('owner')!='clamshield' or value.get('schema')!=1 or
                value.get('state') not in ('applying','active','removing','restored','review') or
                not isinstance(value.get('expected'),dict) or set(value['expected'])!={str(self.config),str(self.plugin)}):
            raise EngineError('Native safety receipt is invalid')
        if (not isinstance(value.get('names'),list) or not 1<=len(value['names'])<=256 or
                any(not isinstance(name,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}',name) for name in value['names']) or
                any(not isinstance(value.get(key),str) or not re.fullmatch(r'[a-f0-9]{64}',value[key]) for key in ('revision','source_sha256'))):
            raise EngineError('Native safety configuration binding is invalid')
        for item in value['expected'].values():
            if item is None:continue
            if (not isinstance(item,dict) or set(item)!={'sha256','fingerprint'} or
                    not isinstance(item['sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',item['sha256']) or
                    not isinstance(item['fingerprint'],dict)):
                raise EngineError('Native safety ownership receipt is invalid')
            attributes=item['fingerprint']
            if (set(attributes)!={'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_mode','st_nlink'} or
                    any(type(number) is not int or number<0 for number in attributes.values()) or
                    attributes['st_uid']!=0 or attributes['st_nlink']!=1 or not stat.S_ISREG(attributes['st_mode']) or attributes['st_mode']&0o022):
                raise EngineError('Native safety file identity is invalid')
        return value

    def service(self):
        for unit in ('spamd.service','spamassassin.service'):
            result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,ControlGroup,LoadState,Job'],capture_output=True,text=True,timeout=3)
            if len(result.stdout)>4096:raise EngineError('Native SpamAssassin state is unavailable')
            value=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
            if result.returncode and value.get('LoadState')!='not-found':raise EngineError('Native SpamAssassin state is unavailable')
            if value.get('Job','0') not in ('','0'):raise EngineError('Observe the current native SpamAssassin service job')
            if value.get('ActiveState')=='active' and re.fullmatch(r'[1-9][0-9]*',value.get('MainPID','')):
                group=value.get('ControlGroup','');name=group.rsplit('/',1)[-1]
                if group not in ('/system.slice/spamd.service','/system.slice/spamassassin.service'):raise EngineError('Native SpamAssassin service identity is unsupported')
                return dict(active=True,unit=name,pid=int(value['MainPID']),birth=process_start(int(value['MainPID'])))
            if value.get('ActiveState') not in ('inactive','failed') and value.get('LoadState')!='not-found':
                raise EngineError('Observe the current native SpamAssassin transition')
        return dict(active=False)

    def inspect(self,text=''):
        trusted(HELPER);account=pwd.getpwnam('debian-spamd')
        command=['/usr/bin/setpriv','--reuid=debian-spamd','--regid=debian-spamd','--init-groups','--no-new-privs','/usr/bin/perl',str(HELPER)]
        result=bounded(command,timeout=40,data=text.encode())
        if len(result.stdout)>4*1024**2:raise EngineError('Native SpamAssassin catalog exceeds its limit')
        value=json.loads(result.stdout)
        if not isinstance(value,dict) or not isinstance(value.get('rules'),list) or len(value['rules'])>12000:raise EngineError('Native SpamAssassin catalog is invalid')
        return value

    def configuration_stamp(self):
        paths=set()
        for root in (Path('/etc/spamassassin'),Path('/usr/share/spamassassin'),Path('/var/lib/spamassassin')):
            if not root.exists():continue
            for pattern in ('*.cf','*.pre'):
                paths.update(path for path in root.rglob(pattern) if path.is_file())
        prefs=Path(pwd.getpwnam('debian-spamd').pw_dir)/'.spamassassin/user_prefs'
        if prefs.exists() or prefs.is_symlink():paths.add(prefs)
        if len(paths)>12000:raise EngineError('Native rules inventory exceeds its limit')
        values={}
        for path in sorted(paths):
            if path.is_symlink():raise EngineError('Native rules symlink needs review')
            info=path.lstat()
            if not path.is_file() or info.st_nlink!=1 or info.st_mode&0o022:raise EngineError('Native rules file is untrusted')
            values[str(path)]=[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_uid,info.st_gid,info.st_mode]
        return hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()

    @staticmethod
    def names(catalog):
        result=set(INFRASTRUCTURE_RULES)
        for row in catalog['rules']:
            if infrastructure_rule(row['name'],row.get('description','')):result.add(row['name'])
        if len(result)>256:raise EngineError('Too many native administrative rules')
        return sorted(result)

    @staticmethod
    def verify_catalog(catalog):
        for row in catalog['rules']:
            if infrastructure_rule(row['name'],row.get('description','')) and (
                    not isinstance(row.get('scores'),list) or len(row['scores'])!=4 or any(type(score) not in (int,float) or score!=0 for score in row['scores'])):
                raise EngineError('Native SpamAssassin administrative scores are not zero')

    def restart(self,service):
        if self.service()!=service:raise Conflict('Native SpamAssassin changed before its restart')
        result=subprocess.run(['/usr/bin/systemctl','try-restart',service['unit']],capture_output=True,timeout=45)
        if result.returncode:raise EngineError('Native SpamAssassin restart failed; review required, no automatic retry')

    def probe(self,revision):
        from .native_spam_client import NativeSpamAssassin
        raw=('From: probe@localhost\r\nTo: probe@localhost\r\nSubject: Native configuration proof\r\nX-ClamShield-Native-Safety: '+revision+'\r\n\r\nClamShield local native configuration proof.\r\n').encode()
        fd=os.memfd_create('native-spam-safety',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        try:
            os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
            value=NativeSpamAssassin().scan(fd,deadline=time.monotonic()+20)
            if not re.search(r'\bCLAMSHIELD_NATIVE_SAFE_'+revision[:16]+r'\b',value['report']):
                raise EngineError('Native daemon has not proved zero administrative scores')
        finally:os.close(fd)

    def ensure(self):
        with self.locked():
            trusted(self.source)
            if self.source.stat().st_size>65536:raise EngineError('Native safety source exceeds its limit')
            prior=self.receipt();actual=self.files();service=self.service();stamp=self.configuration_stamp();source=self.source.read_bytes()
            if prior and prior['state'] not in ('active','restored'):raise Conflict('Native safety operation needs review; no automatic retry')
            if prior and prior['state']=='active' and actual!=prior['expected']:raise Conflict('Owned native safety files changed; preserve administrator edits')
            if (not prior or prior['state']=='restored') and any(item is not None for item in actual.values()):raise Conflict('Native safety target is already occupied')
            if prior and prior['state']=='active' and prior.get('stamp')==stamp and prior.get('source_sha256')==hashlib.sha256(source).hexdigest() and prior.get('verified_service')==service:
                return dict(protected_rules=len(prior['names']),verified=service['active'],unchanged=True)
            names=self.names(self.inspect());revision=hashlib.sha256(json.dumps(dict(names=names,plugin=hashlib.sha256(source).hexdigest()),sort_keys=True).encode()).hexdigest()
            self.verify_catalog(self.inspect(render(names,self.source,revision)))
            value=dict(owner='clamshield',schema=1,state='applying',operation='apply',expected=actual,names=names,revision=revision,source_sha256=hashlib.sha256(source).hexdigest(),before_service=service)
            write_json(self.path,value)
            try:
                changed=False
                for path,data in ((self.plugin,source),(self.config,render(names,self.plugin,revision).encode())):
                    if self.files()!=value['expected']:raise Conflict('Native safety files changed during activation')
                    for parent in reversed(path.parents):trusted(parent,directory=True)
                    if value['expected'][str(path)] is None or value['expected'][str(path)]['sha256']!=hashlib.sha256(data).hexdigest():
                        value['pending']=dict(path=str(path),sha256=hashlib.sha256(data).hexdigest());write_json(self.path,value)
                        write(path,data,0o644);value['expected']=self.files();del value['pending'];write_json(self.path,value);changed=True
                self.verify_catalog(self.inspect())
                if service['active']:
                    if changed:
                        value['phase']='restart-intent';write_json(self.path,value);self.restart(service)
                    probed=self.service();probed_stamp=self.configuration_stamp()
                    if not probed['active']:raise Conflict('Native SpamAssassin stopped before its live proof')
                    self.probe(revision)
                    if self.service()!=probed or self.configuration_stamp()!=probed_stamp:
                        raise Conflict('Native SpamAssassin changed during its live proof')
                value.update(state='active',verified_service=probed if service['active'] else service,
                             stamp=probed_stamp if service['active'] else self.configuration_stamp());write_json(self.path,value)
            except Exception:
                value['state']='review';write_json(self.path,value);raise
            return dict(protected_rules=len(names),verified=value['verified_service']['active'])

    def restore(self):
        with self.locked():
            value=self.receipt()
            if value is None or value['state']=='restored':return dict(restored=False)
            service=self.service();actual=self.files()
            pending=value.get('pending')
            if pending:
                if not isinstance(pending,dict) or set(pending)!={'path','sha256'} or pending['path'] not in value['expected']:raise EngineError('Native safety write intent is invalid')
                item=actual[pending['path']]
                if item!=value['expected'][pending['path']]:
                    if item is None or item['sha256']!=pending['sha256'] or item['fingerprint']['st_mode']&0o777!=0o644:raise Conflict('Uncertain native safety file differs from its write intent')
                    value['expected'][pending['path']]=item
                del value['pending']
            if any(item is not None and item!=value['expected'][name] for name,item in actual.items()):raise Conflict('Native safety file changed; preserved for review before removal')
            if value.get('operation')=='restore' and value.get('phase')=='restart-intent':
                if not any(actual.values()) and (not service['active'] or service!=value.get('before_service')):
                    value.update(state='restored',expected=actual,verified_service=None);write_json(self.path,value);return dict(restored=True)
                raise Conflict('Native safety removal restart is uncertain; inspect the original service action')
            value.update(state='removing',operation='restore',expected=actual,before_service=service,phase='remove-files');write_json(self.path,value)
            try:
                for path in (self.config,self.plugin):
                    if self.files()!=value['expected']:raise Conflict('Native safety removal changed concurrently')
                    if value['expected'][str(path)] is not None:path.unlink();sync_directory(path.parent)
                    value['expected']=self.files();write_json(self.path,value)
                if service['active']:
                    value['phase']='restart-intent';write_json(self.path,value);self.restart(service)
                value.update(state='restored',verified_service=None);write_json(self.path,value)
            except Exception:
                value['state']='review';write_json(self.path,value);raise
            return dict(restored=True)

    def status(self):
        value=self.receipt()
        if value is None:return dict(state='not-configured',verified=False)
        if value['state']!='active':return dict(state=value['state'],verified=False,review_required=value['state']!='restored')
        service=self.service();intact=self.files()==value['expected'] and self.configuration_stamp()==value.get('stamp')
        return dict(state='active',protected_rules=len(value['names']),service_active=service['active'],
                    verified=intact and service['active'] and service==value.get('verified_service'),review_required=not intact)
