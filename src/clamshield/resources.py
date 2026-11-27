"""Owned systemd limits and website-engine lifecycle, with durable recovery."""
from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from .atomic import write,write_json,sync_directory
from .engines import ClamAV
from .errors import ClamShieldError,Conflict,EngineError
from .generations import current as generation
from .website_generation import pinned
from .website_policy import validate_policy,website_policy

MARKER='# Managed by clamshield resources\n'
SERVICES={
    'website_worker':('clamshield-worker.service','Website scan worker',100,1024),
    'website_clamav':('clamshield-clamd.service','Website ClamAV',100,2048),
    'mail_broker':('clamshield-mail.service','Email broker and YARA',150,1024),
    'mail_clamav':('clamshield-mail-clamd.service','Email ClamAV',100,2048),
    'mail_spamassassin':('clamshield-mail-spamd.service','Email SpamAssassin',100,512)}
SERVICES['maintenance']=('clamshield-maintenance.service','Signature and rule maintenance',100,3072)
DEFAULTS={key:dict(cpu_percent=row[2],memory_mib=row[3],io_weight=100) for key,row in SERVICES.items()}


def validate(value):
    if not isinstance(value,dict) or set(value)!=set(SERVICES):raise ClamShieldError('Choose limits for every ClamShield service')
    for row in value.values():
        if not isinstance(row,dict) or set(row)!={'cpu_percent','memory_mib','io_weight'}:raise ClamShieldError('Unsupported resource setting')
        for key,minimum,maximum in (('cpu_percent',1,10000),('memory_mib',128,1048576),('io_weight',1,10000)):
            if type(row[key]) is not int or not minimum<=row[key]<=maximum:raise ClamShieldError('Resource limit is outside its supported range')
    return deepcopy(value)


def revision(value):return hashlib.sha256(json.dumps(validate(value),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_metadata(value):
    if (not isinstance(value,dict) or set(value)!={'owner','schema','policy','revision','applied_at'} or
            value['owner']!='clamshield' or type(value['schema']) is not int or value['schema']!=1 or
            value['revision']!=revision(value['policy']) or type(value['applied_at']) not in (int,float) or
            not 0<=value['applied_at']<10**12):raise EngineError('Resource policy metadata is invalid')
    return value


def render(row):
    return MARKER+'[Service]\nCPUQuota='+str(row['cpu_percent'])+'%\nMemoryMax='+str(row['memory_mib'])+'M\nIOWeight='+str(row['io_weight'])+'\n'


def quota(value):
    if value=='infinity':return None
    units={'us':Decimal('.000001'),'ms':Decimal('.001'),'s':Decimal(1),'min':Decimal(60),'h':Decimal(3600),'d':Decimal(86400)}
    parts=re.findall(r'(\d+(?:\.\d+)?)(us|ms|min|s|h|d)',value)
    if not parts or re.sub(r'\d+(?:\.\d+)?(?:us|ms|min|s|h|d)|\s+','',value):raise EngineError('Unsupported systemd CPU quota response')
    return float(sum(Decimal(number)*units[unit] for number,unit in parts)*100)


class Resources:
    def __init__(self,settings,*,unit_dir=Path('/etc/systemd/system')):
        self.settings,self.unit_dir=settings,Path(unit_dir)
        self.metadata=settings.state/'resources.json'
        self.journal=settings.state/'resources-activation.json'
        self.website_journal=settings.state/'website-engine-activation.json'
        self.website_metadata=settings.state/'website-engine.json'

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'resources.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as lock:
            self.safe(path,private=True);fcntl.flock(lock,fcntl.LOCK_EX);yield

    @contextmanager
    def worker_lock(self, *, timeout=None):
        path=self.settings.state/'worker.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as lock:
            self.safe(path)
            if timeout is None:fcntl.flock(lock,fcntl.LOCK_EX)
            else:
                deadline=time.monotonic()+timeout
                while True:
                    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                    except BlockingIOError:
                        if time.monotonic()>=deadline:raise EngineError('Website scanner control timed out waiting for the active scan; review scan progress and retry') from None
                        time.sleep(.1)
            yield

    @staticmethod
    def safe(path,private=False,directory=False):
        info=path.lstat()
        if (path.resolve()!=path or info.st_uid!=os.geteuid() or info.st_mode&(0o077 if private else 0o022) or
                (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)):
            raise EngineError('Resource control path is not owned or protected')
        return info

    def config_path(self,key):return self.unit_dir/(SERVICES[key][0]+'.d')/'clamshield-resources.conf'

    def snapshot(self,path,*,limits=False):
        if not path.exists() and not path.is_symlink():return None
        info=self.safe(path,private=path.parent==self.settings.state)
        if info.st_size>65536:raise EngineError('Resource control file exceeds its limit')
        text=path.read_text()
        if limits and not re.fullmatch(re.escape(MARKER)+r'\[Service\]\nCPUQuota=\d+%\nMemoryMax=\d+M\nIOWeight=\d+\n',text):
            raise Conflict('Refusing an unmanaged resource drop-in')
        return dict(text=text,mode=info.st_mode&0o777,gid=info.st_gid)

    def configured(self):
        snapshot=self.snapshot(self.metadata)
        if snapshot is None:return None
        return validate_metadata(json.loads(snapshot['text']))

    def prepare(self):
        self.settings.prepare()
        for key,row in SERVICES.items():
            unit=self.unit_dir/row[0];info=self.safe(unit)
            if info.st_size>65536 or not unit.read_text().startswith('# Managed by clamshield\n'):
                raise EngineError('Only owned ClamShield units can be managed')
            folder=self.config_path(key).parent
            if not folder.exists():folder.mkdir(mode=0o755)
            self.safe(folder,directory=True);self.snapshot(self.config_path(key),limits=True)

    @staticmethod
    def system(*args,check=True):
        value=subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,text=True,timeout=120)
        if check and value.returncode:raise EngineError('Owned service resource operation failed')
        return value

    def inspect(self,key):
        unit=SERVICES[key][0]
        result=self.system('show',unit,'-p','ActiveState','-p','UnitFileState','-p','MainPID','-p','ControlGroup',
                           '-p','CPUQuotaPerSecUSec','-p','MemoryMax','-p','MemoryCurrent','-p','IOWeight')
        fields=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        def numeric(name):
            value=fields.get(name,'')
            return int(value) if value.isdigit() and int(value)<2**63 else None
        info=dict(active=fields.get('ActiveState') in ('active','activating','deactivating') and bool(numeric('MainPID')),enabled=fields.get('UnitFileState')=='enabled',
                  pid=numeric('MainPID') or 0,cpu_percent=quota(fields.get('CPUQuotaPerSecUSec','infinity')),
                  memory_bytes=numeric('MemoryMax'),memory_current=numeric('MemoryCurrent'),io_weight=numeric('IOWeight'),cgroup=None)
        group=fields.get('ControlGroup','')
        if info['active']:
            if not group.startswith('/') or '..' in Path(group).parts or not group.endswith('/'+unit):
                raise EngineError('Owned service cgroup identity is unavailable')
            base=Path('/sys/fs/cgroup')/group.lstrip('/')
            cpu=(base/'cpu.max').read_text().split();weight=(base/'io.weight').read_text().split() if (base/'io.weight').exists() else []
            info['memory_current']=int((base/'memory.current').read_text())
            info['cgroup']=dict(cpu_percent=None if cpu[0]=='max' else int(cpu[0])*100/int(cpu[1]),
                memory_bytes=None if (base/'memory.max').read_text().strip()=='max' else int((base/'memory.max').read_text()),
                io_weight=int(weight[1]) if len(weight)>=2 and weight[0]=='default' else None)
        return info

    def status(self):
        try:
            value=self.configured();policy=value['policy'] if value else deepcopy(DEFAULTS)
            services={key:dict(title=row[1],**self.inspect(key)) for key,row in SERVICES.items()}
            memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
            return dict(policy=policy,configured=value is not None,revision=value['revision'] if value else None,
                services=services,memory=memory,website_policy=website_policy(self.settings),recovery_pending=self.journal.exists() or self.website_journal.exists())
        except (OSError,ValueError,KeyError,TypeError,ClamShieldError,subprocess.SubprocessError):
            return dict(error='Resource state is unavailable or changed; inspect recovery',recovery_pending=self.journal.exists() or self.website_journal.exists())

    def check_memory(self,policy):
        for key,row in policy.items():
            used=self.inspect(key)['memory_current'] or 0
            if used and row['memory_mib']*1024**2<used+max(64*1024**2,used//10):
                raise Conflict('Memory limit for '+SERVICES[key][1]+' is below current use plus headroom')

    def verify(self,policy):
        for key,row in policy.items():
            value=self.inspect(key)
            expected=dict(cpu_percent=row['cpu_percent'],memory_bytes=row['memory_mib']*1024**2,io_weight=row['io_weight'])
            if any(value[k]!=v for k,v in expected.items()) or (value['active'] and any(value['cgroup'][k]!=v for k,v in expected.items())):
                raise EngineError('Effective resource limits differ from the requested profile; check other unit overrides')

    def record(self):
        value=json.loads(self.snapshot(self.journal)['text'])
        if (not isinstance(value,dict) or set(value)!={'owner','schema','committed','files','metadata','target'} or
                value.get('owner')!='clamshield' or type(value.get('schema')) is not int or value['schema']!=1 or
                not isinstance(value.get('files'),dict) or set(value['files'])!=set(SERVICES) or type(value.get('committed')) is not bool):
            raise EngineError('Invalid resource recovery journal')
        validate_metadata(value['target'])
        for key,snapshot in list(value['files'].items())+[('metadata',value['metadata'])]:
            if snapshot is None:continue
            if (not isinstance(snapshot,dict) or set(snapshot)!={'text','mode','gid'} or
                    not isinstance(snapshot['text'],str) or len(snapshot['text'])>65536 or
                    type(snapshot['mode']) is not int or not 0<=snapshot['mode']<=0o777 or snapshot['mode']&0o022 or
                    type(snapshot['gid']) is not int or not 0<=snapshot['gid']<2**31):raise EngineError('Invalid saved resource configuration')
            if key=='metadata':validate_metadata(json.loads(snapshot['text']))
            elif not re.fullmatch(re.escape(MARKER)+r'\[Service\]\nCPUQuota=\d+%\nMemoryMax=\d+M\nIOWeight=\d+\n',snapshot['text']):
                raise EngineError('Saved resource drop-in is invalid')
        return value

    def put(self,path,saved):
        if saved is None:path.unlink(missing_ok=True);sync_directory(path.parent)
        else:
            write(path,saved['text'],saved['mode']);os.chown(path,os.geteuid(),saved['gid'])

    def check_files(self,saved):
        for key,before in saved['files'].items():
            actual=self.snapshot(self.config_path(key),limits=True)
            desired=dict(text=render(saved['target']['policy'][key]),mode=0o644,gid=os.getegid())
            if actual not in (before,desired):raise Conflict('Resource drop-in changed outside its pending transaction')
        actual=self.snapshot(self.metadata)
        desired=dict(text=json.dumps(saved['target'],sort_keys=True,separators=(',',':')),mode=0o600,gid=os.getegid())
        if actual not in (saved['metadata'],desired):raise Conflict('Resource policy changed outside its pending transaction')

    def restore(self,saved):
        self.check_files(saved)
        for key,before in saved['files'].items():self.put(self.config_path(key),before)
        self.put(self.metadata,saved['metadata']);self.system('daemon-reload')
        self.journal.unlink(missing_ok=True);sync_directory(self.settings.state)

    def finish(self,saved):
        self.check_files(saved)
        for key,row in saved['target']['policy'].items():write(self.config_path(key),render(row),0o644)
        self.system('daemon-reload');self.verify(saved['target']['policy'])
        write_json(self.metadata,saved['target']);self.journal.unlink(missing_ok=True);sync_directory(self.settings.state)

    def apply(self,policy):
        policy=validate(policy)
        with self.locked(),self.worker_lock():
            self.prepare()
            if self.journal.exists() or self.website_journal.exists():raise Conflict('Resource recovery is pending')
            self.configured();self.check_memory(policy)
            saved=dict(owner='clamshield',schema=1,committed=False,files={key:self.snapshot(self.config_path(key),limits=True) for key in SERVICES},
                metadata=self.snapshot(self.metadata),target=dict(owner='clamshield',schema=1,policy=policy,revision=revision(policy),applied_at=time.time()))
            write_json(self.journal,saved)
            try:
                for key,row in policy.items():write(self.config_path(key),render(row),0o644)
                self.system('daemon-reload');self.verify(policy)
                saved['committed']=True;write_json(self.journal,saved)
                self.finish(saved)
                return dict(applied=True,revision=saved['target']['revision'],services=len(SERVICES),restarted=False)
            except Exception:
                if not saved['committed']:self.restore(saved)
                raise

    def recover_limits(self):
        with self.locked(),self.worker_lock():
            if not self.journal.exists():return False
            self.prepare();saved=self.record()
            if saved['committed']:self.finish(saved)
            else:self.restore(saved)
            current=self.configured()
            return dict(recovered=True,committed=saved['committed'],revision=current['revision'] if current else None,policy=current['policy'] if current else None)

    def website_ready(self):
        engine=ClamAV(self.settings.clamd_socket,timeout=2)
        from .native_integration import enabled,ManagedNativeClamAV
        if enabled(self.settings):engine=ManagedNativeClamAV(self.settings,timeout=2)
        deadline=time.monotonic()+120
        while True:
            try:engine.version();break
            except EngineError:
                if time.monotonic()>=deadline:raise
                time.sleep(.2)
        with pinned(self.settings,engine,generation(self.settings)) as bound:
            with tempfile.NamedTemporaryFile(dir=self.settings.snapshots) as sample:
                sample.write(b'ClamShield inert website readiness.');sample.flush()
                if bound.scan(Path(sample.name)):raise EngineError('Website readiness input was flagged')

    def website_restore(self,saved):
        self.check_website_policy(saved)
        target=saved['target'] if saved['committed'] else saved['before']
        unit=SERVICES['website_clamav'][0]
        self.system('start' if target['active'] else 'stop',unit)
        if target['active'] and saved['committed']:self.website_ready()
        self.system('enable' if target['enabled'] else 'disable',unit)
        self.website_publish(saved)

    def check_website_policy(self,saved):
        if 'policy_target' not in saved:return  # Pre-policy recovery journal.
        actual=self.snapshot(self.website_metadata)
        desired=dict(text=json.dumps(saved['policy_target'],sort_keys=True,separators=(',',':')),mode=0o600,gid=os.getegid())
        if actual not in (saved['policy_before'],desired):raise Conflict('Website engine policy changed outside its pending transaction')

    def website_publish(self,saved):
        self.check_website_policy(saved)
        if 'policy_target' in saved:
            if saved['committed']:write_json(self.website_metadata,saved['policy_target'])
            else:self.put(self.website_metadata,saved['policy_before'])
        self.website_journal.unlink(missing_ok=True);sync_directory(self.settings.state)

    def website(self,enabled, *, progress=lambda _phase:None):
        if type(enabled) is not bool:raise ClamShieldError('Invalid website service state')
        from .native_integration import enabled as native_enabled,NativeIntegration,GATE,UNIT
        if native_enabled(self.settings):
            with self.locked(),self.worker_lock(timeout=120):
                if enabled:
                    progress('starting')
                    self.system('start',UNIT,GATE)
                    progress('verifying');self.website_ready()
                write_json(self.website_metadata,dict(owner='clamshield',schema=1,enabled=enabled,changed_at=time.time()))
                return dict(active=enabled,enabled=enabled,verified=enabled,shared_native=True)
        progress('waiting-scan')
        with self.locked(),self.worker_lock(timeout=120):
            self.prepare()
            if self.journal.exists() or (enabled and self.website_journal.exists()) or (self.settings.state/'signature-activation.json').exists():
                raise Conflict('Scanner recovery is pending')
            pending=self.website_record() if self.website_journal.exists() else None
            website_policy(self.settings)
            before=self.inspect('website_clamav')
            saved=dict(owner='clamshield',schema=1,committed=False,before={k:before[k] for k in ('active','enabled')},target=dict(active=enabled,enabled=enabled),
                policy_before=self.snapshot(self.website_metadata),policy_target=dict(owner='clamshield',schema=1,enabled=enabled,changed_at=time.time()))
            if pending:saved['superseded']={'committed':pending['committed'],'target':pending['target']}
            write_json(self.website_journal,saved)
            try:
                progress('starting' if enabled else 'stopping')
                self.system('start' if enabled else 'stop',SERVICES['website_clamav'][0])
                if enabled:
                    progress('verifying');self.website_ready()
                self.system('enable' if enabled else 'disable',SERVICES['website_clamav'][0])
                saved['committed']=True;write_json(self.website_journal,saved)
                self.website_publish(saved)
                return dict(active=enabled,enabled=enabled,verified=enabled)
            except Exception:
                self.website_restore(saved);raise

    def recover_website(self):
        with self.locked(),self.worker_lock():
            if not self.website_journal.exists():return False
            saved=self.website_record()
            self.prepare();self.website_restore(saved)
            target=saved['target'] if saved['committed'] else saved['before']
            return dict(recovered=True,committed=saved['committed'],**target,verified=saved['committed'] and target['active'])

    def website_record(self):
        saved=json.loads(self.snapshot(self.website_journal)['text'])
        if (not isinstance(saved,dict) or saved.get('owner')!='clamshield' or saved.get('schema')!=1 or type(saved.get('committed')) is not bool or
                any(not isinstance(saved.get(k),dict) or set(saved[k])!={'active','enabled'} or any(type(v) is not bool for v in saved[k].values()) for k in ('before','target'))):
            raise EngineError('Invalid website engine recovery journal')
        if 'policy_target' in saved or 'policy_before' in saved:
            validate_policy(saved.get('policy_target'))
            if saved['policy_target']['enabled']!=saved['target']['enabled']:raise EngineError('Website recovery intent differs from its target')
            if 'policy_before' not in saved:raise EngineError('Missing prior website engine policy')
            snapshot=saved['policy_before']
            if snapshot is not None:
                if (not isinstance(snapshot,dict) or set(snapshot)!={'text','mode','gid'} or
                        not isinstance(snapshot['text'],str) or len(snapshot['text'])>4096 or
                        type(snapshot['mode']) is not int or not 0<=snapshot['mode']<=0o700 or snapshot['mode']&0o077 or
                        type(snapshot['gid']) is not int or not 0<=snapshot['gid']<2**31):raise EngineError('Invalid prior website engine policy')
                validate_policy(json.loads(snapshot['text']))
        return saved
