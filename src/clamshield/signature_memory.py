"""Measured signature load peaks, independent of native service RAM and limits.

Fresh APT clamscan processes run sequentially in a bounded transient unit as
clamav. Mail keeps its resident native daemon. Results apply only to the exact
active data/engine; no disk-size multiplier or additive provider estimate.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import statistics
import subprocess
import tempfile
import time
import uuid

from .atomic import write,write_json,sync_directory
from .errors import ClamShieldError,Conflict,EngineError
from .mail_adapter import trusted
from .mail_bridge import process_start
from .mail_runtime import read
from .provider_fetch import regular_copy

LABELS={'securiteinfo':'SecuriteInfo','sanesecurity':'SaneSecurity','local':'Local signatures'}
METHOD='fresh-process-load-peak-rss'
MAX_SECONDS=180


def selection(manifest):
    files=[{key:row[key] for key in ('name','provider','sha256','size')} for row in manifest['files']]
    return hashlib.sha256(json.dumps(sorted(files,key=lambda row:row['name']),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def configurations(files):
    optional=sorted(set(row['provider'] for row in files)&set(LABELS))
    requests={'baseline':[row for row in files if row['provider'] not in LABELS],'all':files}
    requests.update({'without-'+provider:[row for row in files if row['provider']!=provider] for provider in optional})
    cases=[];aliases={};seen={}
    for label,rows in requests.items():
        names=tuple(sorted(row['name'] for row in rows))
        if names not in seen:
            seen[names]='case-'+str(len(cases));cases.append(dict(id=seen[names],files=rows))
        aliases[label]=seen[names]
    return cases,aliases


def summarize(rows,aliases):
    def values(label):return [row['peak_rss_bytes'] for row in rows if row['case']==aliases[label]]
    def summary(label):
        numbers=values(label)
        return dict(median_bytes=int(statistics.median(numbers)),minimum_bytes=min(numbers),maximum_bytes=max(numbers))
    full=summary('all');groups=[]
    for provider,title in LABELS.items():
        if 'without-'+provider not in aliases:continue
        removed=summary('without-'+provider)
        groups.append(dict(provider=provider,label=title,delta_bytes=full['median_bytes']-removed['median_bytes'],
                           minimum_delta_bytes=full['minimum_bytes']-removed['maximum_bytes'],
                           maximum_delta_bytes=full['maximum_bytes']-removed['minimum_bytes']))
    return dict(baseline=summary('baseline'),all=full,providers=groups)


def validate_report(value):
    if (not isinstance(value,dict) or set(value)!={'schema','method','selection','engine','measured','rows','aliases','limits','machine'} or
            type(value['schema']) is not int or value['schema']!=1 or value['method']!=METHOD or not isinstance(value['selection'],str) or
            not re.fullmatch('[a-f0-9]{64}',value['selection']) or not isinstance(value['engine'],dict) or
            set(value['engine'])!={'version','binary_sha256','packages'} or not isinstance(value['engine']['version'],str) or
            len(value['engine']['version'])>200 or not isinstance(value['engine']['binary_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',value['engine']['binary_sha256']) or
            not isinstance(value['engine']['packages'],str) or len(value['engine']['packages'])>16384 or
            not isinstance(value['aliases'],dict) or not {'baseline','all'}<=set(value['aliases']) or
            set(value['aliases'])-{'baseline','all',*('without-'+name for name in LABELS)} or
            any(not isinstance(case,str) or not re.fullmatch('case-[0-4]',case) for case in value['aliases'].values()) or
            type(value['measured']) not in (int,float) or not math.isfinite(value['measured']) or not 0<value['measured']<10**12 or
            not isinstance(value['rows'],list) or len(value['rows'])>15 or not isinstance(value['limits'],dict) or
            set(value['limits'])!={'memory_bytes','cpu_percent','runtime_seconds'} or
            any(type(value['limits'][key]) is not int or not 0<value['limits'][key]<=128*1024**3 for key in value['limits']) or
            value['limits']['cpu_percent']!=50 or value['limits']['runtime_seconds']!=MAX_SECONDS or
            not isinstance(value['machine'],str) or not re.fullmatch('[A-Za-z0-9_-]{1,100}',value['machine'])):
        raise EngineError('Invalid signature memory measurement')
    seen=set()
    for row in value['rows']:
        if (not isinstance(row,dict) or set(row)!={'case','repeat','peak_rss_bytes','elapsed_seconds'} or
                row['case'] not in value['aliases'].values() or type(row['repeat']) is not int or row['repeat'] not in (0,1,2) or
                type(row['peak_rss_bytes']) is not int or not 0<row['peak_rss_bytes']<=128*1024**3 or
                type(row['elapsed_seconds']) not in (int,float) or not math.isfinite(row['elapsed_seconds']) or
                not 0<=row['elapsed_seconds']<=MAX_SECONDS or (row['case'],row['repeat']) in seen):
            raise EngineError('Incomplete or invalid signature memory sample')
        seen.add((row['case'],row['repeat']))
    if seen!={(case,repeat) for case in value['aliases'].values() for repeat in range(3)}:
        raise EngineError('Signature memory measurement did not finish every sample')
    return value


class SignatureMemory:
    def __init__(self,settings):
        self.settings=settings;self.path=settings.state/'signature-memory.json';self.work=settings.state/'signature-memory-work.json'

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'signature-memory.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            trusted(path)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Conflict('A signature memory measurement is already running') from None
            yield
        finally:os.close(fd)

    @staticmethod
    def engine():
        path=Path('/usr/bin/clamscan');trusted(path)
        version=subprocess.check_output([str(path),'--version'],timeout=5).decode().strip().split('/',1)[0]
        packages=subprocess.check_output(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Status}\n',
                                          'clamav','clamav-daemon','libclamav*'],timeout=5).decode()
        if len(packages)>16384 or len(version)>200:raise EngineError('ClamAV identity exceeds its limit')
        return dict(version=version,binary_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),packages='\n'.join(sorted(packages.splitlines())))

    def record(self):
        value=read(self.work)
        if value is None:return None
        from .native_integration import SNAPSHOTS
        if (not isinstance(value,dict) or set(value)!={'owner','schema','token','unit','directory','device','inode'} or
                value['owner']!='clamshield' or value['schema']!=1 or not isinstance(value['token'],str) or
                not re.fullmatch('[a-f0-9]{32}',value['token']) or value['unit']!='clamshield-signature-memory-'+value['token']+'.service' or
                not isinstance(value['directory'],str) or Path(value['directory']).parent!=SNAPSHOTS or
                Path(value['directory']).name!='memory-'+value['token'] or
                any(type(value[key]) is not int or value[key]<0 for key in ('device','inode'))):
            raise EngineError('Invalid signature memory workspace receipt')
        return value

    @staticmethod
    def unit_live(record):
        result=subprocess.run(['/usr/bin/systemctl','show',record['unit'],'-p','LoadState','-p','ActiveState','-p','Description','-p','User','-p','Transient'],
                              capture_output=True,text=True,timeout=5)
        fields=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if fields.get('LoadState')=='not-found':return False
        if result.returncode or fields.get('LoadState')!='loaded':raise EngineError('Could not inspect the existing signature memory unit; workspace retained')
        if (fields.get('Description')!='ClamShield signature memory '+record['token'] or fields.get('User')!='clamav' or fields.get('Transient')!='yes'):
            raise Conflict('Signature memory unit ownership changed; review before cleanup')
        if fields.get('ActiveState') not in ('active','activating','deactivating','reloading','inactive','failed'):
            raise EngineError('Signature memory unit state is unknown; workspace retained')
        return fields['ActiveState'] in ('active','activating','deactivating','reloading')

    def cleanup(self,record):
        folder=Path(record['directory']);trusted(folder.parent,directory=True)
        if folder.exists() or folder.is_symlink():
            info=trusted(folder,directory=True)
            if (info.st_dev,info.st_ino)!=(record['device'],record['inode']):raise Conflict('Signature memory workspace was replaced')
            marker=folder/'.owner';trusted(marker)
            if marker.read_text()!=record['token']+'\n':raise Conflict('Signature memory workspace ownership changed')
            for path in folder.rglob('*'):
                trusted(path,directory=path.is_dir())
            shutil.rmtree(folder)
        self.work.unlink();sync_directory(self.settings.state)

    def recover(self):
        with self.locked():
            record=self.record()
            if record is None:return dict(running=False)
            if self.unit_live(record):return dict(running=True)
            self.cleanup(record);return dict(running=False,recovered=True)

    def status(self):
        try:
            from .signatures import Signatures
            from .native_integration import enabled
            manager=Signatures(self.settings);record=self.record();report=read(self.path);current=manager.manifest() if enabled(self.settings) else None
            value=dict(available=bool(current and current.get('engine_mode')=='native-shared'),running=bool(record and self.unit_live(record)),report=None)
            if report is not None:
                validate_report(report)
                if current is not None:manager.verify_data((manager.base/'current').resolve(),current)
                value['report']=dict(measured=report['measured'],engine=report['engine']['version'],repeats=3,method=METHOD,
                    stale=current is None or selection(current)!=report['selection'] or self.engine()!=report['engine'],**summarize(report['rows'],report['aliases']))
            return value
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
            return dict(available=False,running=False,report=None,error='Signature memory measurements need review')

    @staticmethod
    def allowed():
        if not any(line.endswith(':/system.slice/clamshield-maintenance.service') for line in Path('/proc/self/cgroup').read_text().splitlines()):
            raise EngineError('Run signature memory measurement through the maintenance service')

    def measure(self,progress=lambda phase:None):
        from .signatures import Signatures
        from .signature_catalog import engine_lock
        from .resources import Resources
        from .native_integration import NativeIntegration,enabled
        self.allowed();self.settings.prepare()
        if not enabled(self.settings):raise EngineError('Enable the shared native ClamAV before measuring signature memory')
        native=NativeIntegration(self.settings);manager=Signatures(self.settings);record=None
        with self.locked():
            previous=self.record()
            if previous:
                if self.unit_live(previous):raise Conflict('The previous signature memory unit is still running')
                self.cleanup(previous)
            with Resources(self.settings).worker_lock(timeout=1),engine_lock(self.settings,exclusive=False,blocking=True),manager.locked():
                manifest=manager.manifest();stage=(manager.base/'current').resolve();manager.verify_data(stage,manifest)
                if manifest.get('engine_mode')!='native-shared' or len(manifest['files'])>256:raise EngineError('Unsupported active signature memory selection')
                identity=self.engine();fingerprint=selection(manifest);cases,aliases=configurations(manifest['files'])
                required=sum(row['size'] for case in cases for row in case['files'])
                native.prepare_runtime()
                if shutil.disk_usage(native.snapshots).free<required+128*1024**2:raise EngineError('Insufficient free disk space for signature memory measurement')
                token=uuid.uuid4().hex;folder=native.snapshots/('memory-'+token);folder.mkdir(mode=0o750);gid=pwd.getpwnam('clamav').pw_gid;os.chown(folder,0,gid);folder.chmod(0o750)
                write(folder/'.owner',token+'\n',0o440);os.chown(folder/'.owner',0,gid);info=folder.stat()
                record=dict(owner='clamshield',schema=1,token=token,unit='clamshield-signature-memory-'+token+'.service',directory=str(folder),device=info.st_dev,inode=info.st_ino)
                write_json(self.work,record)
                try:
                    progress('preparing')
                    for case in cases:
                        target=folder/case['id'];target.mkdir(mode=0o750);os.chown(target,0,gid);target.chmod(0o750)
                        for row in case['files']:
                            destination=target/row['name']
                            if regular_copy(stage/row['name'],destination)!=row['sha256']:raise Conflict('Signature data changed while preparing measurement')
                            os.chown(destination,0,gid);destination.chmod(0o440)
                            if row['provider']=='sanesecurity':
                                signed=target/(row['name']+'.sig');regular_copy(stage/signed.name,signed,maximum=1024**2);os.chown(signed,0,gid);signed.chmod(0o440)
                        canary=target/'clamshield-generation.hdb';regular_copy(stage/canary.name,canary);os.chown(canary,0,gid);canary.chmod(0o440)
                        case['directory']=str(target)
                    sample=folder/'canary.txt';write(sample,manifest['canary']['payload'],0o440);os.chown(sample,0,gid)
                    plan=folder/'plan.json';write_json(plan,dict(cases=[dict(id=case['id'],directory=case['directory']) for case in cases],input=str(sample),canary=manifest['canary']['signature']+'.UNOFFICIAL'))
                    os.chown(plan,0,gid);plan.chmod(0o440)
                    available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
                    budget=min(2*1024**3,available-256*1024**2)
                    if budget<1152*1024**2:raise EngineError('At least 1408 MiB of available RAM is required for a bounded signature memory check')
                    limits=dict(memory_bytes=budget,cpu_percent=50,runtime_seconds=MAX_SECONDS)
                    probe=Path(__file__).resolve().parents[2]/'tools/signature-memory-probe.py';trusted(probe)
                    command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit='+record['unit'],
                        '-p','Description=ClamShield signature memory '+token,'-p','User=clamav','-p','Group=clamav',
                        '-p','BindsTo=clamshield-maintenance.service','-p','CPUQuota=50%','-p','IOWeight=10',
                        '-p','MemoryMax='+str(budget),'-p','MemorySwapMax=0','-p','RuntimeMaxSec='+str(MAX_SECONDS),'-p','LimitFSIZE=1048576',
                        '-p','TimeoutStopSec=5','-p','KillMode=control-group','-p','PrivateTmp=yes','-p','PrivateNetwork=yes',
                        '-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','NoNewPrivileges=yes','/usr/bin/python3','-I','-B',str(probe),str(plan)]
                    progress('measuring')
                    with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
                        result=subprocess.run(command,stdout=output,stderr=errors,timeout=MAX_SECONDS+20)
                        if result.returncode or output.tell()>65536:
                            errors.seek(0);output.seek(0)
                            write_json(self.settings.state/'signature-memory-last-error.json',dict(measured=time.time(),unit=record['unit'],exit=result.returncode,
                                stderr=errors.read(65536).decode(errors='replace'),stdout=output.read(65536).decode(errors='replace')))
                            raise EngineError('Signature memory load did not complete; previous measurements retained')
                        output.seek(0);lines=output.read().splitlines()
                    try:measured=json.loads(lines[-1])
                    except (ValueError,IndexError) as exc:raise EngineError('Signature memory output is incomplete') from exc
                    if measured.get('complete') is not True:raise EngineError('Signature memory output is incomplete')
                    if self.engine()!=identity or selection(manager.manifest())!=fingerprint:raise Conflict('Engine or signature selection changed while measuring')
                    manager.verify_data(stage,manifest)
                    report=dict(schema=1,method=METHOD,selection=fingerprint,engine=identity,measured=time.time(),rows=measured.get('rows'),aliases=aliases,limits=limits,machine=platform.machine())
                    validate_report(report);write_json(self.path,report)
                    return dict(measured=report['measured'],configurations=len(cases),samples=len(report['rows']))
                finally:
                    if record is not None and not self.unit_live(record):self.cleanup(record)
