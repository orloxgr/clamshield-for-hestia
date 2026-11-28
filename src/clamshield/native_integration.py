"""Durable handoff from owned engines to the existing Ubuntu clamd service."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import re
import subprocess
import time

from .atomic import write,write_json,sync_directory
from .errors import Conflict,EngineError
from .native_admission import NativeAdmission
from .native_clamav import NativeClamAV,configuration,CONFIG,UNIT
from .native_configuration import NativeConfiguration,directives

GATE='clamshield-native-gate.service'
BACKEND='/run/clamav/clamshield-native.ctl'
RUNTIME=Path('/run/clamshield-native')
SNAPSHOTS=Path('/var/lib/clamav/clamshield-snapshots')
AA_LOCAL=Path('/etc/apparmor.d/local/usr.sbin.clamd')
AA_RULE=Path('/etc/apparmor.d/local/clamshield-native-clamd')
AA_BLOCK='# ClamShield native integration\n#include if exists <local/clamshield-native-clamd>\n'
OLD_UNITS=('clamshield-clamd.service','clamshield-mail-clamd.service')


def config_fingerprint(path):
    value=path.stat()
    return [value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns]


def retain_size(value,floor):
    match=re.fullmatch(r'([0-9]+)([KMG]?)',value.upper())
    if not match:raise EngineError('Unsupported native ClamAV size configuration')
    size=int(match[1])*{'':1,'K':1024,'M':1024**2,'G':1024**3}[match[2]]
    return '0' if size==0 else str(max(floor,size))


class NativeIntegration:
    def __init__(self,settings,*,config=CONFIG,runtime=RUNTIME,snapshots=SNAPSHOTS,unit_directory=Path('/etc/systemd/system')):
        self.settings=settings;self.config=Path(config);self.runtime=Path(runtime);self.snapshots=Path(snapshots)
        self.record=settings.state/'native-clamav.json';self.journal=settings.state/'native-clamav-transition.json'
        self.editor=NativeConfiguration(settings,path=self.config)
        self.unit_directory=Path(unit_directory)

    @staticmethod
    def system(*args):
        return subprocess.run(['/usr/bin/systemctl',*args],check=True,capture_output=True,timeout=150)

    @staticmethod
    def active(unit):
        return subprocess.run(['/usr/bin/systemctl','is-active','--quiet',unit],capture_output=True,timeout=5).returncode==0

    def read(self,path=None):
        path=path or self.record
        if not path.exists() and not path.is_symlink():return None
        NativeConfiguration.trusted(path,512*1024)
        value=json.loads(path.read_text())
        if not isinstance(value,dict) or value.get('owner')!='clamshield' or value.get('schema')!=1:
            raise Conflict('Native ClamAV integration metadata is invalid')
        return value

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'native-clamav-transition.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            NativeConfiguration.trusted(path,1024);fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    @staticmethod
    def directory(path,mode,gid=0):
        if path.is_symlink() or path.parent.resolve()!=path.parent:raise Conflict('Unsafe native engine directory')
        marker=path/'.clamshield-native-owner'
        if path.exists():
            NativeConfiguration.trusted(marker,64)
            if marker.read_text()!='clamshield\n':raise Conflict('Native engine directory is not owned')
        else:
            path.mkdir(mode=mode);write(marker,'clamshield\n')
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise Conflict('Native engine directory is not owned by root')
        os.chown(path,0,gid);path.chmod(mode)

    def prepare_runtime(self):
        self.directory(self.runtime,0o700);self.directory(self.runtime/'slots',0o700)
        self.directory(self.snapshots,0o710,pwd.getpwnam('clamav').pw_gid)

    def client(self,purpose='website',*,timeout=45,maximum=50*1024**2,transition=False):
        value=self.read()
        if value is None or value.get('phase') not in (('connecting','active') if transition else ('active',)):
            raise EngineError('Native ClamAV integration is not ready')
        config=configuration(self.config)
        for key,expected in value['required'].items():
            if config.get(key)!=expected:raise EngineError('Native ClamAV setting changed: '+key)
        identity=NativeClamAV.native_identity()
        if identity!=tuple(value.get('identity',())):
            with self.locked():
                value=self.read()
                if config_fingerprint(self.config)!=value.get('configuration_fingerprint'):
                    raise EngineError('Native ClamAV restarted with changed settings; review the native configuration')
                self.verify_arguments(identity)
                value['identity']=identity;write_json(self.record,value)
        admission=NativeAdmission(self.runtime/'slots',native_threads=int(config['MaxThreads']),
                                  maximum_seconds=int(config['MaxScanTime'])/1000)
        return NativeClamAV.discover(self.snapshots,path=self.config,timeout=timeout,maximum=maximum,
                                    admission=admission,purpose=purpose)

    def verify_arguments(self,identity):
        arguments=Path('/proc/'+str(identity[0])+'/cmdline').read_bytes().split(b'\0')
        values=[item.decode() for item in arguments if item]
        if not values or not os.path.samefile(values[0],'/usr/sbin/clamd'):
            raise EngineError('Native ClamAV launch contract changed')
        allowed={'--foreground','--foreground=true','-F','--config-file='+str(self.config)}
        if any(item not in allowed for item in values[1:]):
            raise EngineError('Native ClamAV launch options can override its configuration')

    def ready(self,manifest,*,timeout=100):
        from .engines import sealed_file
        self.prepare_runtime();deadline=time.monotonic()+timeout
        sample=self.runtime/'generation-check'
        write(sample,manifest['canary']['payload'])
        try:
            while time.monotonic()<deadline:
                try:
                    client=NativeClamAV.discover(self.snapshots,path=self.config,timeout=3)
                    if manifest['canary']['signature']+'.UNOFFICIAL' in [hit['signature'] for hit in client.scan(sample)]:
                        return client.identity
                except (OSError,EngineError):pass
                time.sleep(.3)
            raise EngineError('Native ClamAV did not load the shared signature generation')
        finally:sample.unlink(missing_ok=True)

    def apparmor(self,value):
        profile=Path('/etc/apparmor.d/usr.sbin.clamd')
        if not profile.exists():return
        if not AA_LOCAL.exists():
            value['apparmor_created']=True;write_json(self.journal,value);write(AA_LOCAL,'',0o644)
        if AA_BLOCK not in AA_LOCAL.read_text():
            if value.get('apparmor') is None:
                editor=NativeConfiguration(self.settings,path=AA_LOCAL);before=editor.snapshot()
                target=before['text']+('' if not before['text'] or before['text'].endswith('\n') else '\n')+AA_BLOCK
                value['apparmor']=dict(before=before,block=AA_BLOCK,target=target)
                write_json(self.journal,value)
                editor.publish(before,target)
            else:raise Conflict('Native AppArmor integration changed outside installation')
        rules=('# Managed by clamshield\n'+str(self.settings.signatures)+'/** r,\n'+
               BACKEND+' w,\n'+str(self.snapshots)+'/** r,\n')
        digest=hashlib.sha256(rules.encode()).hexdigest()
        if AA_RULE.exists():
            NativeConfiguration.trusted(AA_RULE,16384)
            if value.get('apparmor_rule_sha256')!=digest or AA_RULE.read_text()!=rules:
                raise Conflict('Owned native AppArmor rules changed or were not recorded')
        else:
            value['apparmor_rule_sha256']=digest;write_json(self.journal,value)
            write(AA_RULE,rules,0o644)
        self.reload_apparmor()

    @staticmethod
    def reload_apparmor():
        profiles=Path('/sys/kernel/security/apparmor/profiles')
        if profiles.exists() and '/usr/sbin/clamd (' in profiles.read_text():
            flags=['-r','-C'] if '/usr/sbin/clamd (complain)' in profiles.read_text() else ['-r']
            subprocess.run(['/usr/sbin/apparmor_parser',*flags,'/etc/apparmor.d/usr.sbin.clamd'],check=True,capture_output=True,timeout=20)

    def restore_apparmor(self,value):
        if value.get('apparmor') and AA_LOCAL.exists():
            editor=NativeConfiguration(self.settings,path=AA_LOCAL);current=editor.snapshot()
            block=value['apparmor']['block'];before=value['apparmor']['before']
            if current['text'].count(block)>1:raise Conflict('Native AppArmor include is ambiguous')
            target=before['text'] if current['text']==value['apparmor']['target'] else current['text'].replace(block,'',1)
            if target!=current['text']:editor.publish(current,target)
            if value.get('apparmor_created') and AA_LOCAL.read_text()=='':AA_LOCAL.unlink();sync_directory(AA_LOCAL.parent)
        if AA_RULE.exists() and value.get('apparmor_rule_sha256'):
            NativeConfiguration.trusted(AA_RULE,16384)
            if hashlib.sha256(AA_RULE.read_bytes()).hexdigest()!=value['apparmor_rule_sha256']:
                raise Conflict('Owned native AppArmor rules changed before removal')
            AA_RULE.unlink();sync_directory(AA_RULE.parent)
        self.reload_apparmor()

    def cleanup_runtime(self):
        retained=[]
        for path in (self.snapshots,self.runtime/'slots',self.runtime):
            if not path.exists():continue
            marker=path/'.clamshield-native-owner'
            NativeConfiguration.trusted(marker,64)
            if marker.read_text()!='clamshield\n':raise Conflict('Native runtime directory is not owned')
            for item in path.iterdir():
                if item==marker:continue
                allowed=((path==self.snapshots and re.fullmatch(r'message-[A-Za-z0-9_-]+\.eml',item.name)) or
                         (path==self.runtime/'slots' and re.fullmatch(r'(website|mail|native-mail)-[0-3]\.lock',item.name)) or
                         (path==self.runtime and item.name in ('listener.json','generation-check')))
                if not allowed:continue
                info=item.lstat()
                if stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022:item.unlink()
            if set(path.iterdir())=={marker}:marker.unlink();path.rmdir()
            else:retained.append(str(path))
        return retained

    def connect(self):
        from .signatures import Signatures
        from .providers import Providers,require_shared_selection
        saved=self.read()
        if saved and saved['phase']=='active':self.client()
        with self.locked():
            if self.journal.exists():raise Conflict('Recover the native ClamAV transition before connecting')
            saved=self.read()
            if saved and saved['phase']=='active':
                return saved
            # Reject an incompatible saved selection before a transition journal
            # or any service stop. The installer exposes an explicit opt-in;
            # activating the union silently would change existing scan policies.
            providers=require_shared_selection(Providers(self.settings).read())
            unit=self.unit_directory/GATE
            NativeConfiguration.trusted(unit,16384)
            if '# Managed by clamshield' not in unit.read_text():raise Conflict('Native gateway unit is not owned')
            original=configuration(self.config,require_all_matches=False)
            if original.get('TCPSocket'):raise Conflict('Review existing native TCP scanner clients before shared activation')
            value=dict(owner='clamshield',schema=1,phase='connecting',operation='connect',
                       original_socket=original['LocalSocket'],original_directory=original['DatabaseDirectory'],
                       old_active={unit:self.active(unit) for unit in OLD_UNITS},
                       native_active=self.active(UNIT),apparmor=None,required={})
            write_json(self.journal,value)
            manager=Signatures(self.settings)
            value['previous_generation']=str((manager.base/'current').resolve()) if (manager.base/'current').is_symlink() else None
            write_json(self.journal,value)
            try:
                for unit,active in value['old_active'].items():
                    if active:self.system('stop',unit)
                manager.base.mkdir(mode=0o755,exist_ok=True)
                stage,manifest=manager.stage(providers,native_directory=value['original_directory'])
                value['generation']=manifest['generation'];write_json(self.journal,value)
                with manager.activation_lock():
                    self.system('stop',UNIT,'clamav-daemon.socket')
                    manager.pointer('current',stage)
                    self.prepare_runtime();self.apparmor(value)
                    required=dict(LocalSocket=BACKEND,LocalSocketMode='600',DatabaseDirectory=str(manager.base/'current'),
                                  AllowAllMatchScan='true',MaxThreads=str(max(8,int(original.get('MaxThreads','12')))),
                                  MaxQueue=str(max(64,int(original.get('MaxQueue','100')))),MaxScanTime='20000',
                                  MaxFileSize=retain_size(original.get('MaxFileSize','25M'),80*1024**2),
                                  StreamMaxLength=retain_size(original.get('StreamMaxLength','25M'),80*1024**2),
                                  AlertExceedsMax='true',AlertEncrypted='true',
                                  ScanMail='true',ScanArchive='true',HeuristicScanPrecedence='false',OfficialDatabaseOnly='false')
                    self.editor.configure(required);value['required']=required;write_json(self.journal,value)
                    value['configuration_fingerprint']=config_fingerprint(self.config)
                    self.system('daemon-reload');self.system('start','clamav-daemon.socket',UNIT)
                    value['identity']=self.ready(manifest);self.verify_arguments(value['identity'])
                    if config_fingerprint(self.config)!=value['configuration_fingerprint']:
                        raise Conflict('Native configuration changed while its process was starting')
                    write_json(self.record,value)
                self.system('enable','--now',GATE)
                self.frontend_ready(value)
                for unit in OLD_UNITS:self.system('disable',unit)
                value.update(phase='active',connected_at=time.time());write_json(self.record,value)
                self.journal.unlink();sync_directory(self.settings.state)
                return value
            except Exception:
                self.rollback(value)
                raise

    def frontend_ready(self,value):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.settimeout(2);connection.connect(value['original_socket']);connection.sendall(b'zVERSION\0')
                    if connection.recv(4096).startswith(b'ClamAV '):return
            except OSError:pass
            time.sleep(.2)
        raise EngineError('Native antivirus gateway did not become ready')

    def rollback(self,value):
        from .signatures import Signatures
        self.system('stop',GATE)
        self.system('stop',UNIT,'clamav-daemon.socket')
        self.editor.recover();self.editor.restore()
        manager=Signatures(self.settings);previous=value.get('previous_generation')
        if previous:manager.pointer('current',Path(previous))
        elif (manager.base/'current').is_symlink():(manager.base/'current').unlink()
        self.restore_apparmor(value);self.system('daemon-reload')
        if value.get('native_active'):self.system('start','clamav-daemon.socket',UNIT)
        for unit,active in value['old_active'].items():
            if active:self.system('start',unit)
        self.record.unlink(missing_ok=True);self.journal.unlink(missing_ok=True);sync_directory(self.settings.state)

    def activate(self,stage,manifest):
        from .signatures import Signatures
        from .signature_catalog import SignatureCatalog
        manager=Signatures(self.settings);manager.verify_data(stage,manifest)
        if manifest.get('engine_mode')!='native-shared':raise Conflict('Native ClamAV requires a shared data generation')
        with SignatureCatalog(stage,manifest):pass
        with self.locked(),manager.activation_lock():
            saved=self.read()
            if saved is None or saved['phase']!='active' or self.journal.exists():
                raise Conflict('Native ClamAV is not ready for data activation')
            previous=(manager.base/'current').resolve()
            journal=dict(saved,operation='generation',before=saved,previous_generation=str(previous),candidate=str(stage))
            write_json(self.journal,journal)
            try:
                write_json(self.record,dict(saved,phase='updating'))
                manager.pointer('current',stage);self.system('reload',UNIT)
                identity=self.ready(manifest)
                manager.pointer('previous',previous)
                write_json(self.record,dict(saved,phase='active',generation=manifest['generation'],identity=identity))
                self.journal.unlink();sync_directory(self.settings.state)
                return manifest
            except Exception:
                manager.pointer('current',previous);self.system('reload',UNIT)
                self.ready(manager.manifest());write_json(self.record,saved)
                self.journal.unlink();sync_directory(self.settings.state)
                raise

    def recover(self):
        with self.locked():
            value=self.read(self.journal)
            if value is None:return False
            if value['operation']=='generation':
                from .signatures import Signatures
                manager=Signatures(self.settings)
                with manager.activation_lock():
                    manager.pointer('current',Path(value['previous_generation']));self.system('reload',UNIT)
                    self.ready(manager.manifest());write_json(self.record,value['before'])
                    self.journal.unlink();sync_directory(self.settings.state)
            elif value['operation']=='connect':self.rollback(value)
            else:
                self.finish_disconnect(value)
            return True

    def disconnect(self):
        with self.locked():
            value=self.read()
            if value is None:return dict(disconnected=False)
            self.editor.recover();self.editor.preview_restore()
            value=dict(value,operation='disconnect');write_json(self.journal,value)
            return self.finish_disconnect(value)

    def finish_disconnect(self,value):
        self.editor.recover();plan=self.editor.preview_restore()
        gate_active=self.active(GATE)
        try:
            self.system('disable','--now',GATE)
            self.system('stop',UNIT,'clamav-daemon.socket')
            result=self.editor.restore(expected=plan);self.restore_apparmor(value)
            self.system('daemon-reload');self.system('start','clamav-daemon.socket',UNIT)
        except Exception:
            # Retain the journal and administrator changes. A failed uninstall
            # must not simply leave the previously running native scanner off.
            # The gateway is needed only while the backend socket is still the
            # managed one; after restoration, native Exim connects directly.
            try:
                self.system('daemon-reload');self.system('start','clamav-daemon.socket',UNIT)
                current=self.editor.snapshot()
                socket=directives(current['text']).get('LocalSocket',{}).get('value')
                if gate_active and socket==BACKEND:self.system('enable','--now',GATE)
            except Exception as recovery:
                raise EngineError('Native ClamAV removal failed and service recovery needs review; ownership journal retained') from recovery
            raise
        # Restore native operation before dropping ownership metadata.
        deadline=time.monotonic()+100
        while True:
            try:
                NativeClamAV.discover(self.snapshots,path=self.config,require_all_matches=False).version();break
            except (OSError,EngineError):
                if time.monotonic()>=deadline:raise
                time.sleep(.3)
        self.record.unlink(missing_ok=True);self.journal.unlink();sync_directory(self.settings.state)
        return dict(disconnected=True,configuration=result,retained_directories=self.cleanup_runtime())


def enabled(settings):
    manager=NativeIntegration(settings)
    return manager.record.exists() or manager.record.is_symlink() or manager.journal.exists() or manager.journal.is_symlink()


class ManagedNativeClamAV(NativeClamAV):
    """Discover lazily after the worker has admitted and pinned its job."""
    def __init__(self,settings,timeout=45,maximum=50*1024**2):
        self.manager=NativeIntegration(settings);self.timeout=timeout;self.maximum=maximum;self.bound=None

    def client(self):
        if self.bound is None:self.bound=self.manager.client('website',timeout=self.timeout,maximum=self.maximum)
        return self.bound

    def scan(self,path):return self.client().scan(path)
    def version(self):return self.client().version()
