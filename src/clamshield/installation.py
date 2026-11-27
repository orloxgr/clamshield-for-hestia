"""Owned integration inventory and resumable removal; retained custody is never purged."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from .atomic import write_json,sync_directory
from .errors import ClamShieldError,Conflict

UNITS=('clamshield-clamd.service','clamshield-mail-clamd.service','clamshield-mail-spamd.service',
    'clamshield-native-gate.service',
    'clamshield-mail.service','clamshield-maintenance.service','clamshield-maintenance.timer',
    'clamshield-monitor.service','clamshield-monitor.timer','clamshield-recovery.service',
    'clamshield-recovery.timer','clamshield-worker.service','clamshield-worker.timer',
    'clamshield-notifications.service','clamshield-notifications.timer')
PROFILES=('clamshield-clamd','clamshield-freshclam','clamshield-mail-clamd')
TIMERS=tuple(name for name in UNITS if name.endswith('.timer'))
CONTROLLERS=('clamshield-worker.service','clamshield-monitor.service','clamshield-maintenance.service','clamshield-recovery.service','clamshield-notifications.service')


class Installation:
    def __init__(self,settings,*,root=Path('/')):
        self.settings,self.root=settings,Path(root)
        self.manifest=settings.state/'installation.json';self.journal=settings.state/'uninstall.json'
        self.install_journal=settings.state/'install-pending.json'
        self.target=self.at('/opt/clamshield');self.releases=self.at('/opt/clamshield.releases')

    def at(self,path):return self.root/path.lstrip('/')

    @contextmanager
    def locked(self,*,exclusive=False,control=False,timeout=None):
        self.settings.prepare();path=self.settings.state/('installation-control.lock' if control else 'installation.lock')
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as stream:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:
                raise Conflict('Untrusted installation lock')
            operation=fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            if timeout is None:
                fcntl.flock(stream,operation)
            else:
                deadline=time.monotonic()+timeout
                while True:
                    try:fcntl.flock(stream,operation|fcntl.LOCK_NB);break
                    except BlockingIOError:
                        if time.monotonic()>=deadline:
                            raise TimeoutError('ClamShield installation lock is still held by an active request; retry the installer')
                        time.sleep(.05)
            yield

    def update_units(self):
        """Only interrupt controllers recorded as our exact owned integrations."""
        manifest=self.read(self.manifest);pending=self.read(self.install_journal)
        if manifest is None and not self.target.exists():return (),()
        inventory=self.inventory(allow_legacy=True) if manifest is not None else {'files':{}}
        published=None
        if pending and pending.get('owner')=='clamshield' and pending.get('schema')==1 and self.target.exists():
            published=self.target.resolve();self.code(published)
        selected=[]
        for names in (TIMERS,CONTROLLERS):
            units=[]
            for name in names:
                path=self.at('/etc/systemd/system')/name
                if not path.exists() and not path.is_symlink():continue
                actual=self.digest(path);expected=inventory['files'].get(str(path))
                staged=published/'systemd'/name if published else None
                if actual!=expected and not (staged and staged.is_file() and actual==self.digest(staged)):
                    raise Conflict('Owned controller changed outside installation: '+name)
                units.append(name)
            selected.append(tuple(units))
        native_gate=self.at('/etc/systemd/system/clamshield-native-gate.service')
        if native_gate.exists() or native_gate.is_symlink():
            actual=self.digest(native_gate);expected=inventory['files'].get(str(native_gate))
            staged=published/'systemd'/native_gate.name if published else None
            if actual!=expected and not (staged and staged.is_file() and actual==self.digest(staged)):
                raise Conflict('Native gateway unit changed outside its owned installation')
        return tuple(selected)

    @contextmanager
    def update(self,source,*,grace=15,timeout=15,report=lambda _message:None):
        """Close admission before stopping background work, then publish exclusively."""
        with self.locked(exclusive=True,control=True,timeout=15):
            timers,controllers=self.update_units()
            self.begin_install(source)
            report('Update takes priority: new ClamShield requests are paused')
            if timers:
                report('Pausing ClamShield background timers')
                self.system('stop',*timers,timeout=20)
            if controllers:
                report('Stopping ClamShield background jobs; scan results and recovery journals are retained')
                self.system('stop','--no-block',*controllers,timeout=10)
                if not self.controllers_stopped(controllers,grace):
                    report('Stopping remaining ClamShield controller processes')
                    self.system('kill','--kill-whom=all','--signal=SIGKILL',*controllers,check=False,timeout=10)
                    if not self.controllers_stopped(controllers,timeout):
                        raise TimeoutError('ClamShield controllers did not stop; installation remains paused for retry')
            report('Finishing active requests before applying the update')
            with self.locked(exclusive=True,timeout=timeout):
                if self.settings.database.exists():
                    from .store import Store
                    result=Store(self.settings.database).interrupt_for_update()
                    report('Interrupted scans retained: '+str(result['interrupted'])+'; full scans queued again: '+str(result['requeued']))
                yield

    def controllers_stopped(self,controllers,timeout):
        # A subprocess can outlive its lock-holding Python parent. Do not publish
        # code/config until systemd has finished stopping the complete services.
        deadline=time.monotonic()+timeout
        while True:
            result=self.system('show','--property=ActiveState','--value',*controllers,timeout=5)
            states=result.stdout.decode().split()
            if len(states)==len(controllers) and all(state in ('inactive','failed') for state in states):return True
            if time.monotonic()>=deadline:return False
            time.sleep(.05)

    @contextmanager
    def runtime(self):
        self.available()
        with self.locked():self.available();yield

    def available(self):
        if self.install_journal.exists() or self.install_journal.is_symlink():raise Conflict('ClamShield installation is pending; rerun the root installer')
        if self.journal.exists() or self.journal.is_symlink():raise Conflict('ClamShield removal is pending; resume the root uninstaller')
        value=self.read(self.manifest)
        if value is not None:
            value=self.inventory()
            if value['phase']=='removed':raise Conflict('ClamShield is uninstalled; reinstall to resume service')

    @staticmethod
    def read(path):
        if not path.exists() and not path.is_symlink():return None
        info=path.lstat()
        if path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>1024*1024:
            raise Conflict('Untrusted installation metadata')
        value=json.loads(path.read_text())
        if not isinstance(value,dict):raise Conflict('Installation metadata must be an object')
        return value

    def files(self):
        paths=[self.at('/etc/systemd/system')/name for name in UNITS]
        paths.extend(self.at('/etc/apparmor.d')/name for name in PROFILES)
        paths.extend((self.at('/usr/local/hestia/web/plugins/clamshield/index.php'),
            self.at('/usr/local/hestia/web/js/custom_scripts/clamshield.js'),self.at('/usr/local/hestia/bin/v-clamshield')))
        return paths

    @staticmethod
    def digest(path):
        info=path.lstat()
        if path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>8*1024**2:
            raise Conflict('Owned integration is missing, linked or writable')
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def code(self,release):
        release=Path(release)
        if release.parent!=self.releases or not release.name.startswith('release-') or release.resolve()!=release:
            raise Conflict('Unexpected installed code generation')
        for folder in (self.releases,release):
            info=folder.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise Conflict('Untrusted code directory')
        marker=release/'.clamshield-owner'
        self.digest(marker)
        if marker.read_text()!='clamshield\n':raise Conflict('Unmanaged installed code generation')

    def begin_install(self,source):
        if self.journal.exists() or self.journal.is_symlink():raise Conflict('Resume the root uninstaller before reinstalling')
        previous=self.read(self.install_journal)
        if previous is not None and (previous.get('owner')!='clamshield' or previous.get('schema')!=1):raise Conflict('Untrusted pending installation')
        value=dict(owner='clamshield',schema=1,source=str(source),started=time.time())
        if previous and 'website_coverage' in previous:
            from .website_coverage import validate_migration
            value['website_coverage']=validate_migration(previous['website_coverage'])
        write_json(self.install_journal,value)

    def finish_install(self):
        if 'website_coverage' in (self.read(self.install_journal) or {}):raise Conflict('Website coverage migration is still pending')
        self.install_journal.unlink();sync_directory(self.settings.state)

    def migrate_website_coverage(self):
        """Resume only fixed own config/service changes under installer gates."""
        from .native_integration import enabled
        if enabled(self.settings):return None
        from .engines import ClamAV
        from .errors import CoverageUnavailable
        from .resources import Resources
        from .store import Store
        from .website_coverage import harden,validate_migration,verify
        pending=self.read(self.install_journal)
        if not pending or pending.get('owner')!='clamshield' or pending.get('schema')!=1:
            raise Conflict('Website coverage migration requires the root installation gate')
        inventory=self.inventory();unit='clamshield-clamd.service';unit_path=self.at('/etc/systemd/system')/unit
        if self.digest(unit_path)!=inventory['files'].get(str(unit_path)) or not unit_path.read_text().startswith('# Managed by clamshield\n'):
            raise Conflict('Only the recorded owned website service can be migrated')
        resources=Resources(self.settings,unit_dir=self.at('/etc/systemd/system'))
        path=self.at('/etc/clamshield/clamd.conf')
        with resources.locked(),resources.worker_lock():
            actual=resources.snapshot(path)
            if actual is None:raise Conflict('Website ClamAV configuration is missing')
            saved=pending.get('website_coverage')
            if saved is None:
                desired=dict(actual,text=harden(actual['text']))
                active=resources.inspect('website_clamav')['active']
                if actual==desired:
                    if not active:return dict(changed=False,verified=False)
                    try:verify(ClamAV(self.settings.clamd_socket,timeout=3),self.settings)
                    except CoverageUnavailable:pass  # Config changed without daemon reload.
                    else:return dict(changed=False,verified=True)
                saved=dict(before=actual,after=desired,was_active=active)
                validate_migration(saved)
                pending['website_coverage']=saved;write_json(self.install_journal,pending)
            else:validate_migration(saved)
            if actual not in (saved['before'],saved['after']):
                raise Conflict('Website config changed outside its pending coverage migration')
            self.system('stop',unit)
            resources.put(path,saved['after'])
            if saved['was_active']:
                self.system('start',unit);resources.website_ready()
            before=hashlib.sha256(saved['before']['text'].encode()).hexdigest()
            after=hashlib.sha256(saved['after']['text'].encode()).hexdigest()
            store=Store(self.settings.database)
            with store.connection(True) as db:
                if not db.execute("SELECT 1 FROM audit WHERE owner='@admin' AND action='installation.coverage_migrated' AND subject=?",(after,)).fetchone():
                    store.audit(dict(actor='clamshield-installer',owner='@admin',identity=''),'installation.coverage_migrated',after,
                        dict(before_sha256=before,after_sha256=after,was_active=saved['was_active']),db)
            del pending['website_coverage'];write_json(self.install_journal,pending)
            return dict(changed=True,verified=saved['was_active'],before_sha256=before,after_sha256=after)

    def recover_configuration(self):
        """Recover existing scanner intent before publication, under installer gates."""
        names=('resources-activation.json','signature-activation.json','spamassassin-activation.json','website-engine-activation.json')
        pending=[name for name in names if (self.settings.state/name).exists() or (self.settings.state/name).is_symlink()]
        if not pending:return {}
        self.code(self.target.resolve())
        # Refuse foreign/linked metadata before invoking any recovery controller.
        for name in pending:self.read(self.settings.state/name)
        from .resources import Resources
        from .signatures import Signatures
        from .spamassassin import SpamAssassinControls
        from .store import Store
        resources=Resources(self.settings,unit_dir=self.at('/etc/systemd/system'))
        handlers={'resources-activation.json':resources.recover_limits,
            'signature-activation.json':lambda:Signatures(self.settings).recover(),
            'spamassassin-activation.json':lambda:SpamAssassinControls(self.settings).recover(),
            'website-engine-activation.json':resources.recover_website}
        store=Store(self.settings.database);context=dict(actor='clamshield-installer',owner='@admin',identity='');result={}
        for name in pending:
            path=self.settings.state/name
            journal_sha=hashlib.sha256(path.read_bytes()).hexdigest()
            store.audit(context,'installation.recovery_started',name,dict(journal_sha256=journal_sha))
            recovered=handlers[name]()
            if path.exists() or path.is_symlink():raise Conflict('Scanner recovery did not finish before installation: '+name)
            result[name]=recovered
            store.audit(context,'installation.configuration_recovered',name,dict(journal_sha256=journal_sha,result=recovered))
            store.notify('@admin','','installation.recovered',name,dict(message='Interrupted scanner configuration recovered before code installation'))
        return result

    def recover_mail_configuration(self):
        path=self.settings.state/'mail-integration-journal.json'
        if not path.exists() and not path.is_symlink():return None
        self.read(path);release=self.target.resolve();self.code(release)
        # Recovery must agree with the still-installed broker, adapter source
        # and guard templates, rather than importing the unpublished checkout.
        script=('import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                'from clamshield.settings import Settings;from clamshield.store import Store;'
                'from clamshield.hestia import Hestia;from clamshield.mail_integration import MailIntegration;'
                'settings=Settings(state=Path(sys.argv[2]),hestia=Path(sys.argv[3]));'
                'print(json.dumps(MailIntegration(settings,Store(settings.database),Hestia(settings.hestia)).recover()))')
        result=subprocess.run(['/usr/bin/python3','-I','-B','-c',script,str(release/'src'),
                               str(self.settings.state),str(self.settings.hestia)],capture_output=True,check=True)
        value=json.loads(result.stdout)
        if not isinstance(value,dict) or value.get('recovered') is not True or path.exists() or path.is_symlink():
            raise Conflict('Installed mail integration recovery did not finish before code publication')
        from .store import Store
        Store(self.settings.database).audit(dict(actor='clamshield-installer',owner='@admin',identity=''),
                                           'installation.configuration_recovered',path.name,value)
        return value

    def migrate_signatures(self):
        """Complete retained data compatibility before opening the install gate."""
        from .signatures import Signatures
        from .store import Store
        manager=Signatures(self.settings);result=manager.migrate_current()
        manifest=manager.manifest()
        # Finish audit after a crash following activation but before recording it.
        if result is None and manifest and manifest.get('rebuilt_from'):
            result=dict(previous=manifest['rebuilt_from'],generation=manifest['generation'],catalog_policy=manifest['catalog']['policy'])
        if result is None:return None
        store=Store(self.settings.database)
        with store.connection(True) as db:
            if not db.execute("SELECT 1 FROM audit WHERE owner='@admin' AND action='signatures.catalog_migrated' AND subject=?",(result['generation'],)).fetchone():
                store.audit(dict(actor='clamshield-installer',owner='@admin',identity=''),'signatures.catalog_migrated',result['generation'],result,db)
                store.notify('@admin','','signatures.catalog_migrated',result['generation'],dict(message='Retained signature provenance catalog migrated; original data generation retained',**result),result['generation'],db)
        return result

    def restore_website(self):
        """Honor saved Start without changing its policy bytes or restarting a healthy daemon."""
        from .resources import Resources
        from .website_policy import website_policy
        from .native_integration import enabled,NativeIntegration
        if enabled(self.settings):
            policy=website_policy(self.settings)
            if policy and policy['enabled']:
                NativeIntegration(self.settings).client().version()
                return dict(started=False,verified=True)
            return dict(started=False,verified=False)
        resources=Resources(self.settings,unit_dir=self.at('/etc/systemd/system'))
        with resources.locked(),resources.worker_lock():
            policy=website_policy(self.settings);unit='clamshield-clamd.service'
            if policy is None or not policy['enabled']:
                self.system('enable' if policy is None else 'disable',unit)
                return dict(started=False,verified=False)
            if resources.journal.exists() or resources.website_journal.exists() or (self.settings.state/'signature-activation.json').exists():
                raise Conflict('Recover scanner configuration before restoring saved website Start')
            active=resources.inspect('website_clamav')['active']
            self.system('enable',unit)
            if not active:self.system('start',unit)
            try:resources.website_ready()
            except Exception:
                if not active:self.system('stop',unit)
                raise
            return dict(started=not active,verified=True)

    def register(self,release):
        self.code(release)
        files={str(path):self.digest(path) for path in self.files() if path.exists() or path.is_symlink()}
        required=set(map(str,self.files()))-{str(self.at('/etc/apparmor.d')/name) for name in PROFILES}
        if not required<=set(files):raise Conflict('Installation integration inventory is incomplete')
        if not self.target.is_symlink() or self.target.resolve()!=Path(release):raise Conflict('Installation code pointer changed')
        value=dict(owner='clamshield',schema=1,phase='installed',release=str(release),files=files,updated=time.time())
        write_json(self.manifest,value);return value

    def inventory(self,*,allow_legacy=False):
        value=self.read(self.manifest)
        required=set(map(str,self.files()))-{str(self.at('/etc/apparmor.d')/name) for name in PROFILES}
        # Only the installer may admit the exact pre-Bell inventory. Runtime and
        # removal still require the complete current inventory. Existing foreign
        # files at the new unit paths are checked separately by update_units.
        if allow_legacy and isinstance(value,dict) and value.get('phase')!='removed' and isinstance(value.get('files'),dict) and isinstance(value.get('release'),str):
            added={'clamshield-notifications.service','clamshield-notifications.timer'}
            paths={str(self.at('/etc/systemd/system')/name) for name in added}
            release=Path(value['release']);self.code(release)
            if not paths.intersection(value['files']) and not (release/'src/clamshield/notification_preferences.py').exists() and not any((release/'systemd'/name).exists() for name in added):
                required-=paths
            native_path=str(self.at('/etc/systemd/system/clamshield-native-gate.service'))
            if (native_path not in value['files'] and not (release/'src/clamshield/native_integration.py').exists() and
                    not (release/'systemd/clamshield-native-gate.service').exists()):
                required.discard(native_path)
        if (not isinstance(value,dict) or value.get('owner')!='clamshield' or value.get('schema')!=1 or
                value.get('phase') not in ('installed','removed') or not isinstance(value.get('files'),dict) or
                not isinstance(value.get('release'),str) or len(value['release'])>4096 or not required<=set(value['files']) or
                set(value['files'])-set(map(str,self.files())) or any(not isinstance(v,str) or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for v in value['files'].values())):
            raise Conflict('Install/update ClamShield to establish a valid owned integration inventory')
        if value['phase']=='removed':
            # Completed removal no longer executes the recorded code. Its
            # private inventory still authenticates any remaining controllers.
            release=Path(value['release'])
            if release.parent!=self.releases or not release.name.startswith('release-'):
                raise Conflict('Unexpected installed code generation')
        else:self.code(value['release'])
        return value

    def resources(self):
        from .resources import Resources,SERVICES,render
        resources=Resources(self.settings,unit_dir=self.at('/etc/systemd/system'));configured=resources.configured();files={}
        for key in SERVICES:
            path=resources.config_path(key)
            if not path.exists() and not path.is_symlink():continue
            digest=self.digest(path)
            if configured is None or path.read_text()!=render(configured['policy'][key]):raise Conflict('Resource override changed; retained policy does not own these bytes')
            files[str(path)]=digest
        return files

    @staticmethod
    def system(*args,check=True,timeout=180):
        result=subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,timeout=timeout)
        if check and result.returncode:raise ClamShieldError('Owned installation service operation failed')
        return result

    def validate_files(self,value):
        allowed=set(map(str,self.files()))
        from .resources import SERVICES
        allowed.update(str(self.at('/etc/systemd/system')/(row[0]+'.d')/'clamshield-resources.conf') for row in SERVICES.values())
        if set(value['files'])-allowed or any(not isinstance(v,str) or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for v in value['files'].values()):raise Conflict('Removal journal contains an unexpected path or hash')
        for name,expected in value['files'].items():
            path=Path(name)
            if not path.exists() and not path.is_symlink():continue
            if self.digest(path)!=expected:raise Conflict('Owned integration changed; no foreign bytes were removed: '+name)

    def recover_operations(self):
        from .signature_memory import SignatureMemory
        if SignatureMemory(self.settings).recover().get('running'):raise Conflict('Signature memory unit is stopping; retry removal after it finishes')
        from .store import Store
        from .hestia import Hestia
        from .resources import Resources
        from .signatures import Signatures
        from .spamassassin import SpamAssassinControls
        from .repairs import Repairs
        from .quarantine import Quarantine
        store=Store(self.settings.database);hestia=Hestia(self.settings.hestia);resources=Resources(self.settings)
        from .native_integration import NativeIntegration
        native=NativeIntegration(self.settings)
        if native.journal.exists():native.recover()
        if resources.journal.exists():resources.recover_limits()
        if resources.website_journal.exists():resources.recover_website()
        if (self.settings.state/'signature-activation.json').exists():Signatures(self.settings).recover()
        if (self.settings.state/'spamassassin-activation.json').exists():SpamAssassinControls(self.settings).recover()
        Repairs(self.settings,store,hestia).recover_pending();Quarantine(self.settings,store,hestia).recover_pending()

    def detach_mail(self):
        from .store import Store
        from .hestia import Hestia
        from .mail_integration import MailIntegration,MACRO,GUARD,DEFAULT
        integration=MailIntegration(self.settings,Store(self.settings.database),Hestia(self.settings.hestia))
        if integration.journal.exists():integration.recover()
        result=integration.disable()
        if GUARD.exists() or GUARD.is_symlink() or (MACRO.exists() and '/opt/clamshield' in MACRO.read_text()) or (DEFAULT.exists() and DEFAULT.read_text().startswith('# Managed by clamshield:')):
            raise Conflict('Untracked mail hook/guard remains; no integration files were removed')
        return result

    def unload_profile(self,path):
        profiles=self.at('/sys/kernel/security/apparmor/profiles')
        if path.parent==self.at('/etc/apparmor.d') and profiles.exists() and any(line.split(' ',1)[0]==path.name for line in profiles.read_text().splitlines()):
            result=subprocess.run(['/usr/sbin/apparmor_parser','-R',str(path)],capture_output=True,timeout=30)
            if result.returncode:raise ClamShieldError('Owned AppArmor profile could not be unloaded')

    def remove_file(self,path,expected):
        if not path.exists() and not path.is_symlink():return
        if self.digest(path)!=expected:raise Conflict('Owned integration changed during removal')
        self.unload_profile(path);path.unlink();sync_directory(path.parent)

    def check_pointer(self,release,allow_missing=False):
        if allow_missing and not self.target.exists() and not self.target.is_symlink():return
        if not self.target.is_symlink() or self.target.resolve()!=Path(release):raise Conflict('Installed code pointer changed; no foreign target was removed')

    def retained_directories(self):
        paths=[(self.at('/etc/clamshield'),'Service configuration and saved settings'),
               (self.settings.state,'Policies, credentials, scan/email history, quarantine, recovery originals and YARA rules'),
               (self.settings.signatures,'Validated ClamAV signature generations'),
               (self.settings.provider_cache,'Downloaded signature data and provider cache'),
               (self.settings.mail_adapters,'Compiled mail adapters and verification data'),
               (self.at('/var/lib/clamshield-spamd'),'ClamShield SpamAssassin state'),
               (self.releases,'ClamShield application code snapshots'),
               (self.at('/opt/clamshield-mail'),'ClamShield mail library'),
               (self.at('/usr/local/hestia/web/plugins/clamshield'),'ClamShield panel directory and ownership marker')]
        paths.extend((self.at('/etc/systemd/system')/(name+'.d'),'ClamShield unit overrides, including any administrator additions') for name in UNITS)
        paths.extend((self.at('/run')/name,'ClamShield runtime files') for name in
                     ('clamshield','clamshield-mail','clamshield-mail-scan','clamshield-mail-clamd','clamshield-mail-spamd',
                      'clamshield-native','clamshield-exim'))
        paths.append((self.at('/var/lib/clamav/clamshield-snapshots'),'Native scan snapshots, including any preserved administrator additions'))
        return [dict(path=str(path),purpose=purpose) for path,purpose in paths if path.exists() or path.is_symlink()]

    def uninstall(self):
        with self.locked(exclusive=True,control=True):
            if self.install_journal.exists() or self.install_journal.is_symlink():raise Conflict('Finish the pending root installation before uninstalling')
            manifest=self.inventory();value=self.read(self.journal)
            if value is None:
                if manifest['phase']=='removed':return dict(uninstalled=True,unchanged=True,data_retained=True,retained_directories=self.retained_directories())
                self.check_pointer(manifest['release'])
                value=dict(owner='clamshield',schema=1,phase='quiescing',release=manifest['release'],files=manifest['files']|self.resources(),started=time.time())
                self.validate_files(value);write_json(self.journal,value)
            if (value.get('owner')!='clamshield' or value.get('schema')!=1 or value.get('release')!=manifest['release'] or
                    value.get('phase') not in ('quiescing','detaching-mail','recovering','removing','removed') or not isinstance(value.get('files'),dict) or
                    any(value['files'].get(name)!=digest for name,digest in manifest['files'].items())):
                raise Conflict('Untrusted removal journal')
            self.validate_files(value)
            self.check_pointer(value['release'],allow_missing=value['phase'] in ('removing','removed'))
            if value['phase'] in ('quiescing','detaching-mail','recovering'):
                self.system('disable','--now',*TIMERS);self.system('stop',*CONTROLLERS)
            with self.locked(exclusive=True):
                if value['phase']=='quiescing':value['phase']='detaching-mail';write_json(self.journal,value)
                if value['phase']=='detaching-mail':
                    self.detach_mail();value['phase']='recovering';write_json(self.journal,value)
                if value['phase']=='recovering':
                    self.recover_operations()
                    from .native_integration import NativeIntegration,enabled
                    if enabled(self.settings):NativeIntegration(self.settings).disconnect()
                    self.system('stop',*(name for name in UNITS if name.endswith('.service')))
                    self.system('disable',*UNITS)
                    value['phase']='removing';write_json(self.journal,value)
                if value['phase']=='removing':
                    self.validate_files(value)
                    for name,expected in value['files'].items():self.remove_file(Path(name),expected)
                    if self.target.exists() or self.target.is_symlink():
                        if not self.target.is_symlink() or self.target.resolve()!=Path(value['release']):raise Conflict('Installed code pointer changed during removal')
                        self.target.unlink();sync_directory(self.target.parent)
                    self.system('daemon-reload')
                    value['phase']='removed';write_json(self.journal,value)
                manifest.update(phase='removed',updated=time.time());write_json(self.manifest,manifest)
                self.journal.unlink();sync_directory(self.settings.state)
                return dict(uninstalled=True,data_retained=True,code_retained=True,packages_removed=False,retained_directories=self.retained_directories())
