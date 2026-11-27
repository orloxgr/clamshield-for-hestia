"""Journaled owned hook/service lifecycle and native policy restoration."""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import re
import uuid

from .atomic import write,write_json,sync_directory
from .errors import ClamShieldError,Conflict,EngineError
from .mail_adapter import MailAdapter,native,trusted,sha
from .mail_runtime import read,state,mode,fingerprint,submission_guard
from .mail_bridge import process_start

LIBRARY=Path('/opt/clamshield-mail/local_scan.so')
MACRO=Path('/etc/exim4/exim4.conf.localmacros')
GUARD=Path('/etc/systemd/system/exim4.service.d/clamshield-mail.conf')
HOOK_RUNTIME=Path('/run/clamshield-exim')
HOOK_INCLUDE=HOOK_RUNTIME/'hook.conf'
LEGACY_MACRO_TEXT='# Managed by clamshield\nlocal_scan_path = '+str(LIBRARY)+'\n'
MACRO_TEXT='# Managed by clamshield\n.include_if_exists '+str(HOOK_INCLUDE)+'\n'
UNITS=('clamshield-mail-clamd.service','clamshield-mail-spamd.service','clamshield-mail.service')


def runtime_hook_ready():
    try:
        trusted(HOOK_RUNTIME,directory=True);trusted(HOOK_INCLUDE)
        return HOOK_INCLUDE.read_text()=='local_scan_path = '+str(LIBRARY)+'\n'
    except (OSError,ValueError,EngineError):return False


class MailIntegration:
    def __init__(self,settings,store,hestia,*,code_generation=None):
        self.settings,self.store,self.hestia=settings,store,hestia
        self.installation_generation=Path(code_generation) if code_generation is not None else None
        self.state=settings.state/'mail-integration.json'
        self.owner=settings.state/'mail-integration-owner.json'
        self.journal=settings.state/'mail-integration-journal.json'
        self.refresh_status=settings.state/'mail-integration-refresh.json'

    def code_identity(self):
        # Installed code generations are immutable, root-owned release trees.
        if self.installation_generation is not None:
            # The installer imports its checkout before publishing the release.
            # Freeze the connection to the actual published generation, never
            # to that transient checkout (which would cause a second refresh).
            from .installation import Installation
            lifecycle=Installation(self.settings);pending=lifecycle.read(lifecycle.install_journal)
            generation=self.installation_generation;manifest=lifecycle.inventory()
            if (not pending or pending.get('owner')!='clamshield' or pending.get('schema')!=1 or
                    not generation.is_absolute() or generation.resolve()!=generation or
                    manifest['phase']!='installed' or manifest['release']!=str(generation) or
                    not lifecycle.target.is_symlink() or lifecycle.target.resolve()!=generation):
                raise Conflict('Mail installer generation is not the pending published installation')
            lifecycle.code(generation)
            return str(generation)
        return str(Path(__file__).resolve().parents[2])

    @staticmethod
    def guard_text():
        return (Path(__file__).resolve().parents[2]/'config/exim4-clamshield.conf').read_text()

    @contextmanager
    def locked(self):
        self.settings.prepare();path=self.settings.state/'mail-integration.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:trusted(path);fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    @staticmethod
    def system(*args,check=True,timeout=120):
        result=subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,timeout=timeout)
        if check and result.returncode:raise EngineError('Owned mail service operation failed')
        return result

    def unit_states(self):
        return {unit:dict(active=self.system('is-active','--quiet',unit,check=False).returncode==0,
                         enabled=self.system('is-enabled',unit,check=False).stdout.strip()==b'enabled') for unit in UNITS}

    def service_units(self):
        from .native_integration import enabled
        return UNITS[1:] if enabled(self.settings) else UNITS

    @staticmethod
    def snapshot(path):
        if not path.exists() and not path.is_symlink():return None
        info=trusted(path)
        if info.st_size>8*1024**2:raise EngineError('Owned mail lifecycle file exceeds its limit')
        content=path.read_bytes()
        return dict(content=base64.b64encode(content).decode(),sha256=hashlib.sha256(content).hexdigest(),mode=info.st_mode&0o777)

    def begin(self,action):
        if self.journal.exists():raise Conflict('Mail integration recovery is pending')
        files={str(p):self.snapshot(p) for p in (self.state,self.owner,LIBRARY,MACRO,GUARD)}
        result=dict(owner='clamshield',schema=1,transaction_id=uuid.uuid4().hex,action=action,phase='prepared',files=files,expected={},units=self.unit_states())
        with submission_guard(self.settings,exclusive=True):write_json(self.journal,result)
        return result

    def transaction(self):
        value=read(self.journal)
        if value is None:return None
        paths={str(p) for p in (self.state,self.owner,LIBRARY,MACRO,GUARD)}
        if (not isinstance(value,dict) or value.get('owner')!='clamshield' or value.get('schema')!=1 or
                value.get('action') not in ('enable','disable','refresh') or set(value.get('files',{}))!=paths or
                set(value.get('units',{}))!=set(UNITS) or set(value.get('expected',{}))-paths):
            raise EngineError('Invalid owned mail integration journal')
        if value.get('phase') not in ('prepared','starting-services','attaching','draining','commit-enable','commit-disable','commit-refresh','refreshing','detaching','stopping','rolling-back'):
            raise EngineError('Invalid owned mail integration transition phase')
        if 'transaction_id' in value and (not isinstance(value['transaction_id'],str) or not re.fullmatch('[a-f0-9]{32}',value['transaction_id'])):
            raise EngineError('Invalid mail integration transaction identity')
        if value.get('committed') is not None:
            target=value.get('target')
            if (value['committed'] is not True or not isinstance(target,dict) or target.get('owner')!='clamshield' or
                    target.get('schema')!=1 or target.get('phase')!=('disabled' if value['action']=='disable' else 'active')):
                raise EngineError('Invalid committed mail integration target')
        for unit,settings in value['units'].items():
            if set(settings)!={'active','enabled'} or any(type(v) is not bool for v in settings.values()):
                raise EngineError('Invalid owned mail service recovery state')
        for path,saved in value['files'].items():
            if saved is None:continue
            content=base64.b64decode(saved['content'],validate=True)
            if len(content)>8*1024**2 or hashlib.sha256(content).hexdigest()!=saved['sha256'] or type(saved['mode']) is not int or not 0<=saved['mode']<=0o777:
                raise EngineError('Invalid mail integration recovery snapshot')
        for values in value['expected'].values():
            if not isinstance(values,list) or len(values)>64 or any(v is not None and (not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v)) for v in values):
                raise EngineError('Invalid mail integration mutation history')
        rebases=value.get('rebases',[])
        if not isinstance(rebases,list) or len(rebases)>16:
            raise EngineError('Invalid mail integration refresh history')
        for previous in rebases:
            if (not isinstance(previous,dict) or set(previous)!={'adapter','code_generation','native','source_sha256','superseded_at'} or
                    not isinstance(previous['adapter'],str) or not re.fullmatch('[A-Za-z0-9_-]{1,100}',previous['adapter']) or
                    not isinstance(previous['code_generation'],str) or len(previous['code_generation'])>4096 or
                    not isinstance(previous['native'],dict) or len(json.dumps(previous['native']))>8192 or
                    not isinstance(previous['source_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',previous['source_sha256']) or
                    type(previous['superseded_at']) not in (int,float) or not 0<=previous['superseded_at']<10**12):
                raise EngineError('Invalid superseded mail integration target')
        return value

    def put(self,transaction,path,content,permissions=0o644):
        key=str(path);current=self.snapshot(path);before=transaction['files'][key]
        allowed={None if before is None else before['sha256']}|set(transaction['expected'].get(key,[]))
        if (None if current is None else current['sha256']) not in allowed:
            raise Conflict('Owned mail lifecycle file changed concurrently')
        intended=None if content is None else hashlib.sha256(content if isinstance(content,bytes) else content.encode()).hexdigest()
        transaction['expected'].setdefault(key,[]).append(intended)
        write_json(self.journal,transaction)
        if content is None:path.unlink(missing_ok=True);sync_directory(path.parent)
        else:write(path,content,permissions)

    def record(self,transaction,value):
        self.put(transaction,self.owner,'{"owner":"clamshield","schema":1}',0o600)
        self.put(transaction,self.state,json.dumps(value,sort_keys=True,separators=(',',':')),0o600)

    def phase(self,transaction,value):
        transaction['phase']=value;write_json(self.journal,transaction)

    def restart_native(self):
        # The broad mail command also restarts Dovecot. This hook/ABI belongs
        # only to Exim; use Hestia's fixed single-service restart command.
        result=subprocess.run([str(self.settings.hestia/'bin/v-restart-service'),'exim4','yes'],capture_output=True,timeout=120,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HESTIA':str(self.settings.hestia),'LANG':'C.UTF-8'})
        if result.returncode:raise EngineError('Native Exim restart failed')
        result=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','exim4'],capture_output=True,timeout=5)
        if result.returncode:raise EngineError('Native Exim did not restart')

    def stop_native(self):
        result=self.system('show','exim4.service','-p','KillMode','--value')
        if result.stdout.strip()!=b'control-group':
            raise Conflict('Native Exim must stop its full service process group before adapter refresh')
        self.system('stop','exim4.service')
        if self.system('is-active','--quiet','exim4.service',check=False).returncode==0:
            raise EngineError('Native Exim did not stop before adapter refresh')

    def preflight(self):
        if HOOK_RUNTIME.exists() or HOOK_RUNTIME.is_symlink():
            trusted(HOOK_RUNTIME,directory=True)
            current=state(self.settings)
            if (not current or not GUARD.exists() or sha(GUARD)!=current.get('guard_sha256') or
                    'RuntimeDirectory=clamshield-exim\n' not in GUARD.read_text()):
                raise Conflict('Existing native startup runtime directory is not owned by this integration')
        from .signatures import Signatures
        from .providers import Providers
        from .mail_service import configuration
        manager=Signatures(self.settings);manifest=manager.manifest();providers=Providers(self.settings).read()
        if manifest is None and (providers['sanesecurity']['enabled'] or providers['securiteinfo']['enabled'] or any((self.settings.state/'local-signatures').glob('*'))):
            raise Conflict('Activate validated signature data before enabling mail integration')
        if configuration()['yara_enabled'] and not self.settings.rules.is_file():
            raise Conflict('Activate validated YARA rules before enabling mail integration')
        from .spamassassin import SpamAssassinControls,DEFAULTS
        controls=SpamAssassinControls(self.settings)
        if controls.configured() is None:
            initial=Path(__file__).resolve().parents[2]/'config/spamassassin.cf'
            if controls.active.read_bytes()!=initial.read_bytes():
                raise Conflict('Validate isolated SpamAssassin settings in the UI before enabling mail')
            controls.apply(DEFAULTS)
        adapter=MailAdapter(self.settings);adapter.build();adapter.verify()
        return adapter.candidate(expected=native())

    def ready(self):
        from .mail_readiness import ask
        deadline=time.monotonic()+75
        while True:
            try:
                result=ask(timeout=min(30,max(.1,deadline-time.monotonic())))
                if result['complete'] and not result['errors']:return
            except (OSError,ValueError,EngineError):pass
            if time.monotonic()>=deadline:raise EngineError('Owned mail scanners did not become ready')
            time.sleep(.3)

    def wait_connected(self):
        from .mail_service import transport_active
        deadline=time.monotonic()+15
        while not transport_active(require_active=False):
            if time.monotonic()>=deadline:raise EngineError('Native Exim is not connected to the owned broker')
            time.sleep(.2)

    def pending(self,*,inflight_only=False):
        with self.store.connection() as db:
            count=0 if inflight_only else db.execute("SELECT count(*) FROM mail_recipients WHERE status IN ('ready','release_queued','delivery_preparing','delivery_pending')").fetchone()[0]
            attempts=db.execute("SELECT count(*) FROM mail_delivery_attempts WHERE status IN ('submitting')" if inflight_only else
                                "SELECT count(*) FROM mail_delivery_attempts WHERE status IN ('preparing','prepared','submitting')").fetchone()[0]
            sources=db.execute("SELECT metadata FROM mail_acceptance WHERE status IN ('armed','response_sent','uncertain','proven')").fetchall()
            native_children=db.execute("SELECT metadata FROM mail_delivery_attempts WHERE status IN ('submitting','uncertain','native_queued')").fetchall()
        live=0
        for row in sources:
            data=json.loads(row['metadata'])
            try:live+=process_start(data['peer_pid'])==data['peer_start']
            except (ClamShieldError,OSError,KeyError,TypeError):pass
        for row in native_children:
            data=json.loads(row['metadata'])
            try:live+=process_start(data['pid'])==data['pid_start']
            except (ClamShieldError,OSError,KeyError,TypeError):pass
        return count+attempts+live

    def drain(self,*,inflight_only=False):
        stable=0;deadline=time.monotonic()+75
        while time.monotonic()<deadline:
            path=Path('/run/clamshield-mail/status.json')
            status=None
            if path.exists():
                trusted(path)
                if path.stat().st_size>65536:raise EngineError('Broker heartbeat exceeds its limit')
                status=json.loads(path.read_text())
                if status.get('owner')!='clamshield' or not 0<=time.time()-status['heartbeat']<10:
                    status=None
            if status is not None:
                counts=status.get('counts',{})
                running=sum(counts.get('started_'+kind,0)-counts.get('finished_'+kind,0) for kind in ('regular','reinjections'))
            else:
                running=1 if self.unit_states()[UNITS[-1]]['active'] else 0
            if not running and not self.pending(inflight_only=inflight_only):
                stable+=1
                if stable>=3:return
            else:stable=0
            time.sleep(1.1)
        raise Conflict('Mail handoffs are still active; drain did not finish, integration retained')

    def rollback(self,transaction):
        touched_native=str(MACRO) in transaction['expected']
        self.phase(transaction,'rolling-back')
        if transaction['action'] in ('disable','refresh') and not touched_native:
            for path in (LIBRARY,MACRO,GUARD):
                original=transaction['files'][str(path)]
                current=self.snapshot(path)
                if (None if current is None else current['sha256'])!=(None if original is None else original['sha256']):
                    raise Conflict('Mail runtime changed while recovering an uncommitted drain')
            self.restore(transaction,self.owner);self.restore(transaction,self.state)
            self.journal.unlink();sync_directory(self.settings.state)
            return
        # Keep the broker alive until the native hook is restored/removed.
        for path in (GUARD,MACRO):self.restore(transaction,path)
        self.system('daemon-reload')
        if touched_native:self.restart_native()
        for unit in reversed(UNITS):self.system('stop',unit)
        self.restore(transaction,LIBRARY)
        for unit,saved in transaction['units'].items():
            if unit not in self.service_units():
                self.system('disable',unit);continue
            self.system('enable' if saved['enabled'] else 'disable',unit)
            if saved['active']:self.system('start',unit)
        self.restore(transaction,self.owner)
        before=transaction['files'][str(self.state)]
        if before is not None:
            restored=json.loads(base64.b64decode(before['content']))
            if restored['phase']=='active':
                self.ready();self.wait_connected()
                restored['runtime']={str(path):fingerprint(path) for path in (LIBRARY,MACRO,Path('/usr/sbin/exim4'))}
                self.put(transaction,self.state,json.dumps(restored,sort_keys=True,separators=(',',':')),0o600)
            else:self.restore(transaction,self.state)
        else:self.restore(transaction,self.state)
        self.journal.unlink();sync_directory(self.settings.state)

    def restore(self,transaction,path):
        before=transaction['files'][str(path)];current=self.snapshot(path)
        allowed={None if before is None else before['sha256']}|set(transaction['expected'].get(str(path),[]))
        if (None if current is None else current['sha256']) not in allowed:
            raise Conflict('Mail rollback found a changed owned file; review is required')
        if before is None:path.unlink(missing_ok=True);sync_directory(path.parent)
        else:write(path,base64.b64decode(before['content']),before['mode'])

    def commit(self,transaction,target):
        transaction.update(committed=True,target=target,phase='commit-'+transaction['action'])
        with submission_guard(self.settings,exclusive=True):write_json(self.journal,transaction)

    def finish_active(self,transaction,target):
        for unit in self.service_units():self.system('enable',unit);self.system('start',unit)
        self.ready();self.wait_connected()
        value=dict(target,runtime=self.guard()['runtime'])
        self.record(transaction,value)
        self.journal.unlink();sync_directory(self.settings.state)
        return {'enabled':True,'adapter':value['adapter']['generation'],'native_dnsbl':self.native_dnsbl_protection(),'native_spam_safety':self.native_spam_protection()}

    def finish_disabled(self,transaction,target):
        # A final send may have crossed the old draining gate just before the
        # durable disable commit. New submits are now blocked; finish that send.
        self.drain(inflight_only=True)
        from .native_rejection import NativeRejection
        rejection=NativeRejection(self.settings,self.hestia)
        rejection.remove_extension();rejection.restore()
        from .native_dnsbl import NativeDnsbl
        NativeDnsbl(self.settings,self.hestia).restore()
        from .native_spam_safety import NativeSpamSafety
        NativeSpamSafety(self.settings).restore()
        self.clear_native_activation()
        self.phase(transaction,'detaching');self.put(transaction,MACRO,None)
        # Stop while the old unit still declares RuntimeDirectory. Removing the
        # drop-in and daemon-reloading first loses systemd's cleanup ownership
        # and leaves an orphan that correctly blocks the next activation.
        self.stop_native()
        self.put(transaction,GUARD,None);self.system('daemon-reload');self.restart_native()
        self.phase(transaction,'stopping')
        for unit in reversed(UNITS):self.system('stop',unit);self.system('disable',unit)
        self.record(transaction,target)
        self.journal.unlink();sync_directory(self.settings.state)
        return {'enabled':False,'custody_retained':True}

    def refresh_reasons(self,current):
        if current is None or current['phase']!='active':return []
        # Refresh may replace a known old adapter, never bless foreign edits.
        if (sha(LIBRARY)!=current['adapter']['library_sha256'] or MACRO.read_text() not in (MACRO_TEXT,LEGACY_MACRO_TEXT) or
                sha(GUARD)!=current.get('guard_sha256',hashlib.sha256(self.guard_text().encode()).hexdigest())):
            raise Conflict('Mail hook, guard or library changed; automatic refresh requires review')
        reasons=[]
        if MACRO.read_text()!=MACRO_TEXT:reasons.append('startup-hook')
        elif '.include_if_exists ' in MACRO_TEXT and not runtime_hook_ready():reasons.append('startup-hook')
        if current['adapter']['native']!=native():reasons.append('native-package')
        if current['adapter']['source_sha256']!=sha(MailAdapter(self.settings).source):reasons.append('adapter-source')
        if current.get('code_generation')!=self.code_identity():reasons.append('addon-code')
        if current.get('runtime')!={str(path):fingerprint(path) for path in (LIBRARY,MACRO,Path('/usr/sbin/exim4'))}:
            reasons.append('runtime-identity')
        services=self.unit_states()
        if any(not services[unit]['active'] for unit in self.service_units()):reasons.append('owned-services')
        return reasons

    def verified_refresh_candidate(self,target):
        adapter=MailAdapter(self.settings);candidate=adapter.generation(target['adapter']['generation'],expected=native())
        if (candidate!=target['adapter'] or candidate['source_sha256']!=sha(adapter.source) or
                target['code_generation']!=self.code_identity()):
            raise Conflict('Native package, candidate or code changed during mail refresh; review is required')
        return candidate

    def refresh_target(self,transaction,target):
        """Advance pending protection intent to a newer installed native/code ABI.

        Preserve every earlier mutation intent and frozen-generation reference.
        A new candidate is proven before changing the committed target; an
        interrupted publication leaves either complete target recoverable.
        """
        current_native=native();current_code=self.code_identity()
        current_source=sha(MailAdapter(self.settings).source)
        if (target['adapter']['native']==current_native and target['code_generation']==current_code and
                target['adapter']['source_sha256']==current_source):return target
        for path in (LIBRARY,MACRO,GUARD):
            key=str(path);before=transaction['files'][key];actual=self.snapshot(path)
            allowed={None if before is None else before['sha256']}|set(transaction['expected'].get(key,[]))
            if (None if actual is None else actual['sha256']) not in allowed:
                raise Conflict('Mail runtime changed outside its pending refresh; review is required')
        previous=list(transaction.get('rebases',[]))
        if len(previous)>=16:raise Conflict('Too many overlapping mail updates; review is required')
        candidate=self.preflight()
        if (candidate['native']!=native() or candidate['source_sha256']!=sha(MailAdapter(self.settings).source) or
                current_code!=self.code_identity()):
            raise Conflict('Native package or code changed during refresh target preparation')
        previous.append(dict(adapter=target['adapter']['generation'],code_generation=target['code_generation'],
                             native=target['adapter']['native'],source_sha256=target['adapter']['source_sha256'],superseded_at=time.time()))
        value=dict(target,adapter=candidate,code_generation=current_code,last_refresh_rebases=len(previous),
                   guard_sha256=hashlib.sha256(self.guard_text().encode()).hexdigest(),refreshed_at=time.time(),runtime={})
        transaction['rebases']=previous
        self.commit(transaction,value)
        return value

    def record_rebases(self,transaction,target):
        previous=transaction.get('rebases',[])
        identity=transaction.get('transaction_id') or hashlib.sha256(json.dumps(transaction['files'],sort_keys=True).encode()).hexdigest()
        successors=previous[1:]+[dict(adapter=target['adapter']['generation'],code_generation=target['code_generation'],
                                    native=target['adapter']['native'],source_sha256=target['adapter']['source_sha256'])]
        with self.store.connection(True) as db:
            for index,(before,after) in enumerate(zip(previous,successors),1):
                subject='mail-refresh:'+identity+':'+str(index)
                if db.execute("SELECT 1 FROM audit WHERE owner='@admin' AND identity='' AND action='mail.refresh_rebased' AND subject=?",(subject,)).fetchone():continue
                self.store.audit({'actor':'clamshield-maintenance','owner':'@admin','identity':''},'mail.refresh_rebased',subject,
                                 {'from_adapter':before['adapter'],'to_adapter':after['adapter'],
                                  'from_code':before['code_generation'],'to_code':after['code_generation'],
                                  'from_native':before['native'],'native':after['native'],
                                  'source_sha256':after['source_sha256'],'rebase':index},db)

    def finish_refresh(self,transaction,target):
        target=self.refresh_target(transaction,target)
        candidate=self.verified_refresh_candidate(target)
        self.phase(transaction,'refreshing')
        # Stop native listeners/children before replacing an ABI library. An old
        # SMTP process must never dlopen bytes built for a newly installed Exim.
        self.stop_native()
        # All new sends are gated. Accepted but not yet submitted work remains
        # durable and resumes only after the new native/API binding is active.
        for unit in reversed(UNITS):self.system('stop',unit)
        content=(self.settings.mail_adapters/candidate['generation']/'local_scan.so').read_bytes()
        if hashlib.sha256(content).hexdigest()!=candidate['library_sha256']:
            raise EngineError('Frozen mail adapter changed before activation')
        self.put(transaction,LIBRARY,content)
        self.put(transaction,MACRO,MACRO_TEXT)
        self.put(transaction,GUARD,self.guard_text())
        self.record(transaction,dict(target,phase='recovering',runtime={}))
        self.system('daemon-reload')
        for unit in self.service_units():self.system('enable',unit);self.system('start',unit)
        self.ready();self.restart_native();self.wait_connected()
        value=dict(target,runtime=self.guard()['runtime'])
        self.record(transaction,value)
        self.record_rebases(transaction,target)
        self.journal.unlink();sync_directory(self.settings.state)
        return {'enabled':True,'refreshed':True,'adapter':candidate['generation'],'native_dnsbl':self.native_dnsbl_protection(),'native_spam_safety':self.native_spam_protection()}

    def _refresh(self,current):
        if current is None or current['phase']!='active':raise Conflict('Enable mail integration before refreshing it')
        if self.journal.exists():raise Conflict('Mail integration recovery is pending')
        self.refresh_reasons(current)
        candidate=self.preflight()
        if state(self.settings)!=current:raise Conflict('Mail integration changed during refresh preparation')
        transaction=self.begin('refresh')
        try:
            self.record(transaction,dict(current,phase='draining'))
            self.phase(transaction,'draining');self.drain(inflight_only=True)
            target=dict(current,phase='active',adapter=candidate,code_generation=self.code_identity(),
                        guard_sha256=hashlib.sha256(self.guard_text().encode()).hexdigest(),refreshed_at=time.time(),runtime={},last_refresh_rebases=0)
            self.commit(transaction,target)
            return self.finish_refresh(transaction,target)
        except Exception:
            if not transaction.get('committed'):self.rollback(transaction)
            raise

    def refresh(self):
        with self.locked():return self._refresh(state(self.settings))

    def clear_native_activation(self):
        path=self.settings.state/'native-rejection-activation.json';value=read(path)
        if value and value.get('phase')=='active':
            path.unlink();sync_directory(self.settings.state)

    def native_policies(self):
        """Apply inherited native delegation once per installed code generation.

        A durable attempted state also prevents an interrupted/failed change
        from becoming an automatic retry loop. Explicit activation can resolve
        a reviewed transition through the same generation-bound receipts.
        """
        self.native_dnsbl_protection()
        from .mail_policy import MailPolicies
        if not MailPolicies(self.store,self.hestia).server_defaults().get('enabled',False):return
        path=self.settings.state/'native-rejection-activation.json';previous=read(path)
        if previous:
            if previous.get('phase')!='active':return {'review_required':True}
            if previous.get('code_generation')==self.code_identity():return {'configured':True}
        value=dict(code_generation=self.code_identity(),phase='applying');write_json(path,value)
        try:
            from .native_rejection import NativeRejection
            result=NativeRejection(self.settings,self.hestia).activate(self.store)
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
            write_json(path,dict(value,phase='review'))
            self.store.notify('@admin','','mail.refresh_failed','native-rejection',
                {'message':'Native mail delivery policy delegation needs review'},'native-rejection-failed:'+self.code_identity())
            return {'review_required':True}
        write_json(path,dict(value,phase='active'));return result

    def native_dnsbl_protection(self):
        from .native_dnsbl import NativeDnsbl
        try:
            result=NativeDnsbl(self.settings,self.hestia).protect()
            if not result.get('review_required'):return result
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
            result={'review_required':True}
        self.store.notify('@admin','','mail.refresh_failed','native-dnsbl',
            {'message':'Native DNSBL error-reply filters need review; no automatic retry was attempted'},'native-dnsbl-review')
        return result

    def native_spam_protection(self):
        from .native_spam_safety import NativeSpamSafety
        try:return NativeSpamSafety(self.settings).ensure()
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
            self.store.notify('@admin','','mail.refresh_failed','native-spam-safety',
                {'message':'Native SpamAssassin administrative scores need review; no failed service action will be retried automatically'},'native-spam-safety-review')
            return {'review_required':True}

    def reconcile(self):
        with self.locked():
            current=state(self.settings)
            if self.journal.exists():raise Conflict('Mail integration recovery is pending')
            if current is None or current['phase']!='active':return {'refreshed':False}
            previous=read(self.refresh_status)
            if previous and previous.get('code_generation')==self.code_identity() and previous.get('retry_after',0)>time.time():
                return {'refreshed':False,'retry_pending':True}
            try:
                if not self.refresh_reasons(current):
                    return {'refreshed':False,'native_policies':self.native_policies(),'native_spam_safety':self.native_spam_protection()}
                result=self._refresh(current)
            except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
                write_json(self.refresh_status,dict(code_generation=self.code_identity(),retry_after=time.time()+60,
                           error='Automatic mail refresh needs recovery or review'))
                self.store.notify('@admin','','mail.refresh_failed','mail-integration',
                                  {'message':'Automatic mail refresh needs recovery or review'},'mail-refresh-failed:'+self.code_identity())
                return {'refreshed':False,'review_required':True}
            write_json(self.refresh_status,dict(code_generation=self.code_identity(),last_success=time.time()))
            self.store.notify('@admin','','mail.refreshed','mail-integration',{'adapter':result['adapter']})
            result['native_policies']=self.native_policies()
            return result

    def enable(self):
        with self.locked():
            current=state(self.settings)
            if current and current['phase']=='active' and not self.journal.exists():
                if self.refresh_reasons(current):return self._refresh(current)
                self.guard();self.ready();self.wait_connected()
                verified=self.guard()
                current['runtime']=verified['runtime'];write_json(self.state,current)
                return {'enabled':True,'unchanged':True,'native_dnsbl':self.native_dnsbl_protection(),'native_spam_safety':self.native_spam_protection()}
            if self.journal.exists():raise Conflict('Mail integration recovery is pending')
            if any(row['active'] for row in self.unit_states().values()):raise Conflict('Untracked owned mail services must be reviewed before activation')
            if MACRO.exists() or MACRO.is_symlink():raise Conflict('Existing Exim local macros are not replaced; review the integration conflict')
            if GUARD.exists() or GUARD.is_symlink():raise Conflict('Existing Exim ClamShield guard must be reviewed')
            parent=LIBRARY.parent
            if not parent.exists():parent.mkdir(mode=0o755);parent.chmod(0o755);write(parent/'.clamshield-owner','clamshield\n',0o644)
            trusted(parent,directory=True);trusted(parent/'.clamshield-owner')
            if (parent/'.clamshield-owner').read_text()!='clamshield\n':raise Conflict('Unmanaged mail adapter destination')
            GUARD.parent.mkdir(mode=0o755,parents=True,exist_ok=True);trusted(GUARD.parent,directory=True)
            candidate=self.preflight();transaction=self.begin('enable')
            try:
                value=dict(owner='clamshield',schema=1,phase='starting',adapter=candidate,runtime={},code_generation=self.code_identity(),
                           guard_sha256=hashlib.sha256(self.guard_text().encode()).hexdigest())
                self.record(transaction,value)
                self.put(transaction,LIBRARY,(self.settings.mail_adapters/candidate['generation']/'local_scan.so').read_bytes())
                self.put(transaction,GUARD,self.guard_text());self.system('daemon-reload')
                self.phase(transaction,'starting-services')
                for unit in self.service_units():self.system('enable',unit);self.system('start',unit)
                self.ready();self.phase(transaction,'attaching')
                self.put(transaction,MACRO,MACRO_TEXT)
                value['runtime']={str(path):fingerprint(path) for path in (LIBRARY,MACRO,Path('/usr/sbin/exim4'))}
                self.record(transaction,value);self.restart_native();self.wait_connected()
                value['runtime']=self.guard()['runtime']
                value['phase']='active';value['activated_at']=time.time()
                self.commit(transaction,value)
                return self.finish_active(transaction,value)
            except Exception:
                if not transaction.get('committed'):self.rollback(transaction)
                raise

    def disable(self):
        with self.locked():
            current=state(self.settings)
            if self.journal.exists():
                transaction=self.transaction()
                if transaction['action']!='refresh':raise Conflict('Mail integration recovery is pending')
                # An explicitly requested disable can supersede a failed refresh.
                # Use its existing mutation history, never discard recovery data.
                self.drain(inflight_only=True)
                transaction['superseded_action']='refresh';transaction['action']='disable'
                target=dict(current,phase='disabled',disabled_at=time.time(),runtime={})
                self.commit(transaction,target)
                return self.finish_disabled(transaction,target)
            if current is None or current['phase']=='disabled':
                from .native_rejection import NativeRejection
                rejection=NativeRejection(self.settings,self.hestia)
                rejection.remove_extension();restored=rejection.restore()
                from .native_dnsbl import NativeDnsbl
                NativeDnsbl(self.settings,self.hestia).restore()
                from .native_spam_safety import NativeSpamSafety
                NativeSpamSafety(self.settings).restore()
                self.clear_native_activation()
                return {'enabled':False,'unchanged':True,**restored}
            # Detaching a known owned hook must remain possible after a native
            # package change, even when the old adapter is no longer usable.
            if MACRO.read_text() not in (MACRO_TEXT,LEGACY_MACRO_TEXT) or not GUARD.read_text().startswith('# Managed by clamshield\n'):
                raise Conflict('Native mail hook/guard ownership changed; review is required')
            transaction=self.begin('disable')
            try:
                value=dict(current,phase='draining');self.record(transaction,value)
                self.phase(transaction,'draining');self.drain()
                value.update(phase='disabled',disabled_at=time.time(),runtime={})
                self.commit(transaction,value)
                return self.finish_disabled(transaction,value)
            except Exception:
                # Restore active service after a failed drain; no accepted mail is discarded.
                if transaction['phase'] in ('prepared','draining'):
                    self.restore(transaction,self.owner);self.restore(transaction,self.state)
                    self.journal.unlink();sync_directory(self.settings.state)
                elif not transaction.get('committed'):self.rollback(transaction)
                raise

    def recover(self):
        with self.locked():
            transaction=self.transaction()
            if transaction is None:return {'recovered':False}
            if transaction.get('owner')!='clamshield' or transaction.get('schema')!=1:raise EngineError('Invalid mail integration recovery journal')
            if transaction.get('committed'):
                method={'enable':self.finish_active,'disable':self.finish_disabled,'refresh':self.finish_refresh}[transaction['action']]
                method(transaction,transaction['target'])
                return {'recovered':True,'completed':transaction['action']}
            self.rollback(transaction);return {'recovered':True,'rolled_back':transaction['action']}

    def guard(self,*,check_configuration=True,startup=False):
        current=state(self.settings)
        if current is None or current['phase']=='disabled':return {'guarded':False}
        transaction=self.transaction()
        if transaction and transaction.get('committed') and transaction['action']=='disable' and not MACRO.exists():
            return {'guarded':True,'disabling':True}
        if transaction and transaction['phase']=='rolling-back':
            before=transaction['files'][str(self.state)]
            previous=json.loads(base64.b64decode(before['content'])) if before else None
            if previous is None or previous['phase']=='disabled':return {'guarded':False,'recovering':True}
            current=previous
        before={str(path):fingerprint(path) for path in (LIBRARY,MACRO,Path('/usr/sbin/exim4'))}
        compatible=(sha(Path('/usr/sbin/exim4'))==current['adapter']['native'].get('binary_sha256') if startup else current['adapter']['native']==native())
        if not compatible or current['adapter']['library_sha256']!=sha(LIBRARY):
            raise EngineError('Native Exim/adapter changed; prepare and refresh integration before startup')
        if MACRO.read_text() not in ((MACRO_TEXT,) if startup else (MACRO_TEXT,LEGACY_MACRO_TEXT)):
            raise EngineError('Owned Exim hook changed')
        if current['adapter']['source_sha256']!=sha(MailAdapter(self.settings).source):
            raise EngineError('Addon adapter source changed; prepare and refresh integration')
        if check_configuration:
            parsed=subprocess.run(['/usr/sbin/exim4','-bP','local_scan_path'],capture_output=True,text=True,timeout=5)
            if parsed.returncode or parsed.stdout.strip()!='local_scan_path = '+str(LIBRARY):
                raise EngineError('Native configuration has lost the owned mail hook')
        after={str(path):fingerprint(path) for path in (LIBRARY,MACRO,Path('/usr/sbin/exim4'))}
        if before!=after:raise EngineError('Mail runtime changed during startup verification')
        return {'guarded':True,'runtime':after}

    def startup(self):
        """Publish an optional hook only after exact byte/ABI identity checks.

        systemd supplies an empty owned RuntimeDirectory on every native start.
        This method neither regenerates native configuration nor starts/stops a
        service. Failure leaves the optional include absent and native mail up.
        """
        trusted(HOOK_RUNTIME,directory=True)
        if HOOK_INCLUDE.exists() or HOOK_INCLUDE.is_symlink():
            trusted(HOOK_INCLUDE)
            if HOOK_INCLUDE.read_text()!='local_scan_path = '+str(LIBRARY)+'\n':
                raise Conflict('Foreign runtime hook configuration retained')
            HOOK_INCLUDE.unlink();sync_directory(HOOK_RUNTIME)
        try:
            result=self.guard(check_configuration=False,startup=True)
            if not result.get('guarded') or result.get('disabling') or result.get('recovering'):
                return {'hook_enabled':False,'native_fallback':True}
            # The include is the final publication, never an early readiness flag.
            write(HOOK_INCLUDE,'local_scan_path = '+str(LIBRARY)+'\n',0o644)
            return {'hook_enabled':True,'native_fallback':False}
        except (OSError,ValueError,KeyError,TypeError,ClamShieldError):
            return {'hook_enabled':False,'native_fallback':True,'error':'Hook compatibility check failed; native mail retained'}

    def status(self):
        try:
            current=state(self.settings);journal=read(self.journal)
            from .native_dnsbl import NativeDnsbl
            try:dnsbl=NativeDnsbl(self.settings,self.hestia).status()
            except (OSError,ValueError,KeyError,TypeError,ClamShieldError):dnsbl={'state':'needs-review','review_required':True}
            from .native_spam_safety import NativeSpamSafety
            try:spam_safety=NativeSpamSafety(self.settings).status()
            except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):spam_safety={'state':'needs-review','verified':False,'review_required':True}
            return dict(configured=current is not None,phase=current['phase'] if current else 'unconfigured',
                        hook_enabled=runtime_hook_ready() if current and MACRO.exists() and MACRO.read_text()==MACRO_TEXT else None,
                        transition=journal['phase'] if journal else None,units=self.unit_states(),
                        native_dnsbl=dnsbl,native_spam_safety=spam_safety,
                        native_filters='Native domain filters run before the ClamShield hook',
                        pending=self.pending(),mode=mode(self.settings))
        except (OSError,ValueError,KeyError,TypeError,ClamShieldError,subprocess.SubprocessError):
            return dict(phase='needs-review',error='Mail integration needs recovery or native runtime verification')
