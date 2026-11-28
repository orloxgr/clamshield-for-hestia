"""Root broker joining native requests, real scans, policy and durable custody."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import sqlite3
import stat
import subprocess
import threading
import time
import uuid

from .atomic import write_json
from .errors import AccessDenied,ClamShieldError,EngineError
from .hestia import Hestia
from .mail_acceptance import MailAcceptance
from .mail_bridge import Decision,receive,respond
from .mail_custody import MailCustody
from .mail_delivery import MailDelivery,PROTOCOL
from .mail_inventory import inventory,resolve
from .mail_policy import MailPolicies,evaluate,transaction_decisions,transaction_plan
from .mail_scanners import MailClamAV,SpamAssassin,digest_snapshot
from .mail_generation import GenerationMailScanner
from .engines import Yara
from .settings import Settings
from .store import Store

RUNTIME=Path('/run/clamshield-mail')
SOCKET=RUNTIME/'policy.sock'
CONFIG=Path('/etc/clamshield/mail.json')
LIBRARY=Path('/opt/clamshield-mail/local_scan.so')


def configuration():
    value={'_managed':'Managed by clamshield','workers':2,'timeout':25,'yara_enabled':True}
    if CONFIG.exists() or CONFIG.is_symlink():
        info=CONFIG.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:
            raise AccessDenied('Mail service configuration is not trusted')
        incoming=json.loads(CONFIG.read_text())
        if not isinstance(incoming,dict) or set(incoming)-set(value) or incoming.get('_managed')!=value['_managed']:
            raise ClamShieldError('Mail service configuration is invalid')
        value.update(incoming)
    if (type(value['workers']) is not int or not 1<=value['workers']<=8 or
        type(value['timeout']) is not int or not 5<=value['timeout']<=25 or type(value['yara_enabled']) is not bool):
        raise ClamShieldError('Mail service limits are invalid')
    return value


def transport_active(*,require_active=True):
    try:
        if require_active:
            from .mail_runtime import mode
            if mode(Settings()) not in ('legacy','active'):return False
        path=RUNTIME/'status.json';info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:return False
        value=json.loads(path.read_text())
        return value.get('owner')=='clamshield' and value.get('connected') is True and 0<=time.time()-value['heartbeat']<10
    except (OSError,ValueError,KeyError,TypeError,ClamShieldError):return False


class MailBroker:
    def __init__(self,settings,store,hestia,scanner_factory,*,native=None):
        self.settings,self.store,self.hestia=settings,store,hestia;self.scanner_factory=scanner_factory
        self.policies=MailPolicies(store,hestia);self.custody=MailCustody(settings,store,hestia)
        self.acceptance=MailAcceptance(settings,store,hestia,native);self.delivery=MailDelivery(settings,store,hestia,native)

    def plan(self,request):
        rows=inventory(self.hestia);original=[resolve(rows,recipient) for recipient in request.recipients]
        # Only authenticated native ACL variables reach this path. Aggregate
        # diagnostics are optional; their storage cannot block delivery.
        if request.native_dnsbl_zone or request.native_dnsbl_value:
            from .native_dnsbl_health import NativeDnsblHealth
            try:NativeDnsblHealth(self.settings).observe(request.native_dnsbl_zone,request.native_dnsbl_value)
            except (OSError,ValueError,sqlite3.Error,ClamShieldError):
                import logging
                logging.getLogger(__name__).warning('Native DNSBL observation could not be saved')
        policies=[]
        for target in original:
            if target is None:policies.append(None);continue
            if target['suspended']:raise AccessDenied('Native mail recipient is unavailable')
            context=self.hestia.authorize(target['owner'])
            if context['identity']!=target['identity']:raise AccessDenied('Native mail owner changed')
            policies.append(self.policies.get(context,target['domain'],target['mailbox'])['effective'])
        native_av=[bool(target and next(row['native_antivirus'] for row in rows
                   if row['owner']==target['owner'] and row['domain']==target['domain'])) for target in original]
        from .native_rejection import NativeRejection
        delegated=NativeRejection(self.settings,self.hestia).delegated(rows)
        native_spam=[bool(target and (target['owner'],target['identity'],target['domain']) in delegated and
                          not (policy and policy['enabled'])) for target,policy in zip(original,policies)]
        managed=any(policy and policy['enabled'] for policy in policies)
        native_observed=bool(request.native_mime_blocked or request.native_dnsbl_zone or request.native_dnsbl_value)
        if not managed and not any(native_av) and not any(native_spam) and not native_observed:return None
        native_result=None
        if any(native_spam):
            from .native_spam import rejection_threshold
            from .native_spam_client import NativeSpamAssassin
            try:
                threshold=rejection_threshold()
                native_result=(dict(score=request.native_spam_score,source='native-exim-acl') if request.native_spam_score is not None
                               else NativeSpamAssassin().scan(request.fd,deadline=self.hestia.deadline or time.monotonic()+20))
                native_result=dict(native_result,threshold=threshold,complete=True)
            except (ClamShieldError,OSError,ValueError,subprocess.SubprocessError):
                native_result=dict(complete=False,source='native-spamd-unavailable')
        sha256=digest_snapshot(request.fd)
        if managed or any(native_av):
            scanner=self.scanner_factory()
            if hasattr(scanner,'timeout'):
                remaining=25 if self.hestia.deadline is None else self.hestia.deadline-time.monotonic()
                if remaining<=0:raise EngineError('Mail request time budget is exhausted')
                scanner.timeout=min(scanner.timeout,remaining)
            scan=scanner.scan(request.fd)
        else:scan=dict(complete=False,sha256=sha256,spam_score=None,detections=[],errors=[])
        if scan.get('sha256')!=sha256:raise EngineError('Mail scan does not match the native snapshot')
        current=inventory(self.hestia);items=[]
        for index,recipient in enumerate(request.recipients):
            target=resolve(current,recipient)
            if target!=original[index]:raise AccessDenied('Native recipient changed during scanning')
            if target is None:items.append({'decision':{'action':'deliver'}});continue
            context=self.hestia.authorize(target['owner'])
            if context['identity']!=target['identity']:raise AccessDenied('Native mail owner changed')
            context=dict(context,actor='clamshield-mail')
            policy=self.policies.get(context,target['domain'],target['mailbox'])['effective']
            decision=evaluate(policy,scan,sender=request.sender,sha256=sha256,
                              native_dnsbl=(request.native_dnsbl_zone,request.native_dnsbl_value))
            from .native_mime_context import observe as mime_observation
            mime=mime_observation(request.native_mime_blocked)
            if mime is not None:decision['native_mime']=mime
            if request.native_spam_score is not None:
                decision['native_spamassassin']={'score':request.native_spam_score,'source':'native-exim-acl'}
            if not policy['enabled'] and native_av[index]:
                from .native_gate import baseline
                retained=[]
                for hit in scan.get('detections',[]):
                    if hit.get('engine')!='clamav':continue
                    origin={key:value for key,value in hit.items() if key not in ('engine','signature')}
                    if baseline([hit['signature']],lambda _name:origin):retained.append(hit)
                decision.update(action='reject' if retained else 'deliver',
                    classification='native-malware' if retained else 'unmanaged' if scan.get('complete') else 'incomplete',
                    scan_complete=scan.get('complete') is True,detections=retained)
            if not policy['enabled'] and decision['action']!='reject':
                from .native_dnsbl_context import verified_policy_match
                if verified_policy_match(decision.get('native_dnsbl')):
                    decision.update(action='reject',classification='native-dnsbl')
                elif mime is not None:
                    decision.update(action='reject',classification='native-mime')
                elif decision.get('native_dnsbl') is not None:
                    decision.update(action='deliver',classification='incomplete',scan_complete=False)
            if native_spam[index] and not policy['enabled']:
                decision['native_spamassassin']=native_result
                if native_result['complete']:
                    if native_result['score']>native_result['threshold']['required_score']:
                        if decision['action']!='reject':decision.update(action='reject',classification='native-spam')
                    elif not native_av[index] and decision['action']!='reject' and decision.get('native_dnsbl') is None:
                        decision.update(action='deliver',classification='unmanaged',scan_complete=True)
                elif decision['action']!='reject':decision.update(action='deliver',classification='incomplete',scan_complete=False)
            if policy['enabled'] and decision['action']=='deliver' and decision['scan_complete']:decision['capture']=True
            decision.update(smtp_outcome='pending',policy_action=decision['action'],policy_classification=decision['classification'])
            items.append({'context':context,'target':target,'decision':decision,'managed':policy['enabled']})
        decisions=transaction_decisions([item['decision'] for item in items])
        items=[dict(item,decision=decision) for item,decision in zip(items,decisions)]
        return {'items':items,'sha256':sha256,'plan':transaction_plan(decisions)}

    def handle(self,connection,*,expected_uid,expected_binary='/usr/sbin/exim4',request=None):
        replied=False;event=uuid.uuid4().hex;phase='receive';self.last_error=None;items=None
        try:
            if request is None:request=receive(connection,expected_uid=expected_uid,expected_binary=expected_binary,timeout=3)
            self.hestia.deadline=time.monotonic()+25
            phase='reinjection';reinjected=self.delivery.authorize_reinjection(request)
            if reinjected:
                respond(connection,Decision.ACCEPT,reinjected['attempt']);return 'reinjected'
            from .mail_runtime import mode
            if mode(self.settings) not in ('legacy','active'):
                respond(connection,Decision.NATIVE_FALLBACK,event);return 'transition'
            phase='plan';result=self.plan(request)
            if result is None:
                respond(connection,Decision.ACCEPT,event);return 'unmanaged'
            items,plan=result['items'],result['plan']
            phase='record'
            for item in items:
                if item.get('managed') or item['decision'].get('classification') in ('native-malware','native-spam','native-mime','native-dnsbl'):
                    self.policies.record(item['context'],item['target'],request,result['sha256'],item['decision'])
            if plan['smtp']!='accept':
                self.policies.outcome(request.message_id,plan['smtp'])
                respond(connection,Decision.REJECT if plan['smtp']=='reject' else Decision.DEFER,event)
                return plan['smtp']
            if not plan['custody']:
                incomplete=any(item['decision'].get('classification')=='incomplete' for item in items)
                if incomplete:self.policies.outcome(request.message_id,'accepted',native_fallback=True)
                respond(connection,Decision.NATIVE_FALLBACK if incomplete else Decision.ACCEPT,event)
                return 'native-fallback' if incomplete else 'unmanaged'
            phase='stage';staged=self.custody.stage(request,items)
            phase='arm';response=self.acceptance.arm(staged,request);phase='respond'
            respond(connection,response['decision'],response['event'],response['selected']);replied=True
            self.acceptance.response_sent(staged['transaction_id']);return 'custody'
        except Exception as exc:
            self.last_error=type(exc).__name__+':'+phase
            if not replied:
                denied=isinstance(exc,AccessDenied) and phase in ('receive','reinjection')
                tags=None;tag_names={}
                if (not denied and isinstance(exc,(OSError,sqlite3.Error)) and request is not None and
                        request.fallback_tags_supported and items is not None):
                    from .mail_bridge import FALLBACK_TAGS
                    # These decisions came from the sealed snapshot/current policies,
                    # never browser fields or sender-supplied status headers.
                    try:
                        tags=[];owners={}
                        if len(items)!=len(request.recipients):raise ClamShieldError('Changed native envelope')
                        for item in items:
                            decision=item['decision'];code=0
                            if decision['action']=='tag':
                                context=item['context'];owner=context['owner']
                                if owner not in owners:owners[owner]=self.hestia.authorize(owner)['identity']
                                if owners[owner]!=context['identity']:raise AccessDenied('Mail owner was replaced')
                                category=next((kind for kind in ('malware','phishing','spam') if
                                    any(hit.get('category')==kind for hit in decision.get('detections',[]))),decision.get('classification'))
                                code=FALLBACK_TAGS.get(category,0)
                            tags.append(code)
                        if not any(tags):tags=None
                        else:tag_names={request.recipients[i].lower():name for i,code in enumerate(tags)
                                        for name,value in FALLBACK_TAGS.items() if code==value}
                    except (ClamShieldError,OSError,ValueError,KeyError,TypeError):tags=None;tag_names={}
                if request is not None:
                    try:self.policies.outcome(request.message_id,'defer' if denied else 'accepted',native_fallback=not denied,
                                             **({'fallback_tags':tag_names} if tags is not None else {}))
                    except Exception:pass
                try:
                    if tags is not None:respond(connection,Decision.TAGGED_FALLBACK,event,tags=tags)
                    else:respond(connection,Decision.DEFER if denied else Decision.NATIVE_FALLBACK,event)
                except OSError:pass
            return 'error'
        finally:
            if request is not None:request.close()


def scanner_factory(settings,config):
    clam=pwd.getpwnam('clamav');spam=pwd.getpwnam('debian-spamd')
    def factory():
        yara=Yara(settings.yara_binary,settings.rules.resolve(strict=True),timeout=config['timeout'],purpose='mail') if config['yara_enabled'] else None
        from .native_integration import NativeIntegration,enabled
        from .native_clamav import NativeMailClamAV
        native=(NativeMailClamAV(NativeIntegration(settings).client('mail',timeout=config['timeout'],maximum=65*1024**2))
                if enabled(settings) else MailClamAV('/run/clamshield-mail-clamd/clamd.sock','/run/clamshield-mail-scan',
                expected_uid=clam.pw_uid,group=clam.pw_gid,timeout=config['timeout']))
        return GenerationMailScanner(settings,native,
            SpamAssassin('/run/clamshield-mail-spamd/spamd.sock',expected_uid=spam.pw_uid,timeout=config['timeout']),
            yara=yara,timeout=config['timeout'])
    return factory


def serve(settings=None):
    settings=settings or Settings();settings.prepare();config=configuration();store=Store(settings.database)
    account=pwd.getpwnam('Debian-exim');clam=pwd.getpwnam('clamav')
    for path,group,mode in ((RUNTIME,account.pw_gid,0o750),(Path('/run/clamshield-mail-scan'),clam.pw_gid,0o710)):
        if path.is_symlink():raise AccessDenied('Unsafe mail runtime directory')
        path.mkdir(exist_ok=True);info=path.stat()
        if info.st_uid!=0 or not stat.S_ISDIR(info.st_mode):raise AccessDenied('Untrusted mail runtime directory')
        os.chown(path,0,group);path.chmod(mode)
    lock=os.open(RUNTIME/'service.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    info=os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
        os.close(lock);raise AccessDenied('Untrusted mail service lock')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if SOCKET.exists() or SOCKET.is_symlink():
        info=SOCKET.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0:raise AccessDenied('Untrusted mail socket')
        SOCKET.unlink()
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);listener.bind(str(SOCKET))
    os.chown(SOCKET,0,account.pw_gid);SOCKET.chmod(0o660);listener.listen(16);listener.settimeout(.5)
    stop=threading.Event();slots=threading.BoundedSemaphore(config['workers']);reinjections=threading.BoundedSemaphore(1)
    counts={};count_lock=threading.Lock();maintenance_ok=[0]
    def count(name):
        with count_lock:counts[name]=counts.get(name,0)+1
    def shutdown(_signal,_frame):stop.set()
    for name in (signal.SIGTERM,signal.SIGINT):signal.signal(name,shutdown)
    def handle(connection,request,capacity):
        kind='reinjections' if capacity is reinjections else 'regular'
        count('started_'+kind)
        try:
            with connection:
                broker=MailBroker(settings,store,Hestia(settings.hestia,timeout=2),scanner_factory(settings,config))
                count(broker.handle(connection,expected_uid=account.pw_uid,request=request))
                if broker.last_error:count('error_'+broker.last_error)
        finally:count('finished_'+kind);capacity.release()
    def pump():
        acceptance=MailAcceptance(settings,store,Hestia(settings.hestia));delivery=MailDelivery(settings,store,Hestia(settings.hestia))
        while not stop.is_set():
            try:
                from .mail_runtime import may_deliver
                acceptance.recover()
                delivery.once() if may_deliver(settings) else delivery.recover()
                maintenance_ok[0]=time.monotonic()
            except Exception:count('maintenance_errors')
            stop.wait(.5)
    from .mail_readiness import serve as serve_readiness
    readiness=serve_readiness(stop,scanner_factory(settings,config))
    maintenance=threading.Thread(target=pump,daemon=True);maintenance.start();last_heartbeat=0
    try:
        with ThreadPoolExecutor(max_workers=config['workers']+1) as executor:
            while not stop.is_set():
                if time.monotonic()-last_heartbeat>=1:
                    result=subprocess.run(['/usr/sbin/exim4','-bP','local_scan_path'],capture_output=True,text=True,timeout=3)
                    connected=result.returncode==0 and result.stdout.strip()=='local_scan_path = '+str(LIBRARY)
                    with count_lock:current_counts=dict(counts)
                    write_json(RUNTIME/'status.json',{'owner':'clamshield','heartbeat':time.time(),'connected':connected,'counts':current_counts},0o644)
                    last_heartbeat=time.monotonic()
                try:connection,_=listener.accept()
                except socket.timeout:continue
                request=None
                try:request=receive(connection,expected_uid=account.pw_uid,expected_binary='/usr/sbin/exim4',timeout=.5)
                except (OSError,ClamShieldError):pass
                capacity=reinjections if request is not None and request.protocol.startswith(PROTOCOL) else slots
                ready=request is not None and (capacity is reinjections or time.monotonic()-maintenance_ok[0]<30)
                if ready and capacity.acquire(False):executor.submit(handle,connection,request,capacity)
                else:
                    count('busy')
                    if request is not None:request.close()
                    with connection:
                        try:respond(connection,Decision.NATIVE_FALLBACK,uuid.uuid4().hex)
                        except OSError:pass
    finally:
        stop.set();listener.close();readiness.join(timeout=30);maintenance.join(timeout=35);SOCKET.unlink(missing_ok=True)
        (RUNTIME/'status.json').unlink(missing_ok=True);os.close(lock)
