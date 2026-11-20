"""Reviewable WordPress recovery batches using existing journaled file actions."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import time
import uuid

from .atomic import write
from .errors import AccessDenied, ClamShieldError, Conflict
from .generations import current as generation
from .paths import absence, relative_path, snapshot, walk
from .quarantine import Quarantine
from .repairs import Repairs, preview
from .store import encode
from .website_permissions import WebsitePermissions
from .wordpress import WordPress, joined
from .wordpress_database import WordPressDatabase, packed, unpacked, replacement as db_replacement
from .wordpress_sources import token
from .recovery_references import RecoveryReferences


def options(value):
    defaults=dict(uploads_php=True,uploads_js=False,additional=True,database=True,versions={},packages={})
    if not isinstance(value,dict) or set(value)-set(defaults):raise Conflict('Invalid recovery options')
    result=defaults|value
    for key in ('uploads_php','uploads_js','additional','database'):
        if type(result[key]) is not bool:raise Conflict('Invalid recovery toggle')
    for key in ('versions','packages'):
        if not isinstance(result[key],dict) or len(result[key])>200:raise Conflict('Invalid component selections')
        result[key]={relative_path(path):token(version,'version') if key=='versions' else relative_path(version,allow_root=False) for path,version in result[key].items()}
    return result


class WordPressRecovery:
    def __init__(self,settings,store,hestia,references=None):
        self.settings,self.store,self.hestia,self.references=settings,store,hestia,references
        self.quarantine=Quarantine(settings,store,hestia);self.repairs=Repairs(settings,store,hestia)

    @contextmanager
    def locked(self):
        self.settings.prepare()
        fd=os.open(self.settings.state/'wordpress-recovery.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:raise AccessDenied('Recovery lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def context(self,plan,actor=None):
        live=self.hestia.authorize(actor or plan['actor'],plan['owner'])
        if live['identity']!=plan['identity']:raise AccessDenied('Recovery account was replaced')
        self.quarantine.validate_site(live,plan)
        return live

    def get(self,context,plan_id):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM wordpress_recovery WHERE id=? AND owner=? AND identity=?',(plan_id,*self.store.scope(context))).fetchone()
        if not row:raise AccessDenied('Recovery plan unavailable')
        return dict(row)|{key:json.loads(row[key]) for key in ('options','report','selection')}

    def items(self,plan):
        with self.store.connection() as db:rows=db.execute('SELECT * FROM wordpress_recovery_items WHERE plan_id=? ORDER BY path,id',(plan['id'],)).fetchall()
        return [dict(row)|{'detail':json.loads(row['detail'])} for row in rows]

    def save(self,plan,**changes):
        if set(changes)-{'status','revision','report','selection','work_job','error'}:raise ValueError('Invalid recovery update')
        with self.store.connection(True) as db:
            db.execute('UPDATE wordpress_recovery SET '+','.join(key+'=?' for key in changes)+' WHERE id=?',
                       (*[encode(value) if key in ('report','selection') else value for key,value in changes.items()],plan['id']))
        plan.update(changes)

    def save_item(self,item,**changes):
        if set(changes)-{'status','detail'}:raise ValueError('Invalid recovery item update')
        with self.store.connection(True) as db:
            db.execute('UPDATE wordpress_recovery_items SET '+','.join(key+'=?' for key in changes)+' WHERE id=? AND plan_id=?',
                       (*[encode(value) if key=='detail' else value for key,value in changes.items()],item['id'],item['plan_id']))
        item.update(changes)

    def add(self,plan,path,kind,action,detail):
        item=dict(id=uuid.uuid4().hex,plan_id=plan['id'],path=path,kind=kind,action=action,status='proposed',detail=detail)
        with self.store.connection(True) as db:
            count=db.execute('SELECT count(*) FROM wordpress_recovery_items WHERE plan_id=?',(plan['id'],)).fetchone()[0]
            if count>=10000:raise Conflict('Recovery plan exceeds the item limit')
            db.execute('INSERT INTO wordpress_recovery_items VALUES(?,?,?,?,?,?,?)',
                       (item['id'],plan['id'],path,kind,action,'proposed',encode(detail)))
        return item

    def artifact(self,plan,item_id,suffix):
        if not re.fullmatch(r'[a-f0-9]{32}',plan['id']) or not re.fullmatch(r'[a-f0-9]{32}',item_id) or suffix not in ('replacement','db-before','db-after'):
            raise AccessDenied('Invalid recovery artifact')
        folder=self.settings.state/'wordpress-recovery'/plan['id'];folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        if folder.is_symlink():raise AccessDenied('Invalid recovery artifact directory')
        return folder/(item_id+'.'+suffix)

    def analyze(self,context,domain,target,value):
        value=options(value);target=relative_path(target)
        site=next((site for site in self.hestia.sites(context['owner']) if site['domain']==domain and not site['suspended']),None)
        if not site:raise AccessDenied('Website unavailable')
        with self.locked():
            job=self.store.enqueue(context,site,target,source='wordpress-recovery',generation=generation(self.settings))
            with self.store.connection(True) as db:
                db.execute('INSERT INTO wordpress_recovery(id,owner,identity,actor,domain,root,target,created,status,revision,options,work_job) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                           (job,*self.store.scope(context),context['actor'],domain,site['root'],target,time.time(),'analyzing',uuid.uuid4().hex,encode(value),job))
            return {'plan_id':job,'jobs':[job]}

    def inspect(self,job,engines):
        plan=self.get(job,job['id']);context=self.context(plan)
        refs=self.references or RecoveryReferences(self.settings,plan['root'],plan['options'],owner=context['owner'])
        result=WordPress(self.settings,self.store,self.hestia,refs).run(job,finish=False)
        report=result['report'];counters=result['counters'];counters.setdefault('suppressed',0)
        if result['status'] in ('failed','cancelled'):raise Conflict(report.get('error','WordPress analysis was not completed'))
        if not report['installations']:raise Conflict('No WordPress installation was discovered in the selected folder')
        if len(report['installations'])>50 or len(report['components'])>500:raise Conflict('Select a smaller WordPress folder; the recovery inventory exceeds its limit')
        plan['report']=dict(installations=report['installations'],components=report['components'],coverage=counters,
                            database=[],errors=[],investigation=[],packages={},warning='Integrity differences and cleanup-policy matches are not malware verdicts. Pause website writes before applying recovery. Updates may require application/database migration and compatibility checks.')
        discovered={component['path'] for component in report['components']}
        unused=(plan['options']['versions'].keys()|plan['options']['packages'].keys())-discovered
        for path in sorted(unused):
            plan['report']['errors'].append('Component selection was not found: '+(path or 'WordPress root'));counters['errors']+=1
        for component in report['components']:component['recovery_version']=plan['options']['versions'].get(component['path'],component.get('version','Unverified'))
        if {engine.name for engine in engines}!={'clamav','yara'}:raise Conflict('Recovery analysis requires both ClamAV and YARA')
        with self.store.connection() as db:
            findings=[dict(row)|{'fingerprint':json.loads(row['fingerprint'])} for row in db.execute('SELECT * FROM findings WHERE job_id=? ORDER BY path',(job['id'],))]
        known={}
        for finding in findings:
            self.check_cancel(job)
            detail=finding['fingerprint'].get('wordpress',{});component=detail.get('component',{})
            action='replace' if detail.get('expected') else 'quarantine'
            item=self.add(plan,finding['path'],'integrity',action,dict(finding_id=finding['id'],reason=finding['signature'],
                           recommended=action=='replace' or (plan['options']['additional'] and component.get('kind')!='core') or
                           (plan['options']['additional'] and detail.get('file','').startswith(('wp-admin/','wp-includes/')))))
            known[finding['path']]=item
            if action=='replace':
                try:
                    content,provenance=refs.replacement(component,detail['file'],detail['expected'])
                    if len(content)>self.settings.max_file_bytes:raise Conflict('Replacement exceeds the file limit')
                    destination=self.artifact(plan,item['id'],'replacement');write(destination,content)
                    hits=[hit for engine in engines for hit in engine.scan(destination)]
                    if hits:raise Conflict('Replacement was flagged by a scanning engine')
                    self.save_item(item,detail=item['detail']|dict(replacement=provenance|{'sha256':hashlib.sha256(content).hexdigest()},candidate=True))
                except (OSError,ClamShieldError) as exc:
                    self.save_item(item,status='blocked',detail=item['detail']|dict(error=self.message(exc)))
                    plan['report']['errors'].append('Replacement unavailable: '+finding['path'])
        recent=[]
        for path,state,_ in walk(plan['root'],plan['target']):
            self.check_cancel(job)
            if state!='regular':continue  # Integrity discovery already records coverage gaps.
            try:
                with snapshot(plan['root'],path,self.settings.snapshots,self.settings.max_file_bytes) as (copy,fp):
                    counters['bytes']+=fp['size'];counters['seen']+=1
                    if fp['links']!=1:raise Conflict('Hard-linked file requires review')
                    detections=[]
                    for engine in engines:detections.extend(engine.scan(copy))
                    counters['scanned']+=1;counters['infected']+=bool(detections)
                    installation=next((row['path'] for row in sorted(report['installations'],key=lambda row:len(row['path']),reverse=True) if path.startswith(joined(row['path'],'wp-content/uploads')+'/')),None)
                    suffix=PurePosixPath(path).suffix.lower()
                    policy=installation is not None and ((plan['options']['uploads_php'] and (suffix in ('.php','.php3','.php4','.php5','.php7','.php8','.phtml','.pht','.phar','.cgi','.pl','.py','.sh') or re.search(rb'<\?(?:php|=)',copy.read_bytes()[:1048576],re.I))) or (plan['options']['uploads_js'] and suffix in ('.js','.mjs','.cjs')))
                    reason='Selected uploads cleanup policy' if policy else 'Scanner detection' if detections else None
                    name=PurePosixPath(path).name
                    if not reason and name in ('.htaccess','.user.ini','php.ini','wp-config.php'):
                        content=copy.read_bytes()[:256*1024]
                        if re.search(rb'auto_(?:prepend|append)_file|(?:RewriteRule|Redirect)\s+[^\r\n]*https?://|AddHandler[^\r\n]*(?:php|phtml)',content,re.I):
                            reason='Configuration directive requires review'
                    if reason and path not in known:
                        finding_id=self.store.add_finding(job,path,fp,dict(engine='recovery-policy' if policy else 'recovery-review',signature='WordPress.Uploads.Policy' if policy else 'WordPress.Recovery.Review',provider='local-policy',severity='review'))
                        item=self.add(plan,path,'uploads-policy' if policy else 'scanner' if detections else 'configuration','quarantine',
                                      dict(finding_id=finding_id,reason=reason,recommended=bool(policy or detections),detections=detections))
                        known[path]=item
                    for hit in detections:self.store.add_finding(job,path,fp,hit)
                    counters['detections']+=len(detections)
                    recent.append(dict(path=path,modified=fp['mtime_ns']/1e9,size=fp['size'],mode=oct(fp['mode'])))
                    if len(recent)>200:recent=sorted(recent,key=lambda value:value['modified'],reverse=True)[:100]
            except (OSError,ClamShieldError) as exc:
                counters['errors']+=1
                if len(plan['report']['errors'])<100:plan['report']['errors'].append(path+': '+self.message(exc))
            self.store.progress(job['id'],counters)
        plan['report']['investigation']=sorted(recent,key=lambda value:value['modified'],reverse=True)[:100]
        if plan['options']['database']:
            for installation in report['installations']:
                self.check_cancel(job)
                try:
                    database=WordPressDatabase(self.settings,self.hestia,context,plan['root'],installation['path'])
                    def emit(evidence):
                        before=unpacked(evidence.pop('before'))
                        item=self.add(plan,evidence['table']+'.'+evidence['column'],'database','database',evidence|dict(recommended=False,reason='Database content requires review'))
                        write(self.artifact(plan,item['id'],'db-before'),before)
                    outcome=database.inspect(emit,cancelled=lambda:self.store.cancelled(job['id']))
                except (OSError,ClamShieldError,ImportError) as exc:
                    outcome=dict(status='unavailable',error=self.message(exc));counters['errors']+=1
                plan['report']['database'].append(dict(installation=installation['path'],**outcome))
        plan['report']['packages']=getattr(refs,'receipts',{})
        plan['report']['processes']=self.processes(plan['root'])
        if len(encode(plan['report']).encode())>1024**2:raise Conflict('Recovery report exceeds its limit; select a smaller folder')
        self.save(plan,status='ready',report=plan['report'],work_job=None,error=None,revision=uuid.uuid4().hex)
        self.store.finish(job,'partial' if counters.get('errors') or counters.get('skipped') or counters.get('unverified') else 'completed',counters)

    @staticmethod
    def message(exc):
        return str(exc) if isinstance(exc,ClamShieldError) else 'Inspection or recovery data is unavailable'

    @staticmethod
    def processes(root):
        """Informational open-file/cwd snapshot, never evidence of a write."""
        result=[];budget=10000;prefix=root.rstrip('/')+'/'
        try:pids=[path for path in Path('/proc').iterdir() if path.name.isdigit()][:2000]
        except OSError:return result
        for pid in pids:
            try:
                matched=[];cwd=os.readlink(pid/'cwd')
                if cwd==root or cwd.startswith(prefix):matched.append('cwd: '+cwd)
                for path in (pid/'fd').iterdir():
                    budget-=1
                    if budget<0:return result
                    try:target=os.readlink(path)
                    except OSError:continue
                    if target.startswith(prefix):matched.append(target)
                    if len(matched)>=10:break
                if matched:result.append(dict(pid=int(pid.name),executable=Path(os.readlink(pid/'exe')).name,files=matched,note='Open files/cwd do not establish that this process changed them.'))
                if len(result)>=100:return result
            except OSError:continue
        return result

    def check_cancel(self,job):
        if self.store.cancelled(job['id']):raise Conflict('Recovery was cancelled; completed changes are retained for undo')

    def selected(self,plan):
        selected=set(plan['selection'])
        return sorted((item for item in self.items(plan) if item['id'] in selected),key=lambda item:(0 if item['action']=='database' else 2 if PurePosixPath(item['path']).name=='wp-config.php' else 1,item['path'],item['id']))

    def require(self,context,items,undo=False):
        permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        for capability in ({'restore'} if undo else {'repair' if item['action'] in ('replace','database') else 'quarantine' for item in items}):
            permissions.require(context,capability)

    def request(self,context,plan_id,operation,revision,value=None):
        with self.locked():
            plan=self.get(context,plan_id);self.context(plan,actor=context['actor'])
            if revision!=plan['revision']:raise Conflict('Recovery plan changed; reload it before continuing')
            if plan['work_job']:
                job=self.store.job(context,plan['work_job'])
                if job['status'] in ('queued','running'):raise Conflict('Recovery work is already pending')
                interrupted={'analyzing':'analysis-failed','preparing':'preview-failed','applying':'interrupted','undoing':'undo-interrupted'}
                self.save(plan,status=interrupted.get(plan['status'],plan['status']),work_job=None)
            if operation=='preview':
                if plan['status'] not in ('ready','reviewed','preview-failed'):raise Conflict('Analyze a new plan before changing its selection')
                if not isinstance(value,dict) or set(value)-{'items','edits'}:raise Conflict('Invalid recovery selection')
                selected=value.get('items');edits=value.get('edits',{})
                if not isinstance(selected,list) or not selected or len(selected)>10000 or any(not isinstance(v,str) for v in selected) or len(set(selected))!=len(selected):raise Conflict('Select recovery actions to review')
                if not isinstance(edits,dict) or set(edits)-set(selected):raise Conflict('Invalid database edits')
                items={item['id']:item for item in self.items(plan)}
                if set(selected)-items.keys():raise AccessDenied('Recovery selection belongs to another plan')
                chosen=[items[key] for key in selected];self.require(context,chosen)
                # A failed attempt to revise a database edit must never leave
                # an older approval usable against newly written candidate data.
                self.save(plan,status='preview-failed',revision=uuid.uuid4().hex,error='Review preparation did not finish')
                for item in chosen:
                    if item['status']=='blocked':raise Conflict('A selected action has no validated replacement')
                    if item['action']=='database':
                        edit=edits.get(item['id'])
                        if not isinstance(edit,dict) or set(edit)!={'find','replace'} or not item['detail']['editable']:raise Conflict('Database changes require an exact reviewed fragment and primary key')
                        before=self.artifact(plan,item['id'],'db-before').read_bytes()
                        if hashlib.sha256(before).hexdigest()!=item['detail']['sha256']:raise Conflict('Database evidence changed')
                        after=db_replacement(before,edit['find'],edit['replace']);write(self.artifact(plan,item['id'],'db-after'),after)
                        self.save_item(item,detail=item['detail']|dict(after_sha256=hashlib.sha256(after).hexdigest(),preview=preview(before,after)))
                self.save(plan,selection=selected)
            else:
                allowed={'apply':('reviewed','interrupted'),'undo':('applied','interrupted','undo-interrupted','undone')}
                if operation not in allowed or plan['status'] not in allowed[operation]:raise Conflict('Recovery action is not ready')
                self.require(context,self.selected(plan),undo=operation=='undo')
            site=dict(owner=plan['owner'],identity=plan['identity'],domain=plan['domain'],root=plan['root'])
            job=self.store.enqueue(context,site,plan['target'],source='wordpress-recovery-'+operation,generation=generation(self.settings))
            self.save(plan,status={'preview':'preparing','apply':'applying','undo':'undoing'}[operation],work_job=job,error=None)
            self.store.audit(context,'wordpress.recovery_'+operation+'_queued',plan_id,dict(job_id=job,selected=len(plan['selection'])))
            return dict(plan_id=plan_id,jobs=[job])

    def repair_source(self,context,finding,item_id):
        with self.store.connection() as db:row=db.execute('SELECT plan_id,detail,action FROM wordpress_recovery_items WHERE id=?',(item_id,)).fetchone()
        if not row or row['action']!='replace':raise AccessDenied('Recovery replacement unavailable')
        plan=self.get(context,row['plan_id']);detail=json.loads(row['detail'])
        if detail['finding_id']!=finding['id'] or item_id not in plan['selection']:raise AccessDenied('Recovery replacement does not match this finding')
        return dict(kind='recovery-package',plan_id=plan['id'],item_id=item_id)

    def replacement(self,context,finding,source):
        verified=self.repair_source(context,finding,source['item_id'])
        if verified!=source:raise AccessDenied('Recovery source changed')
        plan=self.get(context,source['plan_id']);item=next(item for item in self.items(plan) if item['id']==source['item_id'])
        content=self.artifact(plan,item['id'],'replacement').read_bytes();provenance=item['detail']['replacement']
        if hashlib.sha256(content).hexdigest()!=provenance['sha256']:raise Conflict('Recovery replacement changed')
        return content,provenance

    def claim_preview(self,plan,context,item,job,engines):
        repair_id=self.repairs.queue(context,item['detail']['finding_id'],recovery=item['id'])
        self.save_item(item,detail=item['detail']|{'repair_id':repair_id})
        repair=self.repairs.get(context,repair_id)
        if repair['status']=='queued':
            with self.store.connection(True) as db:
                db.execute("UPDATE jobs SET status='running',worker=?,started=?,heartbeat=? WHERE id=? AND status='queued'",(job['worker'],time.time(),time.time(),repair_id))
            child=self.store.job(context,repair_id)
            if child['worker']!=job['worker']:raise Conflict('Replacement preview belongs to another worker')
            self.repairs.prepare(child,engines);repair=self.repairs.get(context,repair_id)
        if repair['status']!='ready':raise Conflict(repair['error'] or 'Replacement preview is not ready')
        # The repair already retains its full diff. Avoid duplicating every
        # large diff in the batch inventory loaded for mutation/recovery.
        summary={key:value for key,value in repair['metadata']['preview'].items() if key!='diff'}
        self.save_item(item,status='prepared',detail=item['detail']|dict(preview=summary))

    def preflight(self,plan,context,items,*,allow_applied=False):
        for item in items:
            if allow_applied and item['status']=='applying':continue
            if allow_applied and item['status']=='done':
                if item['action']=='replace':
                    repair=self.repairs.get(context,item['detail']['repair_id'])
                    if not self.repairs.target_matches(repair,repair['metadata']['replacement_fingerprint']):raise Conflict('A completed replacement changed; inspect it before resuming')
                elif item['action']=='quarantine':absence(plan['root'],item['path'])
                else:
                    after=self.artifact(plan,item['id'],'db-after').read_bytes()
                    WordPressDatabase(self.settings,self.hestia,context,plan['root'],item['detail']['installation']).change(item['detail'],after,after,inspect_only=True)
                continue
            if item['action']=='database':
                before=self.artifact(plan,item['id'],'db-before').read_bytes();after=self.artifact(plan,item['id'],'db-after').read_bytes()
                if hashlib.sha256(before).hexdigest()!=item['detail']['sha256'] or hashlib.sha256(after).hexdigest()!=item['detail']['after_sha256']:raise Conflict('Database recovery evidence changed')
                WordPressDatabase(self.settings,self.hestia,context,plan['root'],item['detail']['installation']).change(item['detail'],before,after,inspect_only=True)
            else:
                finding=self.store.finding(context,item['detail']['finding_id']);self.quarantine.validate_site(context,finding)
                expected={key:value for key,value in finding['fingerprint'].items() if key!='wordpress'}
                actual=absence(plan['root'],item['path']) if expected.get('missing') else None
                if actual is None:
                    with snapshot(plan['root'],item['path'],self.settings.snapshots,self.settings.max_file_bytes) as (_,actual):pass
                if expected!=actual:raise Conflict('A selected file changed after analysis: '+item['path'])

    def work(self,job,engines):
        # Match the HTTP analysis guard's lock order: delegation, then recovery.
        # Reversing this order can deadlock an analysis request and revocation.
        with WebsitePermissions(self.settings,self.store,self.hestia).locked(),self.locked():
            with self.store.connection() as db:row=db.execute('SELECT id FROM wordpress_recovery WHERE work_job=?',(job['id'],)).fetchone()
            if not row:raise AccessDenied('Recovery work unavailable')
            plan=self.get(job,row['id']);context=self.context(plan,actor=job['actor'])
            if job['source']=='wordpress-recovery':
                WebsitePermissions(self.settings,self.store,self.hestia).require(context,'scan')
                return self.inspect(job,engines)
            operation=job['source'].removeprefix('wordpress-recovery-');items=self.selected(plan)
            counters=dict(seen=len(items),scanned=0,infected=0,detections=0,skipped=0,errors=0,bytes=0)
            try:
                self.require(context,items,undo=operation=='undo')
                if operation!='undo':self.preflight(plan,context,items,allow_applied=operation=='apply')
                if operation=='preview':
                    for item in items:
                        self.check_cancel(job)
                        if item['action']=='replace':self.claim_preview(plan,context,item,job,engines)
                        else:self.save_item(item,status='prepared')
                        counters['scanned']+=1;self.store.progress(job['id'],counters)
                    self.save(plan,status='reviewed',revision=uuid.uuid4().hex,work_job=None)
                else:
                    for item in reversed(items) if operation=='undo' else items:
                        self.check_cancel(job);self.context(plan,actor=context['actor'])
                        if (operation=='apply' and item['status']=='done') or (operation=='undo' and item['status'] in ('undone','proposed','prepared')):continue
                        self.perform(plan,context,item,undo=operation=='undo')
                        counters['scanned']+=1;self.store.progress(job['id'],counters)
                    site=dict(owner=plan['owner'],identity=plan['identity'],domain=plan['domain'],root=plan['root'])
                    checks=[self.store.enqueue(context,site,plan['target'],source=source,generation=generation(self.settings)) for source in ('wordpress-integrity','wordpress-recovery-recheck')]
                    self.save(plan,status='undone' if operation=='undo' else 'applied',work_job=None,
                              report=plan['report']|dict(recheck_jobs=checks),revision=uuid.uuid4().hex)
                self.store.audit(context,'wordpress.recovery_'+operation,plan['id'],dict(selected=len(items),completed=counters['scanned']))
                self.store.finish(job,'completed',counters)
            except (OSError,ClamShieldError) as exc:
                counters['errors']+=1;message=self.message(exc)
                self.save(plan,status={'preview':'preview-failed','apply':'interrupted','undo':'undo-interrupted'}.get(operation,'interrupted'),error=message,work_job=None,revision=uuid.uuid4().hex)
                self.store.finish(job,'failed',counters,message)

    def perform(self,plan,context,item,undo=False):
        detail=item['detail']
        # Commit intent before calling a mutator. Resume inspects its durable
        # journal/current content instead of blindly repeating a write.
        if item['action']=='replace':
            repair=self.repairs.get(context,detail['repair_id'])
            if repair['status'] in ('applying','undoing','recovery_required'):
                self.repairs.recover(context,repair['id']);repair=self.repairs.get(context,repair['id'])
            self.save_item(item,status='undoing' if undo else 'applying')
            if undo:
                if repair['status']=='ready':pass  # Intent was saved but publication never began.
                elif repair['status']=='failed':
                    original=repair['metadata'].get('recovery_fingerprint',repair['metadata'].get('fingerprint',{}))
                    if not self.repairs.target_matches(repair,original):raise Conflict('Interrupted repair original needs review')
                elif repair['status']!='undone':self.repairs.undo(context,repair['id'])
            elif repair['status']=='ready':self.repairs.apply(context,repair['id'])
            elif repair['status'] in ('repaired','verified','recheck_failed'):
                if not self.repairs.target_matches(repair,repair['metadata']['replacement_fingerprint']):raise Conflict('Completed replacement changed before recovery could be confirmed')
            else:raise Conflict('Interrupted replacement needs a fresh preview or undo')
        elif item['action']=='quarantine':
            operation=detail.get('operation_id')
            if operation:
                with self.store.connection() as db:record=db.execute('SELECT status FROM operations WHERE id=? AND owner=? AND identity=?',(operation,*self.store.scope(context))).fetchone()
                if record is None:
                    if not undo:self.quarantine.capture(context,detail['finding_id'],operation_id=operation,extra={'wordpress_recovery':plan['id']})
                    self.save_item(item,status='undone' if undo else 'done');return
                row=self.quarantine.recover(context,operation)
                if undo:
                    self.save_item(item,status='undoing')
                    if row['status']!='restored':self.quarantine.restore(context,operation)
                elif row['status']=='failed':
                    operation=uuid.uuid4().hex;self.save_item(item,detail=detail|{'operation_id':operation})
                    self.quarantine.capture(context,detail['finding_id'],operation_id=operation,extra={'wordpress_recovery':plan['id']})
                elif row['status']=='quarantined':absence(plan['root'],item['path'])
                else:raise Conflict('Interrupted quarantine needs review before continuing')
            elif not undo:
                operation=uuid.uuid4().hex;detail=detail|{'operation_id':operation}
                self.save_item(item,status='applying',detail=detail)
                self.quarantine.capture(context,detail['finding_id'],operation_id=operation,extra={'wordpress_recovery':plan['id']})
        else:
            before=self.artifact(plan,item['id'],'db-before').read_bytes();after=self.artifact(plan,item['id'],'db-after').read_bytes()
            if hashlib.sha256(before).hexdigest()!=detail['sha256'] or hashlib.sha256(after).hexdigest()!=detail['after_sha256']:raise Conflict('Database recovery evidence changed')
            self.save_item(item,status='undoing' if undo else 'applying')
            WordPressDatabase(self.settings,self.hestia,context,plan['root'],detail['installation']).change(detail,after if undo else before,before if undo else after)
        self.save_item(item,status='undone' if undo else 'done')

    def status(self,context,plan_id,offset=0):
        plan=self.get(context,plan_id)
        if type(offset) is not int or not 0<=offset<=10000:raise AccessDenied('Invalid recovery page')
        items=self.items(plan);work=self.store.job(context,plan['work_job']) if plan['work_job'] else None
        if work and work['status'] not in ('queued','running'):
            interrupted={'analyzing':'analysis-failed','preparing':'preview-failed','applying':'interrupted','undoing':'undo-interrupted'}
            # Expose interrupted worker state without changing evidence in a read.
            plan=plan|dict(status=interrupted.get(plan['status'],plan['status']),error=work.get('error') or 'Recovery worker stopped; review or resume retained work')
        pages=[];page_bytes=0
        for item in items[offset:offset+100]:
            detail=item['detail']
            public={key:detail[key] for key in ('reason','recommended','error','detections','replacement','preview','excerpt','evidence','editable','table','column','installation') if key in detail}
            if detail.get('repair_id'):public['preview']=self.repairs.get(context,detail['repair_id'])['metadata'].get('preview',detail.get('preview',{}))
            entry=dict(id=item['id'],path=item['path'],kind=item['kind'],action=item['action'],status=item['status'],selected=item['id'] in plan['selection'],detail=public)
            amount=len(encode(entry).encode())
            if pages and page_bytes+amount>2*1024**2:break
            pages.append(entry);page_bytes+=amount
        checks=[self.store.job(context,key) for key in plan['report'].get('recheck_jobs',[])]
        return dict(plan={key:plan[key] for key in ('id','domain','target','created','status','revision','options','report','error')},items=pages,total=len(items),
                    recommended=[item['id'] for item in items if item['detail'].get('recommended') and item['status']!='blocked'],selection=plan['selection'],
                    next_offset=offset+len(pages) if offset+len(pages)<len(items) else None,
                    work={key:work[key] for key in ('id','status','counters','error')} if work else None,
                    rechecks=[{key:check[key] for key in ('id','source','status','counters','error')} for check in checks])

    def list(self,context):
        with self.store.connection() as db:rows=db.execute('SELECT id,domain,target,status,created FROM wordpress_recovery WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 50',self.store.scope(context)).fetchall()
        return [dict(row) for row in rows]
