"""Scoped automatic website actions with durable discovery and revocable intent."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat
import time
import uuid

from .errors import AccessDenied,ClamShieldError,Conflict
from .exceptions import Exceptions
from .generations import current as generation
from .paths import directory
from .quarantine import Quarantine
from .repairs import Repairs
from .store import encode
from .website_permissions import WebsitePermissions,MODE_REQUIREMENTS
from .website_generation import advisory_kind
from .rule_sources import finding_supported

MODES=('report','quarantine','cleanup','cleanup-or-quarantine')
SOURCES=('manual','scheduled','watch','watch-initial')
PENDING=('queued','preparing','applying','verifying')


class Remediation:
    def __init__(self,settings,store,hestia):self.settings,self.store,self.hestia=settings,store,hestia

    @contextmanager
    def locked(self,blocking=True):
        self.settings.prepare();fd=os.open(self.settings.state/'remediation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as lock:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise AccessDenied('Unsafe remediation lock')
            fcntl.flock(lock,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB));yield

    def native(self,context,domain=None):
        live=self.hestia.authorize(context['actor'],context['owner'])
        if live['identity']!=context['identity']:raise AccessDenied('Remediation account was replaced')
        if domain is None:return None
        site=next((row for row in self.hestia.sites(context['owner']) if row['domain']==domain and not row['suspended']),None)
        if not site:raise AccessDenied('Remediation website is unavailable')
        with directory(site['root']) as fd:
            info=os.fstat(fd);binding=dict(path=site['root'],device=info.st_dev,inode=info.st_ino)
        return site,binding

    def saved(self,context,domain):
        with self.store.connection() as db:row=db.execute('SELECT * FROM remediation_policies WHERE owner=? AND identity=? AND domain=?',(*self.store.scope(context),domain)).fetchone()
        return dict(row)|{'settings':json.loads(row['settings'])} if row else None

    def account_policy(self,context,local=None):
        local=self.saved(context,'') if local is None else local
        common=self.saved(dict(owner='@server',identity=''),'')
        if not local:return common
        if local['settings']['mode']!='inherit':return local
        if not common:return dict(local,settings=dict(local['settings'],mode='report'))
        return dict(common,updated=max(local['updated'],common['updated']),
                    revision=hashlib.sha256(encode([local['revision'],common['revision']]).encode()).hexdigest())

    def resolve(self,site,account,specific,permissions):
        with directory(site['root']) as fd:
            info=os.fstat(fd);root=dict(path=site['root'],device=info.st_dev,inode=info.st_ino)
        mode=account['settings']['mode'] if account else 'report';updated=account['updated'] if account else 0
        revisions=[account['revision'] if account else 'default'];controller=account
        if specific:
            revisions.append(specific['revision']);updated=max(updated,specific['updated'])
            if specific['settings']['root']!=root:mode='report'
            elif specific['settings']['mode']!='inherit':mode=specific['settings']['mode'];controller=specific
        authority=controller['settings'].get('authority','account') if controller else 'account'
        requested=mode;blocked=None
        if authority!='administrator':
            revisions.append(permissions['revision']);updated=max(updated,permissions['updated'])
            if any(not permissions['permissions'][key] for key in MODE_REQUIREMENTS[mode]):
                mode='report';blocked='Automatic action is disabled by the administrator'
        token=hashlib.sha256(encode(dict(root=root,revisions=revisions,mode=mode)).encode()).hexdigest()
        return dict(mode=mode,revision=token,updated=updated,root=root,requested_mode=requested,authority=authority,blocked_reason=blocked)

    def effective(self,context,domain):
        site,_=self.native(context,domain)
        return self.resolve(site,self.account_policy(context),self.saved(context,domain),WebsitePermissions(self.settings,self.store,self.hestia).snapshot(context)),site

    def site_policies(self,context,sites):
        """Use the caller's freshly authorized inventory once for display."""
        self.native(context)
        with self.store.connection() as db:
            saved={row['domain']:dict(row)|{'settings':json.loads(row['settings'])} for row in db.execute('SELECT * FROM remediation_policies WHERE owner=? AND identity=?',self.store.scope(context))}
        permissions=WebsitePermissions(self.settings,self.store,self.hestia).snapshot(context)
        account=self.account_policy(context,saved.get(''))
        for site in sites:
            try:
                if site['suspended']:raise AccessDenied('Remediation website is suspended')
                specific=saved.get(site['domain'])
                site['remediation']=dict(site=dict(mode=specific['settings']['mode'] if specific else 'inherit'),effective=self.resolve(site,account,specific,permissions))
            except (OSError,ClamShieldError):site['remediation']={'error':'Automatic policy unavailable; actions require review'}

    def policy(self,context,domain=None,server=False):
        self.native(context)
        if server and not context['admin']:raise AccessDenied('Administrator access required')
        account=self.saved(dict(owner='@server',identity='') if server else context,'')
        common=self.account_policy(context) if not server else account
        result=dict(account=dict(mode=account['settings']['mode'] if account else ('inherit' if common else 'report'),
                                 effective_mode=common['settings']['mode'] if common else 'report',revision=account['revision'] if account else None))
        if domain is not None:
            effective,_=self.effective(context,domain);saved=self.saved(context,domain)
            result.update(site=dict(mode=saved['settings']['mode'] if saved else 'inherit'),effective=effective)
        return result

    def save(self,context,policy,domain=None,server=False):
        if not isinstance(policy,dict) or set(policy)!={'mode'} or not isinstance(policy['mode'],str) or policy['mode'] not in MODES+(('inherit',) if not server else ()):
            raise ClamShieldError('Choose a supported automatic remediation mode')
        permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        with permissions.locked(),self.locked():
            live=permissions.require(context,'automatic')
            if server and not live['admin']:raise AccessDenied('Administrator access required')
            selected=policy['mode']
            if selected=='inherit':selected=self.account_policy(context)['settings']['mode'] if self.account_policy(context) else 'report'
            if not live['admin']:
                for key in MODE_REQUIREMENTS[selected]:permissions.require(context,key)
            result=self.native(context,domain);settings=dict(policy,authority='administrator' if live['admin'] else 'account')
            if result:settings['root']=result[1]
            now=time.time();revision=uuid.uuid4().hex
            with self.store.connection(True) as db:
                scope=('@server','') if server else self.store.scope(context)
                db.execute('INSERT INTO remediation_policies VALUES(?,?,?,?,?,?) ON CONFLICT(owner,identity,domain) DO UPDATE SET settings=excluded.settings,updated=excluded.updated,revision=excluded.revision',(*scope,domain or '',encode(settings),now,revision))
                self.store.audit(dict(context,owner='@admin',identity='') if server else context,'automatic.policy_saved',domain or ('server' if server else 'account'),dict(policy,revision=revision),db)
        return self.policy(context,domain,server)

    def discover(self,job_id=None):
        with self.store.connection() as db:
            query="SELECT j.* FROM jobs j LEFT JOIN remediation_scans r ON r.job_id=j.id WHERE j.status='completed' AND j.cancel_requested=0 AND COALESCE(r.finished,0)=0 AND j.source IN ("+','.join('?' for _ in SOURCES)+')'
            values=list(SOURCES)
            if job_id is not None:query+=' AND j.id=?';values.append(job_id)
            jobs=[dict(row) for row in db.execute(query+' ORDER BY j.finished LIMIT 20',values)]
        for job in jobs:
            context=dict(actor=job['owner'],owner=job['owner'],identity=job['identity'])
            try:
                policy,site=self.effective(context,job['domain'])
                eligible=policy['mode']!='report' and policy['updated']<=job['created'] and job['root']==site['root'] and job['finished']>=time.time()-86400 and generation(self.settings)==job['generation']
            except (OSError,ClamShieldError):eligible=False
            with self.store.connection(True) as db:
                db.execute('INSERT OR IGNORE INTO remediation_scans(job_id) VALUES(?)',(job['id'],))
                cursor=db.execute('SELECT cursor FROM remediation_scans WHERE job_id=?',(job['id'],)).fetchone()[0]
                rows=db.execute("SELECT * FROM file_results WHERE job_id=? AND id>? AND status='infected' ORDER BY id LIMIT 50",(job['id'],cursor)).fetchall() if eligible else []
                for result in rows:
                    data=json.loads(result['detail'])
                    candidates=db.execute("SELECT * FROM findings WHERE job_id=? AND path=? AND status='open' AND engine IN ('clamav','yara') AND COALESCE(json_extract(detail,'$.review_only'),0)!=1 ORDER BY created,id",(job['id'],result['path'])).fetchall()
                    finding=next((v for v in candidates if finding_supported(v) and (v['engine']!='clamav' or not advisory_kind(json.loads(v['detail'])))),None)
                    from .yara_settings import YaraSettings
                    required={'clamav','yara'} if YaraSettings(self.settings).read()['enabled'] else {'clamav'}
                    if finding and not data.get('failures') and set(data.get('engines',[]))==required:
                        fp=json.loads(finding['fingerprint'])
                        if fp.get('sha256')==data.get('sha256') and fp.get('links')==1:
                            action=uuid.uuid4().hex;now=time.time()
                            changed=db.execute('INSERT OR IGNORE INTO remediation_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                                (action,*self.store.scope(context),context['actor'],job['id'],finding['id'],result['path'],'queued',now,now,encode(dict(policy=policy)),None)).rowcount
                            if changed:self.store.audit(context,'automatic.queued',action,dict(job_id=job['id'],path=result['path'],mode=policy['mode']),db)
                db.execute('UPDATE remediation_scans SET cursor=?,finished=? WHERE job_id=?',(rows[-1]['id'] if rows else cursor,int(len(rows)<50),job['id']))
        return len(jobs)

    def get(self,context,action_id):
        with self.store.connection() as db:row=db.execute(self.history_query()+' WHERE a.id=? AND a.owner=? AND a.identity=?',(action_id,*self.store.scope(context))).fetchone()
        if not row:raise AccessDenied('Automatic action unavailable')
        return dict(row)|{'detail':json.loads(row['detail'])}

    @staticmethod
    def history_query():
        # Keep the action's historical result and show subsequent restore/undo
        # separately. Never offer Restore again for an already restored object.
        return '''SELECT a.*,j.domain,j.root,o.status AS operation_status,p.status AS plan_status
            FROM remediation_actions a
            LEFT JOIN jobs j ON j.id=a.job_id AND j.owner=a.owner AND j.identity=a.identity
            LEFT JOIN operations o ON o.id=json_extract(a.detail,'$.operation_id') AND o.owner=a.owner AND o.identity=a.identity
            LEFT JOIN repair_plans p ON p.id=json_extract(a.detail,'$.plan_id') AND p.owner=a.owner AND p.identity=a.identity'''

    def history(self,context):
        self.native(context)
        with self.store.connection() as db:rows=db.execute(self.history_query()+' WHERE a.owner=? AND a.identity=? ORDER BY a.created DESC LIMIT 200',self.store.scope(context)).fetchall()
        return [dict(row)|{'detail':json.loads(row['detail'])} for row in rows]

    def update(self,row,status,error=None):
        with self.store.connection(True) as db:
            db.execute('UPDATE remediation_actions SET status=?,detail=?,updated=?,error=? WHERE id=?',(status,encode(row['detail']),time.time(),error,row['id']))
            if status!=row['status'] or error!=row['error']:
                self.store.audit(row,'automatic.'+status,row['id'],dict(path=row['path'],mode=row['detail']['policy']['mode'],error=error),db)
                if status in ('quarantined','cleaned','needs_review','cancelled'):
                    self.store.notify(row['owner'],row['identity'],'automatic.'+status,row['path'],dict(action_id=row['id'],error=error),row['id']+':'+status,db)
        row.update(status=status,error=error)

    def cancel(self,context,action_id):
        with self.locked():
            self.native(context);row=self.get(context,action_id)
            if row['status'] not in ('queued','preparing'):raise Conflict('Action already started; use restore or undo after recovery')
            self.update(row,'cancelled','Cancelled by the account')
        return {'cancelled':True}

    def validate(self,row):
        context={key:row[key] for key in ('actor','owner','identity')}
        job=self.store.job(context,row['job_id']);policy,site=self.effective(context,job['domain'])
        if policy['revision']!=row['detail']['policy']['revision'] or policy['mode']=='report':raise Conflict('Automatic policy or website root changed')
        if job['status']!='completed' or self.store.cancelled(job['id']) or job['root']!=site['root'] or job['generation']!=generation(self.settings) or row['created']<time.time()-86400:
            raise Conflict('Scan coverage expired, changed or was cancelled; scan again')
        finding=self.store.finding(context,row['finding_id'])
        if not finding_supported(finding):raise Conflict('Finding belongs to a removed rule source; scan again with current rules')
        if finding['detail'].get('review_only') is True or finding['engine']=='clamav' and advisory_kind(finding['detail']):
            raise Conflict('Finding requires manual review')
        if finding['status']!='open':raise Conflict('Finding was handled or excepted')
        visible,_=Exceptions(self.store).filter(job,finding['path'],finding['fingerprint'],[finding['detail']])
        if not visible:raise Conflict('A current exception suppresses this detection')
        return context,finding

    def quarantine(self,row,context):
        operation=row['detail'].setdefault('operation_id',uuid.uuid4().hex);self.update(row,'applying')
        q=Quarantine(self.settings,self.store,self.hestia)
        try:record=q.get(context,operation)
        except AccessDenied:q.capture(context,row['finding_id'],operation_id=operation,extra=dict(automatic_action=row['id']));record=q.get(context,operation)
        if record['status'] in ('prepared','recovery_required'):record=q.recover(context,operation)
        if record['status']!='quarantined':raise Conflict('Quarantine operation requires review')
        self.update(row,'quarantined')

    def perform(self,row):
        context={key:row[key] for key in ('actor','owner','identity')};detail=row['detail'];repairs=Repairs(self.settings,self.store,self.hestia)
        self.native(context)
        # Once publication began, reconcile its durable operation rather than
        # initiating a second mutation or losing track after policy revocation.
        if row['status']=='applying' and detail.get('operation_id'):
            q=Quarantine(self.settings,self.store,self.hestia)
            try:operation=q.get(context,detail['operation_id'])
            except AccessDenied:operation=None
            if operation:
                if operation['status'] in ('prepared','recovery_required'):operation=q.recover(context,operation['id'])
                if operation['status']=='quarantined':self.update(row,'quarantined');return
                raise Conflict('Interrupted quarantine needs review')
        plan=repairs.get(context,detail['plan_id']) if detail.get('plan_id') else None
        if plan and row['status'] in ('applying','verifying'):
            if plan['status']=='verified':self.update(row,'cleaned');return
            if plan['status']=='repaired':self.update(row,'verifying');return
            if plan['status']=='undone':self.update(row,'undone');return
            if plan['status'] in ('applying','undoing','recovery_required'):raise Conflict('Cleaning recovery needs review')
            raise Conflict('Cleaning recheck did not verify the result')
        context,finding=self.validate(row)
        mode=detail['policy']['mode']
        if mode=='quarantine':self.quarantine(row,context);return
        if plan is None:
            detail['plan_id']=repairs.queue(context,finding['id'],cleanup=True);self.update(row,'preparing');return
        if plan['status']=='queued':return
        if plan['status']=='failed':
            if mode=='cleanup-or-quarantine' and plan['metadata'].get('failure_kind')=='unsupported-cleanup':
                detail['fallback']='unsupported-cleanup';self.quarantine(row,context);return
            raise Conflict(plan['error'] or 'Cleaning preview failed')
        if plan['status']!='ready':raise Conflict('Cleaning plan changed; review the file')
        self.update(row,'applying');repairs.apply(context,plan['id']);self.update(row,'verifying')

    def once(self):
        try:
            with WebsitePermissions(self.settings,self.store,self.hestia).locked(),self.locked(False):
                fd=os.open(self.settings.state/'worker.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'a+b'):
                    info=os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise AccessDenied('Unsafe worker lock')
                    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:return {'automatic_busy':True}
                    if any((self.settings.state/name).exists() for name in ('signature-activation.json','resources-activation.json','website-engine-activation.json')):return {'automatic_recovery_pending':True}
                    self.discover()
                    with self.store.connection() as db:rows=[dict(row) for row in db.execute("SELECT * FROM remediation_actions WHERE status IN ('queued','preparing','applying','verifying') ORDER BY updated,created LIMIT 10")]
                    for row in rows:
                        row['detail']=json.loads(row['detail'])
                        try:self.perform(row)
                        except (OSError,ClamShieldError) as exc:self.update(row,'needs_review',str(exc) if isinstance(exc,ClamShieldError) else 'Automatic action could not complete; inspect recovery')
                        # Waiting previews/rechecks must not starve newer actions.
                        with self.store.connection() as db:db.execute('UPDATE remediation_actions SET updated=? WHERE id=?',(time.time(),row['id']))
                    return {'automatic_examined':len(rows)}
        except BlockingIOError:return {'automatic_busy':True}
