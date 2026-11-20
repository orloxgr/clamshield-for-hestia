"""Server event expiry and terminal maintenance compaction with recovery guards."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat
import time
import uuid

from .errors import AccessDenied, ClamShieldError, Conflict
from .history_retention import HistoryRetention
from .store import encode

DEFAULTS = dict(event_days=0, maintenance_days=0)
ANCHORS = ('signatures.catalog_migrated', 'mail.refresh_rebased')
JOURNALS = ('install-pending.json','uninstall.json','signature-activation.json',
            'resources-activation.json','website-engine-activation.json',
            'spamassassin-activation.json','mail-integration-journal.json')


def validate(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULTS) or any(type(v) is not int or not 0<=v<=3650 for v in value.values()):
        raise ClamShieldError('Choose whole server retention periods from 0 to 3650 days; zero keeps history indefinitely')
    return dict(value)


class ServerHistory:
    def __init__(self,settings,store,hestia):
        self.settings,self.store,self.hestia=settings,store,hestia
        self.account=HistoryRetention(settings,store,hestia)

    def admin(self,context):
        context=self.account.custody.authorize(context)
        if not context['admin']:raise AccessDenied('Administrator access required')
        return context

    def snapshot(self,db):
        row=db.execute('SELECT * FROM server_history_retention WHERE id=1').fetchone()
        return dict(row) if row else None

    @contextmanager
    def maintenance_lock(self):
        self.settings.prepare()
        fd=os.open(self.settings.state/'maintenance.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o022:
                raise AccessDenied('Maintenance exclusion lock is not trusted')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
        finally:os.close(fd)

    def pending(self,db):
        if any((self.settings.state/name).exists() or (self.settings.state/name).is_symlink() for name in JOURNALS):
            return 'History pruning waits for pending installation or service recovery'
        if db.execute("SELECT 1 FROM maintenance WHERE status IN ('queued','running') LIMIT 1").fetchone():
            return 'History pruning waits for queued or active maintenance'
        return None

    def tasks_query(self):
        # Keep the latest terminal record for each action and all task IDs. A
        # completed record is never made queued again by history compaction.
        return ''' FROM maintenance m WHERE m.finished IS NOT NULL AND m.finished<?
          AND m.status IN ('completed','failed')
          AND COALESCE(json_extract(m.result,'$.history_expired'),0)=0
          AND EXISTS(SELECT 1 FROM maintenance n WHERE n.action=m.action AND n.status IN ('completed','failed')
            AND (n.finished>m.finished OR (n.finished=m.finished AND n.id>m.id)))
          AND NOT EXISTS(SELECT 1 FROM jobs j WHERE instr(j.counters,m.id)>0)
          AND NOT EXISTS(SELECT 1 FROM repair_plans p WHERE instr(p.metadata,m.id)>0)
          AND NOT EXISTS(SELECT 1 FROM operations o WHERE instr(o.metadata,m.id)>0)
          AND NOT EXISTS(SELECT 1 FROM remediation_actions a WHERE instr(a.detail,m.id)>0)'''

    def events_query(self,table,alias):
        query=self.account.events_query(table,alias)
        if table=='audit':query+=' AND '+alias+'.action NOT IN (?,?)'
        return query

    def counts(self,policy,db,now):
        result=dict(server_events=0,read_server_notifications=0,maintenance_details=0)
        blocked=self.pending(db)
        if blocked:return result,blocked
        if policy['event_days']:
            values=('@admin','',now-policy['event_days']*86400)
            result['server_events']=db.execute('SELECT COUNT(*)'+self.events_query('audit','a'),(*values,*ANCHORS)).fetchone()[0]
            result['read_server_notifications']=db.execute('SELECT COUNT(*)'+self.events_query('notifications','n'),values).fetchone()[0]
        if policy['maintenance_days']:
            result['maintenance_details']=db.execute('SELECT COUNT(*)'+self.tasks_query(),(now-policy['maintenance_days']*86400,)).fetchone()[0]
        return result,None

    def get(self,context,proposed=None):
        self.admin(context)
        with self.store.connection() as db:
            saved=self.snapshot(db);policy=validate(json.loads(saved['settings'])) if saved else dict(DEFAULTS)
            summary,blocked=self.counts(policy if proposed is None else validate(proposed),db,time.time())
        return dict(policy=policy,revision=saved['revision'] if saved else 'default',preview=summary,
                    blocked=blocked,last_run=saved['last_run'] if saved else None,error=saved['error'] if saved else None)

    def save(self,context,value,revision,*,reset=False):
        policy=dict(DEFAULTS) if reset else validate(value)
        with self.account.locked(),self.store.connection(True) as db:
            context=self.admin(context);saved=self.snapshot(db)
            if not isinstance(revision,str) or revision!=(saved['revision'] if saved else 'default'):
                raise Conflict('Server history retention changed. Preview it again before saving.')
            if reset:db.execute('DELETE FROM server_history_retention WHERE id=1')
            else:
                authority=dict(actor=context['actor'],actor_identity=self.hestia.identity(context['actor']))
                db.execute('''INSERT INTO server_history_retention VALUES(1,?,?,?,?,0,NULL) ON CONFLICT(id)
                  DO UPDATE SET settings=excluded.settings,updated=excluded.updated,revision=excluded.revision,authority=excluded.authority,error=NULL''',
                  (encode(policy),time.time(),uuid.uuid4().hex,encode(authority)))
            self.store.audit(dict(actor=context['actor'],owner='@admin',identity=''),
                'history.server_reset' if reset else 'history.server_saved','server',policy,db)
        return self.get(context)

    def authority(self,saved):
        who=json.loads(saved['authority']);context=self.hestia.authorize(who['actor'],who['actor'])
        if not context['admin'] or self.hestia.identity(who['actor'])!=who['actor_identity']:
            raise AccessDenied('Server history authorizing administrator changed; save the policy again')

    def prune(self,policy,db,now):
        result=dict(server_events=0,read_server_notifications=0,maintenance_details=0)
        if policy['event_days']:
            for table,alias,key in (('audit','a','server_events'),('notifications','n','read_server_notifications')):
                values=('@admin','',now-policy['event_days']*86400)
                if table=='audit':values+=ANCHORS
                result[key]=db.execute('DELETE FROM '+table+' WHERE id IN (SELECT '+alias+'.id'+self.events_query(table,alias)+' ORDER BY '+alias+'.created,'+alias+'.id LIMIT 200)',values).rowcount
        if policy['maintenance_days']:
            rows=db.execute('SELECT m.*'+self.tasks_query()+' ORDER BY m.finished,m.id LIMIT 100',(now-policy['maintenance_days']*86400,)).fetchall()
            for row in rows:
                receipt=dict(history_expired=True,
                    payload_sha256=hashlib.sha256(row['payload'].encode()).hexdigest(),
                    result_sha256=hashlib.sha256((row['result'] or '').encode()).hexdigest(),
                    error_sha256=hashlib.sha256((row['error'] or '').encode()).hexdigest())
                db.execute('UPDATE maintenance SET payload=?,result=?,error=? WHERE id=? AND status=?',
                    ('{}',encode(receipt),'Detailed maintenance history expired' if row['error'] else None,row['id'],row['status']))
                result['maintenance_details']+=1
        return result

    def once(self):
        previous=self.hestia.deadline
        saved=None
        self.hestia.deadline=min(previous,time.monotonic()+5) if previous is not None else time.monotonic()+5
        try:
            with self.account.locked(False),self.maintenance_lock(),self.store.connection(True) as db:
                saved=self.snapshot(db)
                if not saved:return dict(server_history_configured=False)
                self.authority(saved);policy=validate(json.loads(saved['settings']));blocked=self.pending(db)
                if blocked:return dict(server_history_deferred=blocked)
                result=self.prune(policy,db,time.time())
                db.execute('UPDATE server_history_retention SET last_run=?,error=NULL WHERE id=1',(time.time(),))
                if any(result.values()):self.store.audit(dict(actor='clamshield-history',owner='@admin',identity=''),'history.server_pruned','server',result,db)
                return result
        except BlockingIOError:return dict(server_history_busy=True)
        except (OSError,ValueError,KeyError,ClamShieldError):
            if saved:
                with self.store.connection(True) as db:
                    db.execute('UPDATE server_history_retention SET error=? WHERE id=1 AND revision=?',('Server history retained because authority or recovery references need review',saved['revision']))
            return dict(server_history_blocked=True)
        finally:self.hestia.deadline=previous
