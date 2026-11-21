"""Small native-generation-scoped queue snapshots and identity-bound cancellation."""
import json
import re
import time

from .errors import AccessDenied,ClamShieldError


class ScanStatus:
    def __init__(self,store,hestia,settings=None):
        from .settings import Settings
        self.store,self.hestia=store,hestia
        self.settings=settings or Settings(state=store.path.parent)

    def context(self,context,scope):
        live=self.hestia.authorize(context['actor'],context['owner'])
        if live['identity']!=context['identity']:raise AccessDenied('Scan account was replaced')
        if scope not in ('account','server'):raise ClamShieldError('Choose account or server scan scope')
        if scope=='server' and not live['admin']:raise AccessDenied('Administrator access required')
        return live

    def list(self,context,scope='account',search='',kind='all',offset=0,limit=100):
        context=self.context(context,scope)
        if not isinstance(search,str) or len(search)>300 or kind not in ('all','active') or type(offset) is not int or not 0<=offset<=10000000 or type(limit) is not int or limit not in (25,50,100):
            raise ClamShieldError('Invalid scan queue filter')
        from .review import visible
        where=' WHERE '+visible('scans')+(' AND r.owner=? AND r.identity=?' if scope=='account' else '')
        values=self.store.scope(context) if scope=='account' else ()
        with self.store.connection() as db:
            db.execute('BEGIN')
            summary=dict(db.execute("SELECT COUNT(*) AS recorded,COALESCE(SUM(status='queued'),0) AS queued,COALESCE(SUM(status='running'),0) AS running FROM jobs r"+where,values).fetchone())
            account_active=db.execute("SELECT COUNT(*) FROM jobs WHERE owner=? AND identity=? AND status IN ('queued','running')",self.store.scope(context)).fetchone()[0]
            filtered=where+" AND (instr(domain,?)>0 OR instr(target,?)>0 OR instr(owner,?)>0 OR instr(id,?)>0)"
            params=(*values,search,search,search,search)
            if kind=='active':filtered+=" AND status IN ('queued','running')"
            total=db.execute('SELECT COUNT(*) FROM jobs r'+filtered,params).fetchone()[0]
            offset=min(offset,max(0,((total-1)//limit)*limit))
            rows=db.execute('''SELECT id,owner,domain,target,source,status,cancel_requested,created,started,finished,
              heartbeat,counters,error FROM jobs r'''+filtered+" ORDER BY CASE status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,created DESC,id LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
        jobs=[dict(row)|dict(counters=json.loads(row['counters']),can_cancel=row['status'] in ('queued','running') and not row['cancel_requested']) for row in rows]
        from .scan_queue import ScanQueue
        ScanQueue(self.settings,self.store).describe(jobs,admin=context['admin'])
        return dict(jobs=jobs,total=total,summary=summary,account_active=account_active,scope=scope,offset=offset,limit=limit,
                    next_offset=offset+len(rows) if offset+len(rows)<total else None,checked=time.time())

    def cancel(self,context,job_id,scope='account'):
        context=self.context(context,scope)
        if not isinstance(job_id,str) or not re.fullmatch(r'[0-9a-f]{32}',job_id):raise AccessDenied('Scan unavailable')
        if scope=='server':
            with self.store.connection() as db:row=db.execute('SELECT owner,identity FROM jobs WHERE id=?',(job_id,)).fetchone()
            if not row:raise AccessDenied('Scan unavailable')
            live=self.hestia.authorize(context['actor'],row['owner'])
            if live['identity']!=row['identity']:raise AccessDenied('Recorded scan account was replaced; no cancellation was performed')
            context=live
        paused=self.store.cancel(context,job_id)
        return dict(cancel_requested=True,job_id=job_id,initial_monitoring_paused=paused)
