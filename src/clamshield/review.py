"""Native account-scoped, bounded Review queries and confirmed log clearing."""
from datetime import datetime,timezone
import json
import re
import time
import uuid

from .errors import AccessDenied,ClamShieldError,Conflict
from .notification_preferences import category
from .store import encode
from .website_availability import WebsiteAvailability

# SQL identifiers and expressions are fixed here, never accepted from requests.
SPECS={
 'findings':("findings r LEFT JOIN jobs j ON j.id=r.job_id AND j.owner=r.owner AND j.identity=r.identity","r.*,j.root",'r.status','r.engine','r.provider',"r.domain||' '||r.path||' '||r.signature||' '||r.owner",('fingerprint','detail')),
 'repairs':("repair_plans r JOIN jobs j ON j.id=r.id AND j.owner=r.owner AND j.identity=r.identity","r.*,j.domain,j.root,j.target",'r.status',"COALESCE(json_extract(r.metadata,'$.source.kind'),'wordpress')",None,"j.domain||' '||j.target||' '||r.owner||' '||COALESCE(r.error,'')",('metadata',)),
 'exceptions':('exceptions r','r.*',"CASE r.enabled WHEN 1 THEN 'enabled' ELSE 'disabled' END",'r.kind','r.engine',"r.domain||' '||r.path||' '||r.signature||' '||r.owner||' '||COALESCE(r.note,'')",()),
 'quarantine':('operations r LEFT JOIN findings f ON f.id=r.finding_id AND f.owner=r.owner AND f.identity=r.identity','r.*,f.domain','r.status','r.kind',None,"COALESCE(f.domain,'')||' '||COALESCE(json_extract(r.metadata,'$.path'),'')||' '||r.owner",('metadata',)),
 'history':('audit r','r.*',None,'r.action',None,"r.actor||' '||r.action||' '||r.subject||' '||r.detail||' '||r.owner",('detail',)),
 'notices':('notifications r','r.*',"CASE WHEN r.read_at IS NULL THEN 'unread' ELSE 'read' END",'r.event',None,"r.event||' '||r.subject||' '||r.detail||' '||r.owner",('detail',)),
 'activity':('maintenance r','r.*','r.status','r.action',None,"r.action||' '||COALESCE(r.error,'')||' '||r.owner",('payload','result')),
 'automatic':("remediation_actions r LEFT JOIN jobs j ON j.id=r.job_id AND j.owner=r.owner AND j.identity=r.identity LEFT JOIN operations o ON o.id=json_extract(r.detail,'$.operation_id') AND o.owner=r.owner AND o.identity=r.identity LEFT JOIN repair_plans p ON p.id=json_extract(r.detail,'$.plan_id') AND p.owner=r.owner AND p.identity=r.identity",'r.*,j.domain,j.root,o.status AS operation_status,p.status AS plan_status','r.status',"COALESCE(json_extract(r.detail,'$.policy.mode'),'report')",None,"COALESCE(j.domain,'')||' '||r.path||' '||r.owner",('detail',)),
 'email-stored':('mail_recipients r','r.id,r.owner,r.identity,r.domain,r.recipient,r.status,r.action,r.created,r.error','r.status','r.action',None,"r.recipient||' '||r.domain||' '||r.owner",()),
 'email-decisions':('mail_decisions r','r.id,r.owner,r.identity,r.domain,r.recipient,r.sender,r.action,r.classification,r.created','r.action','r.classification',None,"r.recipient||' '||r.sender||' '||r.domain||' '||r.owner",()),
}


def visible(kind,alias='r'):
    if kind not in ('history','notices'):return '1=1'
    ident='CAST(c.before_id AS INTEGER)' if kind=='history' else 'c.before_id'
    return f"NOT EXISTS(SELECT 1 FROM review_clears c WHERE c.kind='{kind}' AND c.owner={alias}.owner AND c.identity={alias}.identity AND ({alias}.created<c.before_created OR ({alias}.created=c.before_created AND {alias}.id<={ident})))"


class Review:
    def __init__(self,settings,store,hestia):self.settings,self.store,self.hestia=settings,store,hestia

    def scopes(self,context,scope):
        live=self.hestia.authorize(context['actor'],context['owner'])
        if live['identity']!=context['identity']:raise AccessDenied('Hosting account changed; reload the page')
        if scope not in ('account','server'):raise AccessDenied('Choose account or Global scope')
        if scope=='server':
            if not live['admin']:raise AccessDenied('Administrator access required')
            accounts=self.hestia.inventory()
            scopes=[(a['owner'],a['identity']) for a in accounts]+[('@admin','')]
            sites={a['owner']:a['sites'] for a in accounts}
        else:
            scopes=[(live['owner'],live['identity'])];sites={live['owner']:self.hestia.sites(live['owner'])}
        return live,sorted(set(scopes)),sites

    @staticmethod
    def condition(scopes,alias='r'):
        if not scopes:return '0=1',[]
        return '('+' OR '.join(f'({alias}.owner=? AND {alias}.identity=?)' for _ in scopes)+')',[v for pair in scopes for v in pair]

    def query(self,context,kind,scope='account',filters=None,offset=0,limit=50):
        if kind not in SPECS:raise ClamShieldError('Unknown Review list')
        live,scopes,sites=self.scopes(context,scope)
        if kind=='activity' and not live['admin']:raise AccessDenied('Administrator access required')
        if not isinstance(filters,dict) or set(filters)-{'search','status','type','provider','account','from','to','order','categories'}:raise ClamShieldError('Invalid Review filters')
        if type(offset) is not int or not 0<=offset<=10000000 or type(limit) is not int or limit not in (25,50,100):raise ClamShieldError('Choose 25, 50 or 100 rows and a valid page')
        for key,value in filters.items():
            if key=='categories':
                if not isinstance(value,list) or len(value)>20 or any(not isinstance(v,str) or len(v)>40 for v in value):raise ClamShieldError('Invalid notification categories')
            elif not isinstance(value,str) or len(value)>(300 if key=='search' else 128):raise ClamShieldError('Invalid Review filter value')
        if filters.get('order','newest') not in ('newest','oldest'):raise ClamShieldError('Invalid sort order')
        all_scopes=list(scopes)
        if filters.get('account'):
            scopes=[pair for pair in scopes if pair[0]==filters['account']]
            if not scopes:raise AccessDenied('Account is outside this view')
        where,args=self.condition(scopes);where+=' AND '+visible(kind)
        if kind=='email-stored':where+=" AND r.status NOT IN ('deleted','aborted')"
        source,columns,status,type_expr,provider,search,json_fields=SPECS[kind]
        base_where=where;base_args=list(args)
        for key,expr in [('status',status),('type',type_expr),('provider',provider)]:
            if filters.get(key) and filters[key]!='all':
                if expr is None:raise ClamShieldError('Filter is unavailable for this list')
                where+=' AND '+expr+'=?';args.append(filters[key])
        if filters.get('search'):
            where+=' AND instr(lower('+search+'),lower(?))>0';args.append(filters['search'])
        for key,operator,extra in [('from','>=',0),('to','<',86400)]:
            if filters.get(key):
                try:
                    value=filters[key]
                    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}',value):raise ValueError()
                    stamp=datetime.strptime(value,'%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()+extra
                except (ValueError,OverflowError):raise ClamShieldError('Choose valid UTC dates') from None
                where+=' AND r.created'+operator+'?';args.append(stamp)
        if kind=='notices' and 'categories' in filters:
            # Match the same category groups as personal notification preferences.
            from .notification_preferences import CATEGORIES
            selected=filters['categories']
            if any(v not in CATEGORIES for v in selected):raise ClamShieldError('Unknown notification category')
        with self.store.connection() as db:
            db.create_function('cs_category',1,category,deterministic=True)
            if kind=='notices' and 'categories' in filters:
                selected=filters['categories'];where+=' AND cs_category(r.event) IN ('+','.join('?' for _ in selected)+')' if selected else ' AND 0=1';args.extend(selected)
            db.execute('BEGIN')
            total=db.execute('SELECT count(*) FROM '+source+' WHERE '+where,args).fetchone()[0]
            last=max(0,((total-1)//limit)*limit);offset=min(offset,last)
            direction='ASC' if filters.get('order')=='oldest' else 'DESC'
            rows=db.execute('SELECT '+columns+' FROM '+source+' WHERE '+where+f' ORDER BY r.created {direction},r.id {direction} LIMIT ? OFFSET ?',(*args,limit,offset)).fetchall()
            options={}
            for key,expr in [('status',status),('type',type_expr),('provider',provider)]:
                options[key]=[row[0] for row in db.execute('SELECT DISTINCT '+expr+' FROM '+source+' WHERE '+base_where+' ORDER BY 1 LIMIT 256',base_args) if row[0] is not None] if expr else []
        records=[]
        for row in rows:
            value=dict(row)
            for field in json_fields:value[field]=json.loads(value[field]) if value.get(field) else {}
            if kind=='repairs':value['metadata'].get('preview',{}).pop('diff',None)
            if kind in ('findings','repairs','quarantine','automatic'):
                account=dict(live,owner=value['owner'],identity=value['identity'])
                value['site_availability']=WebsiteAvailability(account,sites.get(value['owner'],[])).describe(value,root=value.get('metadata',{}).get('root') if kind=='quarantine' else None)
            records.append(value)
        view=dict(context=dict(live,view_scope=scope),jobs=[],sites=[],**{key:[] for key in ('findings','repairs','exceptions','quarantine','history','notifications','remediation_history','maintenance')})
        view[{'notices':'notifications','automatic':'remediation_history','activity':'maintenance'}.get(kind,kind)]=records
        if kind=='history':
            subjects=[r['subject'] for r in records]
            if subjects:
                condition,values=self.condition(scopes,'j')
                with self.store.connection() as db:jobs=db.execute('SELECT j.* FROM jobs j WHERE '+condition+' AND j.id IN ('+','.join('?' for _ in subjects)+')',(*values,*subjects)).fetchall()
                view['jobs']=[dict(row) for row in jobs]
        return dict(list=kind,records=records,total=total,offset=offset,limit=limit,next_offset=offset+len(records) if offset+len(records)<total else None,options=options,accounts=[owner for owner,_identity in all_scopes],can_clear=kind in ('history','notices') and (live['admin'] or kind=='notices' or self.history_allowed(live)),view_data=view)

    def history_allowed(self,context):
        with self.store.connection() as db:row=db.execute('SELECT allowed FROM history_permissions WHERE owner=? AND identity=?',self.store.scope(context)).fetchone()
        return row is None or bool(row[0])

    def bulk(self,context,kind,scope,operation,token=None):
        if kind not in ('history','notices') or operation not in ('preview','clear','read'):raise AccessDenied('Unsupported bulk operation')
        if operation=='read' and kind!='notices':raise AccessDenied('Only notifications can be marked read')
        live,scopes,_sites=self.scopes(context,scope)
        own=self.hestia.authorize(context['actor'],context['actor'])
        if not live['admin'] and kind=='history':
            with self.store.connection() as db:permission=db.execute('SELECT allowed FROM history_permissions WHERE owner=? AND identity=?',self.store.scope(live)).fetchone()
            if permission and not permission[0]:raise AccessDenied('History management is disabled by your administrator')
        table='audit' if kind=='history' else 'notifications';condition,args=self.condition(scopes)
        now=time.time()
        with self.store.connection(True) as db:
            if operation=='read':
                count=db.execute('UPDATE notifications AS r SET read_at=? WHERE '+condition+' AND '+visible(kind)+' AND read_at IS NULL',(now,*args)).rowcount
                return dict(changed=count)
            if operation=='preview':
                anchor=db.execute('SELECT r.created,r.id FROM '+table+' r WHERE '+condition+' AND '+visible(kind)+' ORDER BY r.created DESC,r.id DESC LIMIT 1',args).fetchone()
                count=db.execute('SELECT count(*) FROM '+table+' r WHERE '+condition+' AND '+visible(kind),args).fetchone()[0]
                value=dict(kind=kind,scope=scope,scopes=scopes,anchor=list(anchor) if anchor else [0,''],count=count)
                proof=uuid.uuid4().hex
                db.execute('DELETE FROM review_confirmations WHERE created<?',(now-86400,))
                db.execute('INSERT INTO review_confirmations VALUES(?,?,?,?,?)',(proof,own['owner'],own['identity'],now,encode(value)))
                return dict(token=proof,count=count,scope=scope)
            proof=db.execute('SELECT * FROM review_confirmations WHERE token=? AND actor=? AND identity=?',(token,own['owner'],own['identity'])).fetchone()
            if not proof or now-proof['created']>300:raise Conflict('Confirmation expired; preview the deletion again')
            value=json.loads(proof['detail'])
            if value['kind']!=kind or value['scope']!=scope or value['scopes']!=[list(pair) for pair in scopes]:raise Conflict('The view or account identities changed; preview again')
            stamp,ident=value['anchor'];bound=' AND (r.created<? OR (r.created=? AND r.id<=?))'
            count=db.execute('SELECT count(*) FROM '+table+' r WHERE '+condition+' AND '+visible(kind)+bound,(*args,stamp,stamp,ident)).fetchone()[0]
            for owner,identity in scopes:
                old=db.execute('SELECT before_created,before_id FROM review_clears WHERE kind=? AND owner=? AND identity=?',(kind,owner,identity)).fetchone()
                if old and (old[0],int(old[1]) if kind=='history' else old[1])>=(stamp,int(ident or 0) if kind=='history' else ident):continue
                db.execute('INSERT INTO review_clears VALUES(?,?,?,?,?) ON CONFLICT(kind,owner,identity) DO UPDATE SET before_created=excluded.before_created,before_id=excluded.before_id',(kind,owner,identity,stamp,str(ident)))
            if kind=='notices':db.execute('UPDATE notifications AS r SET read_at=COALESCE(read_at,?) WHERE '+condition+bound,(now,*args,stamp,stamp,ident))
            db.execute('DELETE FROM review_confirmations WHERE token=?',(token,))
        return dict(changed=count)
