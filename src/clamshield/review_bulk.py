"""Confirmed Review selection snapshots; content deletion uses custody journals."""
from contextlib import contextmanager
import fcntl
import json
import os
import stat
import time
import uuid

from .errors import AccessDenied,ClamShieldError,Conflict
from .store import encode


def eligible(kind):
    return {
        'scans':"r.status IN ('completed','partial','failed','cancelled')",
        'email-messages':"r.status IN ('delivered','deleted','aborted','rejected','deferred','not_retained')",
        'repairs':"r.status IN ('ready','failed','verified','undone','recheck_failed')",
        'activity':"r.status IN ('completed','failed','cancelled')",
        'automatic':"r.status NOT IN ('queued','preparing','applying','verifying')",
        'quarantine':"r.kind='quarantine' AND r.status IN ('quarantined','deleting','deleted') AND (json_extract(r.metadata,'$.wordpress_recovery') IS NULL OR EXISTS(SELECT 1 FROM wordpress_recovery w WHERE w.id=json_extract(r.metadata,'$.wordpress_recovery') AND w.owner=r.owner AND w.identity=r.identity AND w.status IN ('applied','undone')))",
        'email-stored':"r.status IN ('quarantined','deleting') AND EXISTS(SELECT 1 FROM mail_transactions t LEFT JOIN mail_acceptance a ON a.transaction_id=t.id WHERE t.id=r.transaction_id AND t.status='committed' AND (a.status IS NULL OR a.status='accepted'))",
    }.get(kind,'1=1')


class ReviewBulk:
    def __init__(self,review):
        self.review=review;self.store=review.store;self.hestia=review.hestia;self.settings=review.settings

    @contextmanager
    def locked(self):
        self.settings.prepare()
        fd=os.open(self.settings.state/'review-bulk.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:raise AccessDenied('Unsafe Review lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Conflict('Another Review action is running; retry shortly') from None
            yield
        finally:os.close(fd)

    def run(self,context,kind,scope,operation,token=None,selected=None):
        from .review import SPECS,visible
        if not isinstance(kind,str) or kind not in (*SPECS,'scans') or operation not in ('preview','clear','read'):raise AccessDenied('Unsupported bulk operation')
        if operation=='read' and kind!='notices':raise AccessDenied('Only notifications can be marked read')
        live,scopes,_sites=self.review.scopes(context,scope)
        own=self.hestia.authorize(context['actor'],context['actor'])
        if not live['admin'] and kind not in ('history','notices'):raise AccessDenied('Administrator access required for this bulk action')
        if kind=='history' and not live['admin'] and not self.review.history_allowed(live):raise AccessDenied('History management is disabled by your administrator')
        if selected is not None and (not isinstance(selected,list) or not 1<=len(selected)<=100 or any(not isinstance(v,str) or not 1<=len(v)<=64 for v in selected) or len(set(selected))!=len(selected)):raise ClamShieldError('Select 1 to 100 distinct records from this page')
        condition,args=self.review.condition(scopes);condition+=' AND '+visible(kind)
        if kind=='email-stored':condition+=" AND r.status NOT IN ('deleted','aborted')"
        source='jobs r' if kind=='scans' else SPECS[kind][0];now=time.time()
        if operation=='read':
            with self.store.connection(True) as db:
                count=db.execute('UPDATE notifications AS r SET read_at=? WHERE '+condition+' AND read_at IS NULL',(now,*args)).rowcount
            return dict(changed=count)
        if operation=='preview':
            if selected is not None:
                condition+=' AND CAST(r.id AS TEXT) IN ('+','.join('?' for _ in selected)+')';args.extend(selected)
            with self.store.connection(True) as db:
                total=db.execute('SELECT count(*) FROM '+source+' WHERE '+condition,args).fetchone()[0]
                if selected is not None and total!=len(selected):raise AccessDenied('A selected record is unavailable in this scope; refresh the list')
                proof=uuid.uuid4().hex
                db.execute('DELETE FROM review_confirmations WHERE created<?',(now-86400,))
                value=dict(kind=kind,scope=scope,scopes=scopes,selected=selected is not None)
                db.execute('INSERT INTO review_confirmations VALUES(?,?,?,?,?)',(proof,own['owner'],own['identity'],now,encode(value)))
                db.execute('INSERT INTO review_confirmation_items(token,record_id,owner,identity) SELECT ?,CAST(r.id AS TEXT),r.owner,r.identity FROM '+source+' WHERE '+condition+' AND ('+eligible(kind)+')',(proof,*args))
                count=db.execute('SELECT count(*) FROM review_confirmation_items WHERE token=?',(proof,)).fetchone()[0]
            return dict(token=proof,count=count,retained=total-count,scope=scope,selected=selected is not None)
        if not isinstance(token,str) or len(token)!=32:raise Conflict('Confirmation expired; preview the deletion again')
        with self.locked():
            with self.store.connection(True) as db:
                row=db.execute('SELECT * FROM review_confirmations WHERE token=? AND actor=? AND identity=?',(token,own['owner'],own['identity'])).fetchone()
                if not row or now-row['created']>300:raise Conflict('Confirmation expired; preview the deletion again')
                value=json.loads(row['detail'])
                if value['kind']!=kind or value['scope']!=scope or value['scopes']!=[list(pair) for pair in scopes]:raise Conflict('The view or account identities changed; preview again')
                # Keep the exact preview set even if new records arrive or filters change.
                match=' AND EXISTS(SELECT 1 FROM review_confirmation_items i WHERE i.token=? AND i.record_id=CAST(r.id AS TEXT) AND i.owner=r.owner AND i.identity=r.identity)'
                if kind not in ('quarantine','email-stored'):
                    selected_where=condition+' AND ('+eligible(kind)+')'+match
                    if kind=='exceptions':
                        db.execute('UPDATE exceptions SET enabled=0 WHERE id IN (SELECT r.id FROM '+source+' WHERE '+selected_where+')',(*args,token))
                    bell_pending=0
                    if kind=='notices':
                        from .notification_clear import BellClear
                        bell_pending=BellClear.enqueue(db,own,db.execute('SELECT r.* FROM '+source+' WHERE '+selected_where,(*args,token)))
                        db.execute('UPDATE notifications AS r SET read_at=COALESCE(read_at,?) WHERE '+selected_where,(now,*args,token))
                    count=db.execute('INSERT OR IGNORE INTO review_deleted SELECT ?,CAST(r.id AS TEXT),r.owner,r.identity FROM '+source+' WHERE '+selected_where,(kind,*args,token)).rowcount
                    db.execute('DELETE FROM review_confirmations WHERE token=?',(token,))
                    if kind not in ('history','notices'):self.store.audit(live,'review.cleared',kind,dict(records=count,scope=scope,selected=value['selected']),db)
                    return dict(changed=count,pending=False,**({'bell_pending':bell_pending} if kind=='notices' else {}))
                items=[dict(r) for r in db.execute("SELECT * FROM review_confirmation_items WHERE token=? AND state='pending' ORDER BY record_id LIMIT 5",(token,))]
            for item in items:
                try:
                    account=self.hestia.authorize(context['actor'],item['owner'])
                    if account['identity']!=item['identity']:raise AccessDenied('Hosting account changed')
                    if kind=='quarantine':
                        from .quarantine import Quarantine
                        Quarantine(self.settings,self.store,self.hestia).delete(account,item['record_id'])
                    else:
                        from .mail_custody import MailCustody
                        MailCustody(self.settings,self.store,self.hestia).delete(account,item['record_id'])
                    state,error='done',None
                except (ClamShieldError,OSError) as exc:state,error='failed',str(exc)
                with self.store.connection(True) as db:
                    db.execute('UPDATE review_confirmation_items SET state=?,error=? WHERE token=? AND record_id=? AND owner=? AND identity=?',(state,error,token,item['record_id'],item['owner'],item['identity']))
                    if state=='done':db.execute('INSERT OR IGNORE INTO review_deleted VALUES(?,?,?,?)',(kind,item['record_id'],item['owner'],item['identity']))
            with self.store.connection(True) as db:
                count=db.execute("SELECT count(*) FROM review_confirmation_items WHERE token=? AND state='done'",(token,)).fetchone()[0]
                failures=[dict(r) for r in db.execute("SELECT record_id,error FROM review_confirmation_items WHERE token=? AND state='failed' ORDER BY record_id LIMIT 20",(token,))]
                failed=db.execute("SELECT count(*) FROM review_confirmation_items WHERE token=? AND state='failed'",(token,)).fetchone()[0]
                pending=db.execute("SELECT 1 FROM review_confirmation_items WHERE token=? AND state='pending' LIMIT 1",(token,)).fetchone() is not None
                if pending:db.execute('UPDATE review_confirmations SET created=? WHERE token=?',(time.time(),token))
                else:db.execute('DELETE FROM review_confirmations WHERE token=?',(token,))
            return dict(changed=count,pending=pending,failed=failed,failures=failures)
