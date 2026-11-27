"""Durable source-SMTP custody handoff, separate from socket send completion.

Prepared bytes may be promised to Exim before its final SMTP reply. They must
not become deliverable/viewable until both our hook decision and native source
acceptance are proven. Unknown outcomes retain bytes and never authorize abort.
"""
from contextlib import contextmanager
import fcntl
import json
import os
import stat
import time

from .errors import AccessDenied,ClamShieldError,Conflict
from .mail_bridge import Decision,process_start,validate_snapshot
from .mail_custody import MailCustody,identifier,digest
from .mail_delivery import NativeExim
from .mail_policy import MailPolicies
from .store import encode


class MailAcceptance:
    def __init__(self,settings,store,hestia,native=None):
        self.settings,self.store,self.hestia=settings,store,hestia
        self.custody=MailCustody(settings,store,hestia);self.native=native or NativeExim()

    @contextmanager
    def locked(self,blocking=True):
        self.settings.prepare()
        fd=os.open(self.settings.state/'mail-acceptance.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise AccessDenied('Mail acceptance lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB))
            yield
        finally:os.close(fd)

    def row(self,transaction_id,db):
        row=db.execute('SELECT * FROM mail_acceptance WHERE transaction_id=?',(identifier(transaction_id),)).fetchone()
        if not row:raise Conflict('Native mail acceptance journal unavailable')
        return dict(row)|{'metadata':json.loads(row['metadata'])}

    def arm(self,staged,request):
        """After durable stage, before any HANDLED/SELECTED response is sent."""
        transaction_id=identifier(staged['transaction_id'])
        snapshot=validate_snapshot(request.fd)
        if request.peer_pid is None or request.peer_start is None or process_start(request.peer_pid)!=request.peer_start:
            raise AccessDenied('Mail acceptance requires a live authenticated native process')
        with self.locked(),self.custody.locked() as root:
            with self.store.connection() as db:
                transaction=self.custody.transaction(transaction_id,db)
                rows=[dict(row) for row in db.execute('SELECT * FROM mail_recipients WHERE transaction_id=?',(transaction_id,))]
                exists=db.execute('SELECT 1 FROM mail_acceptance WHERE transaction_id=?',(transaction_id,)).fetchone()
            if transaction['status']!='prepared' or exists:raise Conflict('This custody handoff cannot be armed again')
            expected={key:getattr(request,key) for key in ('message_id','sender','remote_ip','authenticated_id','protocol','flags')}
            expected['recipients']=list(request.recipients)
            meta=transaction['metadata']
            if (transaction['exim_id']!=request.message_id or meta['envelope']!=expected or
                digest(request.fd)!=(transaction['sha256'],snapshot.st_size) or snapshot.st_size!=transaction['size'] or
                staged['custody']!=meta['custody'] or staged['native']!=meta['native']):
                raise Conflict('Mail handoff does not match its durable native capture')
            if not meta['custody'] or sorted(meta['custody']+meta['native'])!=list(range(len(request.recipients))):
                raise Conflict('Mail custody selection is inconsistent')
            for row in rows:
                context={'actor':'clamshield-mail','owner':row['owner'],'identity':row['identity'],'admin':False}
                self.custody._validate_item({'context':context,'target':{key:row[key] for key in
                    ('owner','identity','domain','mailbox','recipient')},'decision':json.loads(row['detail'])},row['recipient'])
            with self.custody.blob(root,transaction):pass
            decision=Decision.SELECTED if meta['native'] else Decision.HANDLED
            metadata={'checkpoint':self.native.checkpoint(),'decision':decision.value,'peer_pid':request.peer_pid,
                      'peer_start':request.peer_start,'response_sent':False,'proof':None}
            now=time.time()
            with self.store.connection(True) as db:
                db.execute('INSERT INTO mail_acceptance VALUES(?,?,?,?,?,?,NULL)',
                           (transaction_id,request.message_id,now,now,'armed',encode(metadata)))
                for row in rows:self.store.audit({'actor':'clamshield-mail','owner':row['owner'],'identity':row['identity']},
                    'mail.smtp_handoff_armed',row['id'],{'exim_id':request.message_id,'event':transaction_id},db)
            selected=[index in meta['custody'] for index in range(len(request.recipients))] if decision==Decision.SELECTED else None
            return {'decision':decision,'event':transaction_id,'selected':selected}

    def response_sent(self,transaction_id):
        """Transport send success is recorded but never treated as acceptance."""
        with self.locked(),self.store.connection(True) as db:
            row=self.row(transaction_id,db);meta=dict(row['metadata'],response_sent=True)
            state='response_sent' if row['status'] in ('armed','response_sent','uncertain') else row['status']
            db.execute('UPDATE mail_acceptance SET status=?,metadata=?,updated=? WHERE transaction_id=?',(state,encode(meta),time.time(),transaction_id))

    def _reconcile(self,transaction_id):
        with self.store.connection() as db:
            row=self.row(transaction_id,db);transaction=self.custody.transaction(transaction_id,db)
        if row['status']=='accepted':return 'accepted'
        if row['status']=='rejected' and transaction['status']=='aborted':return 'rejected'
        meta=row['metadata']
        if row['status'] in ('proven','rejected'):
            observed=meta['proof']
        else:
            try:observed=self.native.observe_acceptance(row['exim_id'],transaction_id,meta['decision'],meta['checkpoint'])
            except (OSError,EOFError,ClamShieldError):observed={'state':'unknown'}
        if observed['state']=='unknown':
            with self.store.connection(True) as db:
                db.execute("UPDATE mail_acceptance SET status='uncertain',error=?,updated=? WHERE transaction_id=?",
                           ('Native source acceptance is unproven; private capture will not deliver or be discarded',time.time(),transaction_id))
            return 'uncertain'
        proven='proven' if observed['state']=='accepted' else 'rejected'
        meta=dict(meta,proof=observed)
        with self.store.connection(True) as db:
            db.execute('UPDATE mail_acceptance SET status=?,metadata=?,error=NULL,updated=? WHERE transaction_id=?',(proven,encode(meta),time.time(),transaction_id))
        MailPolicies(self.store,self.hestia).outcome(row['exim_id'],'accepted' if proven=='proven' or observed['state']=='native' else 'defer',native_fallback=observed['state']=='native')
        try:
            if proven=='proven':
                if transaction['status'] not in ('committed','purged'):self.custody.commit(transaction_id)
                state='accepted'
            else:
                self.custody.abort(transaction_id);state='rejected'
        except (OSError,ClamShieldError):
            with self.store.connection(True) as db:
                db.execute('UPDATE mail_acceptance SET error=?,updated=? WHERE transaction_id=?',
                           ('Native source outcome is proven; private storage or ownership needs recovery/review',time.time(),transaction_id))
            return proven
        with self.store.connection(True) as db:
            db.execute('UPDATE mail_acceptance SET status=?,error=NULL,updated=? WHERE transaction_id=?',(state,time.time(),transaction_id))
        return state

    def reconcile(self,transaction_id):
        with self.locked():return self._reconcile(transaction_id)

    def recover(self):
        try:
            with self.locked(False):
                with self.store.connection() as db:
                    rows=db.execute("SELECT a.transaction_id FROM mail_acceptance a JOIN mail_transactions t ON t.id=a.transaction_id WHERE a.status IN ('armed','response_sent','uncertain','proven') OR (a.status='rejected' AND t.status<>'aborted') ORDER BY a.updated LIMIT 100").fetchall()
                states={}
                for row in rows:
                    state=self._reconcile(row['transaction_id']);states[state]=states.get(state,0)+1
                return {'mail_acceptance_reconciled':len(rows),'mail_acceptance_states':states}
        except BlockingIOError:return {'mail_acceptance_busy':True}
