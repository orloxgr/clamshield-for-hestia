"""Journaled one-recipient handoff to native Exim; never resend uncertainty.

Only internal committed custody rows can create an attempt. SMTP headers never
supply its trusted native protocol reference, envelope or owner generation.
"""
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from .errors import AccessDenied, ClamShieldError, Conflict
from .mail_custody import MailCustody, digest, identifier
from .mail_bridge import process_start, validate_snapshot
from .mail_cleanup import MailCleanup
from .paths import attributes
from .store import encode

PROTOCOL = 'clamshield-delivery-'
MAX_LOG = 32*1024*1024
MAX_PAYLOAD = 66*1024*1024


def payload(original, attempt, action, released=False, classification=None):
    """Preserve MIME bytes; replace only the scanner status header fields."""
    identifier(attempt)
    boundary = re.search(rb'\r?\n\r?\n', original)
    if not boundary or boundary.start()>1024*1024 or len(original)>MAX_PAYLOAD:
        raise Conflict('Stored email has incomplete or oversized headers')
    headers, body = original[:boundary.start()].replace(b'\r\n',b'\n'), original[boundary.end():]
    prefixes={'malware':b'*** MALWARE ***','phishing':b'*** PHISHING ***',
              'spam':b'*** SPAM ***','blocked-sender':b'*** BLOCKED SENDER ***'}
    prefix=prefixes.get(classification)
    kept, skip, subject = [], False, False
    for line in headers.split(b'\n'):
        if line.startswith((b' ', b'\t')):
            if not kept and not skip:
                raise Conflict('Stored email has invalid folded headers')
        else:
            key, colon, _value = line.partition(b':')
            if not colon or not re.fullmatch(rb'[!-9;-~]+', key):
                raise Conflict('Stored email has malformed headers')
            skip = key.lower() in (b'x-spam-status', b'x-spam-score', b'x-spam-bar', b'x-spam-report') or key.lower().startswith(b'x-clamshield-')
        if not skip:
            if line.lower().startswith(b'subject:'):
                subject=True
                if prefix and not line[8:].lstrip().startswith(prefix):line=b'Subject: '+prefix+b' '+line[8:].lstrip()
            kept.append(line)
    if prefix and not subject:kept.append(b'Subject: '+prefix)
    status = 'Released' if released else 'Junk' if action == 'junk' else 'Clean' if action=='deliver' else 'Tagged'
    kept.extend([b'X-ClamShield-Status: '+status.encode(), b'X-ClamShield-Delivery: '+attempt.encode(),
                 b'X-Spam-Status: '+(b'Yes' if action == 'junk' and not released else b'No')])
    return b'\n'.join(kept)+b'\n\n'+body


def _wire_parts(data):
    """Comparable wire headers/body; normalize transport CRLF, no MIME parsing."""
    data=data.replace(b'\r\n',b'\n')
    head,separator,body=data.partition(b'\n\n')
    if not separator or len(head)>1024*1024 or len(data)>MAX_PAYLOAD:
        raise Conflict('Reinjected email is incomplete or oversized')
    fields=[]
    for line in head.split(b'\n'):
        if line.startswith((b' ',b'\t')):
            if not fields:raise Conflict('Invalid reinjected header folding')
            fields[-1]=(fields[-1][0],fields[-1][1]+b'\n'+line)
        else:
            name,colon,_value=line.partition(b':')
            if not colon or not re.fullmatch(rb'[!-9;-~]+',name):
                raise Conflict('Invalid reinjected header field')
            fields.append((name.lower(),line))
    return fields,body


def matches_reinjection(expected,received):
    """Permit exactly the native Received prefix and absent-header fixups.

    Existing header bytes/order and normalized body must match the private send
    copy. Auto-added fields are allowed only once and only when originally absent.
    This is used only after native process/protocol/envelope authentication.
    """
    before,body=_wire_parts(expected);after,actual=_wire_parts(received)
    if not after or after[0][0]!=b'received' or body!=actual:return False
    after=after[1:];names={name for name,_value in before}
    allowed={b'date',b'message-id',b'from',b'sender'}-names
    retained=[];extras=set()
    for name,value in after:
        if name in allowed:
            if name in extras:return False
            extras.add(name)
        else:retained.append((name,value))
    return retained==before


class NativeExim:
    """Use only the distro executable and its root/native-owned local log.

    The trusted -oMr reference is logged on native acceptance. Exit status alone
    is insufficient. An absent/rotated/truncated log cannot prove non-delivery.
    """
    def __init__(self, binary='/usr/sbin/exim4', log='/var/log/exim4/mainlog', *, timeout=30):
        self.binary, self.log, self.timeout = Path(binary), Path(log), timeout

    def _open_log(self, path):
        import pwd
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or
                    info.st_uid not in (0, pwd.getpwnam('Debian-exim').pw_uid)):
                raise AccessDenied('Native mail log is not trusted')
            return fd
        except BaseException:
            os.close(fd); raise

    def checkpoint(self):
        fd = self._open_log(self.log)
        try:
            info = os.fstat(fd)
            return {'device': info.st_dev, 'inode': info.st_ino, 'offset': info.st_size}
        finally:
            os.close(fd)

    def submit(self, attempt, sender, recipient, data, spawned):
        identifier(attempt)
        if (not isinstance(sender, str) or len(sender) > 1024 or any(ord(c)<32 or ord(c)==127 for c in sender) or
                not isinstance(recipient, str) or len(recipient)>320 or recipient.count('@')!=1 or
                any(ord(c)<33 or ord(c)==127 for c in recipient)):
            raise Conflict('Native delivery envelope is invalid')
        info = self.binary.resolve(strict=True).stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AccessDenied('Native Exim executable is untrusted')
        process = subprocess.Popen([str(self.binary), '-odq', '-oi', '-oMr', PROTOCOL+attempt,
                                    '-f', sender, '--', recipient], stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        try:
            spawned(process.pid)
            process.communicate(data, timeout=self.timeout)
        except BaseException:
            process.kill(); process.wait()
            raise
        return process.returncode

    def run_queue(self, native_id):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,127}',native_id):
            raise Conflict('Invalid native delivery reference')
        # Operate on the existing native queue entry, never recreate the mail.
        subprocess.run([str(self.binary),'-Mc',native_id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                       timeout=self.timeout,check=False,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})

    def records(self, checkpoint):
        """Bounded trusted native log records, including surviving rotations."""
        consumed=0
        paths = [self.log.with_name(self.log.name+suffix) for suffix in ('.2.gz','.1.gz','.1','')]
        # If the checkpoint inode survives rotation, older files cannot contain
        # this new attempt. Avoid rereading a large unrelated historical log.
        for index,path in enumerate(paths):
            try:fd=self._open_log(path)
            except FileNotFoundError:continue
            try:
                info=os.fstat(fd)
                if (info.st_dev,info.st_ino)==(checkpoint['device'],checkpoint['inode']):
                    paths=paths[index:];break
            finally:os.close(fd)
        for path in paths:
            try:
                fd = self._open_log(path)
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(fd)
                same = (info.st_dev, info.st_ino) == (checkpoint['device'], checkpoint['inode'])
                with os.fdopen(os.dup(fd), 'rb') as raw:
                    if same and path.suffix != '.gz':
                        if info.st_size < checkpoint['offset']:
                            raise Conflict('Native mail log was truncated')
                        raw.seek(checkpoint['offset'])
                    reader = gzip.GzipFile(fileobj=raw) if path.suffix=='.gz' else raw
                    try:
                        while True:
                            line = reader.readline(65537)
                            if not line: break
                            consumed += len(line)
                            if len(line)>65536 or consumed>MAX_LOG:
                                raise Conflict('Native mail log observation exceeded its limit')
                            if not line.endswith(b'\n'): continue
                            match = re.match(rb'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[+-]\d{4})?(?: \[\d+\])? ([A-Za-z0-9-]{1,128}) (.*)\n$',line)
                            if not match: continue
                            event_id, message = match[1].decode('ascii'), match[2]
                            yield event_id,message
                    finally:
                        if reader is not raw: reader.close()
            finally:
                os.close(fd)

    def observe(self, attempt, checkpoint, native_id=None):
        """Bounded current/rotated log evidence, never infer absence from silence."""
        identifier(attempt)
        receipts,events=set(),{}
        for event_id,message in self.records(checkpoint):
            # These must be native local-receipt fields, not words embedded in
            # a quoted envelope sender.
            if re.match(rb'^<= (?:<>|"(?:[^"\\]|\\.)*"@[^\s]+|[^\s"]+) U=root P='+
                        re.escape((PROTOCOL+attempt).encode())+rb' S=[0-9]+(?: |$)',message):
                receipts.add(event_id)
            flags=events.setdefault(event_id,set())
            if message.startswith((b'=> ',b'-> ')):flags.add('success')
            if message.startswith(b'** '):flags.add('failed')
            if message.startswith(b'Completed'):flags.add('completed')
        if len(receipts)>1:
            raise Conflict('More than one native message matches this delivery attempt')
        if native_id and receipts and native_id not in receipts:
            raise Conflict('Native delivery reference changed')
        if not receipts and not native_id:return {'state':'unknown','native_id':None}
        native_id = native_id or next(iter(receipts)); flags = events.get(native_id,set())
        state = ('native_failed' if 'failed' in flags else 'delivered' if {'completed','success'}<=flags else 'native_queued')
        return {'state':state,'native_id':native_id}

    def observe_acceptance(self,native_id,event,decision,checkpoint):
        """Both our exact C decision and native acceptance must be proven."""
        identifier(event)
        if decision not in (3,4) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,127}',native_id):
            raise Conflict('Invalid source acceptance reference')
        hook=received=rejected=fallback=False;conflicting=False
        expected=f'ClamShield decision={decision} event={event}'.encode()
        for record_id,message in self.records(checkpoint):
            if record_id!=native_id:continue
            if message==expected:hook=True
            elif re.fullmatch(rb'ClamShield decision=[0-4] event=[0-9a-f]{32}',message):conflicting=True
            if message==b'ClamShield native delivery fallback; check incomplete':fallback=True
            if message.startswith(b'<= '):received=True
            if (message.startswith(b'F=') and re.search(rb' (?:temporarily )?rejected by local_scan\(\): (?:ClamShield mail check unavailable; please retry|Message rejected by ClamShield policy)$',message)):
                rejected=True
        if received and rejected:raise Conflict('Native source acceptance evidence is contradictory')
        if fallback and (hook or conflicting):raise Conflict('Native fallback conflicts with a custody decision')
        if received and fallback:
            return {'state':'native','native_id':native_id,'event':event,'decision':decision,'hook_seen':False}
        if received and (not hook or conflicting):raise Conflict('Native source accepted without the expected custody decision')
        state='accepted' if received and hook else 'rejected' if rejected else 'unknown'
        return {'state':state,'native_id':native_id,'event':event,'decision':decision,'hook_seen':hook}


class MailDelivery:
    def __init__(self, settings, store, hestia, native=None):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.custody, self.native = MailCustody(settings,store,hestia), native or NativeExim()

    @contextmanager
    def locked(self):
        self.settings.prepare()
        fd = os.open(self.settings.state/'mail-delivery.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise AccessDenied('Mail delivery lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def _row(self, attempt, db):
        row=db.execute('SELECT * FROM mail_delivery_attempts WHERE id=?',(identifier(attempt),)).fetchone()
        if not row: raise Conflict('Mail delivery attempt unavailable')
        return dict(row)|{'metadata':json.loads(row['metadata'])}

    def _release_authorized(self, row):
        with self.store.connection() as db:
            event=db.execute("SELECT actor,detail FROM audit WHERE owner=? AND identity=? AND action='mail.release_queued' AND subject=? ORDER BY id DESC LIMIT 1",(row['owner'],row['identity'],row['id'])).fetchone()
        if event is None:raise AccessDenied('Mail release authorization is missing')
        context=self.hestia.authorize(event['actor'],row['owner'])
        if (context['identity']!=row['identity'] or self.hestia.identity(event['actor'])!=json.loads(event['detail']).get('actor_identity') or
            (not context['admin'] and not self.custody.policies.permissions(context)['release'])):
            raise AccessDenied('Mail release authorization changed')

    def prepare(self):
        """Caller serializes workers; journal before creating private send bytes."""
        from .mail_runtime import may_deliver
        if not may_deliver(self.settings):return None
        with self.custody.locked() as root:
            with self.store.connection() as db:
                row=db.execute("SELECT r.* FROM mail_recipients r JOIN mail_transactions t ON t.id=r.transaction_id WHERE r.status IN ('ready','release_queued') AND t.status='committed' AND NOT EXISTS(SELECT 1 FROM mail_delivery_attempts a WHERE a.recipient_id=r.id) ORDER BY r.created,r.id LIMIT 1").fetchone()
            if row is None: return None
            row=dict(row)
            try:
                context=self.hestia.authorize(row['owner'])
                if context['identity']!=row['identity']: raise AccessDenied('Native mail account changed')
                if row['status']=='release_queued':self._release_authorized(row)
                self.custody._validate_item({'context':context,'target':{key:row[key] for key in
                    ('owner','identity','domain','mailbox','recipient')},'decision':json.loads(row['detail'])},row['recipient'])
                with self.store.connection() as db:
                    transaction=self.custody.transaction(row['transaction_id'],db)
                with self.custody.blob(root,transaction) as fd:
                    original=os.pread(fd,transaction['size'],0)
                attempt=uuid.uuid4().hex
                classification=json.loads(row['detail']).get('classification')
                data=payload(original,attempt,row['action'],released=row['status']=='release_queued',classification=classification)
                metadata={'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'checkpoint':self.native.checkpoint(),
                          'sender':transaction['metadata']['envelope']['sender'],'recipient':row['recipient'],'pid':None,
                          'released':row['status']=='release_queued','subject_classification':classification}
            except (OSError,ClamShieldError):
                # An unavailable old account must not starve other recipients.
                with self.store.connection(True) as db:
                    db.execute("UPDATE mail_recipients SET status='native_failed',error=?,updated=? WHERE id=? AND status IN ('ready','release_queued')",('Native ownership, private content or mail service unavailable; not submitted',time.time(),row['id']))
                    self.store.audit({'actor':'clamshield-mail','owner':row['owner'],'identity':row['identity']},'mail.delivery_blocked',row['id'],{'submitted':False},db)
                return None
            now=time.time()
            with self.store.connection(True) as db:
                db.execute('INSERT INTO mail_delivery_attempts VALUES(?,?,?,?,?,?,NULL,NULL)',
                           (attempt,row['id'],now,now,'preparing',encode(metadata)))
                db.execute("UPDATE mail_recipients SET status='delivery_preparing',updated=? WHERE id=?",(now,row['id']))
                self.store.audit(context,'mail.delivery_preparing',row['id'],{'attempt':attempt},db)
            fd=os.open(attempt+'.delivery',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root)
            try:
                view=memoryview(data)
                while view:
                    count=os.write(fd,view)
                    if count<=0: raise Conflict('Mail delivery snapshot is incomplete')
                    view=view[count:]
                os.fchmod(fd,0o400);os.fsync(fd);metadata['fingerprint']=attributes(os.fstat(fd))
            finally:os.close(fd)
            os.fsync(root)
            self._prepared(attempt,metadata)
            return attempt

    def _prepared(self, attempt_id, metadata):
        with self.store.connection(True) as db:
            attempt=self._row(attempt_id,db)
            if attempt['status']!='preparing': raise Conflict('Delivery preparation journal changed')
            db.execute("UPDATE mail_delivery_attempts SET status='prepared',metadata=?,updated=? WHERE id=?",(encode(metadata),time.time(),attempt_id))
            db.execute("UPDATE mail_recipients SET status='delivery_pending',updated=? WHERE id=? AND status='delivery_preparing'",(time.time(),attempt['recipient_id']))

    def _recover_preparations(self):
        recovered=failed=0
        with self.custody.locked() as root:
            with self.store.connection() as db:
                attempts=[self._row(row['id'],db) for row in db.execute("SELECT id FROM mail_delivery_attempts WHERE status='preparing' LIMIT 100")]
            for attempt in attempts:
                try:
                    with self.store.connection() as db:
                        row=dict(db.execute('SELECT * FROM mail_recipients WHERE id=?',(attempt['recipient_id'],)).fetchone())
                        transaction=self.custody.transaction(row['transaction_id'],db)
                    if row['status']!='delivery_preparing' or transaction['status']!='committed':
                        raise Conflict('Delivery preparation journal is inconsistent')
                    meta=attempt['metadata']
                    if meta['recipient']!=row['recipient'] or meta['sender']!=transaction['metadata']['envelope']['sender']:
                        raise Conflict('Delivery preparation envelope changed')
                    with self.custody.blob(root,transaction) as fd:
                        data=payload(os.pread(fd,transaction['size'],0),attempt['id'],row['action'],released=meta['released'],classification=meta.get('subject_classification'))
                    if hashlib.sha256(data).hexdigest()!=meta['sha256'] or len(data)!=meta['size']:
                        raise Conflict('Delivery preparation recipe changed')
                    name=attempt['id']+'.delivery'
                    try:fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root)
                    except FileNotFoundError:fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root)
                    try:
                        info=os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or
                            stat.S_IMODE(info.st_mode) not in (0o400,0o600) or info.st_size>len(data) or
                            os.pread(fd,info.st_size,0)!=data[:info.st_size]):
                            raise Conflict('Delivery preparation bytes changed')
                        at=info.st_size
                        while at<len(data):
                            count=os.pwrite(fd,data[at:at+65536],at)
                            if count<=0:raise Conflict('Delivery preparation is incomplete')
                            at+=count
                        os.fchmod(fd,0o400);os.fsync(fd);meta['fingerprint']=attributes(os.fstat(fd))
                    finally:os.close(fd)
                    os.fsync(root);self._prepared(attempt['id'],meta);recovered+=1
                except (OSError,ClamShieldError):
                    with self.store.connection(True) as db:
                        db.execute("UPDATE mail_delivery_attempts SET status='preparation_failed',error=?,updated=? WHERE id=?",('Private send preparation changed; no native submission was attempted',time.time(),attempt['id']))
                        db.execute("UPDATE mail_recipients SET status='native_failed',error=?,updated=? WHERE id=?",('Private send preparation requires review; not submitted',time.time(),attempt['recipient_id']))
                    failed+=1
        return {'mail_delivery_prepared_recovered':recovered,'mail_delivery_preparation_failed':failed}

    def _data(self, root, attempt):
        meta=attempt['metadata'];fd=os.open(attempt['id']+'.delivery',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root)
        try:
            info=os.fstat(fd); expected=meta.get('fingerprint')
            if (not expected or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or
                stat.S_IMODE(info.st_mode)!=0o400 or not 1<=info.st_size<=MAX_PAYLOAD or
                any(attributes(info)[key]!=expected[key] for key in ('device','inode','size','mtime_ns','uid','gid','mode','links')) or
                digest(fd)!=(meta['sha256'],meta['size'])):
                raise Conflict('Mail delivery snapshot changed')
            return os.pread(fd,info.st_size,0)
        finally:os.close(fd)

    def submit(self, attempt_id):
        """Only prepared attempts can run. Submitting/uncertain never run again."""
        from .mail_runtime import may_deliver,submission_guard
        with submission_guard(self.settings):
            if not may_deliver(self.settings):raise Conflict('Mail integration must be active before native submission')
            with self.custody.locked() as root:
                with self.store.connection() as db:
                    attempt=self._row(attempt_id,db)
                    row=dict(db.execute('SELECT * FROM mail_recipients WHERE id=?',(attempt['recipient_id'],)).fetchone())
                if attempt['status']!='prepared' or row['status']!='delivery_pending':
                    raise Conflict('This delivery attempt cannot be submitted again')
                context=self.hestia.authorize(row['owner'])
                if context['identity']!=row['identity']:raise AccessDenied('Native mail account changed')
                if attempt['metadata']['released']:self._release_authorized(row)
                self.custody._validate_item({'context':context,'target':{key:row[key] for key in
                    ('owner','identity','domain','mailbox','recipient')},'decision':json.loads(row['detail'])},row['recipient'])
                data=self._data(root,attempt)
                if attempt['metadata']['recipient']!=row['recipient']:
                    raise Conflict('Delivery recipient changed')
                attempt['metadata']['checkpoint']=self.native.checkpoint()
                with self.store.connection(True) as db:
                    db.execute("UPDATE mail_delivery_attempts SET status='submitting',metadata=?,updated=? WHERE id=?",(encode(attempt['metadata']),time.time(),attempt_id))
        # Do not hold the custody lock while Exim invokes its eventual hook.
        def spawned(pid):
            metadata=dict(attempt['metadata'],pid=pid,pid_start=process_start(pid))
            with self.store.connection(True) as db:
                db.execute('UPDATE mail_delivery_attempts SET metadata=?,updated=? WHERE id=?',(encode(metadata),time.time(),attempt_id))
        try:
            self.native.submit(attempt_id,attempt['metadata']['sender'],row['recipient'],data,spawned)
        except (OSError,subprocess.SubprocessError,ClamShieldError):
            pass  # Native acceptance may already have happened. Reconcile only.
        return self.reconcile(attempt_id)

    def authorize_reinjection(self,request):
        """Internal hook only; kernel peer identity comes from mail_bridge.receive.

        Normal messages return None regardless of sender-supplied headers. A
        reserved native protocol must match one active, exact, unused attempt.
        """
        if not request.protocol.startswith(PROTOCOL):return None
        attempt_id=identifier(request.protocol[len(PROTOCOL):])
        if request.flags!=0 or request.remote_ip or request.peer_pid is None or request.peer_start is None:
            raise AccessDenied('Reinjection requires the journaled local native process')
        info=validate_snapshot(request.fd)
        with self.custody.locked() as root:
            with self.store.connection() as db:
                attempt=self._row(attempt_id,db)
                row=dict(db.execute('SELECT * FROM mail_recipients WHERE id=?',(attempt['recipient_id'],)).fetchone())
            meta=attempt['metadata']
            if (attempt['status']!='submitting' or row['status']!='delivery_pending' or meta.get('reinjection_id') or
                meta.get('pid')!=request.peer_pid or meta.get('pid_start')!=request.peer_start or
                process_start(request.peer_pid)!=request.peer_start or
                request.sender!=meta['sender'] or request.recipients!=(meta['recipient'],) or
                meta['recipient']!=row['recipient']):
                raise AccessDenied('Reinjection does not match its active native delivery attempt')
            context=self.hestia.authorize(row['owner'])
            if context['identity']!=row['identity']:raise AccessDenied('Native mail account changed')
            self.custody._validate_item({'context':context,'target':{key:row[key] for key in
                ('owner','identity','domain','mailbox','recipient')},'decision':json.loads(row['detail'])},row['recipient'])
            if meta['released']:self._release_authorized(row)
            expected=self._data(root,attempt);received=os.pread(request.fd,info.st_size,0)
            if not matches_reinjection(expected,received):
                raise Conflict('Reinjected email differs from the private approved send copy')
            updated=dict(meta,reinjection_id=request.message_id,reinjection_sha256=hashlib.sha256(received).hexdigest(),
                         reinjection_peer_pid=request.peer_pid,reinjection_seen_at=time.time())
            with self.store.connection(True) as db:
                changed=db.execute("UPDATE mail_delivery_attempts SET metadata=?,updated=? WHERE id=? AND status='submitting' AND metadata=?",
                                   (encode(updated),time.time(),attempt_id,encode(meta))).rowcount
                if changed!=1:raise Conflict('Native reinjection authorization was already used or changed')
                self.store.audit(context,'mail.reinjection_authorized',row['id'],{'attempt':attempt_id,'native_id':request.message_id},db)
            return {'authorized':True,'attempt':attempt_id,'native_id':request.message_id}

    def reconcile(self, attempt_id):
        with self.store.connection() as db:attempt=self._row(attempt_id,db)
        if attempt['status'] not in ('submitting','uncertain','native_queued'):
            return attempt['status']
        try:
            observed=self.native.observe(attempt_id,attempt['metadata']['checkpoint'],native_id=attempt['native_id'])
        except Conflict:
            observed={'state':'unknown','native_id':None,'conflict':True}
        except (OSError,EOFError,ClamShieldError):
            observed={'state':'unknown','native_id':None}
        state=observed['state'];error=None
        claimed=attempt['metadata'].get('reinjection_id')
        if claimed and observed['native_id'] and claimed!=observed['native_id']:
            observed={'state':'unknown','native_id':None,'conflict':True};state='unknown'
        if state=='unknown':
            if attempt['native_id'] and not observed.get('conflict'):
                state='native_queued';error='Native acceptance is recorded; completion is currently unverified'
            else:
                state='uncertain';error='Native acceptance is not yet proven; this attempt will not be resent'
        if attempt['native_id'] and observed['native_id'] and attempt['native_id']!=observed['native_id']:
            state='uncertain';error='Native delivery reference changed; manual reconciliation is required'
        recipient_status='delivery_uncertain' if state=='uncertain' else state
        with self.store.connection(True) as db:
            db.execute('UPDATE mail_delivery_attempts SET status=?,native_id=COALESCE(native_id,?),error=?,updated=? WHERE id=?',
                       (state,observed['native_id'],error,time.time(),attempt_id))
            db.execute('UPDATE mail_recipients SET status=?,error=?,updated=? WHERE id=?',
                       (recipient_status,error,time.time(),attempt['recipient_id']))
            row=db.execute('SELECT owner,identity FROM mail_recipients WHERE id=?',(attempt['recipient_id'],)).fetchone()
            if state!=attempt['status']:
                self.store.audit({'actor':'clamshield-mail','owner':row['owner'],'identity':row['identity']},
                    'mail.delivery_'+state,attempt['recipient_id'],{'attempt':attempt_id,'native_id':observed['native_id']},db)
        return state

    def once(self):
        from .mail_runtime import may_deliver
        if not may_deliver(self.settings):return self.recover()|{'mail_integration_inactive':True}
        with self.locked():
            self._recover_preparations()
            with self.store.connection() as db:
                pending=[row['id'] for row in db.execute("SELECT id FROM mail_delivery_attempts WHERE status IN ('submitting','uncertain','native_queued') ORDER BY created LIMIT 100")]
                prepared=db.execute("SELECT id FROM mail_delivery_attempts WHERE status='prepared' ORDER BY created LIMIT 1").fetchone()
            for attempt in pending:self.reconcile(attempt)
            attempt=prepared['id'] if prepared else self.prepare()
            try:
                state=self.submit(attempt) if attempt else None
            except (OSError,ClamShieldError):
                # A controller can gate between preparation and submission.
                # Retain the prepared attempt for resumption after refresh.
                if not may_deliver(self.settings):
                    return {'attempt':attempt,'state':'prepared','mail_integration_inactive':True}
                with self.store.connection(True) as db:
                    row=self._row(attempt,db)
                    if row['status']!='prepared':raise
                    db.execute("UPDATE mail_delivery_attempts SET status='preparation_failed',error=?,updated=? WHERE id=?",('Delivery validation changed before native submission',time.time(),attempt))
                    db.execute("UPDATE mail_recipients SET status='native_failed',error=?,updated=? WHERE id=?",('Delivery validation changed; not submitted',time.time(),row['recipient_id']))
                state='preparation_failed'
            if state=='native_queued':
                with self.store.connection() as db:row=self._row(attempt,db)
                try:self.native.run_queue(row['native_id'])
                except (OSError,subprocess.SubprocessError,ClamShieldError):pass
                state=self.reconcile(attempt)
            cleanup=MailCleanup(self.settings,self.store,self.hestia).once()
            return {'attempt':attempt,'state':state,'reconciled':len(pending)}|cleanup

    def recover(self):
        try:
            with self.locked():
                result=self._recover_preparations()
                with self.store.connection() as db:
                    pending=[row['id'] for row in db.execute("SELECT id FROM mail_delivery_attempts WHERE status IN ('submitting','uncertain','native_queued') ORDER BY created LIMIT 100")]
                for attempt in pending:self.reconcile(attempt)
                return result|{'mail_deliveries_reconciled':len(pending)}|MailCleanup(self.settings,self.store,self.hestia).once()
        except BlockingIOError:
            return {'mail_delivery_worker_busy':True}
