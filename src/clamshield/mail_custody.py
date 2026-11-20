"""Durable private message custody, scoped quarantine and release queue.

Stage/commit are internal mail-service operations. They are never browser API
actions. A prepared transaction is not accepted mail and cannot be delivered.
"""
from contextlib import contextmanager
import email.header
import email.errors
import email.parser
import email.policy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .errors import AccessDenied, ClamShieldError, Conflict
from .mail_bridge import validate_snapshot
from .mail_inventory import resolve
from .mail_policy import MailPolicies, transaction_plan
from .paths import attributes, directory
from .quarantine import rename_noreplace
from .store import encode

TERMINAL = ('deleted', 'delivered')
VIEWABLE = ('quarantined', 'release_queued', 'ready', 'delivery_uncertain',
            'delivery_preparing', 'delivery_pending', 'native_queued', 'native_failed')


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value):
        raise AccessDenied('Invalid mail custody identifier')
    return value


def digest(fd):
    hasher = hashlib.sha256(); at = 0
    while chunk := os.pread(fd, 1024 * 1024, at):
        hasher.update(chunk); at += len(chunk)
    return hasher.hexdigest(), at


class MailCustody:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.policies = MailPolicies(store, hestia)

    @contextmanager
    def locked(self, blocking=True):
        self.settings.prepare()
        with directory(self.settings.state.parent) as parent:
            os.fsync(parent)
        with directory(self.settings.state) as state:
            lock = os.open('mail-custody.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=state)
            try:
                info = os.fstat(lock)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise AccessDenied('Mail custody lock is not private')
                fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                try:
                    os.mkdir('mail-custody', 0o700, dir_fd=state)
                    os.fsync(state)
                except FileExistsError:
                    pass
                root = os.open('mail-custody', os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state)
                try:
                    info = os.fstat(root)
                    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                        raise AccessDenied('Mail custody directory is not private')
                    yield root
                finally:
                    os.close(root)
            finally:
                os.close(lock)

    def authorize(self, context):
        live = self.hestia.authorize(context['actor'], context['owner'])
        if live['identity'] != context['identity']:
            raise AccessDenied('Mail custody belongs to another account generation')
        return live

    def row(self, context, delivery_id, db):
        row = db.execute('SELECT * FROM mail_recipients WHERE id=? AND owner=? AND identity=?',
                         (identifier(delivery_id), *self.store.scope(context))).fetchone()
        if row is None:
            raise AccessDenied('Quarantined email unavailable')
        return dict(row) | {'detail': json.loads(row['detail'])}

    def transaction(self, transaction_id, db):
        row = db.execute('SELECT * FROM mail_transactions WHERE id=?', (identifier(transaction_id),)).fetchone()
        if row is None:
            raise Conflict('Mail transaction unavailable')
        return dict(row) | {'metadata': json.loads(row['metadata'])}

    @staticmethod
    def confirmed(transaction, db):
        acceptance = db.execute('SELECT status FROM mail_acceptance WHERE transaction_id=?',
                                (transaction['id'],)).fetchone()
        if transaction['status'] != 'committed' or (acceptance and acceptance['status'] != 'accepted'):
            raise Conflict('Mail server acceptance is unconfirmed; retained email requires review')

    @contextmanager
    def blob(self, root, transaction, suffix='.eml'):
        name = identifier(transaction['id']) + suffix
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            info = os.fstat(fd); expected = transaction['metadata'].get('fingerprint')
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o400 or not expected or
                    any(attributes(info)[key] != expected[key] for key in
                        ('device', 'inode', 'size', 'mtime_ns', 'uid', 'gid', 'mode', 'links')) or
                    digest(fd) != (transaction['sha256'], transaction['size'])):
                raise Conflict('Stored email content or identity changed')
            yield fd
        finally:
            os.close(fd)

    def _validate_item(self, item, recipient):
        decision=item.get('decision',{}) if isinstance(item,dict) else {}
        if decision.get('action') not in ('quarantine','junk','tag') and not (decision.get('action')=='deliver' and decision.get('capture') is True):
            raise ClamShieldError('Invalid mail custody selection')
        context, target = item['context'], item['target']
        live = self.hestia.authorize(context['owner'])
        if live['identity'] != context['identity']:
            raise AccessDenied('Native mail account changed or is unavailable')
        if (target['owner'], target['identity']) != self.store.scope(context) or target['recipient'] != recipient:
            raise AccessDenied('Mail custody target does not match its envelope')
        actual = resolve(self.policies.targets(context, target['domain']), recipient)
        if not actual or actual['suspended'] or any(actual[k] != target[k] for k in ('owner', 'identity', 'domain', 'mailbox')):
            raise AccessDenied('Native mail custody ownership changed')
        if item['decision'].get('scan_complete') is not True or len(encode(item['decision']).encode()) > 2 * 1024 * 1024:
            raise Conflict('Incomplete or oversized mail decision cannot enter custody')

    def stage(self, request, items):
        """Journal and durably capture before any SMTP handled/selected response.

        items aligns with the entire native envelope. Native-delivery items need
        only a decision; custody items also need native context/target fields.
        Rejection/defer never creates a capture, even with other custody actions.
        """
        if not isinstance(items, list) or len(items) != len(request.recipients):
            raise ClamShieldError('Mail custody decisions do not match the envelope')
        plan = transaction_plan([item['decision'] for item in items])
        if plan['smtp'] != 'accept' or not plan['custody']:
            raise Conflict('This transaction has no accepted recipient custody')
        snapshot = validate_snapshot(request.fd)
        sha256, size = digest(request.fd)
        if size != snapshot.st_size:
            raise Conflict('Mail snapshot size changed')
        metadata = {'envelope': {'message_id': request.message_id, 'sender': request.sender,
                    'recipients': list(request.recipients), 'remote_ip': request.remote_ip,
                    'authenticated_id': request.authenticated_id, 'protocol': request.protocol,
                    'flags': request.flags}, 'custody': plan['custody'], 'native': plan['native'],
                    'summary': safe_headers(os.pread(request.fd, 64 * 1024, 0))}
        for index in plan['custody']:
            self._validate_item(items[index], request.recipients[index])
        if sum(len(encode(items[i]['decision']).encode()) for i in plan['custody']) > 8 * 1024 * 1024:
            raise Conflict('Combined recipient decisions exceed the custody size limit')
        metadata['selection'] = [{key: items[i]['target'][key] for key in
                                  ('owner', 'identity', 'domain', 'mailbox', 'recipient')} |
                                 {'decision_sha256': hashlib.sha256(encode(items[i]['decision']).encode()).hexdigest()}
                                 for i in plan['custody']]
        key = hashlib.sha256(encode(metadata).encode()).hexdigest()
        metadata['request_key'] = key
        with self.locked() as root:
            with self.store.connection() as db:
                existing = db.execute('SELECT id FROM mail_transactions WHERE exim_id=?', (request.message_id,)).fetchone()
                if existing:
                    transaction = self.transaction(existing['id'], db)
                    if (transaction['sha256'], transaction['size'], transaction['metadata']['request_key']) != (sha256, size, key):
                        raise Conflict('Native mail reference was reused for different content or recipients')
                    if transaction['status'] not in ('prepared', 'committed'):
                        raise Conflict('Mail transaction needs recovery before it can be reused')
                    with self.blob(root, transaction):
                        return {'transaction_id': transaction['id'], 'custody': plan['custody'], 'native': plan['native']}
            transaction_id = uuid.uuid4().hex; now = time.time()
            with self.store.connection(True) as db:
                db.execute('INSERT INTO mail_transactions VALUES(?,?,?,?,?,?,?,?,?)',
                           (transaction_id, request.message_id, now, now, 'preparing', sha256, size, encode(metadata), None))
                for index in plan['custody']:
                    item = items[index]; target = item['target']; delivery_id = uuid.uuid4().hex
                    db.execute('INSERT INTO mail_recipients VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                               (delivery_id, transaction_id, *self.store.scope(item['context']), target['domain'], target['mailbox'],
                                target['recipient'], item['decision']['action'], 'preparing', now, now, '', encode(item['decision']), None))
                    self.store.audit(item['context'], 'mail.capture_preparing', delivery_id, {'exim_id': request.message_id}, db)
            partial = transaction_id + '.partial'
            out = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                at = 0
                while chunk := os.pread(request.fd, 1024 * 1024, at):
                    remaining = memoryview(chunk)
                    while remaining:
                        written = os.write(out, remaining)
                        if written <= 0:
                            raise OSError('Incomplete mail custody write')
                        remaining = remaining[written:]
                    at += len(chunk)
                os.fchmod(out, 0o400); os.fsync(out)
                metadata['fingerprint'] = attributes(os.fstat(out))
                with self.store.connection(True) as db:
                    db.execute('UPDATE mail_transactions SET metadata=?,updated=? WHERE id=?', (encode(metadata), time.time(), transaction_id))
                rename_noreplace(root, partial, root, transaction_id + '.eml'); os.fsync(root)
            finally:
                os.close(out)
            self._prepared(transaction_id)
            return {'transaction_id': transaction_id, 'custody': plan['custody'], 'native': plan['native']}

    def _prepared(self, transaction_id):
        with self.store.connection(True) as db:
            db.execute("UPDATE mail_transactions SET status='prepared',updated=?,error=NULL WHERE id=? AND status='preparing'", (time.time(), transaction_id))
            db.execute("UPDATE mail_recipients SET status='prepared',updated=? WHERE transaction_id=? AND status='preparing'", (time.time(), transaction_id))

    def commit(self, transaction_id):
        """Internal acceptance boundary; prepared recovery never calls this."""
        with self.locked() as root:
            with self.store.connection() as db:
                transaction = self.transaction(transaction_id, db)
                rows = [dict(r) for r in db.execute('SELECT * FROM mail_recipients WHERE transaction_id=?', (transaction_id,))]
                transport=db.execute('SELECT status FROM mail_acceptance WHERE transaction_id=?',(transaction_id,)).fetchone()
            if transport and transport['status'] not in ('proven','accepted'):
                raise Conflict('Native SMTP acceptance is not proven; custody cannot be committed')
            if transaction['status'] not in ('prepared', 'committed'):
                raise Conflict('Mail capture is not prepared for acceptance')
            for row in rows:
                context = {'actor': 'clamshield-mail', 'owner': row['owner'], 'identity': row['identity'], 'admin': False}
                self._validate_item({'context': context, 'target': {k: row[k] for k in
                                    ('owner', 'identity', 'domain', 'mailbox', 'recipient')},
                                    'decision': json.loads(row['detail'])}, row['recipient'])
            with self.blob(root, transaction):
                pass
            if transaction['status'] == 'committed':
                return {'committed': True, 'transaction_id': transaction_id}
            with self.store.connection(True) as db:
                db.execute("UPDATE mail_transactions SET status='committed',updated=? WHERE id=?", (time.time(), transaction_id))
                for row in rows:
                    state = 'quarantined' if row['action'] == 'quarantine' else 'ready'
                    db.execute('UPDATE mail_recipients SET status=?,updated=? WHERE id=?', (state, time.time(), row['id']))
                    context = {'actor': 'clamshield-mail', 'owner': row['owner'], 'identity': row['identity']}
                    self.store.audit(context, 'mail.captured', row['id'], {'action': row['action'], 'exim_id': transaction['exim_id']}, db)
            return {'committed': True, 'transaction_id': transaction_id}

    def abort(self, transaction_id):
        """Internal cancellation of a fully prepared, never-accepted capture."""
        with self.locked() as root:
            with self.store.connection(True) as db:
                transaction = self.transaction(transaction_id, db)
                transport=db.execute('SELECT status FROM mail_acceptance WHERE transaction_id=?',(transaction_id,)).fetchone()
                if transport and transport['status']!='rejected':
                    raise Conflict('Native SMTP outcome is not a proven rejection; capture cannot be aborted')
                if transaction['status'] != 'prepared':
                    raise Conflict('Only a prepared, unaccepted mail transaction can be aborted')
                with self.blob(root, transaction):
                    pass
                db.execute("UPDATE mail_transactions SET status='aborting',updated=? WHERE id=?", (time.time(), transaction_id))
                db.execute("UPDATE mail_recipients SET status='aborting',updated=? WHERE transaction_id=? AND status='prepared'", (time.time(), transaction_id))
            self._finish_abort(root, transaction)
        return {'aborted': True}

    def _finish_abort(self, root, transaction):
        with self.store.connection() as db:
            latest = self.transaction(transaction['id'], db)
            active = db.execute("SELECT 1 FROM mail_recipients WHERE transaction_id=? AND status NOT IN ('aborting','aborted') LIMIT 1", (transaction['id'],)).fetchone()
        if latest['status'] != 'aborting' or active:
            raise Conflict('Mail cancellation journal is inconsistent; no content was removed')
        try:
            with self.blob(root, transaction):
                pass
        except FileNotFoundError:
            pass  # Journaled cancellation may have already unlinked its own blob.
        else:
            os.unlink(transaction['id'] + '.eml', dir_fd=root); os.fsync(root)
        with self.store.connection(True) as db:
            rows = db.execute('SELECT id,owner,identity FROM mail_recipients WHERE transaction_id=?', (transaction['id'],)).fetchall()
            db.execute("UPDATE mail_transactions SET status='aborted',updated=? WHERE id=? AND status='aborting'", (time.time(), transaction['id']))
            db.execute("UPDATE mail_recipients SET status='aborted',updated=? WHERE transaction_id=? AND status='aborting'", (time.time(), transaction['id']))
            for row in rows:
                context = {'actor': 'clamshield-mail', 'owner': row['owner'], 'identity': row['identity']}
                self.store.audit(context, 'mail.capture_aborted', row['id'], {}, db)

    def list(self, context, search='', offset=0):
        context = self.authorize(context)
        if not isinstance(search, str) or len(search) > 300 or type(offset) is not int or not 0 <= offset <= 10000000:
            raise ClamShieldError('Invalid mail quarantine search')
        query = ''' FROM mail_recipients r JOIN mail_transactions t ON t.id=r.transaction_id
          LEFT JOIN mail_acceptance a ON a.transaction_id=t.id
          WHERE r.owner=? AND r.identity=? AND r.status NOT IN ('deleted','aborted')
          AND (instr(r.recipient,?)>0 OR instr(t.exim_id,?)>0
            OR instr(json_extract(t.metadata,'$.envelope.sender'),?)>0
            OR instr(COALESCE(json_extract(t.metadata,'$.summary.Subject'),''),?)>0)'''
        values = (*self.store.scope(context), search, search, search, search)
        with self.store.connection() as db:
            count = db.execute('SELECT count(*)' + query, values).fetchone()[0]
            rows = db.execute('''SELECT r.id,r.domain,r.mailbox,r.recipient,r.action,r.status,r.created,r.updated,r.note,r.error,
              t.exim_id,t.sha256,t.size,json_extract(t.metadata,'$.envelope.sender') AS sender,
              json_extract(t.metadata,'$.summary.Subject') AS subject,
              a.status AS source_status,a.error AS source_error''' + query + ' ORDER BY r.created DESC,r.id LIMIT 100 OFFSET ?', (*values, offset)).fetchall()
        from .mail_retention import MailRetention
        messages = [dict(row) for row in rows]
        MailRetention(self.settings, self.store, self.hestia).annotate(context, messages)
        return {'total': count, 'messages': messages,
                'next_offset': offset + len(rows) if offset + len(rows) < count else None,
                'permissions': self.policies.permissions(context)}

    def preview(self, context, delivery_id):
        context = self.authorize(context)
        with self.locked() as root:
            with self.store.connection() as db:
                row = self.row(context, delivery_id, db); transaction = self.transaction(row['transaction_id'], db)
            if row['status'] not in VIEWABLE:
                raise Conflict('This email is not available for quarantine preview')
            with self.blob(root, transaction) as fd:
                prefix = os.pread(fd, 256 * 1024, 0)
        preview = safe_preview(prefix, transaction['size'])
        return {'id': row['id'], 'recipient': row['recipient'], 'sha256': transaction['sha256'],
                'domain': row['domain'], 'mailbox': row['mailbox'],
                'size': transaction['size'], 'status': row['status'], 'decision': row['detail'], **preview}

    def add_exception(self, context, delivery_id, value):
        """Derive content and recipient scope from verified private custody."""
        context = self.authorize(context)
        if not isinstance(value, dict) or set(value) != {'engine', 'signature', 'expires', 'reason'}:
            raise ClamShieldError('Choose a detected signature, expiry and false-positive reason')
        with self.locked() as root:
            with self.store.connection() as db:
                row = self.row(context, delivery_id, db)
                transaction = self.transaction(row['transaction_id'], db)
                acceptance = db.execute('SELECT status FROM mail_acceptance WHERE transaction_id=?',
                                        (transaction['id'],)).fetchone()
            if row['status'] != 'quarantined' or transaction['status'] != 'committed' or (acceptance and acceptance['status'] != 'accepted'):
                raise Conflict('Only accepted quarantined email can create a false-positive exception')
            if not any(hit.get('engine') == value['engine'] and hit.get('signature') == value['signature']
                       for hit in row['detail'].get('detections', [])):
                raise AccessDenied('Choose a signature recorded for this recipient')
            self._validate_item({'context': context, 'target': {k: row[k] for k in
                ('owner', 'identity', 'domain', 'mailbox', 'recipient')}, 'decision': row['detail']}, row['recipient'])
            with self.blob(root, transaction):
                return self.policies.change_exception(context, row['domain'], row['mailbox'], 'add',
                    value | {'sha256': transaction['sha256']}, source=row['id'])

    def queue_release(self, context, delivery_id, note):
        context = self.authorize(context)
        from .mail_runtime import mode
        if not context['admin'] and not self.policies.permissions(context)['release']:
            raise AccessDenied('Email release is disabled for this account')
        if not isinstance(note, str) or not note.strip() or len(note) > 1000:
            raise ClamShieldError('Record a reason for releasing this email')
        with self.locked() as root:
            with self.store.connection() as db:
                row = self.row(context, delivery_id, db); transaction = self.transaction(row['transaction_id'], db)
                self.confirmed(transaction, db)
            if row['status'] != 'quarantined':
                raise Conflict('Only quarantined email can be released')
            if mode(self.settings) not in ('legacy','active'):
                raise Conflict('Enable mail integration before releasing retained email')
            self._validate_item({'context': context, 'target': {k: row[k] for k in
                                ('owner', 'identity', 'domain', 'mailbox', 'recipient')}, 'decision': row['detail']}, row['recipient'])
            with self.blob(root, transaction):
                pass
            with self.store.connection(True) as db:
                db.execute("UPDATE mail_recipients SET status='release_queued',updated=?,note=? WHERE id=? AND owner=? AND identity=?", (time.time(), note, row['id'], *self.store.scope(context)))
                self.store.audit(context, 'mail.release_queued', row['id'],
                                 {'reason': note, 'sha256': transaction['sha256'],
                                  'actor_identity': self.hestia.identity(context['actor'])}, db)
            return {'queued': True, 'id': row['id']}

    def delete(self, context, delivery_id, *, expiry=None):
        context = self.authorize(context)
        if not context['admin'] and not self.policies.permissions(context)['delete']:
            raise AccessDenied('Email deletion is disabled for this account')
        with self.locked() as root:
            with self.store.connection(True) as db:
                row = self.row(context, delivery_id, db)
                if row['status'] != 'quarantined':
                    raise Conflict('Only quarantined email can be deleted')
                transaction = self.transaction(row['transaction_id'], db)
                self.confirmed(transaction, db)
                with self.blob(root, transaction):
                    pass
                if expiry is not None:
                    manager, now = expiry
                    manager.prepare(context, row, transaction, db, now)
                db.execute("UPDATE mail_recipients SET status='deleting',updated=? WHERE id=? AND owner=? AND identity=?", (time.time(), row['id'], *self.store.scope(context)))
                self.store.audit(context, 'mail.delete_requested', row['id'], {}, db)
            self._finish_delete(root, row)
        return {'deleted': True, 'id': row['id']}

    def _finish_delete(self, root, row):
        with self.store.connection() as db:
            current = db.execute('SELECT * FROM mail_recipients WHERE id=?', (row['id'],)).fetchone()
            if (not current or current['status'] != 'deleting' or
                    any(current[key] != row[key] for key in ('transaction_id', 'owner', 'identity'))):
                raise Conflict('Mail deletion journal changed; no content was removed')
            transaction = self.transaction(row['transaction_id'], db)
            self.confirmed(transaction, db)
            from .mail_retention import MailRetention
            retention = MailRetention(self.settings, self.store, self.hestia)
            retention.validate_action(row, transaction, db)
            other = db.execute("SELECT 1 FROM mail_recipients WHERE transaction_id=? AND id<>? AND status NOT IN ('deleted','delivered') LIMIT 1", (row['transaction_id'], row['id'])).fetchone()
        try:
            with self.blob(root, transaction):
                pass
        except FileNotFoundError:
            if other:
                raise Conflict('Stored email is missing while other recipients still need it')
            # A journaled last-recipient deletion may have already unlinked it.
        else:
            if not other:
                os.unlink(transaction['id'] + '.eml', dir_fd=root); os.fsync(root)
        with self.store.connection(True) as db:
            db.execute("UPDATE mail_recipients SET status='deleted',updated=?,error=NULL WHERE id=? AND status='deleting'", (time.time(), row['id']))
            if not other:
                db.execute("UPDATE mail_transactions SET status='purged',updated=? WHERE id=?", (time.time(), transaction['id']))
            context = {'actor': 'clamshield-recovery', 'owner': row['owner'], 'identity': row['identity']}
            self.store.audit(context, 'mail.deleted', row['id'], {}, db)
            retention.finish(row, transaction, db)

    def recover(self):
        recovered, failed = 0, 0
        with self.locked() as root:
            with self.store.connection() as db:
                pending = [self.transaction(r['id'], db) for r in db.execute("SELECT id FROM mail_transactions WHERE status='preparing' LIMIT 100")]
                deleting = [dict(row) for row in db.execute("SELECT * FROM mail_recipients WHERE status='deleting' LIMIT 100")]
                aborting = [self.transaction(r['id'], db) for r in db.execute("SELECT id FROM mail_transactions WHERE status='aborting' LIMIT 100")]
            for transaction in pending:
                try:
                    try:
                        with self.blob(root, transaction):
                            pass
                    except FileNotFoundError:
                        with self.blob(root, transaction, '.partial'):
                            pass
                        rename_noreplace(root, transaction['id'] + '.partial', root, transaction['id'] + '.eml'); os.fsync(root)
                    self._prepared(transaction['id']); recovered += 1
                except (OSError, ClamShieldError):
                    with self.store.connection(True) as db:
                        db.execute("UPDATE mail_transactions SET status='capture_failed',updated=?,error=? WHERE id=?", (time.time(), 'Incomplete or changed private capture requires review', transaction['id']))
                        db.execute("UPDATE mail_recipients SET status='capture_failed',updated=?,error=? WHERE transaction_id=?", (time.time(), 'Mail was not accepted into custody', transaction['id']))
                    failed += 1
            for row in deleting:
                try:
                    self._finish_delete(root, row); recovered += 1
                except (OSError, ClamShieldError):
                    with self.store.connection(True) as db:
                        db.execute('UPDATE mail_recipients SET error=?,updated=? WHERE id=?', ('Email deletion is blocked; review mail acceptance and retained content', time.time(), row['id']))
                    failed += 1
            for transaction in aborting:
                try:
                    self._finish_abort(root, transaction); recovered += 1
                except (OSError, ClamShieldError):
                    with self.store.connection(True) as db:
                        db.execute('UPDATE mail_transactions SET error=?,updated=? WHERE id=?', ('Stored email changed; cancellation requires review', time.time(), transaction['id']))
                    failed += 1
        return {'mail_recovered': recovered, 'mail_recovery_failed': failed}


def clean_text(text, limit):
    return ''.join(c for c in str(text) if ord(c) >= 32 or c in '\n\t')[:limit]


def safe_headers(prefix):
    try:
        message = email.parser.BytesHeaderParser(policy=email.policy.default).parsebytes(prefix[:64 * 1024])
        return {key: clean_text(message.get(key, ''), 1000) for key in ('Subject', 'From', 'To', 'Date')}
    except (ValueError, TypeError, LookupError, RecursionError, IndexError, OverflowError, email.errors.MessageError):
        return {}


def safe_preview(prefix, total):
    """Bounded plaintext preview, never HTML, active content or attachment data."""
    prefix = prefix[:256 * 1024]
    try:
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(prefix)
        headers = safe_headers(prefix)
        text = ''; parts = [(message, 0)]; count = 0
        while parts:
            part, depth = parts.pop(); count += 1
            if count > 500 or depth > 30:
                raise ValueError('MIME preview limit')
            if part.get_content_disposition() == 'attachment' or part.get_filename() is not None:
                continue
            payload = part.get_payload()
            if part.get_content_maintype() == 'message':
                continue
            if isinstance(payload, list):
                parts.extend((child, depth + 1) for child in reversed(payload))
            elif part.get_content_type() == 'text/plain':
                raw = part.get_payload(decode=True) or b''
                try:
                    text = raw.decode(part.get_content_charset() or 'utf-8', errors='replace')
                except LookupError:
                    text = raw.decode('utf-8', errors='replace')
                break
        return {'headers': headers, 'text': clean_text(text, 128 * 1024),
                'truncated': total > len(prefix) or len(text) > 128 * 1024,
                'format': 'plain-text', 'available': True}
    except (ValueError, TypeError, LookupError, RecursionError, IndexError, OverflowError, email.errors.MessageError):
        return {'headers': {}, 'text': '', 'truncated': total > len(prefix),
                'format': 'plain-text', 'available': False}
