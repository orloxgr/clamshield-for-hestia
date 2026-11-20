"""Scoped, revocable quarantine expiry through the ordinary custody journal."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat
import time

from .errors import AccessDenied, ClamShieldError, Conflict
from .mail_custody import MailCustody, identifier
from .mail_policy import MailPolicies
from .store import encode


class NotDue(Conflict):
    pass


def days(value):
    if not isinstance(value, dict) or set(value) != {'days'} or type(value['days']) is not int or not 0 <= value['days'] <= 3650:
        raise ClamShieldError('Choose an integer retention period from 0 to 3650 days; zero keeps mail until manual deletion')
    return value['days']


class MailRetention:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.custody = MailCustody(settings, store, hestia)
        self.policies = MailPolicies(store, hestia)

    def authorize(self, context, domain=None, mailbox=''):
        context = self.custody.authorize(context)
        if domain is not None:
            target, mailbox = self.policies.target(context, domain, mailbox)
            return context, target['domain'], mailbox
        return context

    def manage(self, context):
        if not context['admin'] and not self.policies.permissions(context)['delete']:
            raise AccessDenied('Email deletion permission is required to manage quarantine expiry')

    def saved(self, context, domain, mailbox, db):
        def row(box):
            item = db.execute('SELECT * FROM mail_retention_policies WHERE owner=? AND identity=? AND domain=? AND mailbox=?',
                              (*self.store.scope(context), domain, box)).fetchone()
            return dict(item) if item else None
        parent = row(''); override = row(mailbox) if mailbox else parent
        selected = override if override is not None else parent
        revision = hashlib.sha256(encode([*self.store.scope(context), domain, mailbox, parent, override]).encode()).hexdigest()
        return parent, override, selected, revision

    def summary(self, context, domain, mailbox, period, db, now):
        rows = db.execute('''SELECT COUNT(*) AS quarantined,
          COALESCE(SUM(r.created+?*86400<=?),0) AS due,
          COALESCE(SUM(r.created+?*86400<=? AND t.status='committed' AND (a.status IS NULL OR a.status='accepted')),0) AS eligible,
          MIN(r.created+?*86400) AS next_expiry
          FROM mail_recipients r JOIN mail_transactions t ON t.id=r.transaction_id
          LEFT JOIN mail_acceptance a ON a.transaction_id=t.id
          WHERE r.owner=? AND r.identity=? AND r.domain=? AND (?='' OR r.mailbox=?) AND r.status='quarantined' ''',
          (period, now, period, now, period, *self.store.scope(context), domain, mailbox, mailbox)).fetchone()
        value = dict(rows)
        if not period:value.update(due=0, eligible=0, next_expiry=None)
        value['held'] = value['due'] - value['eligible']
        return value

    def get(self, context, domain, mailbox='', *, proposed=None, now=None):
        if domain is None:raise AccessDenied('Choose a mail domain')
        context, domain, mailbox = self.authorize(context, domain, mailbox)
        with self.store.connection() as db:
            parent, override, selected, revision = self.saved(context, domain, mailbox, db)
            period = selected['days'] if selected else 0
            summary = self.summary(context, domain, mailbox, period if proposed is None else days(proposed), db, time.time() if now is None else now)
        return dict(domain=domain, mailbox=mailbox, effective_days=period,
                    parent_days=parent['days'] if parent else 0,
                    override_days=override['days'] if override else None,
                    inherited=bool(mailbox and override is None), revision=revision, summary=summary,
                    preview_days=period if proposed is None else days(proposed),
                    can_manage=context['admin'] or self.policies.permissions(context)['delete'])

    def save(self, context, domain, mailbox, value, revision):
        if domain is None:raise AccessDenied('Choose a mail domain')
        context, domain, mailbox = self.authorize(context, domain, mailbox)
        self.manage(context)
        inherit = isinstance(value, dict) and value == {'inherit': True} and type(value.get('inherit')) is bool
        if inherit and not mailbox:raise ClamShieldError('Only a mailbox can inherit its domain retention')
        period = None if inherit else days(value)
        with self.custody.locked(), self.store.connection(True) as db:
            context, domain, mailbox = self.authorize(context, domain, mailbox); self.manage(context)
            _parent, _override, _selected, actual = self.saved(context, domain, mailbox, db)
            if not isinstance(revision, str) or revision != actual:
                raise Conflict('Quarantine retention changed. Reload it before saving.')
            authority = dict(actor=context['actor'], actor_identity=self.hestia.identity(context['actor']), admin=context['admin'])
            if inherit:
                db.execute('DELETE FROM mail_retention_policies WHERE owner=? AND identity=? AND domain=? AND mailbox=?',
                           (*self.store.scope(context), domain, mailbox))
            else:
                db.execute('''INSERT INTO mail_retention_policies VALUES(?,?,?,?,?,?,?)
                  ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET days=excluded.days,updated=excluded.updated,authority=excluded.authority''',
                  (*self.store.scope(context), domain, mailbox, period, time.time(), encode(authority)))
            self.store.audit(context, 'mail.retention_inherited' if inherit else 'mail.retention_saved', domain + ('/' + mailbox if mailbox else ''),
                             {'days': period, 'existing_quarantine_included': True}, db)
        return self.get(context, domain, mailbox)

    def authority(self, selected):
        who = json.loads(selected['authority'])
        context = self.hestia.authorize(who['actor'], selected['owner'])
        if (context['identity'] != selected['identity'] or context['admin'] != who['admin'] or
                self.hestia.identity(who['actor']) != who['actor_identity']):
            raise AccessDenied('The account that authorized expiry changed; save the policy again')
        self.manage(context)
        return context

    def prepare(self, context, row, transaction, db, now):
        """Called inside custody's lock/DB commit immediately before deletion."""
        _parent, _override, selected, revision = self.saved(context, row['domain'], row['mailbox'], db)
        if not selected or not selected['days'] or row['created'] + selected['days'] * 86400 > now:
            raise NotDue('Quarantine expiry is disabled or this message is not due')
        live = self.authority(selected)
        if any(live[key] != context[key] for key in ('actor', 'owner', 'identity', 'admin')):
            raise Conflict('Quarantine expiry authority changed')
        self.custody._validate_item({'context': live, 'target': {key: row[key] for key in
            ('owner', 'identity', 'domain', 'mailbox', 'recipient')}, 'decision': row['detail']}, row['recipient'])
        metadata = dict(transaction_id=transaction['id'], sha256=transaction['sha256'], size=transaction['size'],
                        domain=row['domain'], mailbox=row['mailbox'], days=selected['days'],
                        deadline=row['created']+selected['days']*86400, policy_revision=revision,
                        authority=json.loads(selected['authority']))
        old = db.execute('SELECT status FROM mail_expiry_actions WHERE recipient_id=?', (row['id'],)).fetchone()
        if old and old['status'] not in ('blocked',):
            raise Conflict('Quarantine expiry already has a committed action')
        db.execute('''INSERT INTO mail_expiry_actions VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(recipient_id) DO UPDATE SET updated=excluded.updated,status=excluded.status,metadata=excluded.metadata,error=NULL''',
          (row['id'], *self.store.scope(context), now, now, 'deleting', encode(metadata), None))
        self.store.audit(context | {'actor': 'clamshield-retention'}, 'mail.expiry_requested', row['id'], metadata, db)

    def validate_action(self, row, transaction, db):
        action = db.execute('SELECT * FROM mail_expiry_actions WHERE recipient_id=?', (row['id'],)).fetchone()
        if not action or action['status'] == 'blocked':return None
        if action['status'] != 'deleting':raise Conflict('Quarantine expiry journal state changed')
        metadata = json.loads(action['metadata'])
        if (action['owner'], action['identity']) != (row['owner'], row['identity']) or any(
                metadata[key] != transaction[key] for key in ('sha256', 'size')) or metadata['transaction_id'] != transaction['id']:
            raise Conflict('Quarantine expiry identity changed')
        return metadata

    def finish(self, row, transaction, db):
        metadata = self.validate_action(row, transaction, db)
        if metadata is None:return
        db.execute("UPDATE mail_expiry_actions SET status='expired',updated=?,error=NULL WHERE recipient_id=? AND status='deleting'", (time.time(), row['id']))
        self.store.audit(dict(actor='clamshield-retention', owner=row['owner'], identity=row['identity']),
                         'mail.expired', row['id'], metadata, db)

    def block(self, row, message, now):
        with self.store.connection(True) as db:
            current = db.execute('SELECT status FROM mail_recipients WHERE id=? AND owner=? AND identity=?',
                                 (row['id'], row['owner'], row['identity'])).fetchone()
            if not current or current['status'] not in ('quarantined', 'deleting'):return False
            old = db.execute('SELECT status,error FROM mail_expiry_actions WHERE recipient_id=?', (row['id'],)).fetchone()
            db.execute('''INSERT INTO mail_expiry_actions VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(recipient_id)
              DO UPDATE SET updated=excluded.updated,error=excluded.error''',
              (row['id'], row['owner'], row['identity'], now, now, 'blocked', encode({'domain': row['domain'], 'mailbox': row['mailbox']}), message))
            if not old or old['error'] != message:
                context = dict(actor='clamshield-retention', owner=row['owner'], identity=row['identity'])
                self.store.audit(context, 'mail.expiry_blocked', row['id'], {'message': message}, db)
                self.store.notify(row['owner'], row['identity'], 'mail.expiry_blocked', row['id'], {'message': message}, 'expiry:' + row['id'] + ':' + message, db=db)
        return True

    @contextmanager
    def locked(self):
        self.settings.prepare()
        fd = os.open(self.settings.state/'mail-retention.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise AccessDenied('Quarantine expiry lock is not protected')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
        finally:os.close(fd)

    @contextmanager
    def budget(self):
        previous = self.hestia.deadline
        deadline = time.monotonic()+5
        self.hestia.deadline = min(previous, deadline) if previous is not None else deadline
        try:yield
        finally:self.hestia.deadline = previous

    def once(self, *, now=None, limit=50):
        now = time.time() if now is None else now
        if type(now) not in (int, float) or not 0 <= now <= 32503680000 or type(limit) is not int or not 1 <= limit <= 100:
            raise ClamShieldError('Invalid internal expiry batch')
        try:
            with self.locked(), self.budget():
                with self.store.connection() as db:
                    rows = [dict(row) for row in db.execute('''SELECT r.* FROM mail_recipients r
                      LEFT JOIN mail_retention_policies d ON d.owner=r.owner AND d.identity=r.identity AND d.domain=r.domain AND d.mailbox=''
                      LEFT JOIN mail_retention_policies m ON m.owner=r.owner AND m.identity=r.identity AND m.domain=r.domain AND m.mailbox=r.mailbox AND r.mailbox<>''
                      LEFT JOIN mail_expiry_actions a ON a.recipient_id=r.id
                      WHERE r.status='quarantined' AND COALESCE(m.days,d.days,0)>0
                      AND r.created+COALESCE(m.days,d.days,0)*86400<=?
                      AND (a.recipient_id IS NULL OR a.status<>'blocked' OR a.updated<=?)
                      ORDER BY r.created,r.id LIMIT ?''', (now, now-60, limit))]
                expired = blocked = considered = 0; started = time.monotonic()
                for row in rows:
                    if considered and time.monotonic()-started > 5:break
                    considered += 1
                    try:
                        scope = dict(owner=row['owner'], identity=row['identity'])
                        with self.store.connection() as db:_parent, _override, selected, _revision = self.saved(scope, row['domain'], row['mailbox'], db)
                        if not selected or not selected['days'] or row['created']+selected['days']*86400>now:continue
                        context = self.authority(selected)
                        self.custody.delete(context, row['id'], expiry=(self, now)); expired += 1
                    except NotDue:
                        continue
                    except (OSError, ValueError, KeyError, TypeError, ClamShieldError) as exc:
                        message = str(exc)[:300] if isinstance(exc, ClamShieldError) else 'Quarantine expiry needs review; retained content was preserved'
                        if self.block(row, message, now):blocked += 1
                return dict(mail_expired=expired, mail_expiry_blocked=blocked, mail_expiry_considered=considered,
                            mail_expiry_more=len(rows)==limit or considered<len(rows))
        except BlockingIOError:return dict(mail_expiry_busy=True)

    def history(self, context, search='', offset=0):
        context = self.authorize(context)
        if not isinstance(search, str) or len(search)>300 or type(offset) is not int or not 0<=offset<=10000000:
            raise ClamShieldError('Invalid quarantine expiry search')
        query = ''' FROM mail_expiry_actions a JOIN mail_recipients r ON r.id=a.recipient_id
          WHERE a.owner=? AND a.identity=? AND (instr(r.recipient,?)>0 OR instr(a.recipient_id,?)>0)'''
        values = (*self.store.scope(context), search, search)
        with self.store.connection() as db:
            count = db.execute('SELECT COUNT(*)'+query, values).fetchone()[0]
            rows = db.execute('''SELECT a.recipient_id,a.created,a.updated,a.status,a.error,r.recipient,r.status AS custody_status,
              r.error AS custody_error,json_extract(a.metadata,'$.deadline') AS deadline,
              json_extract(a.metadata,'$.days') AS days'''+query+' ORDER BY a.updated DESC,a.recipient_id LIMIT 100 OFFSET ?', (*values, offset)).fetchall()
        return dict(total=count, actions=[dict(row) for row in rows], next_offset=offset+len(rows) if offset+len(rows)<count else None,
                    can_manage=context['admin'] or self.policies.permissions(context)['delete'])

    def retry(self, context, recipient_id):
        context = self.authorize(context); self.manage(context)
        with self.custody.locked(), self.store.connection(True) as db:
            context = self.authorize(context); self.manage(context)
            row = db.execute('''SELECT a.status FROM mail_expiry_actions a JOIN mail_recipients r ON r.id=a.recipient_id
              WHERE a.recipient_id=? AND a.owner=? AND a.identity=? AND r.status IN ('quarantined','deleting')''',
                             (identifier(recipient_id), *self.store.scope(context))).fetchone()
            if not row or row['status'] not in ('blocked', 'deleting'):
                raise AccessDenied('No retryable quarantine expiry is available')
            db.execute('UPDATE mail_expiry_actions SET updated=0 WHERE recipient_id=?', (recipient_id,))
            self.store.audit(context, 'mail.expiry_retry_requested', recipient_id, {}, db)
        return dict(retry_queued=True)

    def annotate(self, context, messages):
        with self.store.connection() as db:
            policies = {(row['domain'], row['mailbox']): row['days'] for row in db.execute(
                'SELECT domain,mailbox,days FROM mail_retention_policies WHERE owner=? AND identity=?', self.store.scope(context))}
        for row in messages:
            period = policies.get((row['domain'], row['mailbox']), policies.get((row['domain'], ''), 0))
            row['expiry_at'] = row['created']+period*86400 if period and row['status']=='quarantined' else None
