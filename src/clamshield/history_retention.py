"""Bounded scoped history pruning, retaining operational and deduplication proof."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat
import time
import uuid

from .errors import AccessDenied, ClamShieldError, Conflict
from .mail_custody import MailCustody
from .store import encode

DEFAULTS = dict(scan_days=0, mail_days=0, event_days=0)


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or any(type(v) is not int or not 0 <= v <= 3650 for v in value.values()):
        raise ClamShieldError('Choose whole retention periods from 0 to 3650 days; zero keeps history indefinitely')
    return dict(value)


class HistoryRetention:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.custody = MailCustody(settings, store, hestia)

    @contextmanager
    def locked(self, blocking=True):
        self.settings.prepare()
        fd = os.open(self.settings.state/'history-retention.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise AccessDenied('History retention lock is not private')
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)); yield
        finally:os.close(fd)

    def snapshot(self, context, db):
        scope = self.store.scope(context)
        row = db.execute('SELECT * FROM history_retention WHERE owner=? AND identity=?', scope).fetchone()
        permission = db.execute('SELECT allowed,revision FROM history_permissions WHERE owner=? AND identity=?', scope).fetchone()
        allowed = bool(permission['allowed']) if permission else True
        permission_revision = permission['revision'] if permission else 'default'
        value = dict(row) if row else None
        revision = hashlib.sha256(encode([*scope, value['revision'] if value else None, permission_revision]).encode()).hexdigest()
        return value, allowed, permission_revision, revision

    def jobs_query(self):
        # Keep headers/dedup keys. Files used by findings, repair/recheck or an
        # unfinished automatic action must not lose their detailed evidence.
        return ''' FROM jobs j WHERE j.owner=? AND j.identity=? AND j.finished IS NOT NULL
          AND j.finished<? AND j.status IN ('completed','partial','cancelled','failed')
          AND (COALESCE(json_extract(j.counters,'$.history_expired'),0)=0 OR COALESCE(json_extract(j.counters,'$.history_prune_pending'),0)=1)
          AND NOT EXISTS(SELECT 1 FROM findings f WHERE f.job_id=j.id)
          AND NOT EXISTS(SELECT 1 FROM repair_plans p WHERE p.id=j.id OR instr(p.metadata,j.id)>0 OR instr(COALESCE(j.dedup_key,''),p.id)>0)
          AND NOT EXISTS(SELECT 1 FROM operations o WHERE instr(o.metadata,j.id)>0 OR instr(COALESCE(j.dedup_key,''),o.id)>0)
          AND NOT EXISTS(SELECT 1 FROM remediation_actions a WHERE a.job_id=j.id OR instr(a.detail,j.id)>0)
          AND NOT EXISTS(SELECT 1 FROM remediation_scans r WHERE r.job_id=j.id AND r.finished=0)'''

    def decisions_query(self):
        return ''' FROM mail_decisions d WHERE d.owner=? AND d.identity=? AND d.created<?
          AND json_extract(d.detail,'$.smtp_outcome') IN ('accepted','reject','defer')
          AND NOT EXISTS(SELECT 1 FROM mail_transactions t LEFT JOIN mail_acceptance a ON a.transaction_id=t.id
            WHERE t.exim_id=d.exim_id AND (t.status NOT IN ('purged','aborted') OR
              (a.status IS NOT NULL AND a.status NOT IN ('accepted','rejected')) OR
              EXISTS(SELECT 1 FROM mail_recipients r WHERE r.transaction_id=t.id AND r.status NOT IN ('delivered','deleted','aborted')) OR
              EXISTS(SELECT 1 FROM mail_recipients r JOIN mail_delivery_attempts x ON x.recipient_id=r.id
                WHERE r.transaction_id=t.id AND x.status NOT IN ('delivered')) OR
              EXISTS(SELECT 1 FROM mail_body_cleanup c WHERE c.status<>'purged' AND
                ((c.kind='source' AND c.subject=t.id) OR (c.kind='delivery' AND c.subject IN
                  (SELECT x.id FROM mail_delivery_attempts x JOIN mail_recipients r ON r.id=x.recipient_id WHERE r.transaction_id=t.id))))))'''

    def protected_subject(self, alias):
        return ' OR '.join('EXISTS(SELECT 1 FROM '+table+' p WHERE p.'+column+'='+alias+'.subject)' for table,column in
            (('jobs','id'),('findings','id'),('operations','id'),('repair_plans','id'),('remediation_actions','id'),
             ('mail_recipients','id'),('mail_transactions','id'),('mail_delivery_attempts','id'),('mail_decisions','id'),('maintenance','id')))

    def events_query(self, table, alias):
        extra = " AND "+alias+".read_at IS NOT NULL" if table == 'notifications' else ''
        return ' FROM '+table+' '+alias+' WHERE '+alias+'.owner=? AND '+alias+'.identity=? AND '+alias+'.created<?'+extra+' AND NOT ('+self.protected_subject(alias)+')'

    def counts(self, context, policy, db, now):
        result = dict(scan_reports=0, scan_file_rows=0, mail_decisions=0, audit_events=0, read_notifications=0)
        scope = self.store.scope(context)
        if policy['scan_days']:
            values = (*scope, now-policy['scan_days']*86400)
            result['scan_reports'] = db.execute('SELECT COUNT(*)'+self.jobs_query(), values).fetchone()[0]
            result['scan_file_rows'] = db.execute('SELECT COUNT(*) FROM file_results WHERE job_id IN (SELECT j.id'+self.jobs_query()+')', values).fetchone()[0]
        if policy['mail_days']:
            result['mail_decisions'] = db.execute('SELECT COUNT(*)'+self.decisions_query(), (*scope, now-policy['mail_days']*86400)).fetchone()[0]
        if policy['event_days']:
            values = (*scope, now-policy['event_days']*86400)
            result['audit_events'] = db.execute('SELECT COUNT(*)'+self.events_query('audit','a'), values).fetchone()[0]
            result['read_notifications'] = db.execute('SELECT COUNT(*)'+self.events_query('notifications','n'), values).fetchone()[0]
        return result

    def get(self, context, proposed=None):
        context = self.custody.authorize(context)
        with self.store.connection() as db:
            saved, allowed, _permission_revision, revision = self.snapshot(context, db)
            policy = validate(json.loads(saved['settings'])) if saved else dict(DEFAULTS)
            summary = self.counts(context, policy if proposed is None else validate(proposed), db, time.time())
        return dict(policy=policy, preview=summary, revision=revision, can_manage=context['admin'] or allowed,
                    user_allowed=allowed, last_run=saved['last_run'] if saved else None, error=saved['error'] if saved else None)

    def save(self, context, value, revision, *, reset=False):
        policy = dict(DEFAULTS) if reset else validate(value)
        with self.locked(), self.store.connection(True) as db:
            context = self.custody.authorize(context)
            _saved, allowed, permission_revision, actual = self.snapshot(context, db)
            if not context['admin'] and not allowed:raise AccessDenied('History retention changes are disabled by the administrator')
            if not isinstance(revision, str) or revision != actual:raise Conflict('History retention changed. Preview it again before saving.')
            if reset:db.execute('DELETE FROM history_retention WHERE owner=? AND identity=?', self.store.scope(context))
            else:
                authority = dict(actor=context['actor'], actor_identity=self.hestia.identity(context['actor']), admin=context['admin'], permission_revision=permission_revision)
                db.execute('''INSERT INTO history_retention VALUES(?,?,?,?,?,?,0,NULL) ON CONFLICT(owner,identity)
                  DO UPDATE SET settings=excluded.settings,updated=excluded.updated,revision=excluded.revision,authority=excluded.authority,error=NULL''',
                  (*self.store.scope(context), encode(policy), time.time(), uuid.uuid4().hex, encode(authority)))
            self.store.audit(context, 'history.retention_reset' if reset else 'history.retention_saved', context['owner'], policy, db)
        return self.get(context)

    def permission(self, context, allowed, revision):
        if type(allowed) is not bool:raise ClamShieldError('Choose whether the hosting user can change retention')
        with self.locked(), self.store.connection(True) as db:
            context = self.custody.authorize(context)
            if not context['admin']:raise AccessDenied('Administrator access required')
            if self.snapshot(context, db)[3] != revision:raise Conflict('History retention changed. Reload before changing permissions.')
            db.execute('INSERT INTO history_permissions VALUES(?,?,?,?) ON CONFLICT(owner,identity) DO UPDATE SET allowed=excluded.allowed,revision=excluded.revision',
                       (*self.store.scope(context), int(allowed), uuid.uuid4().hex))
            self.store.audit(context, 'history.permission_saved', context['owner'], {'allowed': allowed}, db)
        return self.get(context)

    def authority(self, saved, db):
        who = json.loads(saved['authority'])
        context = self.hestia.authorize(who['actor'], saved['owner'])
        if context['identity'] != saved['identity'] or context['admin'] != who['admin'] or self.hestia.identity(who['actor']) != who['actor_identity']:
            raise AccessDenied('History retention authorizing account changed; save the policy again')
        _row, allowed, revision, _cas = self.snapshot(context, db)
        if not context['admin'] and (not allowed or revision != who['permission_revision']):
            raise AccessDenied('History retention permission changed; save the policy again')
        return context

    def prune(self, context, policy, db, now):
        scope = self.store.scope(context); result = dict(scan_reports=0, scan_file_rows=0, mail_decisions=0, audit_events=0, read_notifications=0)
        if policy['scan_days']:
            row = db.execute('SELECT j.id,j.counters'+self.jobs_query()+' ORDER BY j.finished,j.id LIMIT 1', (*scope, now-policy['scan_days']*86400)).fetchone()
            if row:
                result['scan_file_rows'] = db.execute('DELETE FROM file_results WHERE id IN (SELECT id FROM file_results WHERE job_id=? ORDER BY id LIMIT 500)', (row['id'],)).rowcount
                pending = db.execute('SELECT 1 FROM file_results WHERE job_id=? LIMIT 1', (row['id'],)).fetchone() is not None
                counters = json.loads(row['counters']); counters.update(history_expired=True, history_prune_pending=pending)
                db.execute('UPDATE jobs SET counters=? WHERE id=?', (encode(counters), row['id']))
                db.execute('DELETE FROM wordpress_reports WHERE job_id=?', (row['id'],))
                result['scan_reports'] = int(not pending)
        if policy['mail_days']:
            result['mail_decisions'] = db.execute('DELETE FROM mail_decisions WHERE id IN (SELECT d.id'+self.decisions_query()+' ORDER BY d.created,d.id LIMIT 200)', (*scope, now-policy['mail_days']*86400)).rowcount
        if policy['event_days']:
            for table,alias,key in (('audit','a','audit_events'),('notifications','n','read_notifications')):
                result[key] = db.execute('DELETE FROM '+table+' WHERE id IN (SELECT '+alias+'.id'+self.events_query(table,alias)+' ORDER BY '+alias+'.created,'+alias+'.id LIMIT 200)', (*scope, now-policy['event_days']*86400)).rowcount
        return result

    def once(self):
        total = dict(history_accounts=0, history_blocked=0)
        previous = self.hestia.deadline
        self.hestia.deadline = min(previous, time.monotonic()+5) if previous is not None else time.monotonic()+5
        try:
            with self.locked(False), self.custody.locked(False):
                with self.store.connection() as db:
                    candidates = [dict(row) for row in db.execute("SELECT * FROM history_retention WHERE settings<>? ORDER BY last_run,updated LIMIT 10", (encode(DEFAULTS),))]
                for saved in candidates:
                    now = time.time()
                    try:
                        with self.store.connection(True) as db:
                            context = self.authority(saved, db); policy = validate(json.loads(saved['settings']))
                            result = self.prune(context, policy, db, now)
                            db.execute('UPDATE history_retention SET last_run=?,error=NULL WHERE owner=? AND identity=?', (now,*self.store.scope(context)))
                            if any(result.values()):self.store.audit(context | {'actor': 'clamshield-history'}, 'history.pruned', context['owner'], result, db)
                        total['history_accounts'] += 1
                        for key,value in result.items():total[key] = total.get(key,0)+value
                    except (OSError, ValueError, KeyError, ClamShieldError):
                        with self.store.connection(True) as db:
                            db.execute('UPDATE history_retention SET last_run=?,error=? WHERE owner=? AND identity=?',
                                       (now,'History pruning retained data because authority or stored references need review',saved['owner'],saved['identity']))
                        total['history_blocked'] += 1
                return total
        except BlockingIOError:return dict(history_busy=True)
        finally:self.hestia.deadline = previous
