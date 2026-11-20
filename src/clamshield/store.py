"""Durable scoped jobs, findings and retention-controlled audit records."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

from .errors import AccessDenied, Conflict

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL,
 domain TEXT NOT NULL, root TEXT NOT NULL, target TEXT NOT NULL,
 source TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL,
 started REAL, finished REAL, status TEXT NOT NULL DEFAULT 'queued',
 cancel_requested INTEGER NOT NULL DEFAULT 0, worker TEXT, heartbeat REAL,
 counters TEXT NOT NULL DEFAULT '{}', error TEXT, generation TEXT NOT NULL, dedup_key TEXT
);
CREATE INDEX IF NOT EXISTS job_scope ON jobs(owner,identity,created);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL,
 path TEXT NOT NULL, fingerprint TEXT NOT NULL, engine TEXT NOT NULL,
 signature TEXT NOT NULL, provider TEXT NOT NULL, severity TEXT NOT NULL,
 created REAL NOT NULL, status TEXT NOT NULL DEFAULT 'open', detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS finding_scope ON findings(owner,identity,created);
CREATE TABLE IF NOT EXISTS file_results (
 id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
 path TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wordpress_reports (
 job_id TEXT PRIMARY KEY REFERENCES jobs(id), owner TEXT NOT NULL,
 identity TEXT NOT NULL, domain TEXT NOT NULL, report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wordpress_recovery (
 id TEXT PRIMARY KEY REFERENCES jobs(id), owner TEXT NOT NULL, identity TEXT NOT NULL,
 actor TEXT NOT NULL, domain TEXT NOT NULL, root TEXT NOT NULL, target TEXT NOT NULL,
 created REAL NOT NULL, status TEXT NOT NULL, revision TEXT NOT NULL,
 options TEXT NOT NULL, report TEXT NOT NULL DEFAULT '{}', selection TEXT NOT NULL DEFAULT '[]',
 work_job TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS wordpress_recovery_items (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES wordpress_recovery(id),
 path TEXT NOT NULL, kind TEXT NOT NULL, action TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'proposed', detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS recovery_items_plan ON wordpress_recovery_items(plan_id,id);
CREATE TABLE IF NOT EXISTS repair_plans (
 id TEXT PRIMARY KEY REFERENCES jobs(id), finding_id TEXT NOT NULL REFERENCES findings(id),
 owner TEXT NOT NULL, identity TEXT NOT NULL, actor TEXT NOT NULL,
 status TEXT NOT NULL, created REAL NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', error TEXT
);
CREATE TABLE IF NOT EXISTS rule_trials (
 job_id TEXT PRIMARY KEY REFERENCES jobs(id), owner TEXT NOT NULL, identity TEXT NOT NULL,
 generation TEXT NOT NULL, baseline TEXT, result TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS repair_scope ON repair_plans(owner,identity,created);
CREATE INDEX IF NOT EXISTS file_result_job ON file_results(job_id,id);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, created REAL NOT NULL, actor TEXT NOT NULL,
 owner TEXT NOT NULL, identity TEXT NOT NULL, action TEXT NOT NULL,
 subject TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id),
 owner TEXT NOT NULL, identity TEXT NOT NULL, actor TEXT NOT NULL,
 kind TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL,
 metadata TEXT NOT NULL, error TEXT
);
CREATE TABLE IF NOT EXISTS policies (
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL,
 root TEXT NOT NULL, settings TEXT NOT NULL, last_slot TEXT,
 PRIMARY KEY(owner,identity,domain)
);
CREATE TABLE IF NOT EXISTS remediation_policies (
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL,
 settings TEXT NOT NULL, updated REAL NOT NULL, revision TEXT NOT NULL,
 PRIMARY KEY(owner,identity,domain)
);
CREATE TABLE IF NOT EXISTS website_permissions (
 owner TEXT NOT NULL, identity TEXT NOT NULL, settings TEXT NOT NULL,
 updated REAL NOT NULL, revision TEXT NOT NULL, PRIMARY KEY(owner,identity)
);
CREATE TABLE IF NOT EXISTS remediation_scans (
 job_id TEXT PRIMARY KEY REFERENCES jobs(id), cursor INTEGER NOT NULL DEFAULT 0,
 finished INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS remediation_actions (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL,
 actor TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id),
 finding_id TEXT NOT NULL REFERENCES findings(id), path TEXT NOT NULL,
 status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
 detail TEXT NOT NULL, error TEXT, UNIQUE(job_id,path)
);
CREATE INDEX IF NOT EXISTS remediation_pending ON remediation_actions(status,created);
CREATE TABLE IF NOT EXISTS observations (
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL,
 root TEXT NOT NULL, path TEXT NOT NULL, fingerprint TEXT NOT NULL,
 generation TEXT NOT NULL, scanned REAL NOT NULL,
 PRIMARY KEY(owner,identity,domain,path)
);
CREATE TABLE IF NOT EXISTS maintenance (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL, started REAL,
 finished REAL, status TEXT NOT NULL DEFAULT 'queued', worker TEXT, result TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS exceptions (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL,
 domain TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL,
 engine TEXT NOT NULL, signature TEXT NOT NULL, sha256 TEXT, note TEXT NOT NULL,
 created REAL NOT NULL, expires REAL, actor TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL, event TEXT NOT NULL,
 subject TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL, read_at REAL,
 dedup_key TEXT, UNIQUE(owner,identity,event,dedup_key)
);
CREATE TABLE IF NOT EXISTS mail_policies (
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL,
 mailbox TEXT NOT NULL, settings TEXT NOT NULL, updated REAL NOT NULL,
 PRIMARY KEY(owner,identity,domain,mailbox)
);
CREATE TABLE IF NOT EXISTS mail_permissions (
 owner TEXT NOT NULL, identity TEXT NOT NULL, settings TEXT NOT NULL,
 PRIMARY KEY(owner,identity)
);
CREATE TABLE IF NOT EXISTS mail_decisions (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL,
 domain TEXT NOT NULL, mailbox TEXT NOT NULL, recipient TEXT NOT NULL,
 exim_id TEXT NOT NULL, sender TEXT NOT NULL, created REAL NOT NULL,
 sha256 TEXT NOT NULL, action TEXT NOT NULL, classification TEXT NOT NULL,
 detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_decision_scope ON mail_decisions(owner,identity,created);
CREATE TABLE IF NOT EXISTS mail_transactions (
 id TEXT PRIMARY KEY, exim_id TEXT NOT NULL UNIQUE, created REAL NOT NULL,
 updated REAL NOT NULL, status TEXT NOT NULL, sha256 TEXT NOT NULL,
 size INTEGER NOT NULL, metadata TEXT NOT NULL, error TEXT
);
CREATE TABLE IF NOT EXISTS mail_recipients (
 id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL REFERENCES mail_transactions(id),
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL, mailbox TEXT NOT NULL,
 recipient TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL, note TEXT NOT NULL DEFAULT '',
 detail TEXT NOT NULL, error TEXT
);
CREATE INDEX IF NOT EXISTS mail_recipient_scope ON mail_recipients(owner,identity,status,created);
CREATE TABLE IF NOT EXISTS mail_delivery_attempts (
 id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL UNIQUE REFERENCES mail_recipients(id),
 created REAL NOT NULL, updated REAL NOT NULL, status TEXT NOT NULL,
 metadata TEXT NOT NULL, native_id TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS mail_acceptance (
 transaction_id TEXT PRIMARY KEY REFERENCES mail_transactions(id),
 exim_id TEXT NOT NULL UNIQUE, created REAL NOT NULL, updated REAL NOT NULL,
 status TEXT NOT NULL, metadata TEXT NOT NULL, error TEXT
);
CREATE TABLE IF NOT EXISTS mail_body_cleanup (
 kind TEXT NOT NULL, subject TEXT NOT NULL, created REAL NOT NULL,
 updated REAL NOT NULL, status TEXT NOT NULL, metadata TEXT NOT NULL, error TEXT,
 PRIMARY KEY(kind,subject)
);
CREATE INDEX IF NOT EXISTS mail_cleanup_pending ON mail_body_cleanup(status,created);
CREATE TABLE IF NOT EXISTS mail_retention_policies (
 owner TEXT NOT NULL, identity TEXT NOT NULL, domain TEXT NOT NULL, mailbox TEXT NOT NULL,
 days INTEGER NOT NULL, updated REAL NOT NULL, authority TEXT NOT NULL,
 PRIMARY KEY(owner,identity,domain,mailbox)
);
CREATE TABLE IF NOT EXISTS mail_expiry_actions (
 recipient_id TEXT PRIMARY KEY REFERENCES mail_recipients(id),
 owner TEXT NOT NULL, identity TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
 status TEXT NOT NULL, metadata TEXT NOT NULL, error TEXT
);
CREATE INDEX IF NOT EXISTS mail_expiry_scope ON mail_expiry_actions(owner,identity,updated);
CREATE TABLE IF NOT EXISTS history_retention (
 owner TEXT NOT NULL, identity TEXT NOT NULL, settings TEXT NOT NULL,
 updated REAL NOT NULL, revision TEXT NOT NULL, authority TEXT NOT NULL,
 last_run REAL NOT NULL DEFAULT 0, error TEXT, PRIMARY KEY(owner,identity)
);
CREATE TABLE IF NOT EXISTS history_permissions (
 owner TEXT NOT NULL, identity TEXT NOT NULL, allowed INTEGER NOT NULL,
 revision TEXT NOT NULL, PRIMARY KEY(owner,identity)
);
CREATE INDEX IF NOT EXISTS history_audit_scope ON audit(owner,identity,created);
CREATE TABLE IF NOT EXISTS server_history_retention (
 id INTEGER PRIMARY KEY CHECK(id=1), settings TEXT NOT NULL, updated REAL NOT NULL,
 revision TEXT NOT NULL, authority TEXT NOT NULL, last_run REAL NOT NULL DEFAULT 0,
 error TEXT
);
'''


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


class Store:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise AccessDenied('State database cannot be a symbolic link')
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.initialization(),self.connection() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(SCHEMA)
            # Serialize migration checks across simultaneous panel/service starts.
            db.execute('BEGIN IMMEDIATE')
            if 'dedup_key' not in {r['name'] for r in db.execute('PRAGMA table_info(jobs)')}:
                db.execute('ALTER TABLE jobs ADD COLUMN dedup_key TEXT')
            if 'detail' not in {r['name'] for r in db.execute('PRAGMA table_info(findings)')}:
                db.execute("ALTER TABLE findings ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'")
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS job_dedup ON jobs(owner,identity,domain,source,target,dedup_key)')
        self.path.chmod(0o600)

    @contextmanager
    def initialization(self):
        # journal_mode can return SQLITE_BUSY before a BEGIN/SQLite busy handler
        # can serialize simultaneous first starts. Serialize the whole bootstrap.
        fd=os.open(self.path.with_name(self.path.name+'.init.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise AccessDenied('State initialization lock is not private')
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:os.close(fd)

    @contextmanager
    def connection(self, immediate=False):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=20000')
        # Custody/repair state must reach durable WAL before accepting mail or
        # publishing website mutations; NORMAL can lose recent commits on power loss.
        db.execute('PRAGMA synchronous=FULL')
        try:
            if immediate:
                db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def scope(context):
        return (context['owner'], context['identity'])

    def audit(self, context, action, subject, detail, db=None):
        values = (time.time(), context['actor'], *self.scope(context), action, subject, encode(detail))
        if db is None:
            with self.connection() as connection:
                connection.execute('INSERT INTO audit VALUES(NULL,?,?,?,?,?,?,?)', values)
        else:
            db.execute('INSERT INTO audit VALUES(NULL,?,?,?,?,?,?,?)', values)

    def enqueue(self, context, site, target='', source='manual', generation='unknown', dedup_key=None):
        if (site['owner'], site['identity']) != self.scope(context):
            raise AccessDenied('Site does not belong to this account generation')
        job_id = uuid.uuid4().hex
        with self.connection(True) as db:
            if dedup_key is not None:
                existing = db.execute('''SELECT id FROM jobs WHERE owner=? AND identity=? AND domain=?
                  AND source=? AND target=? AND dedup_key=?''',
                  (*self.scope(context), site['domain'], source, target, dedup_key)).fetchone()
                if existing:
                    return existing['id']
            db.execute('''INSERT INTO jobs
              (id,owner,identity,domain,root,target,source,actor,created,generation,dedup_key)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
              (job_id, *self.scope(context), site['domain'], site['root'], target,
               source, context['actor'], time.time(), generation, dedup_key))
            self.audit(context, 'scan.queued', job_id, {'domain': site['domain'], 'target': target}, db)
        return job_id

    def dashboard_counts(self, context):
        """Account-generation totals independent of bounded history previews."""
        scope = self.scope(context)
        with self.connection() as db:
            row = db.execute('''SELECT
              (SELECT count(*) FROM findings WHERE owner=? AND identity=? AND status='open') AS open_findings,
              (SELECT count(*) FROM jobs WHERE owner=? AND identity=? AND status IN ('queued','running')) AS active_scans,
              (SELECT count(*) FROM operations WHERE owner=? AND identity=? AND kind='quarantine' AND status='quarantined') AS quarantined''',
              scope * 3).fetchone()
        return dict(row)

    def list_jobs(self, context):
        with self.connection() as db:
            rows = db.execute('SELECT * FROM jobs WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 200',
                              self.scope(context)).fetchall()
        return [dict(row) | {'counters': json.loads(row['counters'])} for row in rows]

    def job(self, context, job_id):
        with self.connection() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=? AND owner=? AND identity=?',
                             (job_id, *self.scope(context))).fetchone()
        if not row:
            raise AccessDenied('Scan unavailable')
        return dict(row) | {'counters': json.loads(row['counters'])}

    def cancel(self, context, job_id):
        with self.connection(True) as db:
            row = db.execute('SELECT status FROM jobs WHERE id=? AND owner=? AND identity=?',
                             (job_id, *self.scope(context))).fetchone()
            if not row:
                raise AccessDenied('Scan unavailable')
            if row['status'] == 'queued':
                db.execute("UPDATE jobs SET status='cancelled',cancel_requested=1,finished=? WHERE id=?",
                           (time.time(), job_id))
            elif row['status'] == 'running':
                db.execute('UPDATE jobs SET cancel_requested=1 WHERE id=?', (job_id,))
            else:
                raise Conflict('Scan has already finished')
            self.audit(context, 'scan.cancel_requested', job_id, {}, db)

    def claim(self, worker):
        with self.connection(True) as db:
            row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created,id LIMIT 1").fetchone()
            if row is None:
                return None
            now = time.time()
            db.execute("UPDATE jobs SET status='running',worker=?,started=?,heartbeat=? WHERE id=?",
                       (worker, now, now, row['id']))
            result = dict(row)
            result.update(status='running', worker=worker, started=now)
            return result

    def cancelled(self, job_id):
        with self.connection() as db:
            row = db.execute('SELECT cancel_requested FROM jobs WHERE id=?', (job_id,)).fetchone()
        return row is None or bool(row[0])

    def progress(self, job_id, counters):
        with self.connection() as db:
            db.execute("UPDATE jobs SET counters=?,heartbeat=? WHERE id=? AND status='running'",
                       (encode(counters), time.time(), job_id))

    def finish(self, job, status, counters, error=None):
        if status not in ('completed', 'partial', 'failed', 'cancelled'):
            raise ValueError('Invalid terminal status')
        with self.connection(True) as db:
            row = db.execute('SELECT cancel_requested FROM jobs WHERE id=?', (job['id'],)).fetchone()
            if row and row[0]:
                status = 'cancelled'
            db.execute("UPDATE jobs SET status=?,finished=?,heartbeat=?,counters=?,error=? WHERE id=? AND status='running' AND worker=?",
                       (status, time.time(), time.time(), encode(counters), error, job['id'], job['worker']))
            context = {k: job[k] for k in ('actor', 'owner', 'identity')}
            self.audit(context, 'scan.' + status, job['id'], {'counters': counters, 'error': error}, db)
            detail = {'domain': job['domain'], 'job_id': job['id'], 'counters': counters, 'error': error}
            if counters.get('infected', 0):
                self.notify(job['owner'], job['identity'], 'scan.malware_found', job['domain'], detail, job['id'], db)
            if job['source'] == 'wordpress-integrity' and any(counters.get(k, 0) for k in ('modified', 'missing', 'additional')):
                self.notify(job['owner'], job['identity'], 'wordpress.integrity_issues', job['domain'], detail, job['id'], db)
            if status in ('failed', 'partial'):
                self.notify(job['owner'], job['identity'], 'scan.' + status, job['domain'], detail, job['id'], db)

    def file_result(self, job_id, path, status, detail):
        with self.connection() as db:
            db.execute('INSERT INTO file_results(job_id,path,status,detail) VALUES(?,?,?,?)',
                       (job_id, path, status, encode(detail)))

    def observed(self, job, path, fingerprint):
        with self.connection() as db:
            db.execute('''INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(owner,identity,domain,path) DO UPDATE SET root=excluded.root,
              fingerprint=excluded.fingerprint,generation=excluded.generation,scanned=excluded.scanned''',
              (job['owner'], job['identity'], job['domain'], job['root'], path,
               encode(fingerprint), job['generation'], time.time()))

    def add_finding(self, job, path, fingerprint, detection):
        finding_id = uuid.uuid4().hex
        with self.connection() as db:
            previous = db.execute('''SELECT count(*) FROM findings WHERE owner=? AND identity=?
              AND domain=? AND path=? AND engine=? AND signature=? AND job_id<>?''',
              (job['owner'], job['identity'], job['domain'], path, detection['engine'], detection['signature'], job['id'])).fetchone()[0]
            db.execute('''INSERT INTO findings
              (id,job_id,owner,identity,domain,path,fingerprint,engine,signature,provider,severity,created,detail)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
              (finding_id, job['id'], job['owner'], job['identity'], job['domain'], path,
               encode(fingerprint), detection['engine'], detection['signature'],
               detection['provider'], detection.get('severity', 'review'), time.time(),encode(detection)))
            if previous:
                self.notify(job['owner'], job['identity'], 'scan.repeated_detection', job['domain'],
                    {'domain': job['domain'], 'path': path, 'signature': detection['signature'],
                     'previous_detections': previous, 'finding_id': finding_id},
                    job['id'] + ':' + path + ':' + detection['engine'] + ':' + detection['signature'], db)
        return finding_id

    def list_findings(self, context):
        with self.connection() as db:
            rows = db.execute('''SELECT f.*, j.root FROM findings f LEFT JOIN jobs j
                              ON j.id=f.job_id AND j.owner=f.owner AND j.identity=f.identity
                              WHERE f.owner=? AND f.identity=? ORDER BY f.created DESC LIMIT 500''',
                              self.scope(context)).fetchall()
        return [dict(row) | {'fingerprint': json.loads(row['fingerprint']),'detail':json.loads(row['detail'])} for row in rows]

    def finding(self, context, finding_id):
        with self.connection() as db:
            row = db.execute('''SELECT f.*, j.root FROM findings f JOIN jobs j ON j.id=f.job_id
              WHERE f.id=? AND f.owner=? AND f.identity=?''', (finding_id, *self.scope(context))).fetchone()
        if not row:
            raise AccessDenied('Finding unavailable')
        return dict(row) | {'fingerprint': json.loads(row['fingerprint']),'detail':json.loads(row['detail'])}

    def history(self, context):
        with self.connection() as db:
            query='SELECT * FROM audit WHERE (owner=? AND identity=?)'
            if context.get('admin'):query+=" OR (owner='@admin' AND identity='')"
            rows = db.execute(query+' ORDER BY id DESC LIMIT 300',self.scope(context)).fetchall()
        return [dict(row) | {'detail': json.loads(row['detail'])} for row in rows]

    def enqueue_task(self, context, action, payload):
        task_id = uuid.uuid4().hex
        with self.connection(True) as db:
            existing = db.execute("SELECT id FROM maintenance WHERE owner=? AND identity=? AND action=? AND payload=? AND status IN ('queued','running')",
                                  (*self.scope(context), action, encode(payload))).fetchone()
            if existing:
                return existing['id']
            db.execute('INSERT INTO maintenance(id,owner,identity,actor,action,payload,created) VALUES(?,?,?,?,?,?,?)',
                       (task_id, *self.scope(context), context['actor'], action, encode(payload), time.time()))
            self.audit(context, 'maintenance.queued', task_id, {'action': action}, db)
        return task_id

    def list_tasks(self, context):
        with self.connection() as db:
            rows = db.execute('SELECT * FROM maintenance WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 100',
                              self.scope(context)).fetchall()
        return [dict(row) | {'payload': json.loads(row['payload']),
                             'result': json.loads(row['result']) if row['result'] else None} for row in rows]

    def claim_task(self, worker):
        with self.connection(True) as db:
            row = db.execute("SELECT * FROM maintenance WHERE status='queued' ORDER BY created,id LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE maintenance SET status='running',worker=?,started=? WHERE id=?",
                       (worker, time.time(), row['id']))
            return dict(row) | {'payload': json.loads(row['payload']), 'worker': worker}

    def rule_install_status(self, context):
        with self.connection() as db:
            db.execute('BEGIN')
            pending = db.execute("SELECT 1 FROM maintenance WHERE owner=? AND identity=? AND action LIKE 'rules-%' AND status IN ('queued','running') LIMIT 1", self.scope(context)).fetchone()
            row = db.execute("SELECT id,status,error,result,payload FROM maintenance WHERE owner=? AND identity=? AND action='rules-install' ORDER BY created DESC,id DESC LIMIT 1", self.scope(context)).fetchone()
        latest = None
        if row:
            result = json.loads(row['result']) if row['result'] else {}
            payload = json.loads(row['payload'])
            latest = dict(id=row['id'], status=row['status'], error=row['error'],
                          profile=payload.get('profile'), phase=(result or {}).get('phase'),
                          generation=(result or {}).get('generation'), activated=(result or {}).get('activated',False))
        return {'pending': bool(pending), 'latest': latest}

    def task_progress(self, task, phase):
        with self.connection(True) as db:
            db.execute("UPDATE maintenance SET result=? WHERE id=? AND worker=? AND status='running'",
                       (encode({'phase':phase}), task['id'], task['worker']))

    def mail_protection_status(self, context):
        with self.connection() as db:
            db.execute('BEGIN')
            pending=db.execute("SELECT 1 FROM maintenance WHERE owner=? AND identity=? AND action LIKE 'mail-%' AND status IN ('queued','running') LIMIT 1",self.scope(context)).fetchone()
            row=db.execute("SELECT id,action,status,error,result FROM maintenance WHERE owner=? AND identity=? AND action IN ('mail-protection-enable','mail-protection-disable') ORDER BY created DESC,id DESC LIMIT 1",self.scope(context)).fetchone()
        latest=None
        if row:
            result=json.loads(row['result']) if row['result'] else {}
            latest=dict(id=row['id'],action=row['action'],status=row['status'],error=row['error'],phase=(result or {}).get('phase'))
        return {'pending':bool(pending),'latest':latest}

    def finish_task(self, task, result=None, error=None):
        with self.connection(True) as db:
            status = 'failed' if error else 'completed'
            db.execute('UPDATE maintenance SET status=?,finished=?,result=?,error=? WHERE id=? AND worker=?',
                       (status, time.time(), encode(result) if result is not None else None, error, task['id'], task['worker']))
            self.audit(task, 'maintenance.' + status, task['id'], {'action': task['action'], 'error': error}, db)
            self.notify('@admin', '', 'maintenance.' + status, task['action'],
                        {'task_id': task['id'], 'action': task['action'], 'error': error}, task['id'], db)

    def notify(self, owner, identity, event, subject, detail, dedup_key=None, db=None):
        values = (uuid.uuid4().hex, owner, identity, event, subject, encode(detail), time.time(), dedup_key)
        sql = 'INSERT OR IGNORE INTO notifications(id,owner,identity,event,subject,detail,created,dedup_key) VALUES(?,?,?,?,?,?,?,?)'
        if db is not None:
            db.execute(sql, values)
        else:
            with self.connection() as connection:
                connection.execute(sql, values)

    def notifications(self, context):
        with self.connection() as db:
            if context.get('admin'):
                rows = db.execute("SELECT * FROM notifications WHERE (owner=? AND identity=?) OR owner='@admin' ORDER BY created DESC LIMIT 300",
                                  self.scope(context)).fetchall()
            else:
                rows = db.execute('SELECT * FROM notifications WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 300',
                                  self.scope(context)).fetchall()
        return [dict(row) | {'detail': json.loads(row['detail'])} for row in rows]

    def read_notification(self, context, notification_id):
        with self.connection() as db:
            condition = "((owner=? AND identity=?) OR owner='@admin')" if context.get('admin') else '(owner=? AND identity=?)'
            changed = db.execute('UPDATE notifications SET read_at=? WHERE id=? AND ' + condition,
                                 (time.time(), notification_id, *self.scope(context))).rowcount
            if not changed:
                raise AccessDenied('Notification unavailable')
