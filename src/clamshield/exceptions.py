"""False-positive decisions stay inside one native account generation and website."""
import math
import time
import uuid

from .errors import AccessDenied, ClamShieldError


class Exceptions:
    def __init__(self, store):
        self.store = store

    def add(self, context, finding_id, kind='file', note='', expires=None, whole_site=False):
        if kind not in ('file', 'signature') or type(whole_site) is not bool:
            raise ClamShieldError('Invalid exception type')
        if not isinstance(note, str) or len(note) > 1000:
            raise ClamShieldError('Exception note exceeds 1000 characters')
        if expires is not None and (type(expires) not in (int, float) or not math.isfinite(expires) or expires <= time.time()):
            raise ClamShieldError('Exception expiry must be a future time')
        finding = self.store.finding(context, finding_id)
        if finding['fingerprint'].get('missing'):
            raise ClamShieldError('Missing files have no content to trust or suppress')
        exception_id = uuid.uuid4().hex
        path = '' if kind == 'signature' and whole_site else finding['path']
        engine = finding['engine'] if kind == 'signature' else '*'
        signature = finding['signature'] if kind == 'signature' else '*'
        digest = finding['fingerprint']['sha256'] if kind == 'file' else None
        with self.store.connection(True) as db:
            db.execute('''INSERT INTO exceptions(id,owner,identity,domain,root,path,kind,engine,signature,
              sha256,note,created,expires,actor) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
              (exception_id, *self.store.scope(context), finding['domain'], finding['root'], path,
               kind, engine, signature, digest, note, time.time(), expires, context['actor']))
            db.execute("UPDATE findings SET status='excepted' WHERE id=? AND status='open'", (finding_id,))
            self.store.audit(context, 'exception.created', exception_id,
                             {'finding': finding_id, 'kind': kind, 'domain': finding['domain'], 'whole_site': whole_site}, db)
        return exception_id

    def remove(self, context, exception_id):
        with self.store.connection(True) as db:
            changed = db.execute('UPDATE exceptions SET enabled=0 WHERE id=? AND owner=? AND identity=? AND enabled=1',
                                 (exception_id, *self.store.scope(context))).rowcount
            if not changed:
                raise AccessDenied('Exception unavailable')
            self.store.audit(context, 'exception.removed', exception_id, {}, db)

    def list(self, context):
        with self.store.connection() as db:
            return [dict(row) for row in db.execute('SELECT * FROM exceptions WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 500',
                                                    self.store.scope(context)).fetchall()]

    def filter(self, job, path, fingerprint, detections):
        context = {key: job[key] for key in ('owner', 'identity')}
        with self.store.connection() as db:
            exceptions = [dict(row) for row in db.execute('''SELECT * FROM exceptions WHERE owner=? AND identity=?
              AND domain=? AND root=? AND enabled=1 AND (expires IS NULL OR expires>?)''',
              (*self.store.scope(context), job['domain'], job['root'], time.time())).fetchall()]
        visible, suppressed = [], []
        for detection in detections:
            match = next((rule for rule in exceptions if
                (not rule['path'] or rule['path'] == path) and
                ((rule['kind'] == 'file' and rule['sha256'] == fingerprint['sha256']) or
                 (rule['kind'] == 'signature' and rule['engine'] == detection['engine'] and rule['signature'] == detection['signature']))), None)
            if match:
                suppressed.append(detection | {'exception_id': match['id']})
            else:
                visible.append(detection)
        return visible, suppressed
