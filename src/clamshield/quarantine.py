"""Atomic same-filesystem capture, content validation and non-overwriting undo."""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import time
import uuid
from contextlib import contextmanager, nullcontext

from .errors import AccessDenied, Conflict, ClamShieldError
from .paths import attributes, directory, file_handle, hash_fd, parent
from .store import encode


def rename_noreplace(source_fd, source, target_fd, target):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(source_fd, os.fsencode(source), target_fd, os.fsencode(target), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def same_content(fd, expected):
    actual = attributes(os.fstat(fd))
    # Rename changes ctime, so identity/content checks omit ctime only here.
    return all(actual[key] == expected[key] for key in (
        'device', 'inode', 'size', 'mtime_ns', 'uid', 'gid', 'mode', 'links')) and hash_fd(fd) == expected['sha256']


class Quarantine:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia

    @contextmanager
    def locked(self,blocking=True):
        self.settings.prepare()
        fd=os.open(self.settings.state/'quarantine.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as lock:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise AccessDenied('Unsafe quarantine lock')
            fcntl.flock(lock,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB));yield

    def validate_site(self, context, finding):
        live = self.hestia.authorize(context['actor'], context['owner'])
        if live['identity'] != finding['identity']:
            raise AccessDenied('Account identity changed')
        sites = self.hestia.sites(context['owner'])
        if not any(s['domain'] == finding['domain'] and s['root'] == finding['root'] and not s['suspended'] for s in sites):
            raise Conflict('Site configuration changed')

    def storage(self, root, device):
        self.settings.prepare()
        base = self.settings.quarantine
        if base.stat().st_dev != device:
            mount = Path(root)
            while mount.parent.stat().st_dev == device and mount != mount.parent:
                mount = mount.parent
            info = mount.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise AccessDenied('Quarantine requires a trusted filesystem root')
            base = mount / '.clamshield-quarantine'
            if base.exists():
                info = base.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                    raise AccessDenied('Quarantine directory is not owned by ClamShield')
                marker = base / '.clamshield-owner'
                if marker.is_symlink() or not marker.is_file() or marker.read_text() != 'clamshield\n':
                    raise AccessDenied('Quarantine directory is not owned by ClamShield')
            else:
                base.mkdir(mode=0o700)
                (base / '.clamshield-owner').write_text('clamshield\n')
        if base.is_symlink() or base.resolve() != base:
            raise AccessDenied('Unexpected quarantine path')
        return base

    def capture(self, context, finding_id, *, operation_id=None, kind='quarantine', extra=None, source=None):
        with self.locked():return self._capture(context,finding_id,operation_id=operation_id,kind=kind,extra=extra,source=source)

    def _capture(self, context, finding_id, *, operation_id=None, kind='quarantine', extra=None, source=None):
        finding = self.store.finding(context, finding_id)
        self.validate_site(context, finding)
        if finding['status'] != 'open':
            raise Conflict('Finding is no longer open')
        expected = finding['fingerprint']
        if expected.get('missing'):
            raise Conflict('Missing files have no content to quarantine; use a repair preview')
        if expected['links'] != 1:
            raise Conflict('Hard-linked files require manual review')
        operation_id = operation_id or uuid.uuid4().hex
        base = self.storage(finding['root'], expected['device'])
        metadata = {'path': finding['path'], 'root': finding['root'],
                    'storage': str(base), 'object': operation_id,
                    'capture_object': operation_id + '.capture', 'fingerprint': expected}
        metadata.update(extra or {})
        with parent(finding['root'],finding['path']) as (fd,_):metadata['parent']=self.parent_identity(fd)
        with self.store.connection(True) as db:
            active = db.execute("SELECT 1 FROM operations WHERE finding_id=? AND status NOT IN ('restored','failed')",
                                (finding_id,)).fetchone()
            if active:
                raise Conflict('An operation for this finding already exists')
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (operation_id, finding_id, *self.store.scope(context), context['actor'],
                        kind, 'prepared', time.time(), encode(metadata), None))
            self.store.audit(context, 'quarantine.prepared', operation_id, {'finding': finding_id}, db)
        captured = False
        try:
            with (nullcontext(source) if source is not None else parent(finding['root'], finding['path'])) as (source_fd, name), directory(base) as target_fd:
                self.check_parent(metadata,source_fd)
                # Move first, then validate the captured object. There is no
                # check-then-unlink race against a writable tenant directory.
                captured_name = metadata['capture_object']
                rename_noreplace(source_fd, name, target_fd, captured_name)
                captured = True
                os.fsync(source_fd)
                os.fsync(target_fd)
                fd = os.open(captured_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=target_fd)
                try:
                    valid = stat.S_ISREG(os.fstat(fd).st_mode) and same_content(fd, expected)
                    if valid:
                        # A tenant can retain a writable descriptor to a renamed
                        # inode. Store a new root-owned content-verified copy so
                        # that descriptor cannot modify the quarantine object.
                        import hashlib
                        output = os.open(operation_id, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=target_fd)
                        digest = hashlib.sha256()
                        try:
                            os.lseek(fd, 0, os.SEEK_SET)
                            total = 0
                            while chunk := os.read(fd, 1024 * 1024):
                                total += len(chunk)
                                if total > expected['size']:
                                    valid = False
                                    break
                                digest.update(chunk)
                                view = memoryview(chunk)
                                while view:
                                    view = view[os.write(output, view):]
                            os.fsync(output)
                            valid = valid and total == expected['size'] and digest.hexdigest() == expected['sha256']
                        finally:
                            os.close(output)
                        if not valid:
                            os.unlink(operation_id, dir_fd=target_fd)
                finally:
                    os.close(fd)
                if not valid:
                    try:
                        rename_noreplace(target_fd, captured_name, source_fd, name)
                        captured = False
                        os.fsync(source_fd)
                        os.fsync(target_fd)
                    except OSError:
                        # Retain the captured object if a new file occupies its
                        # old name; never overwrite that file or delete either.
                        pass
                    raise Conflict('File changed since detection; capture was not accepted')
                os.unlink(captured_name, dir_fd=target_fd)
                os.fsync(target_fd)
            with self.store.connection(True) as db:
                db.execute("UPDATE operations SET status='quarantined' WHERE id=?", (operation_id,))
                db.execute("UPDATE findings SET status='quarantined' WHERE owner=? AND identity=? AND domain=? AND path=? AND json_extract(fingerprint,'$.sha256')=? AND job_id IN (SELECT id FROM jobs WHERE root=?)",
                           (*self.store.scope(context), finding['domain'], finding['path'], expected['sha256'],finding['root']))
                self.store.audit(context, 'quarantine.captured', operation_id, {'finding': finding_id}, db)
            return operation_id
        except (OSError, Conflict, AccessDenied) as exc:
            with self.store.connection(True) as db:
                db.execute('UPDATE operations SET status=?,error=? WHERE id=?',
                           ('recovery_required' if captured else 'failed', 'Capture interrupted or content changed', operation_id))
                self.store.audit(context, 'quarantine.failed', operation_id,
                                 {'recovery_required': captured}, db)
            if isinstance(exc, (Conflict, AccessDenied)):
                raise
            raise Conflict('File capture failed; inspect operation history') from exc

    def restore(self, context, operation_id):
        with self.locked():
            row=self.get(context,operation_id)
            if row['kind']!='quarantine':raise Conflict('Use repair undo for this backup')
            if row['status']!='quarantined':raise Conflict('This operation requires recovery or was already restored')
            # Refuse an already unavailable site before recording restore
            # intent. Recovery still revalidates after the durable transition.
            self.validate_site(context,self.store.finding(context,row['finding_id']))
            metadata=row['metadata'];metadata.update(phase='restore',restore_staged=operation_id+'.restore-'+uuid.uuid4().hex)
            self.operation(context,row,'restoring')
            return self.recover_operation(context,row)

    def get(self,context,operation_id):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM operations WHERE id=? AND owner=? AND identity=?',(operation_id,*self.store.scope(context))).fetchone()
        if not row:raise AccessDenied('Quarantine operation unavailable')
        return dict(row)|{'metadata':json.loads(row['metadata'])}

    @staticmethod
    def parent_identity(fd):
        info=os.fstat(fd);return dict(device=info.st_dev,inode=info.st_ino)

    def check_parent(self,metadata,fd):
        with parent(metadata['root'],metadata['path']) as (live,_):
            if self.parent_identity(fd)!=self.parent_identity(live) or (metadata.get('parent') and self.parent_identity(fd)!=metadata['parent']):
                raise Conflict('Quarantine parent directory changed')

    def operation(self,context,row,status,error=None):
        with self.store.connection(True) as db:
            db.execute('UPDATE operations SET status=?,metadata=?,error=? WHERE id=? AND owner=? AND identity=?',
                (status,encode(row['metadata']),error,row['id'],*self.store.scope(context)))
            self.store.audit(context,'quarantine.'+status,row['id'],{'error':error},db)
        row.update(status=status,error=error)

    def recover_operation(self,context,row):
        from .repairs import Repairs
        metadata=row['metadata'];finding=self.store.finding(context,row['finding_id'])
        self.validate_site(context,finding)
        if row['kind']!='quarantine':raise Conflict('Use repair recovery for this backup')
        base=self.storage(metadata['root'],metadata['fingerprint']['device'])
        if str(base)!=metadata['storage']:raise Conflict('Quarantine storage changed')
        repair=Repairs(self.settings,self.store,self.hestia)
        plan=dict(root=metadata['root'],target=metadata['path'],metadata=dict(fingerprint=metadata['fingerprint']))
        expected=metadata['fingerprint'];original=row['id'];capture=metadata['capture_object']
        try:
            with parent(metadata['root'],metadata['path']) as (fd,_):self.check_parent(metadata,fd)
            if metadata.get('phase')=='restore':
                if not repair.private_matches(plan,original,expected):raise Conflict('Original quarantine bytes cannot be verified')
                restored=metadata.get('restore_fingerprint')
                if not (restored and repair.target_matches(plan,restored)):
                    with parent(metadata['root'],metadata['path']) as (fd,name):
                        self.check_parent(metadata,fd)
                        try:os.stat(name,dir_fd=fd,follow_symlinks=False)
                        except FileNotFoundError:pass
                        else:raise Conflict('Restore target exists; no file was overwritten')
                    staged=metadata['restore_staged']
                    if not restored:
                        repair.preserve_partial(plan,staged)
                        restored=repair.copy_private(plan,original,staged,expected,True)
                        metadata['restore_fingerprint']=restored;self.operation(context,row,'restoring')
                    with directory(base) as source_fd,parent(metadata['root'],metadata['path']) as (target_fd,name):
                        self.check_parent(metadata,target_fd)
                        with file_handle(base,staged) as (copy,_):
                            if not same_content(copy,restored):raise Conflict('Staged restore changed')
                        self.validate_site(context,finding)
                        rename_noreplace(source_fd,staged,target_fd,name);os.fsync(source_fd);os.fsync(target_fd)
                from .generations import current
                site=dict(owner=row['owner'],identity=row['identity'],domain=finding['domain'],root=metadata['root'])
                metadata['recheck_job']=self.store.enqueue(context,site,metadata['path'],source='quarantine-restore-recheck',generation=current(self.settings),dedup_key=row['id']+':restore')
                self.operation(context,row,'restored')
                with self.store.connection() as db:db.execute("UPDATE findings SET status='restored_unverified' WHERE id=? AND owner=? AND identity=?",(finding['id'],*self.store.scope(context)))
            else:
                if not repair.private_matches(plan,original,expected):
                    if not repair.private_matches(plan,capture,expected):
                        if repair.target_matches(plan,expected):self.operation(context,row,'failed','Capture stopped before moving the original');return row
                        raise Conflict('Captured bytes changed or require manual recovery')
                    repair.preserve_partial(plan,original);repair.copy_private(plan,capture,original,expected)
                # Retain a changed/open-descriptor capture instead of deleting it.
                with directory(base) as fd:
                    try:
                        with file_handle(base,capture) as (copy,_):matches=same_content(copy,expected)
                        if matches:os.unlink(capture,dir_fd=fd);os.fsync(fd)
                        else:metadata['changed_capture_retained']=True
                    except FileNotFoundError:pass
                self.operation(context,row,'quarantined')
                with self.store.connection() as db:
                    db.execute("UPDATE findings SET status='quarantined' WHERE owner=? AND identity=? AND domain=? AND path=? AND json_extract(fingerprint,'$.sha256')=? AND job_id IN (SELECT id FROM jobs WHERE root=?)",(*self.store.scope(context),finding['domain'],finding['path'],expected['sha256'],finding['root']))
            return row
        except (OSError,Conflict,AccessDenied) as exc:
            self.operation(context,row,'recovery_required','Quarantine recovery needs review; existing content was preserved')
            raise Conflict('Quarantine recovery needs review; existing content was preserved') from exc

    def recover(self,context,operation_id):
        with self.locked():
            row=self.get(context,operation_id)
            if row['status'] in ('quarantined','restored','failed'):return row
            return self.recover_operation(context,row)

    def recover_pending(self):
        try:
            with self.locked(False):
                with self.store.connection() as db:rows=db.execute("SELECT * FROM operations WHERE kind='quarantine' AND status IN ('prepared','restoring') ORDER BY created LIMIT 50").fetchall()
                for value in rows:
                    row=dict(value);row['metadata']=json.loads(row['metadata']);context={key:row[key] for key in ('actor','owner','identity')}
                    try:self.recover_operation(context,row)
                    except (OSError,ClamShieldError):self.operation(context,row,'recovery_required','Native account, site or content needs review')
                return {'quarantine_examined':len(rows)}
        except BlockingIOError:return {'quarantine_busy':True}

    def list(self, context):
        with self.store.connection() as db:
            rows = db.execute('''SELECT o.*, f.domain FROM operations o LEFT JOIN findings f
                              ON f.id=o.finding_id AND f.owner=o.owner AND f.identity=o.identity
                              WHERE o.owner=? AND o.identity=? ORDER BY o.created DESC LIMIT 300''',
                              self.store.scope(context)).fetchall()
        return [dict(row) | {'metadata': json.loads(row['metadata'])} for row in rows]
