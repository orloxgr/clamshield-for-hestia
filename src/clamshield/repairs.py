"""Reviewable release repairs with immutable originals and journaled undo."""
from contextlib import contextmanager
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

from .atomic import write
from .errors import AccessDenied, ClamShieldError, Conflict
from .generations import current as generation
from .paths import attributes, directory, file_handle, hash_fd, parent, relative_path, snapshot
from .quarantine import Quarantine, rename_noreplace, same_content
from .store import encode
from .wordpress_sources import References


def digest(content):
    return hashlib.sha256(content).hexdigest()


def preview(before, after):
    result = {'before_sha256': digest(before), 'after_sha256': digest(after),
              'before_bytes': len(before), 'after_bytes': len(after), 'truncated': False}
    try:
        if max(len(before), len(after)) > 256 * 1024 or b'\0' in before + after:
            raise ValueError()
        a, b = before.decode('utf-8').splitlines(True), after.decode('utf-8').splitlines(True)
        if max(len(a), len(b)) > 4000:
            raise ValueError()
        difference = ''.join(difflib.unified_diff(a, b, fromfile='Current file', tofile='Proposed replacement'))
        result.update(kind='text', diff=difference[:256 * 1024], truncated=len(difference) > 256 * 1024)
    except (UnicodeError, ValueError):
        result.update(kind='summary', diff='Binary or large file: compare the content hashes and sizes.')
    return result


class Repairs:
    def __init__(self, settings, store, hestia, references=None):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.quarantine = Quarantine(settings, store, hestia)
        self.references = references or References(settings)

    @contextmanager
    def locked(self, blocking=True):
        self.settings.prepare()
        with (self.settings.state / 'repair.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield

    def get(self, context, plan_id):
        with self.store.connection() as db:
            row = db.execute('''SELECT r.*,j.domain,j.root,j.target FROM repair_plans r JOIN jobs j ON j.id=r.id
              WHERE r.id=? AND r.owner=? AND r.identity=?''', (plan_id, *self.store.scope(context))).fetchone()
        if not row:
            raise AccessDenied('Repair plan unavailable')
        return dict(row) | {'metadata': json.loads(row['metadata'])}

    def update(self, context, plan, status, error=None):
        with self.store.connection(True) as db:
            db.execute('UPDATE repair_plans SET status=?,metadata=?,error=? WHERE id=? AND owner=? AND identity=?',
                       (status, encode(plan['metadata']), error, plan['id'], *self.store.scope(context)))
            if plan['status'] != status or plan['error'] != error:
                event=('cleanup.' if plan['metadata'].get('source',{}).get('kind')=='targeted-cleanup' else 'repair.')+status
                self.store.audit(context, event, plan['id'], {'path': plan['target'], 'error': error}, db)
                if status in ('recovery_required', 'failed', 'verified', 'undone', 'recheck_failed'):
                    self.store.notify(plan['owner'], plan['identity'], event, plan['domain'],
                                      {'plan_id': plan['id'], 'path': plan['target'], 'error': error}, plan['id'] + ':' + status, db)
        plan.update(status=status, error=error)

    def queue(self, context, finding_id, *, backup_path=None, backup_name=None, cleanup=False, recovery=None):
        finding = self.store.finding(context, finding_id)
        self.quarantine.validate_site(context, finding)
        reference = finding['fingerprint'].get('wordpress', {})
        source = {'kind': 'wordpress'}
        if recovery is not None:
            from .wordpress_recovery import WordPressRecovery
            source=WordPressRecovery(self.settings,self.store,self.hestia).repair_source(context,finding,recovery)
        if cleanup:
            if backup_path is not None or backup_name is not None:raise Conflict('Choose one remediation action')
            from .cleanup import eligible,revision
            eligible(finding)
            source=dict(kind='targeted-cleanup',catalog_revision=revision())
        if backup_name is not None:
            if backup_path is not None:raise Conflict('Choose one replacement source')
            from .native_backups import NativeBackups
            source=NativeBackups(self.settings,self.store,self.hestia).selection(context,finding,backup_name)
        if backup_path is not None:
            backup_path = relative_path(backup_path, allow_root=False)
            if len(backup_path) > 4096 or backup_path == finding['path']:
                raise Conflict('Choose a separate backup file inside this website')
            source = {'kind': 'site-backup', 'path': backup_path}
        if finding['status'] != 'open' or (not cleanup and backup_path is None and backup_name is None and not reference.get('expected')):
            raise Conflict('This finding has no verified replacement reference')
        if not finding['fingerprint'].get('missing') and finding['fingerprint']['links'] != 1:
            raise Conflict('Hard-linked files require manual review')
        site = dict(owner=context['owner'], identity=context['identity'], domain=finding['domain'], root=finding['root'])
        with self.locked():
            with self.store.connection() as db:
                active = db.execute("SELECT id FROM repair_plans WHERE finding_id=? AND status IN ('queued','ready','applying','undoing')", (finding_id,)).fetchone()
            if active:
                old = self.get(context, active['id'])
                job = self.store.job(context, active['id'])
                stale = (old['status'] == 'queued' and job['status'] not in ('queued', 'running')) or (
                    old['status'] == 'ready' and (old['metadata']['expires'] < time.time()
                                                 or old['metadata']['generation'] != generation(self.settings)))
                same_source = old['metadata'].get('source', {'kind': 'wordpress'}) == source
                if not stale and same_source:
                    return active['id']
                if not stale and old['status'] != 'ready':
                    raise Conflict('Another repair is in progress; wait or cancel its preview first')
                self.update(context, old, 'failed', 'Preview expired, was cancelled, or its replacement source changed')
            job_id = self.store.enqueue(context, site, finding['path'], source='repair-preview', generation=generation(self.settings))
            with self.store.connection() as db:
                db.execute('INSERT INTO repair_plans(id,finding_id,owner,identity,actor,status,created,metadata) VALUES(?,?,?,?,?,?,?,?)',
                           (job_id, finding_id, *self.store.scope(context), context['actor'], 'queued', time.time(), encode({'source': source})))
                self.store.audit(context, 'cleanup.preview_queued' if cleanup else 'repair.preview_queued', job_id, {'finding': finding_id, 'source': source}, db)
            return job_id

    def validate(self, context, plan):
        finding = self.store.finding(context, plan['finding_id'])
        self.quarantine.validate_site(context, finding)
        if finding['root'] != plan['root'] or finding['path'] != plan['target']:
            raise Conflict('Repair target changed')
        return finding

    @staticmethod
    def parent_identity(fd):
        info = os.fstat(fd)
        return {'device': info.st_dev, 'inode': info.st_ino}

    def check_parent(self, plan, fd):
        if plan['metadata'].get('fingerprint', {}).get('missing'):
            from .missing_files import MissingFiles
            MissingFiles(self).check_anchor(plan)
        expected = plan['metadata']['parent']
        with parent(plan['root'], plan['target']) as (live, _):
            if self.parent_identity(fd) != expected or self.parent_identity(live) != expected:
                raise Conflict('Repair parent directory was moved or replaced')

    @staticmethod
    def parent_identity_from_path(path):
        with directory(path) as fd:
            return Repairs.parent_identity(fd)

    def check_release(self, plan, finding, prepared=False):
        if plan['metadata'].get('source', {'kind':'wordpress'})['kind']!='wordpress':return
        from .wordpress import release_marker
        reference=finding['fingerprint']['wordpress']
        try:actual=release_marker(self.settings,plan['root'],reference['component'])
        except (OSError,ClamShieldError) as exc:
            raise Conflict('Component release identity changed or is unavailable; scan again') from exc
        expected=plan['metadata'].get('release_marker') if prepared else reference.get('release_marker')
        if expected:
            keys=('device','inode','size','uid','gid','mode','links','sha256')
            if actual['path']!=expected['path'] or any(actual['fingerprint'][k]!=expected['fingerprint'][k] for k in keys):
                raise Conflict('Component release marker changed; prepare a fresh integrity scan and preview')
        plan['metadata']['release_marker']=actual

    def prepare(self, job, engines):
        context = {k: job[k] for k in ('owner', 'identity', 'actor')}
        counters = dict(seen=1, scanned=0, infected=0, detections=0, skipped=0, errors=0, bytes=0)
        plan = self.get(context, job['id'])
        try:
            finding = self.validate(context, plan)
            if plan['status'] != 'queued' or finding['status'] != 'open':
                raise Conflict('Finding is no longer available for preview')
            missing = finding['fingerprint'].get('missing', False)
            if missing:
                from .missing_files import MissingFiles
                MissingFiles(self).inspect(plan, finding)
                before = b''
            else:
                with parent(job['root'], job['target']) as (fd, _):
                    plan['metadata']['parent'] = self.parent_identity(fd)
                    with snapshot(job['root'], job['target'], self.settings.snapshots, self.settings.max_file_bytes) as (copy, fingerprint):
                        if fingerprint != {k: v for k, v in finding['fingerprint'].items() if k != 'wordpress'}:
                            raise Conflict('File changed since the integrity check; scan again')
                        before = copy.read_bytes()
                    self.check_parent(plan, fd)
            source = plan['metadata'].get('source', {'kind': 'wordpress'})
            self.check_release(plan,finding)
            if source['kind']=='targeted-cleanup':
                from .cleanup import eligible,transform
                eligible(finding)
                if {engine.name for engine in engines}!={'clamav','yara'}:raise Conflict('Targeted cleaning requires both ClamAV and YARA validation')
                content,provenance=transform(before,finding['path'],source['catalog_revision'])
            elif source['kind']=='recovery-package':
                from .wordpress_recovery import WordPressRecovery
                content,provenance=WordPressRecovery(self.settings,self.store,self.hestia).replacement(context,finding,source)
            elif source['kind']=='hestia-backup':
                from .native_backups import NativeBackups
                content,provenance=NativeBackups(self.settings,self.store,self.hestia).replacement(context,finding,source)
            elif source['kind'] == 'site-backup':
                with snapshot(job['root'], source['path'], self.settings.snapshots, self.settings.max_file_bytes) as (copy, fingerprint):
                    if fingerprint['links'] != 1:
                        raise Conflict('Hard-linked backup files require manual review')
                    content = copy.read_bytes()
                provenance = dict(kind='site-backup', source=source['path'], sha256=digest(content), size=len(content),
                                  fingerprint=fingerprint, authenticity='user-supplied',
                                  warning='This backup is supplied by the account. A successful scan does not prove its authenticity or application compatibility.')
            else:
                reference = finding['fingerprint']['wordpress']
                content, provenance = self.references.replacement(reference['component'], reference['file'], reference['expected'])
            if len(content) > self.settings.max_file_bytes:
                raise Conflict('Replacement exceeds the file size limit')
            candidate = self.settings.state / ('repair-' + plan['id'] + '.candidate')
            write(candidate, content)
            if not engines:
                raise Conflict('Replacement validation requires scanning engines')
            hits = [hit for engine in engines for hit in engine.scan(candidate)]
            if hits:
                raise Conflict('Scanning engines flagged the replacement; review the rules before repair')
            if not missing and digest(content) == digest(before):
                raise Conflict('Replacement is identical to the current file')
            if self.store.cancelled(job['id']):
                raise Conflict('Repair preview was cancelled')
            plan['metadata'].update(candidate=candidate.name, replacement=provenance,
                                    fingerprint=finding['fingerprint'], preview=preview(before, content),
                                    validation={'engines': [engine.name for engine in engines], 'at': time.time()},
                                    generation=job['generation'], expires=time.time() + 86400)
            if missing:
                plan['metadata']['preview'].update(before_missing=True, before_sha256=None)
                plan['metadata']['preview']['diff'] = 'Original file is absent.\n' + plan['metadata']['preview']['diff']
            self.update(context, plan, 'ready')
            counters.update(scanned=1, bytes=len(content))
            self.store.finish(job, 'completed', counters)
        except (OSError, ClamShieldError) as exc:
            from .cleanup import UnsupportedCleaning
            if isinstance(exc,UnsupportedCleaning):plan['metadata']['failure_kind']='unsupported-cleanup'
            message = str(exc) if isinstance(exc, ClamShieldError) else 'Repair preview could not be prepared'
            self.update(context, plan, 'failed', message)
            counters['errors'] = 1
            self.store.finish(job, 'failed', counters, message)

    def storage(self, plan):
        return self.quarantine.storage(plan['root'], plan['metadata']['fingerprint']['device'])

    def copy_private(self, plan, source, output, expected, restore_metadata=False):
        """Copy verified bytes to a new private inode, preserving the source."""
        base = self.storage(plan)
        with directory(base) as fd:
            source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(source_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected['size']:
                    raise Conflict('Backup content metadata does not match')
                content = bytearray()
                while chunk := os.read(source_fd, min(1024 * 1024, expected['size'] + 1 - len(content))):
                    content.extend(chunk)
                    if len(content) > expected['size']:
                        raise Conflict('Backup changed while copying')
                if attributes(before) != attributes(os.fstat(source_fd)) or digest(content) != expected['sha256']:
                    raise Conflict('Backup content verification failed')
            finally:
                os.close(source_fd)
            result = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                view = memoryview(content)
                while view:
                    view = view[os.write(result, view):]
                if restore_metadata:
                    os.fchown(result, expected['uid'], expected['gid'])
                    os.fchmod(result, expected['mode'])
                    os.utime(result, ns=(expected['mtime_ns'], expected['mtime_ns']))
                os.fsync(result)
                fingerprint = attributes(os.fstat(result)) | {'sha256': digest(content)}
            finally:
                os.close(result)
            os.fsync(fd)
        return fingerprint

    def private_matches(self, plan, name, expected):
        try:
            with file_handle(self.storage(plan), name) as (fd, info):
                return info.st_nlink == 1 and info.st_size == expected['size'] and hash_fd(fd) == expected['sha256']
        except (OSError, ClamShieldError):
            return False

    def preserve_partial(self, plan, name):
        # A killed writer may leave a partial private copy. Retain it under a
        # distinct name before rebuilding from a separately verified capture.
        with directory(self.storage(plan)) as fd:
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            rename_noreplace(fd, name, fd, name + '.partial-' + uuid.uuid4().hex)
            os.fsync(fd)

    def target_matches(self, plan, expected, exact=True):
        if not expected or 'sha256' not in expected:
            return False
        try:
            with file_handle(plan['root'], plan['target']) as (fd, _):
                return same_content(fd, expected) if exact else hash_fd(fd) == expected['sha256']
        except (OSError, ClamShieldError):
            return False

    def target_absent(self, plan):
        with parent(plan['root'], plan['target']) as (fd, name):
            self.check_parent(plan, fd)
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
                return False
            except FileNotFoundError:
                return True

    def publish(self, plan, source, target_fd, name):
        self.check_parent(plan, target_fd)
        with directory(self.storage(plan)) as storage_fd:
            rename_noreplace(storage_fd, source, target_fd, name)
            os.fsync(storage_fd)
            os.fsync(target_fd)

    def findings_status(self, context, plan, status):
        with self.store.connection() as db:
            if plan['metadata']['fingerprint'].get('missing'):
                db.execute('UPDATE findings SET status=? WHERE id=? AND owner=? AND identity=?',
                           (status, plan['finding_id'], *self.store.scope(context)))
                return
            db.execute('''UPDATE findings SET status=? WHERE owner=? AND identity=? AND domain=? AND path=?
              AND json_extract(fingerprint,'$.sha256')=? AND job_id IN (SELECT id FROM jobs WHERE root=?)''',
              (status, *self.store.scope(context), plan['domain'], plan['target'], plan['metadata']['fingerprint']['sha256'], plan['root']))

    def finalize(self, context, plan, undone=False):
        if undone and plan['metadata']['fingerprint'].get('missing'):
            from .missing_files import MissingFiles
            return MissingFiles(self).finish_undo(context, plan)
        phase = 'undo' if undone else 'apply'
        site = dict(owner=plan['owner'], identity=plan['identity'], domain=plan['domain'], root=plan['root'])
        job_id = self.store.enqueue(context, site, plan['target'], source='repair-undo-recheck' if undone else 'repair-recheck',
                                    generation=generation(self.settings), dedup_key=plan['id'] + ':' + phase)
        plan['metadata']['undo_recheck_job' if undone else 'recheck_job'] = job_id
        with self.store.connection() as db:
            db.execute('UPDATE operations SET status=? WHERE id=?', ('undone' if undone else 'cleaned' if plan['metadata'].get('source',{}).get('kind')=='targeted-cleanup' else 'repaired', plan['metadata']['operation_id']))
        self.findings_status(context, plan, 'restored_unverified' if undone else 'cleaned_unverified' if plan['metadata'].get('source',{}).get('kind')=='targeted-cleanup' else 'repaired_unverified')
        self.update(context, plan, 'undone' if undone else 'repaired')

    def rolled_back(self, context, plan):
        site = dict(owner=plan['owner'], identity=plan['identity'], domain=plan['domain'], root=plan['root'])
        plan['metadata']['rollback_recheck_job'] = self.store.enqueue(context, site, plan['target'],
            source='repair-rollback-recheck', generation=generation(self.settings), dedup_key=plan['id'] + ':rollback')
        self.findings_status(context, plan, 'restored_unverified')
        with self.store.connection() as db:
            db.execute("UPDATE operations SET status='restored' WHERE id=?", (plan['metadata']['operation_id'],))
        self.update(context, plan, 'failed', 'Interrupted repair rolled back; original content restored')

    def apply(self, context, plan_id):
        with self.locked():
            plan = self.get(context, plan_id)
            finding = self.validate(context, plan)
            metadata = plan['metadata']
            if plan['status'] != 'ready' or finding['status'] != 'open':
                raise Conflict('Repair preview is no longer ready')
            if time.time() > metadata['expires'] or generation(self.settings) != metadata['generation']:
                raise Conflict('Preview expired or scanning data changed; prepare a fresh preview')
            candidate = self.settings.state / metadata['candidate']
            content = candidate.read_bytes()
            if digest(content) != metadata['replacement']['sha256']:
                raise Conflict('Replacement content verification failed')
            if metadata.get('source',{}).get('kind')=='targeted-cleanup':
                from .cleanup import revision
                if metadata['source']['catalog_revision']!=revision():raise Conflict('Cleaning definitions changed; prepare a fresh preview')
            self.check_release(plan,finding,prepared=True)
            if metadata['fingerprint'].get('missing'):
                from .missing_files import MissingFiles
                return MissingFiles(self).apply(context, plan, content)
            operation = uuid.uuid4().hex
            metadata.update(operation_id=operation, phase='apply', staged=operation + '.replacement')
            self.update(context, plan, 'applying')
            try:
                base = self.storage(plan)
                write(base / metadata['staged'], content)
                with file_handle(base, metadata['staged']) as (fd, _):
                    expected = metadata['fingerprint']
                    os.fchown(fd, expected['uid'], expected['gid'])
                    os.fchmod(fd, expected['mode'])
                    os.fsync(fd)
                    metadata['replacement_fingerprint'] = attributes(os.fstat(fd)) | {'sha256': digest(content)}
                self.update(context, plan, 'applying')
                with parent(plan['root'], plan['target']) as (fd, name):
                    self.check_parent(plan, fd)
                    self.quarantine.capture(context, finding['id'], operation_id=operation,
                                            kind='cleanup' if metadata.get('source',{}).get('kind')=='targeted-cleanup' else 'repair',
                                            extra={'repair_plan': plan['id']}, source=(fd, name))
                    self.publish(plan, metadata['staged'], fd, name)
                self.finalize(context, plan)
            except (OSError, ClamShieldError) as exc:
                self.update(context, plan, 'recovery_required', 'Repair interrupted; inspect the operation before another action')
                raise Conflict('Repair interrupted; use recovery before another action') from exc
            return {'plan_id': plan_id, 'recheck_job': metadata['recheck_job']}

    def undo(self, context, plan_id):
        with self.locked():
            plan = self.get(context, plan_id)
            self.validate(context, plan)
            if plan['status'] not in ('repaired', 'verified', 'recheck_failed'):
                raise Conflict('This repair is not available for undo')
            metadata = plan['metadata']; operation = metadata['operation_id']
            if metadata['fingerprint'].get('missing'):
                from .missing_files import MissingFiles
                return MissingFiles(self).undo(context, plan)
            if not self.private_matches(plan, operation, metadata['fingerprint']):
                raise Conflict('Original backup could not be verified')
            if not self.target_matches(plan, metadata['replacement_fingerprint']):
                raise Conflict('Repaired file changed; scan again before undo')
            metadata.update(phase='undo', undo_capture=operation + '.undo.capture',
                            undo_backup=operation + '.undo.backup', undo_staged=operation + '.undo.original')
            self.update(context, plan, 'undoing')
            try:
                with parent(plan['root'], plan['target']) as (fd, name), directory(self.storage(plan)) as storage_fd:
                    self.check_parent(plan, fd)
                    rename_noreplace(fd, name, storage_fd, metadata['undo_capture'])
                    os.fsync(fd); os.fsync(storage_fd)
                    with file_handle(self.storage(plan), metadata['undo_capture']) as (captured, _):
                        if not same_content(captured, metadata['replacement_fingerprint']):
                            try:
                                rename_noreplace(storage_fd, metadata['undo_capture'], fd, name)
                                os.fsync(fd); os.fsync(storage_fd)
                            except OSError:
                                pass
                            raise Conflict('File changed during undo; nothing was overwritten')
                    self.copy_private(plan, metadata['undo_capture'], metadata['undo_backup'], metadata['replacement_fingerprint'])
                    os.unlink(metadata['undo_capture'], dir_fd=storage_fd); os.fsync(storage_fd)
                    metadata['undo_fingerprint'] = self.copy_private(plan, operation, metadata['undo_staged'], metadata['fingerprint'], True)
                    self.update(context, plan, 'undoing')
                    self.publish(plan, metadata['undo_staged'], fd, name)
                self.finalize(context, plan, True)
            except (OSError, ClamShieldError) as exc:
                self.update(context, plan, 'recovery_required', 'Undo interrupted; both content versions are retained')
                raise Conflict('Undo interrupted; use recovery before another action') from exc
            return {'plan_id': plan_id, 'recheck_job': metadata['undo_recheck_job']}

    def recover(self, context, plan_id):
        with self.locked():
            plan = self.get(context, plan_id)
            self.validate(context, plan)
            if plan['status'] not in ('applying', 'undoing', 'recovery_required'):
                raise Conflict('This repair has no pending recovery')
            self.recover_plan(context, plan)
            return {'plan_id': plan_id, 'status': plan['status']}

    def recover_plan(self, context, plan):
        metadata = plan['metadata']; operation = metadata['operation_id']
        if metadata['fingerprint'].get('missing'):
            from .missing_files import MissingFiles
            return MissingFiles(self).recover(context, plan)
        try:
            with parent(plan['root'], plan['target']) as (fd, _):
                self.check_parent(plan, fd)
            if not self.private_matches(plan, operation, metadata['fingerprint']):
                capture = operation + '.capture'
                if self.private_matches(plan, capture, metadata['fingerprint']):
                    self.preserve_partial(plan, operation)
                    self.copy_private(plan, capture, operation, metadata['fingerprint'])
                elif self.target_matches(plan, metadata['fingerprint']):
                    with self.store.connection() as db:
                        db.execute("UPDATE operations SET status='failed' WHERE id=?", (operation,))
                    self.update(context, plan, 'failed', 'Interrupted before capture; original file is unchanged')
                    return
                else:
                    raise Conflict('Original backup requires manual recovery')
            if metadata['phase'] == 'apply' and self.target_matches(plan, metadata.get('replacement_fingerprint', {})):
                self.finalize(context, plan)
                return
            if metadata['phase'] == 'undo' and metadata.get('undo_fingerprint') and self.target_matches(plan, metadata['undo_fingerprint']):
                self.finalize(context, plan, True)
                return
            if metadata.get('recovery_fingerprint') and self.target_matches(plan, metadata['recovery_fingerprint']):
                if metadata['phase'] == 'undo':
                    self.finalize(context, plan, True)
                else:
                    self.rolled_back(context, plan)
                return
            if not self.target_absent(plan):
                raise Conflict('Recovery target contains another file; no content was overwritten')
            if metadata['phase'] == 'undo':
                if not self.private_matches(plan, metadata['undo_backup'], metadata['replacement_fingerprint']):
                    if not self.private_matches(plan, metadata['undo_capture'], metadata['replacement_fingerprint']):
                        raise Conflict('Undo capture requires manual recovery')
                    self.preserve_partial(plan, metadata['undo_backup'])
                    self.copy_private(plan, metadata['undo_capture'], metadata['undo_backup'], metadata['replacement_fingerprint'])
            restored = operation + '.recovery-' + uuid.uuid4().hex
            metadata['recovery_fingerprint'] = self.copy_private(plan, operation, restored, metadata['fingerprint'], True)
            self.update(context, plan, plan['status'])
            with parent(plan['root'], plan['target']) as (fd, name):
                self.publish(plan, restored, fd, name)
            if metadata['phase'] == 'undo':
                self.finalize(context, plan, True)
            else:
                self.rolled_back(context, plan)
        except (OSError, ClamShieldError) as exc:
            self.update(context, plan, 'recovery_required', str(exc) if isinstance(exc, ClamShieldError) else 'Recovery requires manual review')

    def recover_pending(self):
        try:
            with self.locked(False):
                with self.store.connection() as db:
                    rows = db.execute("SELECT id,owner,identity,actor FROM repair_plans WHERE status IN ('applying','undoing') ORDER BY created LIMIT 50").fetchall()
                for row in rows:
                    context = dict(row)
                    plan = self.get(context, row['id'])
                    try:
                        self.validate(context, plan)
                        self.recover_plan(context, plan)
                    except (OSError, ClamShieldError):
                        self.update(context, plan, 'recovery_required', 'Account or site changed; recovery requires administrator review')
                self.reconcile(locked=True)
                return {'examined': len(rows)}
        except BlockingIOError:
            return {'busy': True}

    def reconcile(self, locked=False):
        if not locked:
            with self.locked():
                return self.reconcile(locked=True)
        with self.store.connection() as db:
            rows = db.execute("SELECT id,owner,identity,actor FROM repair_plans WHERE status IN ('queued','repaired') LIMIT 100").fetchall()
        for row in rows:
            context = dict(row); plan = self.get(context, row['id']); metadata = plan['metadata']
            if plan['status'] == 'queued':
                job = self.store.job(context, plan['id'])
                if job['status'] not in ('queued', 'running'):
                    self.update(context, plan, 'failed', 'Preview did not complete; prepare a fresh preview')
                continue
            job_id = metadata.get('recheck_job')
            if not job_id:
                continue
            job = self.store.job(context, job_id)
            if job['status'] in ('queued', 'running'):
                continue
            with self.store.connection() as db:
                result = db.execute('SELECT status,detail FROM file_results WHERE job_id=? AND path=?', (job_id, plan['target'])).fetchone()
            verified = (job['status'] == 'completed' and result is not None and result['status'] == 'clean'
                        and json.loads(result['detail']).get('sha256') == metadata['replacement']['sha256'])
            if verified and metadata.get('release_marker') and metadata['release_marker']['path']!=plan['target']:
                try:self.check_release(plan,self.store.finding(context,plan['finding_id']),prepared=True)
                except (OSError,ClamShieldError):verified=False
            if verified:
                self.findings_status(context, plan, 'cleaned' if metadata.get('source',{}).get('kind')=='targeted-cleanup' else 'repaired')
            self.update(context, plan, 'verified' if verified else 'recheck_failed',
                        None if verified else 'Post-repair scan did not verify the expected replacement')

    def list(self, context):
        with self.store.connection() as db:
            ids = [r['id'] for r in db.execute('SELECT id FROM repair_plans WHERE owner=? AND identity=? ORDER BY created DESC LIMIT 100', self.store.scope(context))]
        plans = [self.get(context, plan_id) for plan_id in ids]
        for plan in plans:
            # Keep the dashboard bounded; full diffs use one scoped plan query.
            plan['metadata'].get('preview', {}).pop('diff', None)
        return plans
