"""Journaled creation of absent files; never overwrite or erase later content."""
import os
import json
from pathlib import Path
import pwd
import time
import uuid

from .atomic import write, write_json
from .errors import ClamShieldError, Conflict
from .generations import current as generation
from .paths import absence, attributes, directory, file_handle, parent
from .quarantine import rename_noreplace, same_content
from .store import encode


class MissingFiles:
    def __init__(self, repairs):
        self.r = repairs

    def check_anchor(self, plan, fd=None):
        expected = plan['metadata']['fingerprint']
        with directory(Path(plan['root'])/expected['anchor_path']) as live:
            if self.r.parent_identity(live) != expected['anchor'] or (fd is not None and self.r.parent_identity(fd) != expected['anchor']):
                raise Conflict('Missing-file anchor directory was moved or replaced')

    def inspect(self, plan, finding):
        expected = {k:v for k,v in finding['fingerprint'].items() if k != 'wordpress'}
        if absence(plan['root'], plan['target']) != expected:
            raise Conflict('Missing path changed since the integrity check; scan again')
        account = pwd.getpwnam(plan['owner'])
        plan['metadata']['creation'] = dict(uid=account.pw_uid, gid=account.pw_gid, mode=0o644, directory_mode=0o755)

    def is_absent(self, plan):
        self.check_anchor(plan)
        try:
            actual = absence(plan['root'], plan['target'])
        except Conflict:
            return False
        expected = {k:v for k,v in plan['metadata']['fingerprint'].items() if k != 'wordpress'}
        if actual == expected:
            return True
        # Publication may have added a whole private directory tree. Bind its
        # final parent as well as the original anchor when proving leaf absence.
        if 'parent' in plan['metadata'] and actual['suffix'] == Path(plan['target']).name:
            with parent(plan['root'], plan['target']) as (fd, _):
                self.r.check_parent(plan, fd)
            return True
        raise Conflict('Missing-file directory chain changed; review is required')

    def build(self, plan, content):
        metadata=plan['metadata'];expected=metadata['fingerprint'];creation=metadata['creation']
        base=self.r.storage(plan);parts=expected['suffix'].split('/')
        output=base/metadata['publish_object'];directories=[]
        if len(parts)>1:
            output.mkdir(mode=0o700)
            current=output
            for index in range(len(parts)-1):
                if index:current=current/parts[index];current.mkdir(mode=0o700)
                os.chown(current,creation['uid'],creation['gid']);current.chmod(creation['directory_mode'])
                directories.append(dict(path='/'.join(filter(None,[expected['anchor_path'],*parts[:index+1]])),
                                        **self.r.parent_identity_from_path(current)))
            target=current/parts[-1]
        else:
            current=Path(plan['root'])/expected['anchor_path'];target=output
        write(target,content)
        with file_handle(target.parent,target.name) as (fd,_):
            os.fchown(fd,creation['uid'],creation['gid']);os.fchmod(fd,creation['mode']);os.fsync(fd)
            metadata['replacement_fingerprint']=attributes(os.fstat(fd))|{'sha256':metadata['replacement']['sha256']}
        metadata['parent']=self.r.parent_identity_from_path(current)
        metadata['created_directories']=directories
        for path in reversed([base/metadata['publish_object']/Path(*parts[1:i+1]) for i in range(len(parts)-1)]):
            with directory(path) as fd:os.fsync(fd)
        with directory(base) as fd:os.fsync(fd)
        self.r.update(self.context(plan),plan,'applying')

    @staticmethod
    def context(plan):
        return {k:plan[k] for k in ('owner','identity','actor')}

    def publish(self, plan):
        metadata=plan['metadata'];expected=metadata['fingerprint']
        with directory(Path(plan['root'])/expected['anchor_path']) as fd, directory(self.r.storage(plan)) as source:
            self.check_anchor(plan,fd)
            rename_noreplace(source,metadata['publish_object'],fd,expected['suffix'].split('/')[0])
            os.fsync(source);os.fsync(fd)

    def apply(self, context, plan, content):
        metadata=plan['metadata'];operation=uuid.uuid4().hex;expected=metadata['fingerprint']
        if not self.is_absent(plan):raise Conflict('The missing-file target now exists; scan again')
        metadata.update(operation_id=operation,phase='apply',publish_object=operation+('.tree' if '/' in expected['suffix'] else '.replacement'))
        self.r.update(context,plan,'applying')
        try:
            base=self.r.storage(plan)
            # The original state is absence, so save that fact rather than an
            # invented empty "original" file. This record survives every rename.
            write_json(base/(operation+'.absence.json'),expected)
            with self.r.store.connection(True) as db:
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (operation,plan['finding_id'],*self.r.store.scope(context),context['actor'],'repair-create','prepared',time.time(),
                     encode(dict(repair_plan=plan['id'],path=plan['target'],root=plan['root'],fingerprint=expected,
                                 object=operation+'.absence.json',storage=str(base),original_missing=True)),None))
            self.build(plan,content)
            self.publish(plan)
            self.r.finalize(context,plan)
        except (OSError,ClamShieldError) as exc:
            self.r.update(context,plan,'recovery_required','File creation interrupted; inspect recovery before another action')
            raise Conflict('File creation interrupted; use recovery before another action') from exc
        return {'plan_id':plan['id'],'recheck_job':metadata['recheck_job']}

    def finish_undo(self, context, plan):
        metadata=plan['metadata']
        site=dict(owner=plan['owner'],identity=plan['identity'],domain=plan['domain'],root=plan['root'])
        metadata['undo_recheck_job']=self.r.store.enqueue(context,site,plan['target'],source='repair-absence-recheck',
            generation=generation(self.r.settings),dedup_key=plan['id']+':undo')
        with self.r.store.connection() as db:db.execute("UPDATE operations SET status='undone' WHERE id=?",(metadata['operation_id'],))
        self.r.findings_status(context,plan,'open')
        self.r.update(context,plan,'undone')

    def verify_record(self, plan):
        name=plan['metadata']['operation_id']+'.absence.json'
        with file_handle(self.r.storage(plan),name) as (fd,info):
            if info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o777!=0o600 or info.st_size>65536:
                raise Conflict('Original absence record is not private or valid')
            try:record=json.loads(os.read(fd,65537))
            except (ValueError,UnicodeError) as exc:raise Conflict('Original absence record is damaged') from exc
            if record!=plan['metadata']['fingerprint']:raise Conflict('Original absence record does not match the preview')

    def retain_capture(self, plan):
        metadata=plan['metadata'];expected=metadata['replacement_fingerprint']
        if not self.r.private_matches(plan,metadata['undo_backup'],expected):
            with file_handle(self.r.storage(plan),metadata['undo_capture']) as (fd,_):
                if not same_content(fd,expected):raise Conflict('Created file changed during undo; captured content retained')
            self.r.preserve_partial(plan,metadata['undo_backup'])
            self.r.copy_private(plan,metadata['undo_capture'],metadata['undo_backup'],expected)
        with directory(self.r.storage(plan)) as fd:
            try:
                with file_handle(self.r.storage(plan),metadata['undo_capture']) as (captured,_):
                    if not same_content(captured,expected):raise Conflict('Undo capture changed; content retained for review')
                os.unlink(metadata['undo_capture'],dir_fd=fd);os.fsync(fd)
            except FileNotFoundError:pass

    def undo(self, context, plan):
        metadata=plan['metadata'];operation=metadata['operation_id']
        self.verify_record(plan)
        if not self.r.target_matches(plan,metadata['replacement_fingerprint']):
            raise Conflict('Created file changed; scan again before undo')
        metadata.update(phase='undo',undo_capture=operation+'.undo.capture',undo_backup=operation+'.undo.backup')
        self.r.update(context,plan,'undoing')
        try:
            with parent(plan['root'],plan['target']) as (fd,name), directory(self.r.storage(plan)) as storage:
                self.r.check_parent(plan,fd)
                rename_noreplace(fd,name,storage,metadata['undo_capture']);os.fsync(fd);os.fsync(storage)
                with file_handle(self.r.storage(plan),metadata['undo_capture']) as (captured,_):
                    if not same_content(captured,metadata['replacement_fingerprint']):
                        try:
                            rename_noreplace(storage,metadata['undo_capture'],fd,name);os.fsync(storage);os.fsync(fd)
                        except OSError:pass
                        raise Conflict('File changed during undo; nothing was overwritten')
            self.retain_capture(plan)
            if not self.is_absent(plan):raise Conflict('Another file appeared during undo; nothing was overwritten')
            self.finish_undo(context,plan)
        except (OSError,ClamShieldError) as exc:
            self.r.update(context,plan,'recovery_required','Undo interrupted; created content is retained')
            raise Conflict('Undo interrupted; use recovery before another action') from exc
        return {'plan_id':plan['id'],'recheck_job':metadata['undo_recheck_job']}

    def recover(self, context, plan):
        metadata=plan['metadata']
        try:
            self.check_anchor(plan)
            if metadata.get('replacement_fingerprint'):self.verify_record(plan)
            if metadata['phase']=='apply':
                if self.r.target_matches(plan,metadata.get('replacement_fingerprint')):
                    with parent(plan['root'],plan['target']) as (fd,_):self.r.check_parent(plan,fd)
                    self.r.finalize(context,plan);return
                if not self.is_absent(plan):raise Conflict('Creation target contains other content; nothing was overwritten')
                with self.r.store.connection() as db:db.execute("UPDATE operations SET status='failed' WHERE id=?",(metadata['operation_id'],))
                self.r.update(context,plan,'failed','Interrupted creation left the original file absent; staged bytes and any created directories are retained')
                return
            if self.r.target_matches(plan,metadata['replacement_fingerprint']):
                # No capture happened. Keep the created file and its existing
                # post-check; a later explicit undo can try again.
                with parent(plan['root'],plan['target']) as (fd,_):self.r.check_parent(plan,fd)
                self.r.finalize(context,plan);return
            if not self.is_absent(plan):raise Conflict('Undo target contains other content; nothing was overwritten')
            self.retain_capture(plan)
            if not self.r.private_matches(plan,metadata['undo_backup'],metadata['replacement_fingerprint']):
                raise Conflict('Created content backup requires review before completing undo')
            self.finish_undo(context,plan)
        except (OSError,ClamShieldError) as exc:
            self.r.update(context,plan,'recovery_required',str(exc) if isinstance(exc,ClamShieldError) else 'Missing-file recovery requires manual review')

    def recheck(self, job):
        with self.r.locked():
            return self.recheck_locked(job)

    def recheck_locked(self, job):
        context={k:job[k] for k in ('owner','identity','actor')}
        counters=dict(seen=1,scanned=0,infected=0,detections=0,skipped=0,errors=0,bytes=0,absent=0)
        try:
            if self.r.store.cancelled(job['id']):
                self.r.store.finish(job,'cancelled',counters);return
            plan_id,_,phase=(job.get('dedup_key') or '').partition(':')
            plan=self.r.get(context,plan_id);self.r.validate(context,plan)
            if (phase!='undo' or plan['root']!=job['root'] or plan['target']!=job['target'] or
                    not plan['metadata']['fingerprint'].get('missing') or not self.is_absent(plan)):
                raise Conflict('The expected missing-file state could not be verified')
            counters['absent']=1
            self.r.store.file_result(job['id'],job['target'],'absent',{'original_missing':True,'plan_id':plan_id})
            self.r.store.finish(job,'completed',counters)
            if self.r.store.job(context,job['id'])['status']!='completed':return
            plan['metadata']['undo_absence_verified']=True
            self.r.update(context,plan,plan['status'])
            self.r.store.audit(context,'repair.absence_verified',plan_id,{'job_id':job['id']})
        except (OSError,ClamShieldError) as exc:
            counters['errors']=1
            self.r.store.finish(job,'failed',counters,str(exc) if isinstance(exc,ClamShieldError) else 'Absence verification failed')
