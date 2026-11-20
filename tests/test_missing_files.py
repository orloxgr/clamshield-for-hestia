import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from clamshield.errors import AccessDenied, ClamShieldError, Conflict, EngineError
from clamshield.exceptions import Exceptions
from clamshield.missing_files import MissingFiles
from clamshield.paths import absence
from clamshield.worker import Worker
import test_repairs as repair_fixtures


class MissingFileRepairs(unittest.TestCase):
    def setUp(self):
        repair_fixtures.ReversibleRepairs.setUp(self)
        self.file.unlink()
        self.set_target(self.file.name)
        self.addCleanup(patch.stopall)
        patch('clamshield.missing_files.pwd.getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())).start()

    def set_target(self,path):
        self.file=self.root/path
        self.missing=absence(self.root,path)
        reference=dict(component=dict(kind='core',slug='wordpress',version='6.8.3',locale='en_US',path=''),
                       file=path,expected=dict(algorithm='sha256',digest=hashlib.sha256(self.after).hexdigest()))
        with self.store.connection() as db:
            db.execute("UPDATE findings SET path=?,fingerprint=?,signature='WordPress.core.Missing' WHERE id=?",
                       (path,json.dumps(self.missing|{'wordpress':reference}),self.finding))

    def ready(self):
        plan_id=self.repairs.queue(self.context,self.finding)
        if self.repairs.get(self.context,plan_id)['status']=='queued':
            self.repairs.prepare(self.store.claim('missing-preview'),[self.engine])
        plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('ready',plan['status'],plan['error'])
        return plan_id

    def test_missing_file_preview_apply_verified_and_undo_to_proven_absence(self):
        plan_id=self.ready();plan=self.repairs.get(self.context,plan_id)
        self.assertTrue(plan['metadata']['preview']['before_missing'])
        self.assertIsNone(plan['metadata']['preview']['before_sha256'])
        self.assertFalse(self.file.exists())
        self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes())
        self.assertEqual((os.getuid(),os.getgid(),0o644),(self.file.stat().st_uid,self.file.stat().st_gid,self.file.stat().st_mode&0o777))
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        plan=self.repairs.get(self.context,plan_id);self.assertEqual('verified',plan['status'])
        proof=self.settings.quarantine/(plan['metadata']['operation_id']+'.absence.json')
        self.assertTrue(json.loads(proof.read_text())['missing']);self.assertEqual(0o600,proof.stat().st_mode&0o777)
        self.repairs.undo(self.context,plan_id);self.assertFalse(self.file.exists())
        self.engine.scan.side_effect=EngineError('Engines cannot scan an absent file')
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        plan=self.repairs.get(self.context,plan_id)
        self.assertTrue(plan['metadata']['undo_absence_verified'])
        self.assertEqual('completed',self.store.job(self.context,plan['metadata']['undo_recheck_job'])['status'])
        self.assertEqual(self.after,(self.settings.quarantine/(plan['metadata']['operation_id']+'.undo.backup')).read_bytes())
        self.assertEqual('open',self.store.finding(self.context,self.finding)['status'])
        with self.store.connection() as db:
            result=db.execute('SELECT status FROM file_results WHERE job_id=?',(plan['metadata']['undo_recheck_job'],)).fetchone()
        self.assertEqual('absent',result['status'])

    def test_missing_parent_tree_is_published_atomically_and_undo_preserves_other_files(self):
        self.set_target('new-parent/child/empty.php')
        plan_id=self.ready();self.assertFalse((self.root/'new-parent').exists())
        self.repairs.apply(self.context,plan_id)
        plan=self.repairs.get(self.context,plan_id)
        self.assertEqual(2,len(plan['metadata']['created_directories']))
        for directory in (self.root/'new-parent',self.file.parent):self.assertEqual(0o755,directory.stat().st_mode&0o777)
        other=self.file.parent/'customer.txt';other.write_bytes(b'Keep this later file')
        self.repairs.undo(self.context,plan_id)
        self.assertFalse(self.file.exists());self.assertEqual(b'Keep this later file',other.read_bytes())
        self.assertTrue(self.file.parent.is_dir())

    def test_file_directory_and_symlink_appearing_after_preview_are_never_overwritten(self):
        for kind in ('file','directory','symlink'):
            plan_id=self.ready()
            if kind=='file':self.file.write_bytes(b'concurrent')
            elif kind=='directory':self.file.mkdir()
            else:self.file.symlink_to('/etc/passwd')
            with self.assertRaises((Conflict,OSError)):self.repairs.apply(self.context,plan_id)
            if kind=='file':self.assertEqual(b'concurrent',self.file.read_bytes());self.file.unlink()
            elif kind=='directory':self.assertTrue(self.file.is_dir());self.file.rmdir()
            else:self.assertTrue(self.file.is_symlink());self.file.unlink()

    def test_concurrent_parent_creation_at_publish_is_retained_and_requires_review(self):
        self.set_target('absent-parent/child.php');plan_id=self.ready()
        publish=MissingFiles.publish
        def compete(instance,plan):
            self.file.parent.mkdir();(self.file.parent/'other.txt').write_bytes(b'concurrent parent')
            return publish(instance,plan)
        with patch.object(MissingFiles,'publish',compete):
            with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.repairs.recover(self.context,plan_id)
        self.assertEqual('recovery_required',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(b'concurrent parent',(self.file.parent/'other.txt').read_bytes())
        self.assertFalse(self.file.exists())

    def test_replaced_anchor_is_refused_after_preview(self):
        plan_id=self.ready();self.root.rename(self.base/'old-root');self.root.mkdir()
        with self.assertRaises((Conflict,OSError)):self.repairs.apply(self.context,plan_id)
        self.assertFalse(self.file.exists())

    def test_changed_created_file_is_never_removed_by_undo(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id);self.file.write_bytes(b'later edit')
        with self.assertRaises(Conflict):self.repairs.undo(self.context,plan_id)
        self.assertEqual(b'later edit',self.file.read_bytes())

    def test_interrupted_creation_before_publish_leaves_absence_and_retains_staging(self):
        self.set_target('new/deep/created.php');plan_id=self.ready()
        with patch.object(MissingFiles,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.repairs.recover_pending();plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('failed',plan['status']);self.assertFalse(self.file.exists())
        self.assertTrue((self.settings.quarantine/plan['metadata']['publish_object']).is_dir())

    def test_interrupted_creation_after_publish_finalizes_exact_file_and_rechecks(self):
        self.set_target('new/deep/created.php');plan_id=self.ready()
        with patch.object(self.repairs,'finalize',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.repairs.recover_pending();Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.assertEqual('verified',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(self.after,self.file.read_bytes())

    def test_undo_interrupted_before_capture_keeps_created_file_and_can_be_retried(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        with patch('clamshield.missing_files.rename_noreplace',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.undo(self.context,plan_id)
        self.repairs.recover_pending();self.assertEqual(self.after,self.file.read_bytes())
        self.repairs.undo(self.context,plan_id);self.assertFalse(self.file.exists())

    def test_undo_interrupted_after_capture_or_after_backup_completes_from_exact_evidence(self):
        for stage in ('retain_capture','finish_undo'):
            if self.file.exists():self.file.unlink()
            self.set_target(self.file.name)
            with self.store.connection() as db:db.execute("UPDATE findings SET status='open' WHERE id=?",(self.finding,))
            plan_id=self.ready();self.repairs.apply(self.context,plan_id)
            with patch.object(MissingFiles,stage,side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):self.repairs.undo(self.context,plan_id)
            self.repairs.recover_pending()
            self.assertEqual('undone',self.repairs.get(self.context,plan_id)['status'])
            self.assertFalse(self.file.exists())
            while Worker(self.settings,self.store,self.hestia,[self.engine]).once():pass

    def test_undo_recovery_retains_a_concurrent_new_file(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        with patch.object(MissingFiles,'retain_capture',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.undo(self.context,plan_id)
        self.file.write_bytes(b'new independent content');self.repairs.recover_pending()
        self.assertEqual(b'new independent content',self.file.read_bytes())
        self.assertEqual('recovery_required',self.repairs.get(self.context,plan_id)['status'])

    def test_missing_findings_cannot_be_quarantined_or_trusted_and_foreign_owners_are_denied(self):
        with self.assertRaises(Conflict):self.repairs.quarantine.capture(self.context,self.finding)
        with self.assertRaises(ClamShieldError):Exceptions(self.store).add(self.context,self.finding)
        plan_id=self.ready()
        for context in (self.context|{'owner':'bob'},self.context|{'identity':'recreated'}):
            for method in (self.repairs.get,self.repairs.apply,self.repairs.undo,self.repairs.recover):
                with self.assertRaises(AccessDenied):method(context,plan_id)

    def test_absent_candidate_requires_clean_complete_engines_and_allows_official_empty_file(self):
        self.engine.scan.side_effect=EngineError('YARA unavailable')
        plan_id=self.repairs.queue(self.context,self.finding);self.repairs.prepare(self.store.claim('failed-preview'),[self.engine])
        self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])
        self.engine.scan.side_effect=None
        self.references.replacement.return_value=(b'',{'source':'official','sha256':hashlib.sha256(b'').hexdigest(),'size':0})
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        self.assertEqual(b'',self.file.read_bytes())

    def test_damaged_absence_record_cannot_authorize_undo(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        plan=self.repairs.get(self.context,plan_id)
        (self.settings.quarantine/(plan['metadata']['operation_id']+'.absence.json')).write_bytes(b'corrupt')
        with self.assertRaises(Conflict):self.repairs.undo(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes())

    def test_cancelled_absence_recheck_cannot_claim_verification(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.repairs.undo(self.context,plan_id);plan=self.repairs.get(self.context,plan_id)
        self.store.cancel(self.context,plan['metadata']['undo_recheck_job'])
        self.assertFalse(Worker(self.settings,self.store,self.hestia,[self.engine]).once())
        self.assertNotIn('undo_absence_verified',self.repairs.get(self.context,plan_id)['metadata'])

    def test_component_upgrade_after_preview_refuses_old_release_creation(self):
        plan_id=self.ready()
        marker=self.root/'wp-includes/version.php'
        marker.write_text("<?php\n$wp_version = '6.9';\n")
        with self.assertRaises(ClamShieldError):self.repairs.apply(self.context,plan_id)
        self.assertFalse(self.file.exists())

    def test_component_upgrade_after_publication_prevents_verified_repair(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        (self.root/'wp-includes/version.php').write_text("<?php\n$wp_version = '6.9';\n")
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.assertEqual('recheck_failed',self.repairs.get(self.context,plan_id)['status'])
