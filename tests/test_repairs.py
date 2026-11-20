import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.errors import AccessDenied, Conflict, EngineError
from clamshield.generations import current as generation
from clamshield.paths import snapshot
from clamshield.quarantine import rename_noreplace
from clamshield.repairs import Repairs, preview
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker


class ReversibleRepairs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.root = self.base/'site'; self.root.mkdir()
        self.settings = Settings(state=self.base/'state'); self.settings.prepare()
        self.store = Store(self.settings.database)
        self.context = dict(actor='alice', owner='alice', identity='generation', admin=False)
        self.site = dict(owner='alice', identity='generation', domain='site.test', root=str(self.root), suspended=False)
        self.hestia = Mock(); self.hestia.authorize.return_value = self.context; self.hestia.sites.return_value = [self.site]
        self.file = self.root/'wp-settings.php'; self.before = b'<?php\n/* changed file */\n'; self.after = b'<?php\n/* verified release */\n'
        self.file.write_bytes(self.before); self.file.chmod(0o640)
        marker=self.root/'wp-includes/version.php';marker.parent.mkdir()
        marker.write_text("<?php\n$wp_version = '6.8.3';\n$wp_local_package = 'en_US';\n")
        job_id = self.store.enqueue(self.context, self.site)
        job = self.store.claim('fixture')
        with snapshot(self.root, self.file.name, self.settings.snapshots, 4096) as (_, fingerprint): self.original = fingerprint
        reference = dict(component=dict(kind='core', slug='wordpress', version='6.8.3', locale='en_US', path=''),
                         file=self.file.name, expected=dict(algorithm='sha256', digest=hashlib.sha256(self.after).hexdigest()))
        self.finding = self.store.add_finding(job, self.file.name, fingerprint | {'wordpress': reference},
                                            dict(engine='integrity', signature='WordPress.core.Modified', provider='wordpress.org'))
        self.store.finish(job, 'completed', {})
        self.references = Mock(); self.references.replacement.return_value = (self.after, dict(source='https://downloads.wordpress.org/release/wordpress-6.8.3.zip',
            reference='https://api.wordpress.org/core/checksums/1.0/', sha256=hashlib.sha256(self.after).hexdigest(), size=len(self.after)))
        self.repairs = Repairs(self.settings, self.store, self.hestia, self.references)
        self.engine = Mock(); self.engine.name='test'; self.engine.scan.return_value=[]

    def ready(self):
        plan_id=self.repairs.queue(self.context,self.finding)
        job=self.store.claim('preview')
        self.repairs.prepare(job,[self.engine])
        plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('ready',plan['status'],plan['error'])
        return plan_id

    def test_preview_does_not_mutate_site_and_binds_diff_hash_and_generation(self):
        plan_id=self.ready();plan=self.repairs.get(self.context,plan_id)
        self.assertEqual(self.before,self.file.read_bytes())
        self.assertIn('-/* changed file */',plan['metadata']['preview']['diff'])
        self.assertIn('+/* verified release */',plan['metadata']['preview']['diff'])
        self.assertEqual(generation(self.settings),plan['metadata']['generation'])
        self.assertEqual(0o600,stat.S_IMODE((self.settings.state/plan['metadata']['candidate']).stat().st_mode))

    def test_apply_preserves_original_metadata_and_recheck_then_undo(self):
        plan_id=self.ready()
        result=self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes())
        self.assertEqual(0o640,stat.S_IMODE(self.file.stat().st_mode))
        plan=self.repairs.get(self.context,plan_id);operation=plan['metadata']['operation_id']
        backup=self.settings.quarantine/operation
        self.assertEqual(self.before,backup.read_bytes());self.assertEqual(0o600,stat.S_IMODE(backup.stat().st_mode))
        self.assertTrue(Worker(self.settings,self.store,self.hestia,[self.engine]).once())
        self.assertEqual('completed',self.store.job(self.context,result['recheck_job'])['status'])
        self.assertEqual('verified',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual('repaired',self.store.finding(self.context,self.finding)['status'])
        self.repairs.undo(self.context,plan_id)
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual(self.original['mtime_ns'],self.file.stat().st_mtime_ns)
        self.assertEqual('undone',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(self.before,backup.read_bytes())
        self.assertEqual(self.after,(self.settings.quarantine/(operation+'.undo.backup')).read_bytes())

    def test_an_open_tenant_handle_cannot_change_saved_original(self):
        plan_id=self.ready()
        with self.file.open('r+b') as stream:
            self.repairs.apply(self.context,plan_id)
            stream.write(b'changed through old descriptor');stream.flush()
        plan=self.repairs.get(self.context,plan_id)
        self.assertEqual(self.before,(self.settings.quarantine/plan['metadata']['operation_id']).read_bytes())
        self.assertEqual(self.after,self.file.read_bytes())

    def test_changed_file_at_apply_is_put_back_and_recovery_does_not_overwrite(self):
        plan_id=self.ready();self.file.write_bytes(b'concurrent edit')
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.assertEqual(b'concurrent edit',self.file.read_bytes())
        self.repairs.recover(self.context,plan_id)
        self.assertEqual(b'concurrent edit',self.file.read_bytes())
        self.assertEqual('recovery_required',self.repairs.get(self.context,plan_id)['status'])

    def test_undo_refuses_changed_replacement_and_retains_both_versions(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id);self.file.write_bytes(b'user changed replacement')
        with self.assertRaises(Conflict):self.repairs.undo(self.context,plan_id)
        self.assertEqual(b'user changed replacement',self.file.read_bytes())

    def test_foreign_or_recreated_account_cannot_read_apply_or_undo(self):
        plan_id=self.ready()
        for context in [self.context|{'owner':'bob','identity':'bob'},self.context|{'identity':'recreated'}]:
            self.assertEqual([],self.repairs.list(context))
            for method in [self.repairs.get,self.repairs.apply,self.repairs.undo,self.repairs.recover]:
                with self.assertRaises(AccessDenied):method(context,plan_id)

    def test_native_site_change_blocks_mutation(self):
        plan_id=self.ready();self.hestia.sites.return_value=[self.site|{'root':'/other/root'}]
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.before,self.file.read_bytes())

    def test_replaced_parent_is_not_used_for_repair(self):
        plan_id=self.ready();moved=self.base/'old-site';self.root.rename(moved);self.root.mkdir();self.file.write_bytes(b'new directory')
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.assertEqual(b'new directory',self.file.read_bytes());self.assertEqual(self.before,(moved/self.file.name).read_bytes())

    def test_failed_or_detecting_engine_never_creates_ready_preview(self):
        for side_effect,values in [(EngineError('Unavailable'),[]),(None,[dict(engine='test',signature='Flag',provider='local')])]:
            self.engine.scan.side_effect=side_effect;self.engine.scan.return_value=values
            plan_id=self.repairs.queue(self.context,self.finding);job=self.store.claim('preview')
            self.repairs.prepare(job,[self.engine])
            self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])
            self.assertEqual(self.before,self.file.read_bytes())

    def test_corrupt_candidate_or_backup_never_gets_published(self):
        plan_id=self.ready();plan=self.repairs.get(self.context,plan_id);candidate=self.settings.state/plan['metadata']['candidate']
        candidate.write_bytes(b'corrupt')
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.before,self.file.read_bytes())
        candidate.write_bytes(self.after);self.repairs.apply(self.context,plan_id)
        plan=self.repairs.get(self.context,plan_id);(self.settings.quarantine/plan['metadata']['operation_id']).write_bytes(b'corrupt backup')
        with self.assertRaises(Conflict):self.repairs.undo(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes())

    def test_expired_or_changed_rules_require_fresh_preview(self):
        plan_id=self.ready()
        with patch('clamshield.repairs.generation',return_value='different'):
            with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        with patch('clamshield.repairs.time.time',return_value=10**12):
            with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
            fresh=self.repairs.queue(self.context,self.finding)
            self.assertNotEqual(plan_id,fresh)

    def test_cancelled_preview_can_be_queued_again(self):
        cancelled=self.repairs.queue(self.context,self.finding)
        self.store.cancel(self.context,cancelled)
        fresh=self.repairs.queue(self.context,self.finding)
        self.assertNotEqual(cancelled,fresh)
        self.assertEqual('failed',self.repairs.get(self.context,cancelled)['status'])

    def test_dashboard_excludes_full_diffs_but_scoped_plan_retains_them(self):
        plan_id=self.ready()
        self.assertNotIn('diff',self.repairs.list(self.context)[0]['metadata']['preview'])
        self.assertIn('diff',self.repairs.get(self.context,plan_id)['metadata']['preview'])

    def test_post_repair_scan_detection_or_failure_is_never_verified(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        self.engine.scan.side_effect=EngineError('Unavailable')
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.assertEqual('recheck_failed',self.repairs.get(self.context,plan_id)['status'])
        self.assertNotEqual('repaired',self.store.finding(self.context,self.finding)['status'])

    def test_interrupted_apply_after_capture_rolls_back_original(self):
        plan_id=self.ready()
        with patch.object(self.repairs,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.assertFalse(self.file.exists());self.assertEqual('applying',self.repairs.get(self.context,plan_id)['status'])
        self.repairs.recover_pending()
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])

    def test_interrupted_apply_after_publish_is_finalized_and_rechecked(self):
        plan_id=self.ready()
        with patch.object(self.repairs,'finalize',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes())
        self.repairs.recover_pending()
        self.assertEqual('repaired',self.repairs.get(self.context,plan_id)['status'])
        Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.assertEqual('verified',self.repairs.get(self.context,plan_id)['status'])

    def test_interrupted_original_backup_copy_is_rebuilt_from_verified_capture(self):
        plan_id=self.ready()
        original_unlink=os.unlink
        def stop_before_capture_unlink(name,*args,**kwargs):
            if str(name).endswith('.capture'):raise KeyboardInterrupt()
            return original_unlink(name,*args,**kwargs)
        with patch('clamshield.quarantine.os.unlink',side_effect=stop_before_capture_unlink):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        plan=self.repairs.get(self.context,plan_id);operation=plan['metadata']['operation_id']
        (self.settings.quarantine/operation).write_bytes(b'partial copy')
        self.repairs.recover_pending()
        self.assertEqual(self.before,self.file.read_bytes())
        self.assertEqual(self.before,(self.settings.quarantine/operation).read_bytes())
        self.assertEqual(1,len(list(self.settings.quarantine.glob(operation+'.partial-*'))))

    def test_interrupted_undo_before_publish_recovers_original(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        with patch.object(self.repairs,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.undo(self.context,plan_id)
        self.assertFalse(self.file.exists())
        self.repairs.recover_pending()
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual('undone',self.repairs.get(self.context,plan_id)['status'])

    def test_interrupted_recovery_itself_is_idempotent(self):
        plan_id=self.ready()
        with patch.object(self.repairs,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        original_publish=self.repairs.publish
        def publish_then_stop(*args):original_publish(*args);raise KeyboardInterrupt()
        with patch.object(self.repairs,'publish',side_effect=publish_then_stop):
            with self.assertRaises(KeyboardInterrupt):self.repairs.recover_pending()
        self.repairs.recover_pending()
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])

    def test_recovery_never_overwrites_concurrent_file_after_capture(self):
        plan_id=self.ready()
        with patch.object(self.repairs,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.file.write_bytes(b'foreign concurrent content');self.repairs.recover_pending()
        self.assertEqual(b'foreign concurrent content',self.file.read_bytes())
        self.assertEqual('recovery_required',self.repairs.get(self.context,plan_id)['status'])

    def test_binary_and_oversized_diff_are_labelled_as_summaries(self):
        for before in (b'a\0b',b'a'*300000):
            result=preview(before,b'after');self.assertEqual('summary',result['kind'])
            self.assertIn('before_sha256',result)

    def backup_ready(self, content=None):
        backup = self.root/'uploads'/'settings.php.bak'
        backup.parent.mkdir(exist_ok=True)
        backup.write_bytes(self.after if content is None else content)
        plan_id = self.repairs.queue(self.context, self.finding, backup_path='uploads/settings.php.bak')
        self.repairs.prepare(self.store.claim('backup-preview'), [self.engine])
        return backup, plan_id

    def test_backup_can_restore_non_wordpress_finding_with_review_and_immutable_undo(self):
        with self.store.connection() as db:
            db.execute('UPDATE findings SET fingerprint=? WHERE id=?', (json.dumps(self.original), self.finding))
        backup, plan_id = self.backup_ready()
        plan = self.repairs.get(self.context, plan_id)
        self.assertEqual('ready', plan['status'], plan['error'])
        self.assertEqual('user-supplied', plan['metadata']['replacement']['authenticity'])
        self.assertEqual(['test'], plan['metadata']['validation']['engines'])
        self.assertEqual('uploads/settings.php.bak', plan['metadata']['replacement']['source'])
        self.assertIn('verified release', plan['metadata']['preview']['diff'])
        self.assertEqual(self.before, self.file.read_bytes())
        backup.write_bytes(b'changed backup after review')
        self.repairs.apply(self.context, plan_id)
        Worker(self.settings, self.store, self.hestia, [self.engine]).once()
        self.assertEqual('verified', self.repairs.get(self.context, plan_id)['status'])
        self.assertEqual(self.after, self.file.read_bytes())
        self.repairs.undo(self.context, plan_id)
        self.assertEqual(self.before, self.file.read_bytes())
        self.assertEqual(b'changed backup after review', backup.read_bytes())

    def test_backup_selection_is_site_relative_and_foreign_findings_are_denied(self):
        for path in ('/etc/passwd', '../other-site/file', '', '.', self.file.name):
            with self.assertRaises((AccessDenied, Conflict)):
                self.repairs.queue(self.context, self.finding, backup_path=path)
        for context in (self.context|{'owner':'bob'}, self.context|{'identity':'recreated'}):
            with self.assertRaises(AccessDenied):
                self.repairs.queue(context, self.finding, backup_path='backup.php')

    def test_symlink_hardlink_and_missing_backup_fail_without_mutation(self):
        for kind in ('symlink', 'hardlink', 'missing'):
            backup = self.root/('backup-'+kind)
            if kind == 'symlink':backup.symlink_to(self.file)
            if kind == 'hardlink':os.link(self.file, backup)
            plan_id = self.repairs.queue(self.context, self.finding, backup_path=backup.name)
            self.repairs.prepare(self.store.claim('backup-preview'), [self.engine])
            self.assertEqual('failed', self.repairs.get(self.context, plan_id)['status'])
            self.assertEqual(self.before, self.file.read_bytes())

    def test_backup_requires_complete_clean_scan_and_different_content(self):
        for failure, hits, content in ((EngineError('YARA unavailable'), [], self.after),
                                      (None, [{'signature':'malware'}], self.after),
                                      (None, [], self.before)):
            self.engine.scan.side_effect = failure; self.engine.scan.return_value = hits
            _, plan_id = self.backup_ready(content)
            self.assertEqual('failed', self.repairs.get(self.context, plan_id)['status'])
            self.assertEqual(self.before, self.file.read_bytes())

    def test_changed_replacement_source_requires_new_preview_and_inflight_is_not_replaced(self):
        old = self.ready()
        backup, new = self.backup_ready()
        self.assertNotEqual(old, new)
        self.assertEqual('failed', self.repairs.get(self.context, old)['status'])
        self.assertEqual(new, self.repairs.queue(self.context, self.finding, backup_path='uploads/settings.php.bak'))
        with self.assertRaises(Conflict):self.repairs.apply(self.context, old)
        with self.store.connection() as db:db.execute("UPDATE repair_plans SET status='applying' WHERE id=?", (new,))
        with self.assertRaises(Conflict):self.repairs.queue(self.context, self.finding)

    def test_backup_interrupted_apply_uses_existing_content_bound_recovery(self):
        _, plan_id = self.backup_ready()
        with patch.object(self.repairs, 'publish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context, plan_id)
        self.repairs.recover_pending()
        self.assertEqual(self.before, self.file.read_bytes())
        self.assertEqual('failed', self.repairs.get(self.context, plan_id)['status'])
