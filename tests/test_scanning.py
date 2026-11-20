import os
import multiprocessing
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock

from clamshield.errors import EngineError, AccessDenied, EncryptedContent
from clamshield.paths import snapshot, walk, relative_path
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker


def hold_snapshot(root, destination, ready):
    with snapshot(root, 'clean', destination, 4096) as (copy, fingerprint):
        ready.send((copy.read_bytes(), copy.stat().st_nlink, fingerprint['size']))
        signal.pause()


class FileScanning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'site'
        self.root.mkdir()
        self.settings = Settings(state=self.base / 'state', max_file_bytes=4096)
        self.settings.prepare()
        self.store = Store(self.settings.database)
        self.context = dict(actor='alice', owner='alice', admin=False, identity='generation')
        self.site = dict(owner='alice', identity='generation', domain='site.test', root=str(self.root), suspended=False)
        self.hestia = Mock()
        self.hestia.authorize.return_value = self.context
        self.hestia.sites.return_value = [self.site]

    def scan(self, engines):
        job_id = self.store.enqueue(self.context, self.site)
        self.assertTrue(Worker(self.settings, self.store, self.hestia, engines).once())
        return self.store.job(self.context, job_id)

    def test_one_engine_failure_keeps_other_detection_and_marks_partial(self):
        (self.root / 'bad.php').write_text('malware')
        bad = Mock(name='clamav'); bad.name = 'clamav'; bad.scan.side_effect = EngineError('Unavailable')
        good = Mock(name='yara'); good.name = 'yara'
        good.scan.return_value = [dict(engine='yara', signature='Webshell', provider='local')]
        job = self.scan([bad, good])
        self.assertEqual('partial', job['status'])
        self.assertEqual(0, job['counters']['scanned'])
        self.assertEqual(1, len(self.store.list_findings(self.context)))

    def test_symlinks_and_oversize_files_never_count_as_clean_coverage(self):
        (self.root / 'large').write_bytes(b'x' * 4097)
        (self.root / 'link').symlink_to('/etc/passwd')
        (self.root / 'clean').write_text('clean')
        engine = Mock(); engine.name = 'test'; engine.scan.return_value = []
        job = self.scan([engine])
        self.assertEqual('partial', job['status'])
        self.assertEqual(2, job['counters']['skipped'])
        self.assertEqual(1, engine.scan.call_count)

    def test_encrypted_content_keeps_independent_yara_evidence_and_incomplete_coverage(self):
        (self.root/'encrypted.sample').write_bytes(b'Encrypted input')
        clam=Mock();clam.name='clamav';clam.scan.side_effect=EncryptedContent('Could not inspect encrypted content')
        yara=Mock();yara.name='yara';yara.scan.return_value=[dict(engine='yara',signature='IndependentRule',provider='local')]
        job=self.scan([clam,yara])
        self.assertEqual('partial',job['status']);self.assertEqual(0,job['counters']['scanned']);self.assertEqual(1,job['counters']['errors'])
        self.assertEqual(['yara'],[v['engine'] for v in self.store.list_findings(self.context)])
        with self.store.connection() as db:result=dict(db.execute('SELECT status,detail FROM file_results WHERE job_id=?',(job['id'],)).fetchone())
        self.assertEqual('error',result['status']);self.assertIn('encrypted',result['detail'])

    def test_private_snapshot_does_not_follow_symlink(self):
        (self.root / 'link').symlink_to('/etc/passwd')
        with self.assertRaises(OSError):
            with snapshot(self.root, 'link', self.settings.snapshots, 4096):
                self.fail('Symlink was followed')

    def test_directory_symlink_is_reported_without_traversal(self):
        (self.root / 'other').symlink_to('/etc', target_is_directory=True)
        rows = list(walk(self.root))
        self.assertEqual([('other', 'skipped', 'Symbolic link or special file was not followed')], rows)

    def test_replaced_account_fails_before_any_file_read(self):
        engine = Mock(); engine.name = 'test'
        self.hestia.authorize.return_value = self.context | {'identity': 'new-generation'}
        job = self.scan([engine])
        self.assertEqual('failed', job['status'])
        engine.scan.assert_not_called()

    def test_parent_traversal_is_rejected(self):
        for target in ('../bob', '/etc/passwd', 'a/../../b', 'a\\b'):
            with self.subTest(target=target), self.assertRaises(AccessDenied):
                relative_path(target)

    def test_abandoned_running_job_is_failed_instead_of_restarted(self):
        old = self.store.enqueue(self.context, self.site)
        self.store.claim('dead-worker')
        self.assertFalse(Worker(self.settings, self.store, self.hestia, []).once())
        self.assertEqual('failed', self.store.job(self.context, old)['status'])

    def test_snapshot_is_removed_after_engine_error(self):
        (self.root / 'clean').write_text('clean')
        engine = Mock(); engine.name = 'test'; engine.scan.side_effect = EngineError('Error')
        self.scan([engine])
        self.assertEqual([], list(self.settings.snapshots.iterdir()))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux anonymous snapshots')
    def test_snapshot_survives_original_change_and_has_no_directory_entry(self):
        original = self.root / 'clean'; original.write_bytes(b'captured bytes')
        with snapshot(self.root, 'clean', self.settings.snapshots, 4096) as (copy, fingerprint):
            original.write_bytes(b'changed later')
            self.assertEqual(b'captured bytes', copy.read_bytes())
            self.assertEqual(b'captured bytes', copy.read_bytes())
            self.assertEqual(14, fingerprint['size'])
            self.assertEqual(0, copy.stat().st_nlink)
            self.assertEqual([], list(self.settings.snapshots.iterdir()))

    @unittest.skipUnless(sys.platform == 'linux', 'Actual Linux SIGKILL')
    def test_sigkill_releases_snapshot_without_python_cleanup(self):
        original = self.root / 'clean'; original.write_bytes(b'captured bytes')
        context = multiprocessing.get_context('fork')
        ready, child_ready = context.Pipe(duplex=False)
        process = context.Process(target=hold_snapshot, args=(self.root, self.settings.snapshots, child_ready))
        process.start(); child_ready.close()
        try:
            self.assertTrue(ready.poll(5), 'Same child did not reach a held snapshot')
            self.assertEqual((b'captured bytes', 0, 14), ready.recv())
            self.assertTrue(process.is_alive())
            self.assertEqual([], list(self.settings.snapshots.iterdir()))
            os.kill(process.pid, signal.SIGKILL); process.join(5)
            self.assertEqual(-signal.SIGKILL, process.exitcode)
            self.assertEqual([], list(self.settings.snapshots.iterdir()))
            self.assertEqual(b'captured bytes', original.read_bytes())
        finally:
            if process.is_alive():process.kill();process.join(5)
            ready.close();process.close()

    def test_unrecovered_database_activation_blocks_claiming_new_scans(self):
        queued = self.store.enqueue(self.context, self.site)
        (self.settings.state / 'signature-activation.json').write_text('{}')
        self.assertFalse(Worker(self.settings, self.store, self.hestia, []).once())
        self.assertEqual('queued', self.store.job(self.context, queued)['status'])
