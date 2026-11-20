import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.errors import AccessDenied, Conflict, ClamShieldError
from clamshield.paths import snapshot
from clamshield.quarantine import Quarantine, rename_noreplace
from clamshield.settings import Settings
from clamshield.store import Store


class ReversibleCapture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'site'
        self.root.mkdir()
        self.settings = Settings(state=self.base / 'state')
        self.settings.prepare()
        self.store = Store(self.settings.database)
        self.context = dict(actor='alice', owner='alice', admin=False, identity='generation')
        self.site = dict(owner='alice', identity='generation', domain='site.test', root=str(self.root), suspended=False)
        self.hestia = Mock()
        self.hestia.authorize.return_value = self.context
        self.hestia.sites.return_value = [self.site]
        self.quarantine = Quarantine(self.settings, self.store, self.hestia)
        self.file = self.root / 'bad.php'
        self.file.write_text('original malicious fixture')
        self.file.chmod(0o640)
        job_id = self.store.enqueue(self.context, self.site)
        job = self.store.claim('worker')
        with snapshot(self.root, 'bad.php', self.settings.snapshots, 4096) as (_, fingerprint):
            self.original = fingerprint
        self.finding_id = self.store.add_finding(job, 'bad.php', fingerprint,
                             dict(engine='yara', signature='Webshell', provider='local'))

    def test_capture_and_restore_preserve_content_and_mode(self):
        operation = self.quarantine.capture(self.context, self.finding_id)
        self.assertFalse(self.file.exists())
        captured = self.settings.quarantine / operation
        self.assertEqual(0o600, stat.S_IMODE(captured.stat().st_mode))
        self.quarantine.restore(self.context, operation)
        self.assertEqual('original malicious fixture', self.file.read_text())
        self.assertEqual(0o640, stat.S_IMODE(self.file.stat().st_mode))
        self.assertEqual(self.original['mtime_ns'], self.file.stat().st_mtime_ns)
        self.assertEqual('restored_unverified', self.store.finding(self.context, self.finding_id)['status'])

    def test_restore_never_overwrites_a_replacement_file(self):
        operation = self.quarantine.capture(self.context, self.finding_id)
        self.file.write_text('replacement clean file')
        with self.assertRaises(Conflict):
            self.quarantine.restore(self.context, operation)
        self.assertEqual('replacement clean file', self.file.read_text())
        self.assertTrue((self.settings.quarantine / operation).exists())

    def test_unavailable_site_restore_keeps_original_intent_and_custody(self):
        operation = self.quarantine.capture(self.context, self.finding_id)
        before = self.quarantine.get(self.context, operation)
        with self.store.connection() as db:count = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        cases = ([self.site | dict(root='/moved/root')], [self.site | dict(suspended=True)], [], [self.site])
        for index, sites in enumerate(cases):
            with self.subTest(case=index):
                self.hestia.sites.return_value = sites
                self.hestia.authorize.return_value = self.context | ({'identity':'replacement'} if index==3 else {})
                with self.assertRaises((Conflict, AccessDenied)):
                    self.quarantine.restore(self.context, operation)
                self.assertEqual(before, self.quarantine.get(self.context, operation))
                self.assertFalse(self.file.exists())
                self.assertEqual('original malicious fixture', (self.settings.quarantine / operation).read_text())
                with self.store.connection() as db:self.assertEqual(count, db.execute('SELECT COUNT(*) FROM audit').fetchone()[0])
        self.hestia.authorize.return_value = self.context; self.hestia.sites.return_value = [self.site]
        self.quarantine.restore(self.context, operation)
        self.assertEqual('original malicious fixture', self.file.read_text())

    def test_native_inventory_failure_does_not_record_restore_intent(self):
        operation = self.quarantine.capture(self.context, self.finding_id)
        before = self.quarantine.get(self.context, operation)
        self.hestia.authorize.side_effect = ClamShieldError('Native inventory unavailable')
        with self.assertRaises(ClamShieldError):self.quarantine.restore(self.context, operation)
        self.assertEqual(before, self.quarantine.get(self.context, operation))
        self.assertFalse(self.file.exists())
        self.assertEqual('original malicious fixture', (self.settings.quarantine / operation).read_text())

    def test_changed_file_is_put_back_and_not_quarantined(self):
        self.file.write_text('changed file after detection')
        with self.assertRaises(Conflict):
            self.quarantine.capture(self.context, self.finding_id)
        self.assertEqual('changed file after detection', self.file.read_text())
        self.assertEqual([], list(self.settings.quarantine.iterdir()))

    def test_racing_replacement_is_retained_for_recovery_without_overwrite(self):
        self.file.write_text('changed file')
        count = 0
        def racing_rename(*args):
            nonlocal count
            result = rename_noreplace(*args)
            count += 1
            if count == 1:
                self.file.write_text('new concurrent file')
            return result
        with patch('clamshield.quarantine.rename_noreplace', side_effect=racing_rename):
            with self.assertRaises(Conflict):
                self.quarantine.capture(self.context, self.finding_id)
        self.assertEqual('new concurrent file', self.file.read_text())
        operations = self.quarantine.list(self.context)
        self.assertEqual('recovery_required', operations[0]['status'])
        self.assertEqual('changed file', (self.settings.quarantine / operations[0]['metadata']['capture_object']).read_text())

    def test_open_tenant_descriptor_cannot_mutate_quarantine_copy(self):
        with self.file.open('r+b') as tenant_handle:
            operation = self.quarantine.capture(self.context, self.finding_id)
            tenant_handle.seek(0)
            tenant_handle.write(b'changed after quarantine')
            tenant_handle.flush()
        captured = self.settings.quarantine / operation
        self.assertEqual('original malicious fixture', captured.read_text())

    def test_foreign_account_cannot_capture_or_restore(self):
        foreign = dict(actor='bob', owner='bob', identity='bob-generation')
        with self.assertRaises(AccessDenied):
            self.quarantine.capture(foreign, self.finding_id)
        operation = self.quarantine.capture(self.context, self.finding_id)
        with self.assertRaises(AccessDenied):
            self.quarantine.restore(foreign, operation)

    def test_hardlinks_are_not_removed(self):
        os.link(self.file, self.root / 'also.php')
        # Even if a link was added after detection, validation rejects the capture.
        with self.assertRaises(Conflict):
            self.quarantine.capture(self.context, self.finding_id)
        self.assertTrue(self.file.exists())
        self.assertTrue((self.root / 'also.php').exists())

    def test_interrupted_capture_rebuilds_private_copy_from_exact_captured_original(self):
        unlink=os.unlink
        def interrupt(name,*args,**kwargs):
            if str(name).endswith('.capture'):raise KeyboardInterrupt()
            return unlink(name,*args,**kwargs)
        with patch('clamshield.quarantine.os.unlink',side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):self.quarantine.capture(self.context,self.finding_id)
        operation=self.quarantine.list(self.context)[0];self.assertEqual('prepared',operation['status']);self.assertFalse(self.file.exists())
        self.quarantine.recover_pending();operation=self.quarantine.get(self.context,operation['id'])
        self.assertEqual('quarantined',operation['status']);self.assertEqual('original malicious fixture',(self.settings.quarantine/operation['id']).read_text())
        self.quarantine.restore(self.context,operation['id']);self.assertEqual('original malicious fixture',self.file.read_text())

    def test_unavailable_native_actor_does_not_stop_later_recovery(self):
        def capture(finding_id):
            unlink=os.unlink
            def interrupted(name,*args,**kwargs):
                if str(name).endswith('.capture'):raise KeyboardInterrupt()
                return unlink(name,*args,**kwargs)
            with patch('clamshield.quarantine.os.unlink',side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):self.quarantine.capture(self.context,finding_id)
        capture(self.finding_id)
        first=self.quarantine.list(self.context)[0]
        another=self.root/'another.php';another.write_text('another inert quarantine fixture')
        job=self.store.job(self.context,self.store.finding(self.context,self.finding_id)['job_id'])
        with snapshot(self.root,'another.php',self.settings.snapshots,4096) as (_,fingerprint):
            second_finding=self.store.add_finding(job,'another.php',fingerprint,dict(engine='yara',signature='Second',provider='local'))
        capture(second_finding)
        first_call=True
        def authorize(*args):
            nonlocal first_call
            if first_call:first_call=False;raise ClamShieldError('Native inventory unavailable')
            return self.context
        self.hestia.authorize.side_effect=authorize
        self.assertEqual(2,self.quarantine.recover_pending()['quarantine_examined'])
        self.assertEqual('recovery_required',self.quarantine.get(self.context,first['id'])['status'])
        others=[row for row in self.quarantine.list(self.context) if row['id']!=first['id']]
        self.assertEqual('quarantined',others[0]['status'])
        self.assertEqual('original malicious fixture',(self.settings.quarantine/first['id']).read_text())

    def test_changed_open_descriptor_capture_is_retained_after_private_copy_committed(self):
        unlink=os.unlink
        def interrupt(name,*args,**kwargs):
            if str(name).endswith('.capture'):raise KeyboardInterrupt()
            return unlink(name,*args,**kwargs)
        with self.file.open('r+b') as stream:
            with patch('clamshield.quarantine.os.unlink',side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):self.quarantine.capture(self.context,self.finding_id)
            stream.seek(0);stream.write(b'Later descriptor edit');stream.flush()
        operation=self.quarantine.list(self.context)[0];self.quarantine.recover_pending();row=self.quarantine.get(self.context,operation['id'])
        self.assertTrue(row['metadata']['changed_capture_retained']);self.assertEqual('original malicious fixture',(self.settings.quarantine/row['id']).read_text())

    def test_restore_interruption_before_or_after_publication_is_idempotently_recovered(self):
        operation=self.quarantine.capture(self.context,self.finding_id)
        with patch('clamshield.quarantine.rename_noreplace',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.quarantine.restore(self.context,operation)
        self.assertFalse(self.file.exists());self.quarantine.recover_pending();row=self.quarantine.get(self.context,operation)
        self.assertEqual('restored',row['status']);self.assertEqual('original malicious fixture',self.file.read_text());self.assertIn('recheck_job',row['metadata'])
        self.quarantine.recover_pending();self.assertEqual('original malicious fixture',self.file.read_text())

    def test_interrupted_restore_never_overwrites_later_tenant_content(self):
        operation=self.quarantine.capture(self.context,self.finding_id)
        with patch('clamshield.quarantine.rename_noreplace',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.quarantine.restore(self.context,operation)
        self.file.write_text('Later tenant content');self.quarantine.recover_pending()
        self.assertEqual('recovery_required',self.quarantine.get(self.context,operation)['status']);self.assertEqual('Later tenant content',self.file.read_text())
        self.assertEqual('original malicious fixture',(self.settings.quarantine/operation).read_text())
