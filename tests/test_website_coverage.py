import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
import zipfile

from clamshield.atomic import write_json
from clamshield.errors import Conflict,CoverageUnavailable,EncryptedContent,EngineError
from clamshield.resources import Resources
from clamshield.store import Store
from clamshield.website_coverage import PROBE,harden,validate_migration,verify
import test_installation as installed

LEGACY='# Managed by clamshield\nDatabaseDirectory /private/frozen-generation\nScanArchive true\nAlertExceedsMax true\nMaxScanSize 123M\n# Administrator comment\n'


class WebsiteCoverageMigration(unittest.TestCase):
    setUp=installed.InstalledLifecycle.setUp

    def fixture(self,active=False,text=LEGACY):
        self.path=self.root/'etc/clamshield/clamd.conf';self.path.write_text(text);self.path.chmod(0o640)
        self.resource=Resources(self.settings,unit_dir=self.root/'etc/systemd/system')
        self.resource.inspect=Mock(return_value=dict(active=active));self.resource.website_ready=Mock()
        self.addCleanup(patch.stopall)
        patch('clamshield.resources.Resources',return_value=self.resource).start()
        self.probe=patch('clamshield.website_coverage.verify').start()
        self.installation.begin_install(self.release)

    def test_explicit_stopped_upgrade_preserves_config_settings_metadata_and_boot_choice(self):
        self.fixture();policy=self.settings.state/'website-engine.json';write_json(policy,dict(owner='clamshield',schema=1,enabled=False,changed_at=1));original=policy.read_bytes()
        result=self.installation.migrate_website_coverage()
        self.assertTrue(result['changed']);self.assertFalse(result['verified'])
        self.assertEqual(LEGACY+'AlertEncrypted true\n',self.path.read_text());self.assertEqual(0o640,self.path.stat().st_mode&0o777)
        self.assertEqual(original,policy.read_bytes());self.assertNotIn(('start','clamshield-clamd.service'),self.installation.calls)
        self.resource.website_ready.assert_not_called();self.installation.finish_install();self.installation.available()

    def test_running_upgrade_verifies_new_daemon_and_repeated_install_has_no_restart(self):
        self.fixture(active=True);self.installation.migrate_website_coverage()
        self.assertEqual([('stop','clamshield-clamd.service'),('start','clamshield-clamd.service')],self.installation.calls)
        self.resource.website_ready.assert_called_once();self.assertFalse(self.installation.migrate_website_coverage()['changed'])
        self.assertEqual(2,len(self.installation.calls));self.probe.assert_called_once()
        with Store(self.settings.database).connection() as db:self.assertEqual(1,db.execute("SELECT count(*) FROM audit WHERE action='installation.coverage_migrated'").fetchone()[0])

    def interrupt(self,phase):
        self.fixture(active=True);original=self.installation.system
        def system(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]==phase:raise KeyboardInterrupt('Process interruption')
            return result
        self.installation.system=system
        with self.assertRaises(KeyboardInterrupt):self.installation.migrate_website_coverage()
        self.installation.system=original
        saved=json.loads(self.installation.install_journal.read_text())['website_coverage']
        self.assertTrue(saved['was_active']);self.assertEqual(LEGACY,saved['before']['text'])
        with self.assertRaises(Conflict):self.installation.finish_install()
        self.resource.inspect.return_value=dict(active=False)
        self.installation.begin_install(self.release)
        self.assertEqual(saved,json.loads(self.installation.install_journal.read_text())['website_coverage'])
        return saved

    def test_resume_after_stop_preserves_original_running_intent(self):
        self.interrupt('stop');self.assertEqual(LEGACY,self.path.read_text())
        self.assertTrue(self.installation.migrate_website_coverage()['verified']);self.assertEqual(harden(LEGACY),self.path.read_text())
        self.resource.website_ready.assert_called_once();self.installation.finish_install()

    def test_resume_after_config_publication_preserves_original_running_intent(self):
        self.interrupt('start');self.assertEqual(harden(LEGACY),self.path.read_text())
        self.assertTrue(self.installation.migrate_website_coverage()['verified']);self.installation.finish_install()

    def test_foreign_change_during_pending_migration_is_not_overwritten_or_restarted(self):
        self.interrupt('stop');self.path.write_text(LEGACY+'MaxThreads 77\n');self.installation.calls.clear()
        with self.assertRaises(Conflict):self.installation.migrate_website_coverage()
        self.assertEqual([],self.installation.calls);self.assertEqual(LEGACY+'MaxThreads 77\n',self.path.read_text())

    def test_invalid_intent_or_foreign_linked_writable_configuration_refused(self):
        self.fixture();self.path.write_text('Native foreign configuration\n')
        with self.assertRaises(Conflict):self.installation.migrate_website_coverage()
        self.path.unlink();self.path.symlink_to(self.custody)
        with self.assertRaises(EngineError):self.installation.migrate_website_coverage()
        self.path.unlink();self.path.write_text(LEGACY);self.path.chmod(0o666)
        with self.assertRaises(EngineError):self.installation.migrate_website_coverage()
        self.assertEqual([],self.installation.calls)
        saved=dict(before=dict(text=LEGACY,mode=0o640,gid=0),after=dict(text=harden(LEGACY),mode=0o640,gid=0),was_active=True)
        for bad in (saved|{'was_active':1},saved|{'after':saved['after']|{'text':harden(LEGACY)+'MaxThreads 99\n'}},saved|{'after':saved['after']|{'mode':0o666}},saved|{'path':'/foreign'}):
            write_json(self.installation.install_journal,dict(owner='clamshield',schema=1,website_coverage=bad))
            with self.assertRaises(Conflict):self.installation.begin_install(self.release)

    def test_safe_config_with_old_loaded_daemon_requires_verified_restart(self):
        self.fixture(active=True,text=harden(LEGACY));self.probe.side_effect=CoverageUnavailable('Old loaded config')
        self.assertTrue(self.installation.migrate_website_coverage()['changed']);self.resource.website_ready.assert_called_once()
        self.assertEqual(2,len(self.installation.calls))

    def test_probe_failure_does_not_silently_restart_an_unavailable_service(self):
        self.fixture(active=True,text=harden(LEGACY));self.probe.side_effect=EngineError('Unavailable')
        with self.assertRaises(EngineError):self.installation.migrate_website_coverage()
        self.assertEqual([],self.installation.calls);self.assertTrue(self.installation.install_journal.exists())

    def test_hardening_preserves_unrelated_settings_and_refuses_ambiguous_or_disabled_flags(self):
        self.assertEqual(harden(LEGACY),harden(harden(LEGACY)))
        text=harden(LEGACY)+'AlertEncrypted no\nScanArchive false\n'
        corrected=harden(text)
        for key in ('AlertEncrypted','AlertExceedsMax','ScanArchive'):self.assertEqual(1,corrected.count(key+' true\n'))
        self.assertIn('MaxScanSize 123M\n# Administrator comment\n',corrected)
        with self.assertRaises(Conflict):harden('Native unowned config\n')

    def test_real_encrypted_probe_is_inert_and_only_exact_encryption_error_is_accepted(self):
        self.fixture()
        with zipfile.ZipFile(io.BytesIO(PROBE)) as archive:
            self.assertEqual(['coverage.txt'],archive.namelist());self.assertTrue(archive.infolist()[0].flag_bits&1)
            self.assertEqual(b'ClamShield encrypted coverage probe\n',archive.read('coverage.txt',pwd=b'clamshield-probe'))
        engine=Mock();engine.scan.return_value=[]
        with self.assertRaises(CoverageUnavailable):verify(engine,self.settings)
        engine.scan.return_value=[dict(signature='Unrelated detection')]
        with self.assertRaises(CoverageUnavailable):verify(engine,self.settings)
        engine.scan.side_effect=EngineError('Unavailable')
        with self.assertRaises(EngineError):verify(engine,self.settings)
        engine.scan.side_effect=EncryptedContent('Not inspected');verify(engine,self.settings)
        self.assertEqual([],list(self.settings.snapshots.iterdir()))
