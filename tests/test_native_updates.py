import hashlib
import json
import os
import pwd
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import EngineError,Conflict
from clamshield.native_updates import NativeUpdates
from clamshield.settings import Settings
from clamshield.signatures import Signatures


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Root native filesystem ownership')
class NativeUpdateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o755)
        self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.updates=NativeUpdates(self.settings);self.native=self.root/'native';self.native.mkdir()
        for name in ('main.cvd','daily.cvd','bytecode.cvd'):(self.native/name).write_bytes(b'Native metadata fixture')
        self.updates.manager.read=Mock(return_value=dict(phase='active',original_directory=str(self.native)))

    def test_new_native_data_is_detected_and_unsafe_files_never_become_an_acknowledged_source(self):
        first=self.updates.fingerprint();self.updates.record(first,'active',generation='generation-fixture')
        self.assertFalse(self.updates.changed())
        (self.native/'daily.cvd').write_bytes(b'Updated native metadata fixture');self.assertTrue(self.updates.changed())
        (self.native/'extra.hdb').symlink_to(self.native/'main.cvd')
        with self.assertRaises(EngineError):self.updates.fingerprint()

    def test_failed_automatic_import_is_not_repeated_for_the_same_source_but_explicit_retry_is_allowed(self):
        manager=Mock();manager.locked.return_value.__enter__=Mock();manager.locked.return_value.__exit__=Mock(return_value=False)
        manager.stage_native_refresh.side_effect=EngineError('Invalid native database')
        with patch('clamshield.signatures.Signatures',return_value=manager):
            for _ in range(2):
                with self.assertRaises(EngineError):self.updates.ingest()
                self.assertEqual('error',self.updates.read()['phase']);self.assertFalse(self.updates.changed())
        self.assertEqual(2,manager.stage_native_refresh.call_count)

    def test_running_native_freshclam_prevents_any_custom_or_parallel_official_downloader(self):
        native_config=self.root/'freshclam.conf';native_config.write_text('DatabaseDirectory '+str(self.native)+'\n');native_config.chmod(0o644)
        with patch('clamshield.native_updates.Path',return_value=native_config),patch('clamshield.native_updates.subprocess.run',return_value=Mock(returncode=0)) as run:
            result=self.updates.check()
        self.assertFalse(result['check_completed']);self.assertEqual('native-updater-active',result['state'])
        run.assert_called_once();self.assertEqual('/usr/bin/systemctl',run.call_args.args[0][0])

    def test_ubuntu_readonly_clamav_owned_configuration_is_accepted_without_changing_its_owner_or_mode(self):
        native_config=self.root/'freshclam.conf';native_config.write_text('DatabaseDirectory '+str(self.native)+'\n')
        account=pwd.getpwnam('clamav');os.chown(native_config,account.pw_uid,account.pw_gid);native_config.chmod(0o444)
        before=native_config.stat()
        with patch('clamshield.native_updates.Path',return_value=native_config),patch('clamshield.native_updates.subprocess.run',return_value=Mock(returncode=0)):
            self.assertFalse(self.updates.check()['check_completed'])
        after=native_config.stat();self.assertEqual((before.st_uid,before.st_gid,before.st_mode),(after.st_uid,after.st_gid,after.st_mode))

    def test_idle_native_updater_uses_its_original_configuration_in_a_bounded_transient_unit(self):
        native_config=self.root/'freshclam.conf';native_config.write_text('DatabaseDirectory '+str(self.native)+'\n');native_config.chmod(0o644)
        with patch('clamshield.native_updates.Path',return_value=native_config),patch('clamshield.native_updates.subprocess.run',side_effect=[Mock(returncode=3),Mock(returncode=0,stdout=b'',stderr=b'')]) as run:
            self.assertTrue(self.updates.check()['check_completed'])
        argv=run.call_args.args[0]
        self.assertEqual('/usr/bin/systemd-run',argv[0]);self.assertIn('--collect',argv);self.assertIn('--wait',argv)
        self.assertIn('/usr/bin/freshclam',argv);self.assertIn('--config-file='+str(native_config),argv)
        self.assertIn('--property=User=clamav',argv);self.assertIn('--property=Group=clamav',argv)
        self.assertFalse(any('clamshield-cache' in item or item.startswith('--datadir') for item in argv))

    def test_native_provider_cooldown_is_retained_without_exposing_raw_diagnostics(self):
        from clamshield.providers import Providers
        native_config=self.root/'freshclam.conf';native_config.write_text('DatabaseDirectory '+str(self.native)+'\n');native_config.chmod(0o644)
        output=b'Private upstream URL\ncool-down until after: 2030-01-01 00:00:00\n'
        with patch('clamshield.native_updates.Path',return_value=native_config),patch('clamshield.native_updates.subprocess.run',side_effect=[Mock(returncode=3),Mock(returncode=17,stdout=output,stderr=b'')]):
            with self.assertRaises(EngineError) as error:self.updates.check()
        self.assertNotIn('Private upstream URL',str(error.exception))
        self.assertGreater(Providers(self.settings).public()['schedule']['official']['retry_after'],1800000000)

    @unittest.skipUnless(Path('/usr/bin/clamscan').is_file() and Path('/usr/bin/sigtool').is_file(),'Real Ubuntu validation and catalog')
    def test_native_refresh_retains_active_profile_choices_and_ignores_unsaved_provider_changes(self):
        manager=Signatures(self.settings);manager.base.mkdir(mode=0o755)
        stage=manager.base/'generation-original';stage.mkdir(mode=0o755)
        files=[]
        for provider,name,signature in (('official','official.ndb','Native.Old'),('local','local--web.ndb','Web.Only'),('local','local--mail.ndb','Mail.Only')):
            content=(signature+':0:*:4142434445464748\n').encode();(stage/name).write_bytes(content)
            files.append(dict(provider=provider,name=name,sha256=hashlib.sha256(content).hexdigest(),size=len(content)))
        manifest=dict(generation=stage.name,engine_mode='native-shared',providers=['official','local'],files=files,
                      profiles=dict(website=['local--web.ndb','official.ndb'],mail=['local--mail.ndb','official.ndb']))
        active,original=manager.complete_stage(stage,manifest);manager.pointer('current',active)
        newer=self.root/'new.ndb';newer.write_bytes((active/'official.ndb').read_bytes())
        with patch('clamshield.native_updates.NativeUpdates.sources',return_value=[('official','official.ndb',newer)]),\
             patch('clamshield.providers.Providers.read',side_effect=AssertionError('Import must not apply pending provider settings')):
            unchanged,metadata=manager.stage_native_refresh()
            self.assertIsNone(unchanged);self.assertEqual(original,metadata)
            newer.write_bytes(b'Native.New:0:*:4142434445464749\n')
            captured,updated=manager.stage_native_refresh()
        self.assertIsNotNone(captured)
        self.assertEqual(original['profiles'],updated['profiles'])
        self.assertEqual(original['providers'],updated['providers'])
        self.assertNotEqual(original['content_sha256'],updated['content_sha256'])
        self.assertEqual(active,(manager.base/'current').resolve())
