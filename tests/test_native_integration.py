from contextlib import nullcontext
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write_json
from clamshield.errors import EngineError
from clamshield.native_integration import NativeIntegration,GATE,UNIT,OLD_UNITS
from clamshield.settings import Settings
from clamshield.signatures import Signatures


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root native integration orchestration')
class NativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.config=self.root/'clamd.conf'
        self.original=('LocalSocket /run/clamav/clamd.ctl\nLocalSocketMode 666\nDatabaseDirectory /var/lib/clamav\n'
                       'User clamav\nAllowAllMatchScan true\nMaxThreads 12\nMaxQueue 100\nMaxScanTime 120000\n'
                       'MaxFileSize 25M\nStreamMaxLength 25M\nLogVerbose true\n')
        self.config.write_text(self.original);self.config.chmod(0o640)
        units=self.root/'units';units.mkdir();(units/GATE).write_text('# Managed by clamshield\n[Service]\n')
        self.manager=NativeIntegration(self.settings,config=self.config,runtime=self.root/'runtime',
                                       snapshots=self.root/'snapshots',unit_directory=units)
        self.active={UNIT:True,OLD_UNITS[0]:True,OLD_UNITS[1]:False,GATE:False}
        self.operations=[]
        def system(*args):
            self.operations.append(args)
            for name in args[1:]:
                if args[0] in ('start','stop') or '--now' in args:
                    self.active[name]=args[0] in ('start','enable')
            return Mock(stdout=b'')
        self.manager.system=Mock(side_effect=system);self.manager.active=lambda unit:self.active.get(unit,False)
        self.manager.apparmor=Mock();self.manager.restore_apparmor=Mock()
        self.manager.ready=Mock(return_value=(123,456));self.manager.verify_arguments=Mock()
        self.manager.frontend_ready=Mock()
        self.signatures=Signatures(self.settings);self.signatures.base.mkdir(mode=0o755)
        self.previous=self.signatures.base/'generation-before';self.previous.mkdir()
        self.signatures.pointer('current',self.previous)
        stage=self.signatures.base/'generation-native';stage.mkdir()
        self.manifest=dict(generation=stage.name,engine_mode='native-shared',canary=dict(payload='fixture',signature='Fixture'))
        self.signatures.stage=Mock(return_value=(stage,self.manifest))
        replacement=patch('clamshield.signatures.Signatures',return_value=self.signatures)
        replacement.start();self.addCleanup(replacement.stop)

    def test_handoff_stops_only_owned_engines_and_records_native_configuration(self):
        value=self.manager.connect()
        self.assertEqual('active',value['phase'])
        self.assertEqual('/var/lib/clamav',value['original_directory'])
        self.assertFalse(self.active[OLD_UNITS[0]]);self.assertFalse(self.active[OLD_UNITS[1]])
        self.assertTrue(self.active[UNIT]);self.assertTrue(self.active[GATE])
        self.assertIn('LocalSocket /run/clamav/clamshield-native.ctl\n',self.config.read_text())
        self.assertIn('MaxScanTime 20000\n',self.config.read_text())
        self.assertEqual(self.manifest['generation'],(self.signatures.base/'current').resolve().name)
        self.assertFalse(self.manager.journal.exists())
        self.manager.client=Mock()
        before=list(self.operations);self.manager.connect();self.assertEqual(before,self.operations)

    def test_failed_frontend_restores_native_bytes_data_pointer_and_owned_service_states(self):
        self.manager.frontend_ready.side_effect=EngineError('not ready')
        with self.assertRaises(EngineError):self.manager.connect()
        self.assertEqual(self.original,self.config.read_text())
        self.assertEqual(self.previous,(self.signatures.base/'current').resolve())
        self.assertTrue(self.active[UNIT]);self.assertTrue(self.active[OLD_UNITS[0]])
        self.assertFalse(self.active[OLD_UNITS[1]])
        self.assertFalse(self.manager.record.exists());self.assertFalse(self.manager.journal.exists())

    def test_initial_rollback_resumes_from_a_durable_transition_record(self):
        self.manager.frontend_ready.side_effect=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.manager.connect()
        self.assertTrue(self.manager.journal.exists())
        self.assertTrue(self.manager.recover());self.assertFalse(self.manager.recover())
        self.assertEqual(self.original,self.config.read_text())
        self.assertEqual(self.previous,(self.signatures.base/'current').resolve())

    def test_disconnect_restores_native_before_removing_owned_runtime_and_preserves_admin_fields(self):
        self.manager.connect()
        self.config.write_text(self.config.read_text()+'LogTime true\n')
        with patch('clamshield.native_integration.NativeClamAV.discover') as discover:
            result=self.manager.disconnect()
        self.assertTrue(result['disconnected']);self.assertTrue(self.active[UNIT])
        self.assertFalse(self.active[GATE]);self.assertFalse(self.manager.record.exists())
        self.assertIn('LocalSocket /run/clamav/clamd.ctl\n',self.config.read_text())
        self.assertTrue(self.config.read_text().endswith('LogTime true\n'))
        self.assertFalse(self.manager.runtime.exists());self.assertFalse(self.manager.snapshots.exists())
        discover.return_value.version.assert_called_once()

    def test_package_restart_is_revalidated_only_when_native_configuration_is_unchanged(self):
        self.manager.connect()
        with patch('clamshield.native_integration.NativeClamAV.native_identity',return_value=(124,789)), \
                patch('clamshield.native_integration.NativeClamAV.discover') as discover:
            self.manager.client('mail');discover.assert_called_once()
        self.assertEqual([124,789],self.manager.read()['identity'])
        self.config.write_text(self.config.read_text()+'LogTime true\n')
        with patch('clamshield.native_integration.NativeClamAV.native_identity',return_value=(125,999)),self.assertRaises(EngineError):
            self.manager.client('mail')

    def test_an_unmanaged_runtime_directory_is_not_claimed_or_purged(self):
        self.manager.runtime.mkdir();(self.manager.runtime/'admin-data').write_text('keep')
        with self.assertRaises(FileNotFoundError):self.manager.prepare_runtime()
        self.assertEqual('keep',(self.manager.runtime/'admin-data').read_text())
