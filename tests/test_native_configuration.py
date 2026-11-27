import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from clamshield.errors import Conflict,EngineError
from clamshield.native_configuration import NativeConfiguration
from clamshield.settings import Settings


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root-owned Ubuntu conffiles')
class NativeConfigurationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.path=self.root/'clamd.conf'
        self.original=('# Native administrator configuration\nLocalSocket /run/clamav/clamd.ctl\n'
                       'DatabaseDirectory /var/lib/clamav\nExcludePath one\nExcludePath two\nMaxFileSize 25M')
        self.path.write_text(self.original);self.path.chmod(0o640)
        self.settings=Settings(state=self.root/'state')
        self.manager=NativeConfiguration(self.settings,path=self.path)

    def test_exact_restoration_preserves_comments_repeated_options_permissions_and_attributes(self):
        os.setxattr(self.path,'user.clamshield-test',b'prior administrator attribute')
        values={'LocalSocket':'/run/clamav/clamshield-native.ctl','DatabaseDirectory':'/var/lib/clamav/clamshield/current',
                'MaxFileSize':'50M','AlertExceedsMax':'true'}
        self.assertTrue(self.manager.configure(values));self.assertFalse(self.manager.configure(values))
        self.assertIn('ExcludePath one\nExcludePath two\n',self.path.read_text())
        self.assertEqual(0o640,self.path.stat().st_mode&0o777)
        self.assertEqual(b'prior administrator attribute',os.getxattr(self.path,'user.clamshield-test'))
        self.assertEqual(sorted(values),self.manager.restore()['restored'])
        self.assertEqual(self.original,self.path.read_text())
        self.assertEqual(b'prior administrator attribute',os.getxattr(self.path,'user.clamshield-test'))
        self.assertFalse(self.manager.receipt.exists());self.assertFalse(self.manager.journal.exists())

    def test_later_administrator_changes_survive_uninstall(self):
        self.manager.configure({'LocalSocket':'/run/clamav/clamshield-native.ctl','MaxFileSize':'50M'})
        current=self.path.read_text().replace('MaxFileSize 50M','MaxFileSize 100M')+'\nLogVerbose true\n'
        self.path.write_text(current)
        result=self.manager.restore()
        self.assertEqual(['MaxFileSize'],result['preserved'])
        self.assertEqual(['LocalSocket'],result['restored'])
        self.assertIn('LocalSocket /run/clamav/clamd.ctl\n',self.path.read_text())
        self.assertIn('MaxFileSize 100M\n',self.path.read_text())
        self.assertTrue(self.path.read_text().endswith('LogVerbose true\n'))

    def test_non_utf8_comments_and_crlf_are_restored_byte_for_byte(self):
        raw=self.original.replace('\n','\r\n').encode()+b'\r\n# legacy comment \xff\r\n'
        self.path.write_bytes(raw)
        self.manager.configure({'MaxScanTime':'20000'})
        self.manager.restore();self.assertEqual(raw,self.path.read_bytes())

    def test_updates_keep_original_ownership_and_refuse_conflicting_admin_edits(self):
        self.manager.configure({'MaxFileSize':'50M'})
        self.manager.configure({'MaxFileSize':'75M','AlertExceedsMax':'true'})
        self.assertEqual(self.original,self.manager.read(self.manager.receipt)['original'])
        self.path.write_text(self.path.read_text().replace('MaxFileSize 75M','MaxFileSize 100M'))
        with self.assertRaisesRegex(Conflict,'Administrator changed'):
            self.manager.configure({'MaxFileSize':'150M'})
        self.assertIn('MaxFileSize 100M',self.path.read_text())

    def test_crash_journal_finishes_authorized_edit_and_recovers_exact_original(self):
        with patch.object(self.manager,'publish',side_effect=OSError('interrupted')),self.assertRaises(OSError):
            self.manager.configure({'LocalSocket':'/run/clamav/clamshield-native.ctl'})
        self.assertTrue(self.manager.journal.exists());self.assertEqual(self.original,self.path.read_text())
        self.assertTrue(self.manager.recover());self.assertFalse(self.manager.recover())
        self.assertIn('clamshield-native.ctl',self.path.read_text())
        self.manager.restore();self.assertEqual(self.original,self.path.read_text())

    def test_concurrent_edits_are_not_overwritten_by_recovery(self):
        with patch.object(self.manager,'publish',side_effect=OSError('interrupted')),self.assertRaises(OSError):
            self.manager.configure({'MaxFileSize':'50M'})
        self.path.write_text(self.original+'\nLogVerbose true\n')
        before=self.path.read_bytes()
        with self.assertRaisesRegex(Conflict,'during configuration recovery'):self.manager.recover()
        self.assertEqual(before,self.path.read_bytes());self.assertTrue(self.manager.journal.exists())

    def test_unsafe_paths_injection_duplicate_directives_and_replaced_files_are_rejected(self):
        for values in ({'LocalSocket':'/tmp/../other'}, {'LocalSocket':'relative'}, {'Bogus':'true'},
                       {'AlertEncrypted':'yes\nLogVerbose true'}, {'MaxThreads':'0'}, {'MaxFileSize':'3G'}):
            with self.subTest(values=values),self.assertRaises(EngineError):self.manager.configure(values)
        self.path.write_text(self.original+'\nLocalSocket /tmp/other\n')
        with self.assertRaisesRegex(Conflict,'Duplicate'):self.manager.configure({'MaxThreads':'12'})
        self.path.unlink();self.path.symlink_to('/etc/hosts')
        with self.assertRaises(Conflict):self.manager.configure({'MaxThreads':'12'})
        self.path.unlink();target=self.root/'original';target.write_text(self.original);os.link(target,self.path)
        with self.assertRaises(Conflict):self.manager.configure({'MaxThreads':'12'})
