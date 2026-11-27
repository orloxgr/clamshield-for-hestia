import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write,write_json
from clamshield.errors import Conflict,EngineError
from clamshield.mail_adapter import sha
from clamshield.mail_integration import MailIntegration
from clamshield.settings import Settings


@unittest.skipUnless(sys.platform=='linux','Protected native Exim file identities')
class MailStartupTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.runtime=self.root/'runtime';self.runtime.mkdir(mode=0o755)
        self.include=self.runtime/'hook.conf'
        self.library=self.root/'local_scan.so';write(self.library,b'verified adapter bytes',0o644)
        self.source=self.root/'source.c';write(self.source,b'verified source bytes',0o644)
        self.macro=self.root/'macros'
        macro_text='# Managed by clamshield\n.include_if_exists '+str(self.include)+'\n';write(self.macro,macro_text,0o644)
        self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.integration=MailIntegration(self.settings,None,None)
        self.value=dict(owner='clamshield',schema=1,phase='active',adapter=dict(
            native=dict(binary_sha256='a'*64),library_sha256=sha(self.library),source_sha256=sha(self.source)))
        write_json(self.integration.owner,dict(owner='clamshield',schema=1));write_json(self.integration.state,self.value)
        for value in (patch('clamshield.mail_integration.HOOK_RUNTIME',self.runtime),
                      patch('clamshield.mail_integration.HOOK_INCLUDE',self.include),
                      patch('clamshield.mail_integration.MACRO',self.macro),
                      patch('clamshield.mail_integration.MACRO_TEXT',macro_text),
                      patch('clamshield.mail_integration.LIBRARY',self.library),
                      patch('clamshield.mail_integration.MailAdapter',return_value=Mock(source=self.source)),
                      patch('clamshield.mail_integration.sha',side_effect=lambda p:'a'*64 if p==Path('/usr/sbin/exim4') else sha(p))):
            value.start();self.addCleanup(value.stop)

    def test_exact_native_library_source_and_owned_macro_publish_hook_without_external_process(self):
        with patch('clamshield.mail_integration.subprocess.run',side_effect=AssertionError('No native recursion')), \
                patch('clamshield.mail_integration.native',side_effect=AssertionError('No package query')):
            self.assertTrue(self.integration.startup()['hook_enabled'])
        self.assertEqual('local_scan_path = '+str(self.library)+'\n',self.include.read_text())
        self.assertEqual(0o644,self.include.stat().st_mode&0o777)

    def test_changed_binary_library_source_or_missing_state_leave_no_old_hook(self):
        for what in ('binary','library','source','state'):
            with self.subTest(what=what):
                write(self.library,b'verified adapter bytes',0o644);write(self.source,b'verified source bytes',0o644)
                write_json(self.integration.state,self.value)
                self.assertTrue(self.integration.startup()['hook_enabled'])
                if what=='binary':write_json(self.integration.state,dict(self.value,adapter=dict(self.value['adapter'],native=dict(binary_sha256='b'*64))))
                elif what=='library':write(self.library,b'other binary',0o644)
                elif what=='source':self.source.unlink()
                else:self.integration.state.unlink()
                result=self.integration.startup()
                self.assertTrue(result['native_fallback']);self.assertFalse(self.include.exists())

    def test_unrelated_or_hostile_runtime_file_is_never_overwritten(self):
        self.include.write_text('administrator data\n');self.include.chmod(0o644)
        with self.assertRaises(Conflict):self.integration.startup()
        self.assertEqual('administrator data\n',self.include.read_text())
        self.include.unlink();self.include.symlink_to(self.library)
        with self.assertRaises(EngineError):self.integration.startup()
        self.assertEqual(b'verified adapter bytes',self.library.read_bytes())

    def test_cli_startup_does_not_open_the_application_database(self):
        from clamshield.cli import execute
        with patch('clamshield.cli.Store',side_effect=AssertionError('No database dependency')), \
                patch('clamshield.mail_integration.MailIntegration.startup',return_value=dict(hook_enabled=False,native_fallback=True)):
            self.assertEqual(0,execute(argparse.Namespace(command='mail-startup'),self.settings))

    def test_owned_unit_recreates_empty_runtime_and_bounds_ignored_startup_failure(self):
        text=MailIntegration.guard_text()
        for line in ('RuntimeDirectory=clamshield-exim','RuntimeDirectoryPreserve=no',
                     'ExecStartPre=-/usr/bin/timeout --kill-after=1s 10s'):
            self.assertIn(line,text)
        self.assertNotIn('ExecStartPre=/usr/local/hestia/bin/v-clamshield mail-guard',text)
