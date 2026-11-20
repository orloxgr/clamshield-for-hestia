import io
import os
import stat
import time
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch,Mock

from clamshield.application import Application
from clamshield.atomic import write
from clamshield.errors import AccessDenied,EngineError
from clamshield.mail_adapter import MailAdapter,extract_headers,bounded
from clamshield.settings import Settings


def archive(entries):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as tar:
        for name,content,kind in entries:
            entry=tarfile.TarInfo(name);entry.type=kind
            if kind==tarfile.REGTYPE:
                entry.size=len(content);tar.addfile(entry,io.BytesIO(content))
            else:
                entry.linkname='../../outside';tar.addfile(entry)
    return output.getvalue()


class FixtureAdapter(MailAdapter):
    probes=0
    fail_probe=False

    def headers(self,stage,current):
        headers=stage/'headers';headers.mkdir()
        write(headers/'local_scan.h','trusted fixture headers',0o644)
        return headers,{'fixture':True}

    def abi_probe(self,stage):
        self.probes+=1
        assert stat.S_IMODE(stage.stat().st_mode)==0o755
        if self.fail_probe:raise EngineError('Native API probe failed')
        assert (stage/'local_scan.so').is_file()


class MailAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.settings=Settings(state=self.root/'state')
        self.adapter=FixtureAdapter(self.settings)
        self.adapter.source=self.root/'source.c';write(self.adapter.source,'trusted application C',0o644)
        self.native=dict(package='exim4-daemon-heavy',version='4.99.1-test1',architecture='amd64',binary_sha256='a'*64)
        def compile(arguments,**kwargs):
            self.assertEqual('/usr/bin/cc',arguments[0])
            write(Path(arguments[-1]),b'fixture ELF bytes',0o644)
            return subprocess.CompletedProcess(arguments,0,b'',b'')
        self.compiler=Mock(side_effect=compile)

    def test_selected_regular_headers_have_no_archive_path_or_link_extraction(self):
        valid=[('./usr/include/exim4/local_scan.h',b'API',tarfile.REGTYPE),
               ('./usr/include/exim4/config.h',b'config',tarfile.REGTYPE)]
        destination=self.root/'headers';destination.mkdir()
        result=extract_headers(archive(valid),destination)
        self.assertEqual({'local_scan.h','config.h'},set(result))
        for bad in [('usr/include/exim4/../../outside.h',b'bad',tarfile.REGTYPE),
                    ('usr/include/exim4/link.h',b'',tarfile.SYMTYPE),
                    ('usr/include/exim4/hard.h',b'',tarfile.LNKTYPE),
                    ('usr/include/exim4/pipe.h',b'',tarfile.FIFOTYPE),
                    ('usr/include/exim4/subdir/other.h',b'bad',tarfile.REGTYPE),valid[0]]:
            with self.subTest(bad=bad):
                target=self.root/('bad-'+str(len(list(self.root.iterdir()))));target.mkdir()
                with self.assertRaises(EngineError):extract_headers(archive(valid+[bad]),target)
        self.assertFalse((self.root/'outside.h').exists())

    def test_repeat_prepare_reuses_verified_bytes_and_new_source_builds_new_candidate(self):
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            first=self.adapter.build();second=self.adapter.build()
            self.assertFalse(first['reused']);self.assertTrue(second['reused'])
            self.assertEqual(first['generation'],second['generation']);self.assertEqual(1,self.adapter.probes)
            write(self.adapter.source,'changed trusted application C',0o644)
            third=self.adapter.build();self.assertNotEqual(first['generation'],third['generation'])
            self.assertEqual(2,self.adapter.probes)

    def test_failed_abi_probe_and_native_package_race_keep_prior_candidate(self):
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            first=self.adapter.build();self.adapter.fail_probe=True
            write(self.adapter.source,'new code',0o644)
            with self.assertRaises(EngineError):self.adapter.build()
            self.assertEqual(first['generation'],self.adapter.candidate()['generation'])
            self.adapter.fail_probe=False
            with patch('clamshield.mail_adapter.native',side_effect=[self.native,self.native|{'binary_sha256':'b'*64}]),self.assertRaises(EngineError):
                self.adapter.build()
            self.assertEqual(first['generation'],self.adapter.candidate()['generation'])
            self.assertEqual(1,len(list(self.settings.mail_adapters.glob('adapter-*'))))

    def test_changed_library_or_pointer_cannot_be_reused_or_blessed(self):
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            first=self.adapter.build();stage=self.settings.mail_adapters/first['generation']
            write(stage/'local_scan.so','changed ELF',0o644)
            with self.assertRaises(EngineError):self.adapter.build()
            pointer=self.settings.mail_adapters/'candidate';pointer.unlink();pointer.symlink_to('/etc')
            with self.assertRaises(EngineError):self.adapter.build()
            self.assertEqual('/etc',str(pointer.readlink()))

    def test_pending_target_reads_exact_frozen_generation_after_later_candidate_preparation(self):
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            first=self.adapter.build();write(self.adapter.source,'newer application source',0o644);second=self.adapter.build()
        self.assertNotEqual(first['generation'],second['generation'])
        self.assertEqual(first['generation'],self.adapter.generation(first['generation'],expected=self.native)['generation'])
        self.assertEqual(second['generation'],self.adapter.candidate()['generation'])
        for invalid in ('../outside','/etc','adapter-'+('a'*32)+'/../outside'):
            with self.subTest(invalid=invalid),self.assertRaises(EngineError):self.adapter.generation(invalid)
        write(self.settings.mail_adapters/first['generation']/'local_scan.so','tampered old frozen bytes',0o644)
        with self.assertRaises(EngineError):self.adapter.generation(first['generation'],expected=self.native)
        self.assertEqual(second['generation'],self.adapter.candidate()['generation'])

    def test_unmanaged_or_symlinked_addon_storage_is_not_overwritten(self):
        other=self.root/'other';other.mkdir();self.settings.mail_adapters.symlink_to(other)
        with self.assertRaises(EngineError):self.adapter.prepare()
        self.assertEqual([],list(other.iterdir()))

    def test_tenant_cannot_query_or_build_global_native_adapter(self):
        class Hestia:
            def authorize(self,*_args):return dict(admin=False,actor='tenant',owner='tenant')
        app=Application(self.settings,None,Hestia())
        for action in ('mail-adapter-status','mail-adapter-build','mail-adapter-verify'):
            with self.subTest(action=action),self.assertRaises(AccessDenied):
                app.dispatch(dict(action=action,actor='tenant',admin=True,path='/tmp/untrusted.c'))

    def test_private_maintenance_umask_does_not_hide_public_adapter_from_native_exim(self):
        previous=os.umask(0o077)
        try:
            with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
                result=self.adapter.build()
            self.assertEqual(0o755,stat.S_IMODE(self.settings.mail_adapters.stat().st_mode))
            self.assertEqual(0o755,stat.S_IMODE((self.settings.mail_adapters/result['generation']).stat().st_mode))
        finally:os.umask(previous)

    def test_publication_sync_failure_retains_complete_visible_generation(self):
        def fail_after_publication(path):
            if path==self.settings.mail_adapters and (path/'candidate').is_symlink():
                raise OSError('Simulated final directory sync failure')
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler),patch('clamshield.mail_adapter.sync_directory',side_effect=fail_after_publication):
            with self.assertRaises(OSError):self.adapter.build()
        candidate=self.adapter.candidate()
        self.assertTrue(candidate['abi_probed'])
        self.assertTrue((self.settings.mail_adapters/candidate['generation']/'local_scan.so').is_file())

    def test_failed_pointer_replace_keeps_old_candidate_and_removes_only_owned_staging(self):
        replace=os.replace
        def fail_pointer(source,target):
            if Path(target)==self.settings.mail_adapters/'candidate':raise OSError('Simulated pointer replace failure')
            return replace(source,target)
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            original=self.adapter.build();write(self.adapter.source,'changed source',0o644)
            with patch('clamshield.mail_adapter.os.replace',side_effect=fail_pointer),self.assertRaises(OSError):self.adapter.build()
        self.assertEqual(original['generation'],self.adapter.candidate()['generation'])
        self.assertFalse((self.settings.mail_adapters/'.candidate-next').exists())
        self.assertFalse((self.settings.mail_adapters/'.candidate-next').is_symlink())

    def test_build_output_limits_and_timeout_do_not_capture_unbounded_root_memory(self):
        good=bounded(['/usr/bin/python3','-c','print("bounded output")'])
        self.assertEqual(b'bounded output\n',good.stdout)
        with self.assertRaises(EngineError):
            bounded(['/usr/bin/python3','-c','import sys;sys.stderr.buffer.write(b"x"*(1024*1024+1))'])
        started=time.monotonic()
        with self.assertRaisesRegex(EngineError,'timed out'):
            bounded(['/usr/bin/python3','-c','import time;time.sleep(10)'],timeout=.1)
        self.assertLess(time.monotonic()-started,2)

    def test_verification_reexecutes_frozen_bytes_without_compiling_and_rejects_native_source_races(self):
        with patch('clamshield.mail_adapter.native',return_value=self.native),patch('clamshield.mail_adapter.bounded',self.compiler):
            original=self.adapter.build();result=self.adapter.verify()
            self.assertTrue(result['verified']);self.assertEqual(original['generation'],result['generation'])
            self.assertEqual(1,self.compiler.call_count);self.assertEqual(2,self.adapter.probes)
            with patch('clamshield.mail_adapter.native',side_effect=[self.native,self.native|{'binary_sha256':'c'*64}]),self.assertRaises(EngineError):
                self.adapter.verify()
            self.adapter.abi_probe=Mock(side_effect=lambda _stage:write(self.adapter.source,'concurrent source change',0o644))
            with self.assertRaises(EngineError):self.adapter.verify()
        self.assertEqual(original['generation'],self.adapter.candidate()['generation'])
        self.assertEqual([],list(self.settings.mail_adapters.glob('verify-*')))
