from contextlib import contextmanager
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from clamshield.backup_archive import Budget,exact,visit
from clamshield.errors import AccessDenied,ClamShieldError,Conflict
from clamshield.native_backups import NativeBackups
from clamshield.paths import snapshot
from clamshield.repairs import Repairs
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker


def tar(entries,format=tarfile.GNU_FORMAT):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=format) as archive:
        for name,content,kind in entries:
            entry=tarfile.TarInfo(name);entry.type=kind
            entry.size=len(content) if kind==tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):entry.linkname='/etc/passwd'
            archive.addfile(entry,io.BytesIO(content))
    return output.getvalue()


class BoundedTar(unittest.TestCase):
    def read(self,data):
        result={}
        def entry(info,stream):result[info.name]=exact(stream,info.size);return True
        visit(Budget(io.BytesIO(data),1024**2),entry)
        return result

    def test_gnu_and_pax_long_paths_are_canonical_without_extraction(self):
        path='public_html/'+'a'*150+'/file.txt'
        for format in (tarfile.GNU_FORMAT,tarfile.PAX_FORMAT):
            self.assertEqual({path:b'content'},self.read(tar([('./'+path,b'content',tarfile.REGTYPE)],format)))

    def test_unsafe_duplicate_and_concatenated_paths_are_rejected(self):
        for names in (['../outside'],['/etc/passwd'],['x','x'],['a/./b']):
            with self.assertRaises(ClamShieldError):self.read(tar([(name,b'x',tarfile.REGTYPE) for name in names]))
        with self.assertRaises(Conflict):self.read(tar([('a',b'x',tarfile.REGTYPE)])+tar([('b',b'x',tarfile.REGTYPE)]))

    def test_truncated_metadata_and_expanded_budget_never_return_a_complete_result(self):
        valid=tar([('public_html/file',b'content',tarfile.REGTYPE)])
        with self.assertRaises(Conflict):self.read(valid[:600])
        with self.assertRaises(Conflict):visit(Budget(io.BytesIO(valid),500),lambda *_:False)
        with self.assertRaises(Conflict):visit(io.BytesIO(valid),lambda *_:False,entries=1)


class NativeBackupRepairs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);native=self.base/'hestia';(native/'conf').mkdir(parents=True)
        self.backups=self.base/'backup';self.backups.mkdir(mode=0o755)
        self.home=self.base/'homes';self.root=self.home/'alice/web/site.test/public_html';self.root.mkdir(parents=True)
        account=native/'data/users/alice';account.mkdir(parents=True);(account/'backup.conf').write_text('fixture')
        (native/'conf/hestia.conf').write_text("BACKUP='"+str(self.backups)+"'\nHOMEDIR='"+str(self.home)+"'\n")
        self.settings=Settings(state=self.base/'state',hestia=native);self.settings.prepare();self.store=Store(self.settings.database)
        self.context=dict(owner='alice',actor='alice',identity='generation',admin=False)
        self.site=dict(owner='alice',identity='generation',domain='site.test',root=str(self.root),suspended=False)
        self.name='alice.2026-11-19_12-00-00.tar';self.file=self.root/'custom.php';self.before=b'<?php /* original changed */';self.after=b'<?php /* backup */'
        self.file.write_bytes(self.before);self.file.chmod(0o640)
        job_id=self.store.enqueue(self.context,self.site);job=self.store.claim('fixture')
        with snapshot(self.root,self.file.name,self.settings.snapshots,4096) as (_,fingerprint):pass
        self.finding_id=self.store.add_finding(job,self.file.name,fingerprint,dict(engine='yara',signature='Inert',provider='local'))
        self.store.finish(job,'completed',{})
        self.hestia=Mock();self.hestia.authorize.return_value=self.context;self.hestia.sites.return_value=[self.site]
        self.hestia.call.return_value={self.name:dict(TYPE='local',WEB='site.test',DATE='2026-11-19')}
        self.addCleanup(patch.stopall);patch('clamshield.native_backups.pwd.getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())).start()
        self.manager=NativeBackups(self.settings,self.store,self.hestia);self.repairs=Repairs(self.settings,self.store,self.hestia)
        self.engine=Mock();self.engine.name='test';self.engine.scan.return_value=[]
        self.archive=self.backups/self.name;self.make()

    @property
    def finding(self):return self.store.finding(self.context,self.finding_id)

    def make(self,compression='gz',inner=None,outer=None):
        entries=inner or [('./public_html/custom.php',self.after,tarfile.REGTYPE),('./private/secret',b'Unrelated secret',tarfile.REGTYPE)]
        payload=tar(entries)
        if compression=='gz':payload=gzip.compress(payload)
        else:
            from compression.zstd import compress
            payload=compress(payload)
        self.archive.write_bytes(tar(outer or [('./web/site.test/domain_data.tar.'+compression,payload,tarfile.REGTYPE),('./pam/shadow',b'Never disclose',tarfile.REGTYPE)]))
        self.archive.chmod(0o640)

    def test_actual_gzip_and_stdlib_zstandard_read_only_selected_website_file(self):
        for compression in ('gz','zst'):
            self.make(compression)
            source=self.manager.selection(self.context,self.finding,self.name)
            content,provenance=self.manager.replacement(self.context,self.finding,source)
            self.assertEqual(self.after,content);self.assertEqual(compression,provenance['compression'])
            self.assertEqual('public_html/custom.php',provenance['member'])
            self.assertNotIn('Never disclose',json.dumps(provenance))

    def test_native_backup_plan_freezes_reviewed_bytes_and_uses_reversible_repair(self):
        plan_id=self.repairs.queue(self.context,self.finding_id,backup_name=self.name)
        self.repairs.prepare(self.store.claim('preview'),[self.engine]);plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('ready',plan['status'],plan['error'])
        self.archive.unlink()
        self.repairs.apply(self.context,plan_id);Worker(self.settings,self.store,self.hestia,[self.engine]).once()
        self.assertEqual('verified',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(self.after,self.file.read_bytes());self.assertEqual(0o640,self.file.stat().st_mode&0o777)
        self.repairs.undo(self.context,plan_id);self.assertEqual(self.before,self.file.read_bytes())

    def test_changed_archive_after_selection_cannot_prepare_old_source(self):
        source=self.manager.selection(self.context,self.finding,self.name)
        self.make(inner=[('./public_html/custom.php',b'changed',tarfile.REGTYPE)])
        with self.assertRaises(Conflict):self.manager.replacement(self.context,self.finding,source)

    def test_source_scope_is_native_account_domain_and_current_root(self):
        for name in ('../alice.tar','bob.2026-11-19_12-00-00.tar','alice.2026-11-19_12-00-00.tar/extra'):
            with self.assertRaises(AccessDenied):self.manager.selection(self.context,self.finding,name)
        self.hestia.call.return_value={self.name:dict(TYPE='local',WEB='other.test')}
        with self.assertRaises(AccessDenied):self.manager.selection(self.context,self.finding,self.name)
        self.hestia.call.return_value={self.name:dict(TYPE='local',WEB='site.test')}
        with self.assertRaises(Conflict):self.manager.selection(self.context,self.finding|{'root':'/srv/other'},self.name)

    def test_old_generation_hardlink_and_symlink_archives_are_denied(self):
        with patch('clamshield.native_backups.birth',side_effect=[200,100]):
            with self.assertRaises(AccessDenied):self.manager.selection(self.context,self.finding,self.name)
        other=self.backups/'linked';os.link(self.archive,other)
        with self.assertRaises(AccessDenied):self.manager.selection(self.context,self.finding,self.name)
        other.unlink();self.archive.unlink();self.archive.symlink_to(self.file)
        with self.assertRaises(OSError):self.manager.selection(self.context,self.finding,self.name)

    def test_link_targets_duplicate_members_and_corrupt_compression_are_rejected(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):
            self.make(inner=[('./public_html/custom.php',b'',kind)])
            source=self.manager.selection(self.context,self.finding,self.name)
            with self.assertRaises(Conflict):self.manager.replacement(self.context,self.finding,source)
        self.make(inner=[('./public_html/custom.php',self.after,tarfile.REGTYPE)]*2)
        with self.assertRaises(Conflict):self.manager.replacement(self.context,self.finding,self.manager.selection(self.context,self.finding,self.name))
        self.make(outer=[('./web/site.test/domain_data.tar.gz',b'bad gzip',tarfile.REGTYPE)])
        with self.assertRaises(Conflict):self.manager.replacement(self.context,self.finding,self.manager.selection(self.context,self.finding,self.name))

    def test_catalog_filters_native_domain_and_reports_unavailable_local_or_remote_sources(self):
        self.assertTrue(self.manager.catalog(self.context,self.finding)['backups'][0]['available'])
        self.archive.unlink();self.assertFalse(self.manager.catalog(self.context,self.finding)['backups'][0]['available'])
        self.hestia.call.return_value={self.name:dict(TYPE='sftp',WEB='site.test')}
        self.assertFalse(self.manager.catalog(self.context,self.finding)['backups'][0]['available'])

    def test_flagged_or_incomplete_candidate_does_not_become_ready(self):
        self.engine.scan.return_value=[{'signature':'Flagged backup'}]
        plan_id=self.repairs.queue(self.context,self.finding_id,backup_name=self.name)
        self.repairs.prepare(self.store.claim('preview'),[self.engine])
        self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(self.before,self.file.read_bytes())

    def test_native_panel_owner_must_have_the_selected_account_group(self):
        def account(name):return SimpleNamespace(pw_uid=1102 if name=='hestiaweb' else 1101,pw_gid=1101)
        with patch('clamshield.native_backups.pwd.getpwnam',side_effect=account):
            os.chown(self.archive,1102,1101)
            self.assertTrue(self.manager.catalog(self.context,self.finding)['backups'][0]['available'])
            os.chown(self.archive,1102,1103)
            self.assertFalse(self.manager.catalog(self.context,self.finding)['backups'][0]['available'])

    def test_account_generation_change_during_native_listing_returns_no_catalog(self):
        rows=self.hestia.call.return_value
        def replaced(*_):
            self.hestia.authorize.return_value=self.context|{'identity':'recreated'}
            return rows
        self.hestia.call.side_effect=replaced
        with self.assertRaises(AccessDenied):self.manager.catalog(self.context,self.finding)
