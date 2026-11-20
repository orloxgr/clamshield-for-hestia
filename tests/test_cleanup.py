import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.application import Application
from clamshield.cleanup import RECIPES,eligible,revision,transform
from clamshield.errors import AccessDenied,Conflict,EngineError
from clamshield.paths import snapshot
from clamshield.repairs import Repairs
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker


class TargetedCleaning(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'site';self.root.mkdir()
        self.settings=Settings(state=self.base/'state');self.settings.prepare();self.store=Store(self.settings.database)
        self.context=dict(actor='alice',owner='alice',identity='one',admin=False)
        self.site=dict(owner='alice',identity='one',domain='site.test',root=str(self.root),suspended=False)
        self.hestia=Mock();self.hestia.authorize.return_value=self.context;self.hestia.sites.return_value=[self.site]
        self.path='blog/wp-includes/post.php';self.file=self.root/self.path;self.file.parent.mkdir(parents=True)
        self.after=b'<?php\n/* Custom code and spacing must survive. */\n$custom = 42;\n'
        self.before=RECIPES[0]['prefix']+self.after;self.file.write_bytes(self.before);self.file.chmod(0o640)
        job_id=self.store.enqueue(self.context,self.site);job=self.store.claim('fixture')
        with snapshot(self.root,self.path,self.settings.snapshots,4096) as (_,fp):self.fp=fp
        self.hit=dict(engine='yara',signature='Published_WPVCD_Loader',provider='local')
        self.finding=self.store.add_finding(job,self.path,fp,self.hit);self.store.finish(job,'completed',{})
        self.repairs=Repairs(self.settings,self.store,self.hestia)
        self.clam=Mock();self.clam.name='clamav';self.clam.scan.return_value=[]
        self.yara=Mock();self.yara.name='yara'
        self.yara.scan.side_effect=lambda path:[self.hit] if any(row['prefix'] in Path(path).read_bytes() for row in RECIPES) else []
        self.engines=[self.clam,self.yara]

    def ready(self):
        plan_id=self.repairs.queue(self.context,self.finding,cleanup=True);job=self.store.claim('preview')
        self.repairs.prepare(job,self.engines);plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('ready',plan['status'],plan['error']);return plan_id

    def test_exact_published_variants_preserve_every_remaining_byte(self):
        for recipe in RECIPES:
            content=recipe['prefix']+self.after
            after,source=transform(content,self.path,revision())
            self.assertEqual(self.after,after);self.assertEqual(len(recipe['prefix']),source['removed_bytes'])
            self.assertEqual(hashlib.sha256(recipe['prefix']).hexdigest(),source['recipes'][0]['prefix_sha256'])
            self.assertTrue(source['recipes'][0]['source'].startswith('https://'))

    def test_benign_changed_embedded_wrong_path_and_boundary_inputs_are_refused(self):
        for content,path in [(self.after,self.path),(b'/* documentation */'+self.before,self.path),
                (self.before.replace(b'file_exists',b'is_file'),self.path),(self.before,'other.php'),
                (self.before,'wp-includes/post.php.txt'),(RECIPES[0]['prefix'],self.path),
                (RECIPES[0]['prefix']+b'$custom=42;',self.path)]:
            with self.assertRaises(Conflict):transform(content,path,revision())

    def test_repeated_exact_prefixes_have_original_offsets_and_bounded_count(self):
        prefix=RECIPES[0]['prefix'];after,source=transform(prefix*2+self.after,self.path,revision())
        self.assertEqual(self.after,after);self.assertEqual([0,len(prefix)],[row['offset'] for row in source['recipes']])
        with self.assertRaises(Conflict):transform(prefix*5+self.after,self.path,revision())

    def test_preview_is_nonmutating_scanned_and_catalog_bound(self):
        plan_id=self.ready();plan=self.repairs.get(self.context,plan_id);metadata=plan['metadata']
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual(revision(),metadata['source']['catalog_revision'])
        self.assertEqual(['clamav','yara'],metadata['validation']['engines'])
        self.assertIn('wp-vcd.php',metadata['preview']['diff']);self.assertEqual('targeted-cleanup',metadata['replacement']['kind'])
        self.assertEqual(self.after,(self.settings.state/metadata['candidate']).read_bytes())

    def test_apply_recheck_distinct_cleaning_audit_original_metadata_and_undo(self):
        plan_id=self.ready();self.repairs.apply(self.context,plan_id)
        self.assertEqual(self.after,self.file.read_bytes());self.assertEqual(0o640,self.file.stat().st_mode&0o777)
        self.assertEqual('cleaned_unverified',self.store.finding(self.context,self.finding)['status'])
        Worker(self.settings,self.store,self.hestia,self.engines).once();plan=self.repairs.get(self.context,plan_id)
        self.assertEqual('verified',plan['status']);self.assertEqual('cleaned',self.store.finding(self.context,self.finding)['status'])
        operation=next(row for row in self.repairs.quarantine.list(self.context) if row['id']==plan['metadata']['operation_id'])
        self.assertEqual(('cleanup','cleaned'),(operation['kind'],operation['status']))
        self.assertEqual(self.before,(self.settings.quarantine/operation['id']).read_bytes())
        with self.assertRaises(Conflict):self.repairs.quarantine.restore(self.context,operation['id'])
        self.repairs.undo(self.context,plan_id);self.assertEqual(self.before,self.file.read_bytes());self.assertEqual(self.fp['mtime_ns'],self.file.stat().st_mtime_ns)
        history=self.store.history(self.context)
        self.assertTrue(all(any(row['action']==action and row['subject']==plan_id for row in history) for action in ('cleanup.preview_queued','cleanup.verified','cleanup.undone')))

    def test_missing_changed_engine_failure_or_candidate_detection_cannot_be_ready(self):
        for engines in ([self.clam],[self.yara],[]):
            plan_id=self.repairs.queue(self.context,self.finding,cleanup=True);job=self.store.claim('preview');self.repairs.prepare(job,engines)
            self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])
        for effect,result in [(EngineError('Unavailable'),[]),(None,[self.hit])]:
            self.clam.scan.side_effect=effect;self.clam.scan.return_value=result
            plan_id=self.repairs.queue(self.context,self.finding,cleanup=True);job=self.store.claim('preview');self.repairs.prepare(job,self.engines)
            self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])
        self.assertEqual(self.before,self.file.read_bytes())

    def test_foreign_recreated_and_changed_native_site_cannot_read_or_apply(self):
        plan_id=self.ready()
        for context in (self.context|{'owner':'bob','identity':'other'},self.context|{'identity':'recreated'}):
            with self.assertRaises(AccessDenied):self.repairs.get(context,plan_id)
            with self.assertRaises(AccessDenied):self.repairs.queue(context,self.finding,cleanup=True)
            with self.assertRaises(AccessDenied):self.repairs.apply(context,plan_id)
        self.hestia.sites.return_value=[self.site|{'root':'/changed'}]
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)

    def test_modified_original_and_changed_cleaning_catalog_refuse_apply(self):
        plan_id=self.ready()
        with patch('clamshield.cleanup.revision',return_value='changed'):
            with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.file.write_bytes(b'concurrent edit')
        with self.assertRaises(Conflict):self.repairs.apply(self.context,plan_id)
        self.assertEqual(b'concurrent edit',self.file.read_bytes())

    def test_interrupted_cleaning_reuses_durable_recovery_and_retains_original(self):
        plan_id=self.ready()
        with patch.object(self.repairs,'publish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.repairs.apply(self.context,plan_id)
        self.assertFalse(self.file.exists());self.repairs.recover_pending()
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual('failed',self.repairs.get(self.context,plan_id)['status'])

    def test_invalid_finding_state_never_authorizes_cleaning(self):
        finding=self.store.finding(self.context,self.finding)
        for row in (finding|{'status':'cleaned'},finding|{'engine':'integrity'},finding|{'fingerprint':self.fp|{'missing':True}},finding|{'fingerprint':self.fp|{'links':2}}):
            with self.assertRaises(Conflict):eligible(row)

    def test_api_uses_native_finding_and_ignores_browser_code_or_transform(self):
        result=Application(self.settings,self.store,self.hestia).dispatch(dict(actor='alice',action='cleanup-preview',finding_id=self.finding,content='evil',path='/etc/passwd',recipe='evil'))
        plan=self.repairs.get(self.context,result['plan_id'])
        self.assertEqual(self.path,plan['target']);self.assertEqual({'kind':'targeted-cleanup','catalog_revision':revision()},plan['metadata']['source'])
