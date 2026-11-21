import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import zipfile

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError, Conflict, EngineError
from clamshield.paths import snapshot
from clamshield.recovery_references import RecoveryReferences
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.wordpress_database import literal, replacement, serialized_replace
from clamshield.wordpress_recovery import WordPressRecovery, options
from clamshield.worker import Worker


class RecoveryPolicyTests(unittest.TestCase):
    def test_uploads_javascript_is_a_separate_explicit_policy(self):
        self.assertTrue(options({})['uploads_php']);self.assertFalse(options({})['uploads_js'])
        self.assertTrue(options({'uploads_js':True})['uploads_js'])
        for value in ({'uploads_js':'true'},{'unknown':True},{'packages':{'x':'../outside'}},{'versions':{'x':'bad version'}}):
            with self.subTest(value=value),self.assertRaises(ClamShieldError):options(value)

    def test_literal_config_never_evaluates_computed_php(self):
        self.assertEqual('pass\'word',literal("define('DB_PASSWORD', 'pass\\'word');",'DB_PASSWORD'))
        self.assertEqual('wp_',literal("$table_prefix = 'wp_';",'table_prefix',assignment=True))
        for text in ("define('DB_NAME', getenv('DB'));", "define('DB_NAME','a'.'b');", "define('DB_NAME',\"$unsafe\");", "define('DB_NAME','one');define('DB_NAME','two');"):
            with self.subTest(text=text),self.assertRaises(Conflict):literal(text,'DB_NAME')

    def test_serialized_replacement_recalculates_utf8_byte_lengths(self):
        before=b'a:1:{s:4:"html";s:21:"<script>bad</script>!";}'
        self.assertEqual(b'a:1:{s:4:"html";s:1:"!";}',replacement(before,'<script>bad</script>',''))
        before='s:2:"é";'.encode();after=replacement(before,'é','κόσμος')
        self.assertEqual(('s:'+str(len('κόσμος'.encode()))+':"κόσμος";').encode(),after)
        for value in (b'O:1:"X":0:{}',b'R:1;',b'a:1:{s:2:"x";s:1:"x";}'):
            with self.subTest(value=value),self.assertRaises(Conflict):replacement(value,'x','new')


class RecoveryBatchTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);base=Path(temp.name)
        self.root=base/'site';self.root.mkdir();self.settings=Settings(state=base/'state',rules=base/'rules.yarac');self.settings.prepare()
        self.store=Store(self.settings.database);owner=pwd.getpwuid(os.getuid()).pw_name
        self.context=dict(actor=owner,owner=owner,identity='native-generation',admin=True)
        self.site=dict(owner=owner,identity='native-generation',domain='fixture.test',root=str(self.root),suspended=False)
        self.native=Mock();self.native.authorize.return_value=self.context;self.native.sites.return_value=[self.site]
        self.refs=Mock();self.refs.receipts={};self.clean={
            'wp-includes/version.php':b"<?php\n$wp_version='6.8.3';\n",
            'wp-settings.php':b'clean core',
            'wp-content/plugins/example/example.php':b'<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/\nclean plugin',
        }
        for path,content in self.clean.items():self.write(path,content)
        def manifest(component):
            prefix=component['path']+'/' if component['path'] else ''
            paths={path[len(prefix):]:content for path,content in self.clean.items() if path.startswith(prefix) and (component['kind']!='core' or not path.startswith('wp-content/'))}
            return dict(source='https://downloads.wordpress.org/fixture',files={path:dict(algorithm='sha256',digest=hashlib.sha256(content).hexdigest()) for path,content in paths.items()})
        self.refs.manifest.side_effect=manifest
        self.refs.replacement.side_effect=lambda component,path,expected:(self.clean[(component['path']+'/' if component['path'] else '')+path],dict(source='https://downloads.wordpress.org/fixture',sha256=expected['digest'],size=10))
        self.enterContext(patch('clamshield.wordpress_recovery.RecoveryReferences',return_value=self.refs))
        self.enterContext(patch('clamshield.wordpress.References',return_value=self.refs))
        self.engines=[Mock(name='clamav'),Mock(name='yara')]
        for engine,name in zip(self.engines,('clamav','yara')):engine.name=name;engine.scan.return_value=[]
        self.worker=Worker(self.settings,self.store,self.native,self.engines)
        self.recovery=WordPressRecovery(self.settings,self.store,self.native)
        self.app=Application(self.settings,self.store,self.native)

    def write(self,path,content):
        target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)

    def analyze(self,**policy):
        result=self.app.dispatch(dict(actor=self.context['actor'],action='wordpress-recovery-analyze',domain='fixture.test',policy={'database':False,**policy}))
        self.worker.once();return result['plan_id']

    def status(self,key):return self.recovery.status(self.context,key)

    def request(self,key,operation,policy=None):
        status=self.status(key)
        return self.app.dispatch(dict(actor=self.context['actor'],action='wordpress-recovery-'+operation,plan_id=key,revision=status['plan']['revision'],policy=policy))

    def run_until(self,key,states):
        for _ in range(30):
            if self.status(key)['plan']['status'] in states:return self.status(key)
            if not self.worker.once():break
        self.fail(str(self.status(key)))

    def test_analysis_is_nonmutating_and_classifies_uploads_as_policy(self):
        self.write('wp-content/uploads/code.php',b'<?php echo 1;');self.write('wp-content/uploads/app.js',b'legitimate JS')
        self.write('wp-content/uploads/.htaccess',b'Require all denied');self.write('wp-content/uploads/photo.jpg',b'image')
        key=self.analyze();status=self.status(key)
        self.assertEqual('ready',status['plan']['status']);self.assertTrue((self.root/'wp-content/uploads/code.php').exists())
        policies=[item for item in status['items'] if item['kind']=='uploads-policy']
        self.assertEqual(['wp-content/uploads/code.php'],[item['path'] for item in policies])
        self.assertEqual('Selected uploads cleanup policy',policies[0]['detail']['reason'])
        self.assertNotIn('wp-content/uploads/.htaccess',[item['path'] for item in status['items']])
        self.assertNotIn('wp-content/uploads/app.js',[item['path'] for item in status['items']])

    def test_media_markers_and_inert_index_do_not_generate_cleanup_findings(self):
        paths=['wp-content/uploads/photo.'+suffix for suffix in ('png','avif','webp','jpg')]
        for path in paths:self.write(path,b'\x00\xff<?=\x12<?php\x80')
        index='wp-content/uploads/smush/index.php';self.write(index,b'<?php\n// Silence is golden.\n')
        key=self.analyze();status=self.status(key)
        self.assertEqual([],status['items'])
        self.assertEqual([],self.store.list_findings(self.context))
        self.assertTrue(all((self.root/path).exists() for path in paths+[index]))

    def test_exempt_media_and_index_still_receive_actual_engine_scans(self):
        paths=['wp-content/uploads/logo.jpg','wp-content/uploads/smush/index.php','wp-content/plugins/example/test.inc']
        for path in paths:self.write(path,b'<?php // Silence is golden.\n' if path.endswith('index.php') else b'\x00<?=fixture')
        self.engines[0].scan.side_effect=lambda copy:[dict(engine='clamav',provider='fixture',signature='Fixture.RealDetection')] if copy.read_bytes() in (b'<?php // Silence is golden.\n',b'\x00<?=fixture') else []
        key=self.analyze();findings=self.store.list_findings(self.context)
        self.assertEqual(set(paths),{finding['path'] for finding in findings if finding['engine']=='clamav'})
        self.assertFalse(any(finding['engine']=='recovery-policy' for finding in findings))

    def test_earlier_media_policy_proposal_cannot_be_previewed_or_applied(self):
        path='wp-content/uploads/logo.jpg';self.write(path,b'\x00<?=image')
        key=self.analyze();plan=self.recovery.get(self.context,key);job=self.store.job(self.context,key)
        with snapshot(self.root,path,self.settings.snapshots,self.settings.max_file_bytes) as (_,fingerprint):
            finding=self.store.add_finding(job,path,fingerprint,dict(engine='recovery-policy',provider='local-policy',signature='WordPress.Uploads.Policy'))
        item=self.recovery.add(plan,path,'uploads-policy','quarantine',dict(finding_id=finding,reason='Selected uploads cleanup policy'))
        self.request(key,'preview',dict(items=[item['id']]))
        status=self.run_until(key,{'preview-failed'})
        self.assertIn('does not match the uploads cleanup policy',status['plan']['error'])
        self.recovery.save(plan,status='reviewed',selection=[item['id']],work_job=None)
        self.request(key,'apply');status=self.run_until(key,{'interrupted'})
        self.assertIn('does not match the uploads cleanup policy',status['plan']['error'])
        self.assertEqual(b'\x00<?=image',(self.root/path).read_bytes())
        with self.store.connection() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM operations').fetchone()[0])

    def test_bulk_repair_quarantine_and_undo_keep_every_original(self):
        self.write('wp-settings.php',b'modified core');self.write('wp-includes/extra.php',b'extra code')
        self.write('wp-content/plugins/example/backdoor.php',b'extra plugin code')
        self.write('wp-content/uploads/app.js',b'custom JS');self.write('wp-content/uploads/a.php',b'<?php echo 1;')
        before={str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        key=self.analyze(uploads_js=True);status=self.status(key)
        self.assertEqual(5,len(status['recommended']))
        self.request(key,'preview',dict(items=status['recommended'],edits={}))
        status=self.run_until(key,{'reviewed','preview-failed'});self.assertEqual('reviewed',status['plan']['status'],status)
        self.assertEqual(b'modified core',(self.root/'wp-settings.php').read_bytes())
        self.request(key,'apply');status=self.run_until(key,{'applied','interrupted'})
        self.assertEqual('applied',status['plan']['status'],status);self.assertEqual(b'clean core',(self.root/'wp-settings.php').read_bytes())
        for path in ('wp-includes/extra.php','wp-content/plugins/example/backdoor.php','wp-content/uploads/app.js','wp-content/uploads/a.php'):self.assertFalse((self.root/path).exists())
        self.assertTrue(status['rechecks']);self.request(key,'undo');status=self.run_until(key,{'undone','undo-interrupted'})
        self.assertEqual('undone',status['plan']['status'],status)
        self.assertEqual(before,{str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})

    def test_changed_file_blocks_entire_preflight_before_mutations(self):
        self.write('wp-content/uploads/a.php',b'<?php first');self.write('wp-content/uploads/b.php',b'<?php second')
        key=self.analyze();status=self.status(key);self.request(key,'preview',dict(items=status['recommended']))
        self.run_until(key,{'reviewed'});self.write('wp-content/uploads/b.php',b'changed after preview')
        self.request(key,'apply');status=self.run_until(key,{'interrupted'})
        self.assertTrue((self.root/'wp-content/uploads/a.php').exists());self.assertIn('changed',status['plan']['error'])

    def test_undo_refuses_to_overwrite_new_destination(self):
        self.write('wp-content/uploads/a.php',b'<?php original');key=self.analyze();status=self.status(key)
        self.request(key,'preview',dict(items=status['recommended']));self.run_until(key,{'reviewed'})
        self.request(key,'apply');self.run_until(key,{'applied'});self.write('wp-content/uploads/a.php',b'new destination')
        self.request(key,'undo');status=self.run_until(key,{'undo-interrupted'})
        self.assertEqual(b'new destination',(self.root/'wp-content/uploads/a.php').read_bytes())
        self.assertEqual('undo-interrupted',status['plan']['status'])

    def test_generation_scope_foreign_items_and_stale_revision_are_rejected(self):
        self.write('wp-content/uploads/a.php',b'<?php x');key=self.analyze();status=self.status(key)
        with self.assertRaises(AccessDenied):self.recovery.status(self.context|{'identity':'recreated'},key)
        with self.assertRaises(AccessDenied):self.request(key,'preview',dict(items=['foreign']))
        with self.assertRaises(Conflict):self.recovery.request(self.context,key,'preview','stale',dict(items=status['recommended']))
        self.native.authorize.return_value=self.context|{'identity':'recreated'}
        with self.assertRaises(AccessDenied):self.recovery.request(self.context,key,'preview',status['plan']['revision'],dict(items=status['recommended']))

    def test_quarantine_and_repair_capabilities_are_checked_independently(self):
        self.write('wp-content/uploads/a.php',b'<?php x');key=self.analyze();status=self.status(key)
        with patch('clamshield.wordpress_recovery.WebsitePermissions.require',side_effect=AccessDenied('revoked')):
            with self.assertRaises(AccessDenied):self.request(key,'preview',dict(items=status['recommended']))

    def test_symlinks_and_unavailable_scanners_never_produce_clean_coverage(self):
        (self.root/'wp-content/uploads').mkdir(parents=True);(self.root/'wp-content/uploads/link.php').symlink_to('/etc/passwd')
        self.engines[0].scan.side_effect=EngineError('unavailable')
        key=self.analyze();status=self.status(key)
        self.assertGreater(status['plan']['report']['coverage']['errors'],0)
        self.assertGreater(status['plan']['report']['coverage']['skipped'],0)

    def test_stopped_analysis_exposes_failure_without_an_enabled_apply(self):
        result=self.recovery.analyze(self.context,'fixture.test','',{'database':False});key=result['plan_id']
        task=self.store.claim('stopped-worker');self.store.finish(task,'failed',{'errors':1},'worker stopped')
        self.assertEqual('analysis-failed',self.status(key)['plan']['status'])
        with self.assertRaises(Conflict):self.request(key,'apply')

    def test_resume_inspects_completed_capture_after_worker_stops_before_item_commit(self):
        self.write('wp-content/uploads/a.php',b'<?php original');key=self.analyze();status=self.status(key)
        self.request(key,'preview',dict(items=status['recommended']));self.run_until(key,{'reviewed'})
        self.request(key,'apply');original=WordPressRecovery.save_item;stopped=[]
        def interrupt(manager,item,**changes):
            if changes.get('status')=='done' and not stopped:
                stopped.append(True);raise OSError('simulated worker interruption after capture')
            return original(manager,item,**changes)
        with patch.object(WordPressRecovery,'save_item',interrupt):self.worker.once()
        self.assertEqual('interrupted',self.status(key)['plan']['status']);self.assertFalse((self.root/'wp-content/uploads/a.php').exists())
        self.request(key,'apply');status=self.run_until(key,{'applied','interrupted'})
        self.assertEqual('applied',status['plan']['status'],status)
        self.assertEqual(1,len(self.quarantine_records()))

    def quarantine_records(self):
        with self.store.connection() as db:return list(db.execute("SELECT id FROM operations WHERE kind='quarantine'"))

    def test_resume_does_not_confirm_a_repaired_file_that_was_changed_after_interruption(self):
        self.write('wp-settings.php',b'compromised core');key=self.analyze();status=self.status(key)
        self.request(key,'preview',dict(items=status['recommended']));self.run_until(key,{'reviewed'});self.request(key,'apply')
        original=WordPressRecovery.save_item;stopped=[]
        def interrupt(manager,item,**changes):
            if changes.get('status')=='done' and not stopped:stopped.append(True);raise OSError('stop after publication')
            return original(manager,item,**changes)
        with patch.object(WordPressRecovery,'save_item',interrupt):self.worker.once()
        self.assertEqual('interrupted',self.status(key)['plan']['status']);self.write('wp-settings.php',b'new edit')
        self.request(key,'apply');status=self.run_until(key,{'interrupted','applied'})
        self.assertEqual('interrupted',status['plan']['status']);self.assertEqual(b'new edit',(self.root/'wp-settings.php').read_bytes())

    def test_array_keys_and_json_structure_are_preserved_during_database_changes(self):
        value=b'a:1:{s:1:"x";s:1:"x";}'
        self.assertEqual(b'a:1:{s:1:"x";s:1:"y";}',replacement(value,'x','y'))
        with self.assertRaises(Conflict):replacement(b'{"code":"hello"}','"hello"','broken')

    def test_action_pages_and_filters_are_scoped_and_select_all_covers_the_filtered_list(self):
        key=self.analyze();plan=self.recovery.get(self.context,key)
        for number in range(113):self.recovery.add(plan,'file-'+str(number).zfill(3),'configuration','quarantine',dict(reason='Review '+str(number),recommended=False))
        first=self.recovery.status(self.context,key,limit=25,filters={'action':'quarantine'})
        self.assertEqual(113,first['filtered_total']);self.assertEqual(25,len(first['items']));self.assertEqual(113,len(first['selectable']))
        second=self.recovery.status(self.context,key,first['next_offset'],25,{'action':'quarantine'})
        self.assertFalse({r['id'] for r in first['items']}&{r['id'] for r in second['items']})
        filtered=self.recovery.status(self.context,key,limit=50,filters={'search':'file-112','type':'configuration','state':'proposed'})
        self.assertEqual(1,filtered['filtered_total']);self.assertEqual('file-112',filtered['items'][0]['path'])
        with self.assertRaises(AccessDenied):self.recovery.status(self.context|{'identity':'foreign'},key)
        with self.assertRaises(Conflict):self.recovery.status(self.context,key,filters={'unknown':'value'})

    def test_large_previews_are_paginated_within_panel_response_limits(self):
        key=self.analyze();plan=self.recovery.get(self.context,key)
        for number in range(12):self.recovery.add(plan,'file-'+str(number),'configuration','quarantine',dict(reason='review',recommended=False,preview={'diff':'x'*(256*1024)}))
        first=self.status(key);self.assertLess(len(first['items']),12);self.assertIsNotNone(first['next_offset'])
        page=first;seen=[]
        while True:
            seen.extend(item['id'] for item in page['items']);self.assertLess(len(json.dumps(page).encode()),4*1024**2)
            if page['next_offset'] is None:break
            page=self.recovery.status(self.context,key,page['next_offset'])
        self.assertEqual(12,len(seen));self.assertEqual(12,len(set(seen)))


class VendorReferencesTests(unittest.TestCase):
    def test_vendor_zip_version_and_archive_paths_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);settings=Settings(state=base/'state');settings.prepare()
            data=io.BytesIO()
            with zipfile.ZipFile(data,'w') as archive:archive.writestr('premium/premium.php','<?php\n/* Plugin Name: Premium\nVersion: 2.0\n*/')
            (base/'premium.zip').write_bytes(data.getvalue())
            component=dict(kind='plugin',slug='premium',path='wp-content/plugins/premium',release_path='wp-content/plugins/premium/premium.php',version='1.0')
            refs=RecoveryReferences(settings,str(base),options({'packages':{component['path']:'premium.zip'},'versions':{component['path']:'2.0'}}))
            with self.assertRaises(ClamShieldError):refs.installed().manifest(component)
            manifest=refs.manifest(component);content,proof=refs.replacement(component,'premium.php',manifest['files']['premium.php'])
            self.assertIn(b'2.0',content);self.assertEqual('user-supplied',proof['authenticity'])
            refs=RecoveryReferences(settings,str(base),options({'packages':{component['path']:'premium.zip'},'versions':{component['path']:'1.0'}}))
            with self.assertRaises(Conflict):refs.manifest(component)
            refs=RecoveryReferences(settings,str(base),options({'packages':{component['path']:'premium.zip'}}))
            refs.manifest(component);self.assertEqual('2.0',component['recovery_version'])

    def test_private_vendor_path_uses_selected_account_home(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);web=base/'web';web.mkdir();home=base/'home';home.mkdir()
            settings=Settings(state=base/'state');settings.prepare();data=io.BytesIO()
            with zipfile.ZipFile(data,'w') as archive:archive.writestr('premium/premium.php','<?php\n/* Plugin Name: Premium\nVersion: 1.0\n*/')
            (home/'premium.zip').write_bytes(data.getvalue())
            component=dict(kind='plugin',slug='premium',path='wp-content/plugins/premium',release_path='wp-content/plugins/premium/premium.php',version='1.0')
            refs=RecoveryReferences(settings,str(web),options({'packages':{component['path']:'~/premium.zip'}}),owner='alice')
            with patch('clamshield.recovery_references.pwd.getpwnam',return_value=SimpleNamespace(pw_dir=str(home))) as native:
                manifest=refs.manifest(component)
            native.assert_called_once_with('alice');self.assertIn('premium.php',manifest['files'])
