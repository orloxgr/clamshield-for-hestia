import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest.mock import Mock, patch
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
        before=b'a:1:{s:4:"html";s:20:"<script>bad</script>!";}'
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


class VendorReferencesTests(unittest.TestCase):
    def test_vendor_zip_version_and_archive_paths_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);settings=Settings(state=base/'state');settings.prepare()
            data=io.BytesIO()
            with zipfile.ZipFile(data,'w') as archive:archive.writestr('premium/premium.php','<?php\n/* Plugin Name: Premium\nVersion: 2.0\n*/')
            (base/'premium.zip').write_bytes(data.getvalue())
            component=dict(kind='plugin',slug='premium',path='wp-content/plugins/premium',release_path='wp-content/plugins/premium/premium.php',version='1.0')
            refs=RecoveryReferences(settings,str(base),options({'packages':{component['path']:'premium.zip'},'versions':{component['path']:'2.0'}}))
            manifest=refs.manifest(component);content,proof=refs.replacement(component,'premium.php',manifest['files']['premium.php'])
            self.assertIn(b'2.0',content);self.assertEqual('user-supplied',proof['authenticity'])
            refs=RecoveryReferences(settings,str(base),options({'packages':{component['path']:'premium.zip'}}))
            with self.assertRaises(Conflict):refs.manifest(component)
