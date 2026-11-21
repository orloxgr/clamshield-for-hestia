"""Fresh release discovery, pinned candidates and explicit application of upgrades."""
import hashlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from urllib.parse import parse_qs,urlsplit
import zipfile

import test_wordpress_recovery as fixtures
from clamshield.errors import Conflict
from clamshield.recovery_references import RecoveryReferences
from clamshield.wordpress_recovery import options
from clamshield.wordpress_sources import ReferenceUnavailable


def zipped(prefix,files):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as archive:
        for path,content in files.items():archive.writestr(prefix+'/'+path,content)
    return data.getvalue()


class ReleaseDiscovery(unittest.TestCase):
    def test_latest_core_plugin_theme_are_pinned_and_metadata_is_not_reused_between_analyses(self):
        with tempfile.TemporaryDirectory() as folder:
            settings=fixtures.Settings(state=Path(folder)/'state');settings.prepare();calls=[];version=['2.0']
            def fetch(url,maximum):
                calls.append(url);query=parse_qs(urlsplit(url).query)
                if '/version-check/' in url:return json.dumps({'offers':[dict(response='upgrade',current='6.9',locale='el'),dict(response='autoupdate',current='6.8.4',locale='el'),dict(response='upgrade',current='7.0-beta1',locale='el')]}).encode()
                return json.dumps({'slug':query['request[slug]'][0],'version':version[0],'download_link':'https://untrusted.test/ignored.zip'}).encode()
            refs=RecoveryReferences(settings,folder,options({'release_policy':'latest'}),fetch=fetch)
            core=dict(kind='core',path='',version='6.8.3',locale='el')
            plugin=dict(kind='plugin',slug='example',path='wp-content/plugins/example',version='1.0')
            theme=dict(kind='theme',slug='example-theme',path='wp-content/themes/example-theme',version='1.0')
            self.assertEqual('6.9',refs.target(core)['version']);self.assertEqual('2.0',refs.target(plugin)['version']);self.assertEqual('2.0',refs.target(theme)['version'])
            version[0]='3.0';self.assertEqual('2.0',refs.target(plugin)['version']);self.assertEqual(3,len(calls))
            self.assertEqual('3.0',RecoveryReferences(settings,folder,options({'release_policy':'latest'}),fetch=fetch).target(plugin)['version'])
            self.assertTrue(all(urlsplit(url).hostname=='api.wordpress.org' for url in calls))

    def test_failed_or_mismatched_latest_metadata_never_silently_uses_installed_version(self):
        with tempfile.TemporaryDirectory() as folder:
            settings=fixtures.Settings(state=Path(folder)/'state')
            component=dict(kind='plugin',path='wp-content/plugins/example',slug='example',version='1.0')
            for value in (b'not JSON',b'[]',b'{"error":"not found"}',b'{"slug":"other","version":"2.0"}',b'{"slug":"example","version":"2.0-RC1"}'):
                refs=RecoveryReferences(settings,folder,options({'release_policy':'latest'}),fetch=lambda *_args:value)
                with self.subTest(value=value),self.assertRaises(ReferenceUnavailable):refs.target(component)
                self.assertNotIn('recovery_version',component)
            no_network=Mock(side_effect=AssertionError('An explicit release must not look up latest'))
            self.assertEqual('1.0',RecoveryReferences(settings,folder,options({'release_policy':'installed'}),fetch=no_network).target(component)['version'])
            self.assertEqual('2.0',RecoveryReferences(settings,folder,options({'versions':{component['path']:'2.0'}}),fetch=no_network).target(component)['version'])
            no_network.assert_not_called()
            for value in ('unknown',True,None,[]):
                with self.assertRaises(Conflict):options({'release_policy':value})


class LatestRecoveryBatch(unittest.TestCase):
    setUp=fixtures.RecoveryBatchTests.setUp
    write=fixtures.RecoveryBatchTests.write
    analyze=fixtures.RecoveryBatchTests.analyze
    status=fixtures.RecoveryBatchTests.status
    request=fixtures.RecoveryBatchTests.request
    run_until=fixtures.RecoveryBatchTests.run_until

    def releases(self,release_policy='latest'):
        core={'wp-includes/version.php':b"<?php\n$wp_version='6.9';\n",'wp-settings.php':b'new core','wp-includes/new.php':b'new required core file'}
        plugin={'example.php':b'<?php\n/* Plugin Name: Example\nVersion: 2.0\n*/\nnew plugin','new.js':b'new plugin asset'}
        calls=[]
        def fetch(url,maximum):
            calls.append(url)
            if '/version-check/' in url:return json.dumps({'offers':[dict(response='upgrade',current='6.9',locale='en_US')]}).encode()
            if '/plugins/info/' in url:return b'{"slug":"example","version":"2.0"}'
            if '/checksums/' in url:
                files=core if parse_qs(urlsplit(url).query)['version']==['6.9'] else {path:data for path,data in self.clean.items() if not path.startswith('wp-content/')}
                return json.dumps({'checksums':{path:dict(sha256=hashlib.sha256(data).hexdigest()) for path,data in files.items()}}).encode()
            if '/plugin-checksums/' in url:
                version='2.0' if url.endswith('/2.0.json') else '1.0';files=plugin if version=='2.0' else {'example.php':self.clean['wp-content/plugins/example/example.php']}
                return json.dumps({'plugin':'example','version':version,'files':{path:dict(sha256=hashlib.sha256(data).hexdigest()) for path,data in files.items()}}).encode()
            if url.endswith('wordpress-6.8.3.zip'):return zipped('wordpress',{path:data for path,data in self.clean.items() if not path.startswith('wp-content/')})
            if url.endswith('example.1.0.zip'):return zipped('example',{'example.php':self.clean['wp-content/plugins/example/example.php']})
            if url.endswith('wordpress-6.9.zip'):return zipped('wordpress',core)
            if url.endswith('example.2.0.zip'):return zipped('example',plugin)
            raise AssertionError(url)
        refs=RecoveryReferences(self.settings,str(self.root),options({'database':False,'release_policy':release_policy}),fetch=fetch)
        self.enterContext(patch('clamshield.wordpress_recovery.RecoveryReferences',return_value=refs))
        return core,plugin,calls

    def test_default_analysis_of_clean_installed_releases_proposes_no_upgrades_or_false_differences(self):
        _core,_plugin,calls=self.releases('installed');key=self.analyze();status=self.status(key)
        self.assertEqual('installed',status['plan']['options']['release_policy'])
        self.assertEqual('installed',status['plan']['report']['comparison']);self.assertEqual([],status['items'])
        self.assertEqual(0,status['plan']['report']['integrity']['modified'])
        self.assertFalse(any('/version-check/' in url or '/plugins/info/' in url for url in calls))

    def test_same_version_repair_still_proposes_real_modified_files(self):
        self.releases('installed');self.write('wp-settings.php',b'changed installed file')
        key=self.analyze();status=self.status(key)
        self.assertEqual(1,status['plan']['report']['integrity']['modified'])
        self.assertEqual(['integrity'],[item['kind'] for item in status['items']])
        self.assertEqual('proposed',status['items'][0]['status'])

    def test_latest_analysis_and_review_preserve_files_then_apply_exact_releases_and_undo(self):
        core,plugin,calls=self.releases();self.write('wp-content/plugins/example/obsolete.php',b'old plugin file')
        before={str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        key=self.analyze(release_policy='latest');status=self.status(key)
        self.assertEqual('ready',status['plan']['status'],status)
        self.assertEqual('installed',status['plan']['report']['comparison'])
        self.assertEqual(0,status['plan']['report']['coverage']['modified'])
        self.assertTrue(any(item['kind']=='version-update' for item in status['items']))
        self.assertEqual({('core','6.8.3','6.9'),('plugin','1.0','2.0')},{(c['kind'],c['version'],c['recovery_version']) for c in status['plan']['report']['components']})
        self.assertEqual(before,{str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        resolved=list(calls);self.request(key,'preview',dict(items=status['recommended'],edits={}))
        reviewed=self.run_until(key,{'reviewed','preview-failed'});self.assertEqual('reviewed',reviewed['plan']['status'],reviewed)
        self.assertEqual(before,{str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        self.request(key,'apply');applied=self.run_until(key,{'applied','interrupted'});self.assertEqual('applied',applied['plan']['status'],applied)
        expected=core|{'wp-content/plugins/example/'+path:content for path,content in plugin.items()}
        self.assertEqual(expected,{str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        self.assertEqual(resolved,calls)
        self.request(key,'undo');undone=self.run_until(key,{'undone','undo-interrupted'});self.assertEqual('undone',undone['plan']['status'],undone)
        self.assertEqual(before,{str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})

    def test_partial_component_version_selection_is_rejected_before_review_or_mutation(self):
        self.releases();key=self.analyze(release_policy='latest');status=self.status(key)
        one=next(item['id'] for item in status['items'] if item['action']=='replace')
        with self.assertRaisesRegex(Conflict,'Select all replacement files'):
            self.request(key,'preview',dict(items=[one],edits={}))
        self.assertEqual('ready',self.status(key)['plan']['status'])
        self.assertIn(b'6.8.3',(self.root/'wp-includes/version.php').read_bytes())

    def test_unavailable_latest_release_is_unverified_without_clean_candidates(self):
        refs=RecoveryReferences(self.settings,str(self.root),options({'database':False,'release_policy':'latest'}),fetch=lambda *_args:b'{"error":"not available"}')
        self.enterContext(patch('clamshield.wordpress_recovery.RecoveryReferences',return_value=refs))
        key=self.analyze(release_policy='latest');status=self.status(key)
        self.assertTrue(all(c['status']=='unverified' and c['recovery_version'] is None for c in status['plan']['report']['components']))
        self.assertEqual([],status['recommended']);self.assertGreater(status['plan']['report']['coverage']['unverified'],0)
