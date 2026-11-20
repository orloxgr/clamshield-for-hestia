import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import ClamShieldError,EngineError
from clamshield.settings import Settings
from clamshield.signature_catalog import SignatureCatalog
from clamshield.signatures import Signatures


@unittest.skipUnless(Path('/usr/bin/clamscan').is_file() and Path('/usr/bin/sigtool').is_file(), 'Ubuntu ClamAV validation/catalog')
class SignatureReuse(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.base.chmod(0o755)
        self.settings=Settings(state=self.base/'state');self.settings.prepare()
        self.manager=Signatures(self.settings);self.manager.base.mkdir(mode=0o755)
        self.content=b'Reuse.Positive:0:*:4142434445464748\n';self.counter=0
        self.active,self.manifest=self.capture();self.manager.pointer('current',self.active)
        self.original_manifest=(self.active/'manifest.json').read_bytes()

    def capture(self,config=None,*,reuse_current=False):
        self.counter+=1;stage=self.manager.base/('generation-test'+str(self.counter));stage.mkdir(mode=0o755)
        source=stage/'local--test.ndb';source.write_bytes(self.content);source.chmod(0o644)
        metadata=dict(generation=stage.name,providers=['local'],files=[dict(provider='local',name=source.name,
                      sha256=hashlib.sha256(self.content).hexdigest(),size=len(self.content))])
        try:return self.manager.complete_stage(stage,metadata,reuse_current=reuse_current)
        except BaseException:
            shutil.rmtree(stage);raise

    def assert_original(self):
        self.assertEqual(self.active,(self.manager.base/'current').resolve())
        self.assertEqual(self.original_manifest,(self.active/'manifest.json').read_bytes())

    def test_unchanged_update_revalidates_with_real_engine_without_build_or_activation(self):
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.active.iterdir()}
        with patch.object(self.manager,'stage',side_effect=self.capture),patch.object(self.manager,'seed_official'),\
             patch.object(self.manager,'validate',wraps=self.manager.validate) as validation,\
             patch('clamshield.signatures.build_catalog',side_effect=AssertionError('Unnecessary catalog rebuild')),\
             patch.object(self.manager,'activate',side_effect=AssertionError('Unnecessary activation')):
            result=self.manager.update('local',acquire=False)
        self.assertFalse(result['changed']);self.assertTrue(result['catalog_reused']);validation.assert_called_once()
        self.assertEqual(self.manifest['generation'],result['generation']);self.assert_original()
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.active.iterdir()})
        self.assertEqual([self.active],list(self.manager.base.glob('generation-*')))

    def test_changed_data_builds_a_new_real_catalog(self):
        self.content=b'Reuse.NewPositive:0:*:4142434445464749\n'
        new,manifest=self.capture(reuse_current=True)
        self.assertNotEqual(self.active,new);self.assertNotEqual(self.manifest['content_sha256'],manifest['content_sha256'])
        with SignatureCatalog(new,manifest) as catalog:
            origin=catalog.resolve('Reuse.NewPositive.UNOFFICIAL')
            self.assertEqual('local',origin['provider']);self.assertEqual(hashlib.sha256(self.content).hexdigest(),origin['source_version'])
        self.assert_original()

    def test_corrupt_active_data_cannot_be_reused(self):
        (self.active/'local--test.ndb').write_bytes(b'altered')
        with self.assertRaises(EngineError):self.capture(reuse_current=True)
        self.assert_original();self.assertEqual([self.active],list(self.manager.base.glob('generation-*')))

    def test_corrupt_active_catalog_cannot_be_reused(self):
        (self.active/'signature-catalog.sqlite3').write_bytes(b'corrupt-index')
        with self.assertRaises(EngineError):self.capture(reuse_current=True)
        self.assert_original();self.assertEqual([self.active],list(self.manager.base.glob('generation-*')))

    def test_legacy_catalog_is_rebuilt_and_published_even_when_file_hashes_match(self):
        legacy=dict(self.manifest);legacy.pop('catalog');(self.active/'manifest.json').write_text(json.dumps(legacy))
        self.original_manifest=(self.active/'manifest.json').read_bytes()
        with patch.object(self.manager,'stage',side_effect=self.capture),patch.object(self.manager,'seed_official'),\
             patch.object(self.manager,'activate',side_effect=lambda path,metadata:metadata) as activate:
            result=self.manager.update('local',acquire=False)
        self.assertTrue(result['changed']);self.assertNotEqual(self.active.name,result['generation'])
        self.assertEqual(self.manifest['content_sha256'],result['content_sha256']);activate.assert_called_once()
        self.assertIn('catalog',result);self.assert_original()

    def test_current_engine_validation_failure_never_reuses_old_catalog(self):
        with patch.object(self.manager,'validate',side_effect=EngineError('Current engine rejects the data')),\
             patch('clamshield.signatures.build_catalog',side_effect=AssertionError('Must not build after validation failed')):
            with self.assertRaises(EngineError):self.capture(reuse_current=True)
        self.assert_original();self.assertEqual([self.active],list(self.manager.base.glob('generation-*')))

    def test_pending_activation_does_not_enter_reuse_or_touch_active_files(self):
        (self.settings.state/'signature-activation.json').write_text('{}')
        with patch.object(self.manager,'stage') as capture:
            with self.assertRaises(ClamShieldError):self.manager.update('local',acquire=False)
        capture.assert_not_called();self.assert_original()
