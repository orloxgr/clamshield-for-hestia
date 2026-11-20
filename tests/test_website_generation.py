import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_scanning as fixtures
from clamshield.engines import ClamAV
from clamshield.errors import EngineError, EncryptedContent
from clamshield.website_coverage import PROBE
from clamshield.signature_catalog import build
from clamshield.signatures import Signatures
from clamshield.website_generation import pinned,AttributedClamAV
from clamshield.worker import Worker


class WebsiteAdvisoryTests(unittest.TestCase):
    def hit(self,origins,signature='Untrusted-looking-name'):
        origins=[dict(source_version='frozen-source-hash',classification_basis='verified-source',**v) for v in origins]
        engine=Mock();engine.scan.return_value=[dict(engine='clamav',signature=signature)]
        resolver=Mock(return_value=dict(origins[0],origins=origins,attribution='exact-database-name'))
        return AttributedClamAV(engine,resolver,'generation-fixed','frozen-hash').scan(Path('/unused'))[0]

    def test_known_software_source_and_spam_are_review_only_in_website_context(self):
        for source,kind in ((dict(provider='securiteinfo',source_id='securiteinfo--securiteinfo-pua-app-and-vulnerabilities.ndb',category='malware'),'software'),
                            (dict(provider='sanesecurity',source_id='sanesecurity--spam.ldb',category='spam'),'spam')):
            with self.subTest(kind=kind):
                hit=self.hit([source]);self.assertTrue(hit['review_only']);self.assertEqual(kind,hit['advisory_kind'])
                self.assertEqual('generation-fixed',hit['signature_generation'])
                self.assertEqual(dict(source_version='frozen-source-hash',classification_basis='verified-source',**source),hit['origins'][0])

    def test_signature_name_cannot_turn_other_sources_into_software_advisories(self):
        hit=self.hit([dict(provider='local',source_id='local--securiteinfo-pua-app-and-vulnerabilities.ndb',category='malware')],
                     'SecuriteInfo.com.PUA.ObsoleteWordPress-1.UNOFFICIAL')
        self.assertNotIn('review_only',hit);self.assertNotIn('advisory_kind',hit)

    def test_independent_malware_or_phishing_origin_prevents_advisory_downgrade(self):
        for category in ('malware','phishing'):
            with self.subTest(category=category):
                hit=self.hit([dict(provider='securiteinfo',source_id='securiteinfo--spam_marketing.ndb',category='spam'),
                              dict(provider='local',source_id='local--strong.ndb',category=category)])
                self.assertNotIn('review_only',hit);self.assertNotIn('advisory_kind',hit)


@unittest.skipUnless(Path('/usr/bin/sigtool').is_file(), 'Ubuntu APT sigtool')
class WebsiteGenerationTests(unittest.TestCase):
    setUp = fixtures.FileScanning.setUp
    scan = fixtures.FileScanning.scan

    def generation(self, suffix='one'):
        self.base.chmod(0o755); self.settings.signatures.mkdir(exist_ok=True, mode=0o755)
        stage = self.settings.signatures/('generation-'+suffix); stage.mkdir(mode=0o755)
        path = stage/'local--fixture.ndb'
        path.write_text('SecuriteInfo.Forged.Fixture:0:*:4142434445464748\n'); path.chmod(0o644)
        manifest = dict(generation=stage.name, content_sha256=hashlib.sha256(suffix.encode()).hexdigest(),
            files=[dict(provider='local', name=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)],
            canary=dict(signature='ClamShield.Generation.'+suffix,payload='inert generation '+suffix))
        manifest['catalog'] = build(stage, manifest)
        (stage/'manifest.json').write_text(json.dumps(manifest)); self.activate(stage)
        return stage, manifest

    def activate(self, stage):
        link = self.settings.signatures/'current'; link.unlink(missing_ok=True); link.symlink_to(stage.name)

    def engine(self, manifest, signature='SecuriteInfo.Forged.Fixture.UNOFFICIAL'):
        engine = ClamAV('/unused')
        def scan(path):
            data=Path(path).read_bytes()
            if data==PROBE:raise EncryptedContent('Cannot inspect encrypted content')
            return ([dict(engine='clamav',signature=manifest['canary']['signature']+'.UNOFFICIAL',provider='unofficial')]
                if Path(path).parent==self.settings.snapshots and data==manifest['canary']['payload'].encode()
                else [dict(engine='clamav',signature=signature,provider='securiteinfo',severity='review')])
        engine.scan=Mock(side_effect=scan)
        return engine

    def test_worker_persists_exact_origin_and_keeps_it_after_data_pointer_changes(self):
        stage, manifest = self.generation(); (self.root/'fixture.txt').write_text('ABCDEFGH')
        job = self.scan([self.engine(manifest)])
        self.assertEqual('completed',job['status']); self.assertEqual(1,job['counters']['infected'])
        before = self.store.list_findings(self.context)[0]
        self.assertEqual('local',before['provider'])
        self.assertEqual(stage.name,before['detail']['signature_generation'])
        self.assertEqual(manifest['files'][0]['sha256'],before['detail']['source_version'])
        self.assertEqual('local--fixture.ndb',before['detail']['origins'][0]['source_id'])
        self.generation('two')
        self.assertEqual(before,self.store.list_findings(self.context)[0])
        self.assertEqual([],self.store.list_findings(self.context | {'identity':'replacement-account'}))

    def test_wrong_daemon_generation_keeps_yara_findings_and_partial_coverage(self):
        stage, manifest = self.generation(); (self.root/'fixture.txt').write_text('ABCDEFGH')
        engine = self.engine(manifest); engine.scan.side_effect = None; engine.scan.return_value = []
        yara = Mock(); yara.name='yara'; yara.scan.return_value=[dict(engine='yara',signature='Independent.Rule',provider='local')]
        job = self.scan([engine,yara])
        self.assertEqual('partial',job['status']); self.assertEqual(0,job['counters']['scanned'])
        self.assertGreater(job['counters']['errors'],0)
        self.assertEqual(['yara'],[row['engine'] for row in self.store.list_findings(self.context)])
        self.assertEqual(1,engine.scan.call_count)

    def test_loaded_profile_without_encrypted_reporting_keeps_yara_and_cannot_claim_coverage(self):
        stage,manifest=self.generation();(self.root/'fixture.txt').write_text('ABCDEFGH')
        engine=self.engine(manifest);scan=engine.scan.side_effect
        engine.scan.side_effect=lambda path: [] if Path(path).read_bytes()==PROBE else scan(path)
        yara=Mock();yara.name='yara';yara.scan.return_value=[dict(engine='yara',signature='Independent.Rule',provider='local')]
        job=self.scan([engine,yara])
        self.assertEqual('partial',job['status']);self.assertEqual(0,job['counters']['scanned']);self.assertGreater(job['counters']['errors'],0)
        self.assertEqual(['yara'],[v['engine'] for v in self.store.list_findings(self.context)])
        self.assertEqual(2,engine.scan.call_count)  # Profile canary and coverage probe; never site input.

    def test_corrupt_catalog_never_reads_a_site_file_through_clamav_or_marks_clean(self):
        stage, manifest = self.generation(); (self.root/'fixture.txt').write_text('ABCDEFGH')
        (stage/'signature-catalog.sqlite3').write_bytes(b'corrupt')
        engine = self.engine(manifest); job = self.scan([engine])
        self.assertEqual('partial',job['status']); self.assertEqual(0,job['counters']['scanned'])
        engine.scan.assert_not_called(); self.assertEqual([],self.store.list_findings(self.context))

    def test_no_files_still_reports_a_binding_failure(self):
        stage, manifest = self.generation(); (stage/'signature-catalog.sqlite3').write_bytes(b'corrupt')
        job = self.scan([self.engine(manifest)])
        self.assertEqual('partial',job['status']); self.assertEqual(0,job['counters']['seen'])
        self.assertGreater(job['counters']['errors'],0)

    def test_pinned_job_generation_must_match_before_even_canary_scanning(self):
        stage, manifest = self.generation(); engine = self.engine(manifest)
        with self.assertRaises(EngineError):
            with pinned(self.settings,engine,'unconfigured|clamav:generation-other'):self.fail('Wrong generation bound')
        engine.scan.assert_not_called()

    def test_recreated_owner_is_denied_before_canary_or_file_scan(self):
        stage, manifest = self.generation(); engine = self.engine(manifest)
        self.hestia.authorize.return_value = self.context | {'identity':'recreated'}
        job = self.scan([engine]); self.assertEqual('failed',job['status']); engine.scan.assert_not_called()

    def test_official_only_mode_does_not_trust_a_provider_word_in_the_name(self):
        path=self.base/'clamd.conf'; path.write_text('# Managed by clamshield\nDatabaseDirectory /var/lib/clamav\n')
        (self.root/'fixture.txt').write_text('fixture')
        engine=ClamAV('/unused');engine.scan=Mock(return_value=[dict(engine='clamav',signature='SecuriteInfo.Official.Name',provider='securiteinfo')])
        def scan(path):
            if Path(path).read_bytes()==PROBE:raise EncryptedContent('Cannot inspect encrypted content')
            return engine.scan.return_value
        engine.scan.side_effect=scan
        with patch.object(Signatures,'website_config',path):job=self.scan([engine])
        self.assertEqual('completed',job['status'])
        finding=self.store.list_findings(self.context)[0]
        self.assertEqual('clamav',finding['provider']);self.assertEqual('ubuntu-native',finding['detail']['signature_generation'])
        engine.scan.return_value=[dict(engine='clamav',signature='Forged.UNOFFICIAL',provider='local')]
        with patch.object(Signatures,'website_config',path):job=self.scan([engine])
        self.assertEqual('partial',job['status']);self.assertEqual(0,job['counters']['scanned'])
