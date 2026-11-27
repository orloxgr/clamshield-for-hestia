import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import fcntl
import threading
from unittest.mock import Mock, patch

from clamshield.errors import ClamShieldError, EngineError
from clamshield.settings import Settings
from clamshield.signature_catalog import SignatureCatalog, build, classify, engine_lock, validate_origin
from clamshield.mail_generation import GenerationMailScanner
from clamshield.mail_policy import evaluate, DEFAULTS
from clamshield.signatures import Signatures
from clamshield.atomic import write_json
import test_mail_custody as fixtures


@unittest.skipUnless(Path('/usr/bin/sigtool').is_file(), 'Ubuntu APT sigtool')
class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name); self.stage.chmod(0o755)
        self.manifest = dict(generation='generation-catalog-test', content_sha256='a'*64, files=[])

    def add(self, provider, filename, content):
        path = self.stage / (provider+'--'+filename); path.write_text(content); path.chmod(0o644)
        self.manifest['files'].append(dict(provider=provider, name=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size))
        return path

    def finish(self):
        self.manifest['catalog'] = build(self.stage, self.manifest)
        return SignatureCatalog(self.stage, self.manifest)

    def test_real_sigtool_binds_source_hash_and_category_without_name_guessing(self):
        self.add('securiteinfo', 'spam_marketing.ndb', 'Completely.Neutral.Name:0:*:4142434445464748\nLegacy.Backtick`Name:0:*:4142434445464749\n')
        self.add('local', 'local.ndb', 'Sanesecurity.Spam.Forged.Name:0:*:4142434445464749\n')
        with self.finish() as catalog:
            spam = catalog.resolve('Completely.Neutral.Name.UNOFFICIAL')
            self.assertEqual('spam', spam['category']); self.assertEqual('securiteinfo', spam['provider'])
            self.assertEqual(self.manifest['files'][0]['sha256'], spam['source_version'])
            self.assertEqual('spam', catalog.resolve('Legacy.Backtick`Name.UNOFFICIAL')['category'])
            self.assertEqual('malware', catalog.resolve('Sanesecurity.Spam.Forged.Name.UNOFFICIAL')['category'])
            self.assertEqual('local', catalog.resolve('Sanesecurity.Spam.Forged.Name.UNOFFICIAL')['provider'])
            self.assertEqual('unclassified', catalog.resolve('Completely.Unknown.UNOFFICIAL')['provider'])
            self.assertEqual('malware', catalog.resolve('Completely.Unknown.UNOFFICIAL')['category'])
            self.assertEqual('clamav', catalog.resolve('Completely.Neutral.Name')['provider'])

    def test_documented_phishing_group_and_mixed_fallback_are_source_bound(self):
        self.add('sanesecurity', 'phish.ndb', 'Sanesecurity.Phishing.Bank.1:0:*:4142434445464748\nSanesecurity.Unknown.Mixed.1:0:*:4142434445464749\n')
        with self.finish() as catalog:
            self.assertEqual('phishing', catalog.resolve('Sanesecurity.Phishing.Bank.1.UNOFFICIAL')['category'])
            self.assertEqual('malware', catalog.resolve('Sanesecurity.Unknown.Mixed.1.UNOFFICIAL')['category'])
            self.assertEqual('phishing', catalog.resolve('Heuristics.Phishing.Email.SpoofedDomain')['category'])
            self.assertEqual('engine-heuristic', catalog.resolve('Heuristics.Phishing.Email.SpoofedDomain')['attribution'])

    def test_shared_engine_selection_ignores_known_other_feeds_but_not_unknown_or_selected_malware(self):
        self.add('securiteinfo','spam_marketing.ndb','Ignored.Spam:0:*:4142434445464748\nShared.Name:0:*:4142434445464748\n')
        self.add('local','malware.ndb','Selected.Malware:0:*:4142434445464749\nShared.Name:0:*:4142434445464749\n')
        with self.finish() as catalog:
            sources=['local--malware.ndb']
            self.assertIsNone(catalog.selected('Ignored.Spam.UNOFFICIAL',sources=sources))
            for name in ('Selected.Malware.UNOFFICIAL','Shared.Name.UNOFFICIAL','Uncatalogued.UNOFFICIAL','Official.Malware'):
                self.assertEqual('malware',catalog.selected(name,sources=sources)['category'])
            self.assertEqual('spam',catalog.selected('Ignored.Spam.UNOFFICIAL',sources=None)['category'])

    def test_same_name_in_different_feeds_retains_all_origins_and_strongest_category(self):
        for provider, name in [('securiteinfo','spam_marketing.ndb'),('local','malware.ndb')]:
            self.add(provider, name, 'Shared.Name:0:*:4142434445464748\n')
        with self.finish() as catalog:
            result = catalog.resolve('Shared.Name.UNOFFICIAL')
            self.assertEqual('malware', result['category']); self.assertEqual('multiple', result['provider'])
            self.assertEqual(2, len(result['origins']))
            scoped = catalog.resolve('Shared.Name.UNOFFICIAL', sources=['securiteinfo--spam_marketing.ndb'])
            self.assertEqual('spam', scoped['category']); self.assertEqual('securiteinfo', scoped['provider'])
            self.assertEqual(1, len(scoped['origins']))
            policy = dict(DEFAULTS, enabled=True)
            scan = dict(complete=True, errors=[], spam_score=0, detections=[dict(engine='clamav', signature='Shared.Name.UNOFFICIAL', **result)])
            decision = evaluate(policy, scan, sender='', sha256='b'*64)
            self.assertEqual('reject', decision['action']); self.assertEqual(result['origins'], decision['detections'][0]['origins'])

    def test_clamav_yara_names_are_catalogued_even_when_sigtool_lists_none(self):
        self.add('local','custom.yara','rule Benign_Yara_Fixture { strings: $a="INERT_CLAMSHIELD_CATALOG_YARA" condition: $a }')
        with self.finish() as catalog:
            result = catalog.resolve('YARA.Benign_Yara_Fixture.UNOFFICIAL')
            self.assertEqual('local', result['provider']); self.assertEqual('local--custom.yara', result['source_id'])

    def test_tampered_index_and_generation_mismatch_are_rejected(self):
        self.add('local','local.ndb','Fixture:0:*:4142434445464748\n')
        with self.finish(): pass
        wrong = dict(self.manifest, generation='generation-other')
        with self.assertRaises(EngineError): SignatureCatalog(self.stage, wrong)
        path = self.stage / self.manifest['catalog']['name']
        with path.open('ab') as stream: stream.write(b'changed')
        with self.assertRaises(EngineError): SignatureCatalog(self.stage, self.manifest)

    def test_repeated_index_verification_is_cached_but_same_size_tampering_is_not(self):
        from clamshield import signature_catalog as module
        self.add('local','local.ndb','Fixture:0:*:4142434445464748\n')
        self.manifest['catalog'] = build(self.stage, self.manifest)
        with module._verification_lock: module._verified.clear()
        with patch.object(module.hashlib, 'file_digest', wraps=hashlib.file_digest) as hasher:
            for _ in range(3):
                with SignatureCatalog(self.stage, self.manifest): pass
            self.assertEqual(1, hasher.call_count)
            path = self.stage/self.manifest['catalog']['name']; info = path.stat()
            with path.open('r+b') as stream:
                stream.seek(-1, os.SEEK_END); value = stream.read(1); stream.seek(-1, os.SEEK_END)
                stream.write(bytes([value[0] ^ 1])); stream.flush(); os.fsync(stream.fileno())
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            with self.assertRaises(EngineError): SignatureCatalog(self.stage, self.manifest)
            self.assertEqual(2, hasher.call_count)

    def test_index_symlinks_hardlinks_and_changed_input_cannot_be_accepted(self):
        path = self.add('local','local.ndb','Fixture:0:*:4142434445464748\n')
        with self.finish(): pass
        index = self.stage / self.manifest['catalog']['name']; saved = index.with_suffix('.saved')
        os.link(index, saved)
        with self.assertRaises(EngineError): SignatureCatalog(self.stage, self.manifest)
        saved.unlink(); index.rename(saved); index.symlink_to(saved)
        with self.assertRaises(OSError): SignatureCatalog(self.stage, self.manifest)
        index.unlink(); path.write_text('changed')
        with self.assertRaises(EngineError): build(self.stage, self.manifest)
        self.assertFalse(index.exists())

    def test_bounded_output_and_invalid_origin_lists_never_become_valid_provenance(self):
        self.add('local','local.ndb','Fixture:0:*:4142434445464748\n')
        with patch('clamshield.signature_catalog.MAX_NAMES', 0), self.assertRaises(EngineError):
            build(self.stage, self.manifest)
        self.assertFalse((self.stage/'signature-catalog.sqlite3').exists())
        for value in ({'origins': 'not-a-list'}, {'category':'spam','origins':[{}]}, {'category':'unknown'}, {'path':'/etc/shadow'}):
            with self.assertRaises(EngineError): validate_origin(value)


class GenerationGateTests(unittest.TestCase):
    setUp = fixtures.MailCustodyTests.setUp
    request_for = fixtures.MailCustodyTests.request_for

    def scanner(self):
        self.clam, self.spam = Mock(), Mock()
        self.spam.scan.return_value = {'score': 0, 'threshold': 5, 'symbols': []}
        return GenerationMailScanner(self.settings, self.clam, self.spam)

    def test_update_lock_and_recovery_journal_defer_without_scanning(self):
        scanner = self.scanner()
        with engine_lock(self.settings, exclusive=True):
            self.assertFalse(scanner.scan(self.request.fd)['complete'])
        self.clam.scan.assert_not_called()
        (self.settings.state/'signature-activation.json').write_text('{}')
        self.assertFalse(scanner.scan(self.request.fd)['complete']); self.clam.scan.assert_not_called()
        (self.settings.state/'signature-activation.json').unlink()
        (self.settings.state/'spamassassin-activation.json').write_text('{}')
        self.assertFalse(scanner.scan(self.request.fd)['complete']); self.clam.scan.assert_not_called()

    def test_unsafe_lock_cannot_authorize_scanning(self):
        scanner = self.scanner(); path = self.settings.state/'mail-engine.lock'; other = self.settings.state/'other'
        other.write_text('private'); path.symlink_to(other)
        self.assertFalse(scanner.scan(self.request.fd)['complete']); self.clam.scan.assert_not_called()

    def test_wrong_loaded_canary_and_corrupt_catalog_never_fall_back_to_official(self):
        self.settings.signatures.mkdir(); stage = self.settings.signatures/'generation-fixture'; stage.mkdir(mode=0o755)
        manifest = dict(generation=stage.name, content_sha256='a'*64, files=[], canary=dict(payload='inert-canary',signature='ClamShield.Generation.Fixture'))
        manifest['catalog'] = build(stage, manifest); (stage/'manifest.json').write_text(json.dumps(manifest))
        (self.settings.signatures/'current').symlink_to(stage.name)
        scanner = self.scanner(); self.clam.scan.return_value = []
        self.assertFalse(scanner.scan(self.request.fd)['complete']); self.spam.scan.assert_not_called()
        self.clam.scan.side_effect = [['ClamShield.Generation.Fixture.UNOFFICIAL'], []]
        result = scanner.scan(self.request.fd)
        self.assertTrue(result['complete']); self.assertEqual(stage.name, result['signature_generation'])
        decision = evaluate(dict(DEFAULTS, enabled=True), result, sender='', sha256=result['sha256'])
        self.assertEqual(stage.name, decision['signature_generation'])
        self.assertEqual(manifest['content_sha256'], decision['signature_content_sha256'])
        for invalid in ({'signature_generation': '../other'}, {'signature_content_sha256': 'invalid'}):
            verdict=evaluate(dict(DEFAULTS, enabled=True), result | invalid, sender='', sha256=result['sha256'])
            self.assertEqual('deliver',verdict['action']);self.assertFalse(verdict['scan_complete'])
        self.clam.reset_mock(); (stage/'signature-catalog.sqlite3').write_bytes(b'corrupted')
        self.assertFalse(scanner.scan(self.request.fd)['complete']); self.clam.scan.assert_not_called()

    def test_old_archive_is_rebuilt_without_mutating_its_files_or_manifest(self):
        manager = Signatures(self.settings); manager.base.mkdir()
        stage = manager.base/'generation-legacy'; stage.mkdir(mode=0o755)
        content = b'ClamShield fixture original data'; (stage/'main.cvd').write_bytes(content); (stage/'main.cvd').chmod(0o644)
        manifest = dict(generation=stage.name, created=0, providers=['official'], files=[dict(provider='official',name='main.cvd',sha256=hashlib.sha256(content).hexdigest(),size=len(content))])
        old = json.dumps(manifest); (stage/'manifest.json').write_text(old); manager.validate = Mock()
        newstage, upgraded = manager.upgrade_archive(stage, manifest)
        self.assertNotEqual(stage, newstage); self.assertEqual(content, (newstage/'main.cvd').read_bytes())
        self.assertEqual(old, (stage/'manifest.json').read_text()); self.assertNotIn('catalog', manifest)
        with SignatureCatalog(newstage, upgraded): pass


class DualActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name); self.settings = Settings(state=root/'state'); self.settings.prepare()
        self.manager = Signatures(self.settings); self.manager.base.mkdir()
        self.manager.website_config = root/'website.conf'; self.manager.mail_config = root/'mail.conf'
        for path in (self.manager.website_config, self.manager.mail_config):
            path.write_text('# Managed by clamshield\nDatabaseDirectory /var/lib/clamav\n')
        for method in ('validate', 'daemon_ready', 'daemon_version_ready', 'mail_ready', 'mail_version_ready', 'restart_mail'):
            setattr(self.manager, method, Mock())
        self.manager.mail_active = Mock(return_value=True)

    def stage(self, suffix):
        stage = self.manager.base/('generation-'+suffix); stage.mkdir(mode=0o755)
        return self.manager.complete_stage(stage, dict(generation=stage.name, files=[]))

    def legacy(self):
        stage,manifest=self.stage('legacy');manifest.pop('catalog')
        (stage/'manifest.json').write_text(json.dumps(manifest));self.manager.pointer('current',stage)
        return stage,(stage/'manifest.json').read_bytes()

    def test_current_catalog_migration_skips_fresh_and_compatible_generations(self):
        with patch.object(self.manager,'upgrade_archive') as rebuild:
            self.assertIsNone(self.manager.migrate_current())
            stage,manifest=self.stage('modern');self.manager.pointer('current',stage)
            self.assertIsNone(self.manager.migrate_current());rebuild.assert_not_called()

    def test_current_legacy_catalog_migration_retains_original_and_uses_no_download(self):
        original,before=self.legacy()
        with patch('clamshield.signatures.subprocess.run',return_value=Mock(returncode=0)),patch.object(self.manager.fetch,'refresh') as fetch:
            result=self.manager.migrate_current()
        current=(self.manager.base/'current').resolve()
        self.assertEqual(original.name,result['previous']);self.assertEqual(current.name,result['generation'])
        self.assertEqual(original,(self.manager.base/'previous').resolve());self.assertEqual(before,(original/'manifest.json').read_bytes())
        with SignatureCatalog(current,self.manager.manifest()):pass
        fetch.assert_not_called();self.assertIsNone(self.manager.migrate_current())

    def test_legacy_migration_preserves_inactive_unconfigured_website(self):
        self.legacy();self.manager.mail_active.return_value=False
        with patch('clamshield.signatures.subprocess.run',return_value=Mock(returncode=3)) as native:
            self.manager.migrate_current()
        self.assertFalse(any(call.args[0][1:]==['restart','clamshield-clamd.service'] for call in native.call_args_list))
        self.manager.daemon_ready.assert_not_called()

    def test_legacy_migration_respects_saved_start_and_stop_independently_of_live_state(self):
        for enabled in (True,False):
            with self.subTest(enabled=enabled):
                original,before=self.legacy() if not (self.manager.base/'generation-legacy').exists() else (None,None)
                if original is None:
                    stage=self.manager.base/'current';manifest=self.manager.manifest();manifest.pop('catalog');(stage.resolve()/'manifest.json').write_text(json.dumps(manifest))
                write_json(self.settings.state/'website-engine.json',dict(owner='clamshield',schema=1,enabled=enabled,changed_at=1))
                self.manager.daemon_ready.reset_mock()
                with patch('clamshield.signatures.subprocess.run',return_value=Mock(returncode=3)):
                    self.manager.migrate_current()
                self.assertEqual(enabled,self.manager.daemon_ready.called)

    def test_migration_build_failure_or_pending_activation_keeps_original_generation(self):
        original,before=self.legacy()
        with patch.object(self.manager,'upgrade_archive',side_effect=EngineError('Retained database changed')):
            with self.assertRaises(EngineError):self.manager.migrate_current()
        self.assertEqual(original,(self.manager.base/'current').resolve());self.assertEqual(before,(original/'manifest.json').read_bytes())
        write_json(self.settings.state/'signature-activation.json',{})
        with self.assertRaises(ClamShieldError):self.manager.migrate_current()

    def test_active_mail_and_website_share_verified_generation_and_journal_clears(self):
        stage, manifest = self.stage('one')
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(stage, manifest)
        self.manager.mail_ready.assert_called_once_with(manifest)
        self.manager.daemon_ready.assert_called_once_with(manifest)
        self.manager.restart_mail.assert_called_once()
        self.assertEqual(self.manager.website_config.read_text(), self.manager.mail_config.read_text())
        self.assertEqual(stage, (self.manager.base/'current').resolve())
        self.assertFalse((self.settings.state/'signature-activation.json').exists())

    def test_changed_database_cannot_activate_or_change_any_config_pointer(self):
        stage = self.manager.base/'generation-changed'; stage.mkdir(mode=0o755)
        path = stage/'main.cvd'; path.write_bytes(b'original-fixture'); path.chmod(0o644)
        manifest = dict(generation=stage.name, files=[dict(provider='official',name='main.cvd',size=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())])
        self.manager.complete_stage(stage, manifest); before = self.manager.website_config.read_text()
        path.write_bytes(b'replaced-fixture')
        with self.assertRaises(EngineError): self.manager.activate(stage, manifest)
        self.assertEqual(before, self.manager.website_config.read_text())
        self.assertEqual(before, self.manager.mail_config.read_text())
        self.assertFalse((self.manager.base/'current').exists())

    def test_inactive_mail_config_updates_without_starting_a_mail_service(self):
        self.manager.mail_active.return_value = False
        stage, manifest = self.stage('one')
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(stage, manifest)
        self.manager.restart_mail.assert_not_called(); self.manager.mail_ready.assert_not_called()
        self.assertIn(str(stage), self.manager.mail_config.read_text())

    def stopped_website(self):
        write_json(self.settings.state/'website-engine.json',dict(owner='clamshield',schema=1,enabled=False,changed_at=0))

    def test_stopped_website_stays_off_while_active_mail_gets_new_databases(self):
        self.stopped_website();stage,manifest=self.stage('stopped')
        with patch('clamshield.signatures.subprocess.run') as run:self.manager.activate(stage,manifest)
        self.assertFalse(any(call.args[0][1:]==['restart','clamshield-clamd.service'] for call in run.call_args_list))
        self.manager.daemon_ready.assert_not_called();self.manager.restart_mail.assert_called_once();self.manager.mail_ready.assert_called_once_with(manifest)
        self.assertEqual(stage,(self.manager.base/'current').resolve())

    def test_stopped_website_stays_off_during_failed_mail_activation_and_recovery(self):
        self.stopped_website();previous,manifest=self.stage('stopped-previous')
        with patch('clamshield.signatures.subprocess.run') as run:
            self.manager.activate(previous,manifest);candidate,newer=self.stage('stopped-next')
            self.manager.mail_ready.side_effect=[EngineError('mail unavailable'),None]
            with self.assertRaises(EngineError):self.manager.activate(candidate,newer)
            self.assertEqual(previous,(self.manager.base/'current').resolve())
            self.manager.mail_ready.side_effect=fixtures.Interrupted()
            with self.assertRaises(fixtures.Interrupted):self.manager.activate(candidate,newer)
            self.manager.mail_ready.side_effect=None;self.assertTrue(self.manager.recover())
        self.assertFalse(any(call.args[0][1:]==['restart','clamshield-clamd.service'] for call in run.call_args_list))
        self.manager.daemon_ready.assert_not_called();self.manager.daemon_version_ready.assert_not_called()
        self.assertEqual(previous,(self.manager.base/'current').resolve())

    def test_legacy_pointer_watching_daemons_stop_before_the_pointer_changes(self):
        previous, manifest = self.stage('previous')
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(previous, manifest)
        for path in (self.manager.website_config, self.manager.mail_config):
            path.write_text('# Managed by clamshield\nDatabaseDirectory '+str(self.manager.base/'current')+'\n')
        candidate, newer = self.stage('candidate'); stopped=[]
        def observed(args, **kwargs):
            if args[1]=='stop':
                self.assertEqual(previous,(self.manager.base/'current').resolve())
                stopped.append(args[2])
            return Mock(returncode=0)
        with patch('clamshield.signatures.subprocess.run',side_effect=observed):
            self.manager.activate(candidate,newer)
        self.assertEqual(['clamshield-clamd.service','clamshield-mail-clamd.service'],stopped)
        for path in (self.manager.website_config,self.manager.mail_config):
            self.assertIn('DatabaseDirectory '+str(candidate)+'\n',path.read_text())

    def test_waiting_for_a_website_job_does_not_exclude_current_mail_scans(self):
        path=self.settings.state/'worker.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
        waiting=threading.Event();entered=threading.Event();release=threading.Event();failures=[]
        fcntl.flock(fd,fcntl.LOCK_EX);original=fcntl.flock
        def observe(handle,operation):
            if threading.current_thread().name=='generation-update':waiting.set()
            return original(handle,operation)
        def update():
            try:
                with self.manager.activation_lock():entered.set();release.wait(3)
            except BaseException as exc:failures.append(exc)
        thread=threading.Thread(target=update,name='generation-update')
        try:
            with patch('clamshield.signatures.fcntl.flock',side_effect=observe):
                thread.start();self.assertTrue(waiting.wait(2))
                with engine_lock(self.settings):pass
                self.assertFalse(entered.is_set())
                original(fd,fcntl.LOCK_UN);self.assertTrue(entered.wait(2))
                with self.assertRaises(BlockingIOError):
                    with engine_lock(self.settings):pass
                release.set();thread.join(3)
        finally:
            release.set();original(fd,fcntl.LOCK_UN);os.close(fd)
            thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual([],failures)

    def test_failed_first_activation_restores_and_waits_for_original_mail_service(self):
        stage, manifest = self.stage('first'); before = self.manager.mail_config.read_text()
        self.manager.mail_ready.side_effect = EngineError('candidate failed')
        with patch('clamshield.signatures.subprocess.run'), self.assertRaises(EngineError):
            self.manager.activate(stage, manifest)
        self.manager.mail_version_ready.assert_called_once()
        self.assertEqual(before, self.manager.mail_config.read_text())
        self.assertFalse((self.manager.base/'current').exists())
        self.assertFalse((self.settings.state/'signature-activation.json').exists())

    def test_mail_readiness_failure_restores_both_daemons_and_previous_pointer(self):
        previous, manifest = self.stage('previous')
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(previous, manifest)
            before = self.manager.mail_config.read_text(); stage, candidate = self.stage('candidate')
            self.manager.mail_ready.side_effect = [EngineError('candidate unavailable'), None]
            with self.assertRaises(EngineError): self.manager.activate(stage, candidate)
        self.assertEqual(previous, (self.manager.base/'current').resolve())
        self.assertEqual(before, self.manager.mail_config.read_text())
        self.assertEqual(before, self.manager.website_config.read_text())
        self.assertEqual(manifest, self.manager.mail_ready.call_args.args[0])
        self.assertFalse((self.settings.state/'signature-activation.json').exists())

    def test_interrupted_dual_activation_recovery_restores_both_original_configs(self):
        previous, manifest = self.stage('previous')
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(previous, manifest)
            before = self.manager.mail_config.read_text(); stage, candidate = self.stage('candidate')
            self.manager.mail_ready.side_effect = fixtures.Interrupted()
            with self.assertRaises(fixtures.Interrupted): self.manager.activate(stage, candidate)
            self.assertTrue((self.settings.state/'signature-activation.json').is_file())
            self.assertEqual(stage, (self.manager.base/'current').resolve())
            self.manager.mail_ready.side_effect = None
            self.assertTrue(self.manager.recover())
        self.assertEqual(previous, (self.manager.base/'current').resolve())
        self.assertEqual(before, self.manager.website_config.read_text())
        self.assertEqual(before, self.manager.mail_config.read_text())
        self.assertEqual(manifest, self.manager.mail_ready.call_args.args[0])
