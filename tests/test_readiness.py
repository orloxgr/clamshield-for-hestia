import fcntl
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.atomic import write_json
from clamshield.errors import EngineError, EncryptedContent
from clamshield.website_coverage import PROBE
from clamshield.health import Health
from clamshield.providers import Providers
from clamshield.readiness import WebsiteReadiness, public_status
from clamshield.rules import Rules
from clamshield.settings import Settings
from clamshield.signatures import Signatures
from clamshield.store import Store


@unittest.skipUnless(Path('/usr/bin/yarac').is_file(), 'Ubuntu APT YARA')
class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.settings = Settings(state=self.base/'state', rules=self.base/'state/rules/current/rules.yarac')
        self.settings.prepare()
        config = self.base/'clamd.conf'
        config.write_text('# Managed by clamshield\nDatabaseDirectory /var/lib/clamav\n')
        self.addCleanup(patch.stopall)
        patch.object(Signatures, 'website_config', config).start()
        self.engine = Mock(); self.engine.scan.return_value=[]; self.scanned_payloads=[]
        def scan(path):
            data=Path(path).read_bytes();self.scanned_payloads.append(data)
            if data==PROBE:raise EncryptedContent('Cannot inspect encrypted content')
            return self.engine.scan.return_value
        self.engine.scan.side_effect=scan
        patch('clamshield.readiness.ClamAV', return_value=self.engine).start()
        self.probe = WebsiteReadiness(self.settings)

    def rules(self):
        return Rules(self.settings).publish(b'rule CleanFixture { condition: false }', dict(provider='local', version='test'))

    def test_actual_yara_load_and_official_stream_probe_are_required(self):
        self.rules()
        result = self.probe.check()
        self.assertEqual('healthy', result['state'])
        self.assertEqual('ubuntu-native', result['clamav']['generation'])
        self.assertEqual('ready', result['yara']['state'])
        self.assertEqual([PROBE,b'ClamShield inert website readiness input.'],self.scanned_payloads)

    def test_version_availability_does_not_hide_missing_catalog(self):
        self.rules()
        config = Providers(self.settings).read()
        config['securiteinfo']['enabled'] = True
        config['securiteinfo']['key'] = 'private-test-credential'
        write_json(Providers(self.settings).path, config)
        self.engine.version.return_value = 'ClamAV available'
        result = self.probe.check()
        self.assertEqual('incomplete', result['state'])
        self.assertEqual('unavailable', result['clamav']['state'])
        self.assertEqual('ready', result['yara']['state'])
        self.engine.scan.assert_not_called()
        self.assertNotIn('private-test-credential', json.dumps(result))

    def test_missing_and_corrupted_compiled_yara_are_not_ready(self):
        self.assertEqual('missing', self.probe.check()['yara']['state'])
        metadata = self.rules()
        (self.settings.state/'rules'/metadata['generation']/'rules.yarac').write_bytes(b'not compiled rules')
        result = self.probe.check()
        self.assertEqual('incomplete', result['state'])
        self.assertEqual('unavailable', result['yara']['state'])
        self.assertEqual('ready', result['clamav']['state'])

    def test_external_pointer_cannot_borrow_a_valid_internal_generation(self):
        metadata = self.rules()
        foreign = self.base/metadata['generation']; foreign.mkdir()
        (foreign/'rules.yarac').write_bytes(b'foreign data')
        pointer = self.settings.state/'rules/current'; pointer.unlink(); pointer.symlink_to(foreign)
        self.assertEqual('unavailable', self.probe.check()['yara']['state'])

    def test_changed_yara_selection_is_pending_without_changing_active_rules(self):
        metadata = self.rules()
        write_json(self.settings.state/'rules-config.json', {'sources': {'another': {'enabled': True}}, 'disabled': []})
        result = self.probe.check()
        self.assertEqual('pending', result['yara']['state'])
        self.assertEqual(metadata['generation'], (self.settings.state/'rules/current').resolve().name)

    def test_daemon_scan_failure_is_not_replaced_by_a_healthy_yara_result(self):
        self.rules(); self.engine.scan.side_effect = EngineError('private diagnostic with credential')
        result = self.probe.check()
        self.assertEqual('incomplete', result['state'])
        self.assertEqual('unavailable', result['clamav']['state'])
        self.assertEqual('ready', result['yara']['state'])
        self.assertNotIn('private diagnostic', json.dumps(result))

    def test_inert_readiness_false_positive_needs_attention(self):
        self.rules(); self.engine.scan.return_value = [dict(signature='Unexpected')]
        self.assertEqual('unavailable', self.probe.check()['clamav']['state'])

    def test_live_worker_and_rule_update_locks_defer_without_engine_requests(self):
        self.rules()
        for path in (self.settings.state/'worker.lock', self.settings.state/'rules/update.lock'):
            with self.subTest(path=path), path.open('a+b') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertIsNone(self.probe.check())
                self.engine.scan.assert_not_called()
        self.assertEqual('healthy', self.probe.check()['state'])

    def test_unsafe_lock_and_pending_installation_do_not_report_ready(self):
        self.rules()
        path = self.settings.state/'worker.lock'; path.symlink_to(self.base/'other')
        self.assertEqual('unavailable', self.probe.check()['state'])
        path.unlink(); (self.settings.state/'install-pending.json').write_text('{}')
        self.assertEqual('incomplete', self.probe.check()['state'])
        self.engine.scan.assert_not_called()

    def test_selected_feed_subset_and_local_content_changes_require_activation(self):
        local = self.settings.state/'local-signatures'; local.mkdir()
        data = local/'fixture.ndb'; data.write_bytes(b'original')
        manifest = dict(providers=['official', 'local'], files=[dict(provider='local', name='local--fixture.ndb', sha256=hashlib.sha256(b'original').hexdigest())])
        self.assertTrue(self.probe.selected_signatures(manifest))
        data.write_bytes(b'changed')
        self.assertFalse(self.probe.selected_signatures(manifest))
        data.write_bytes(b'original')
        config = Providers(self.settings).read(); config['sanesecurity']['enabled'] = True
        write_json(Providers(self.settings).path, config)
        self.assertFalse(self.probe.selected_signatures(manifest))
        manifest['providers'].append('sanesecurity')
        self.assertFalse(self.probe.selected_signatures(manifest))


class CachedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name)/'state'); self.settings.prepare()
        self.store = Store(self.settings.database); self.health = Health(self.settings, self.store)
        self.admin = dict(actor='admin', owner='admin', identity='one', admin=True)

    def test_deferred_check_preserves_observation_time_and_deduplicates_recovery(self):
        with patch('clamshield.health.time.time', return_value=100):
            before = self.health.observe({'website-coverage': {'state': 'healthy', 'message': 'ready'}})['website-coverage']
        with patch('clamshield.health.time.time', return_value=150):
            for _ in range(3):
                deferred = self.health.observe({}, ('website-coverage',))['website-coverage']
        self.assertEqual(before['checked'], deferred['checked'])
        self.assertEqual('checking', public_status(deferred, 150)['state'])
        self.assertEqual('unknown', public_status(deferred, 200)['state'])
        self.assertEqual([], self.store.notifications(self.admin))
        for _ in range(2):
            self.health.observe({'website-coverage': {'state': 'incomplete'}})
        self.health.observe({}, ('website-coverage',))
        for _ in range(2):
            self.health.observe({'website-coverage': {'state': 'healthy'}})
        events = [row['event'] for row in self.store.notifications(self.admin)]
        self.assertEqual(1, events.count('health.problem'))
        self.assertEqual(1, events.count('health.recovered'))

    def test_first_deferred_check_is_never_a_success_or_false_recovery(self):
        value = self.health.observe({}, ('website-coverage',))['website-coverage']
        self.assertIsNone(value['checked'])
        self.assertEqual('unknown', public_status(value, 100)['state'])
        self.health.observe({'website-coverage': {'state': 'healthy'}})
        self.assertEqual([], self.store.notifications(self.admin))

    def test_missing_stale_future_or_invalid_time_is_not_current_ready(self):
        for value in (None, [], {}, {'state': 'healthy'}, {'state': 'healthy', 'checked': None},
                      {'state': 'healthy', 'checked': 9}, {'state': 'healthy', 'checked': 101},
                      {'state': 'healthy', 'checked': True}):
            with self.subTest(value=value):
                result = public_status(value, 100)
                self.assertEqual('unknown', result['state'])
                self.assertIn('checked', result)
        self.assertEqual('healthy', public_status({'state': 'healthy', 'checked': 10}, 100)['state'])
