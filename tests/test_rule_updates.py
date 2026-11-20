from concurrent.futures import ThreadPoolExecutor
from email.message import Message
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from clamshield.errors import ClamShieldError
from clamshield.rule_updates import RuleUpdates
from clamshield.rule_manager import RuleManager, revision
from clamshield.settings import Settings


class RuleUpdateTiming(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.settings = Settings(state=Path(folder.name)/'state')
        self.updates = RuleUpdates(self.settings)

    def test_defaults_and_saved_interval_reject_fast_fractional_boolean_or_unknown_settings(self):
        self.assertEqual(1440, self.updates.status()['interval_minutes'])
        self.assertTrue(self.updates.status()['automatic'])
        for interval in (0, 59, True, 60.0, '60', 525601):
            with self.subTest(interval=interval), self.assertRaises(ClamShieldError):
                self.updates.save({'interval_minutes':interval})
        for value in ({'automatic':1}, {'unexpected':True}, []):
            with self.assertRaises(ClamShieldError): self.updates.save(value)
        saved = self.updates.save({'automatic':False,'interval_minutes':2880})
        self.assertFalse(saved['automatic']); self.assertEqual(2880,saved['interval_minutes'])
        self.assertEqual(saved,RuleUpdates(self.settings).status())

    def test_manual_and_legacy_paths_share_durable_gate_across_profiles_and_restarts(self):
        manager = RuleManager(self.settings)
        with patch.object(manager,'_forge',return_value={'generation':'generation-test'}) as fetch:
            manager.forge('core')
            with self.assertRaisesRegex(ClamShieldError,'Next permitted'):
                manager.install('extended')
            self.assertEqual(1,fetch.call_count)
        from clamshield.rules import Rules
        legacy = Rules(self.settings)
        with patch.object(legacy,'fetch_forge') as fetch, self.assertRaises(ClamShieldError):
            legacy.forge('full')
        fetch.assert_not_called()
        self.assertGreater(RuleUpdates(self.settings).status()['last_success'],0)

    def test_parallel_requests_allow_only_one_operation_and_interval_changes_keep_upstream_cooldown(self):
        self.updates.save({'interval_minutes':60})
        operation = Mock(return_value={'ok':True})
        def start(_):
            try: return RuleUpdates(self.settings).run('core',operation)
            except ClamShieldError: return None
        with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(start,range(8)))
        self.assertEqual(1,operation.call_count)
        self.assertEqual(1,sum(result is not None for result in results))
        deadline=time.time()+172800
        self.updates.record(retry_after=deadline)
        self.updates.save({'interval_minutes':120})
        self.assertEqual(deadline,self.updates.status()['next_allowed'])

    def test_failed_compilation_activation_or_interruption_consumes_interval_without_success(self):
        for error in (ClamShieldError('Compilation failed'),KeyboardInterrupt()):
            self.updates.record(last_attempt=0,last_success=None)
            with self.subTest(error=type(error).__name__),self.assertRaises(type(error)):
                self.updates.run('core',Mock(side_effect=error))
            status=RuleUpdates(self.settings).status()
            self.assertFalse(status.get('last_success'));self.assertEqual('failed',status['state'])
            with self.assertRaises(ClamShieldError):self.updates.run('full',Mock())

    def test_success_is_recorded_after_activation_only_and_failed_activation_preserves_last_success(self):
        manager=RuleManager(self.settings)
        def activate(_):
            self.assertIsNone(self.updates.status().get('last_success'))
            return {'generation':'generation-test'}
        with patch.object(manager,'_forge',return_value={'generation':'generation-test'}),patch.object(manager,'activate',side_effect=activate):
            result=manager.install('core')
        self.assertTrue(result['activated']);previous=self.updates.status()['last_success']
        self.updates.record(last_attempt=1,last_success=1)
        with patch.object(manager,'_forge',return_value={'generation':'generation-test'}),patch.object(manager,'activate',side_effect=ClamShieldError('Changed configuration')):
            with self.assertRaises(ClamShieldError):manager.install('core')
        self.assertEqual(1,self.updates.status()['last_success']);self.assertGreater(previous,1)

    def test_github_retry_after_and_rate_limit_reset_take_precedence_without_exposing_response(self):
        self.updates.save({'interval_minutes':60})
        headers=Message();headers['Retry-After']='7200';deadline=time.time()+10800
        headers['X-RateLimit-Reset']=str(deadline)
        error=HTTPError('https://example.test/private',429,'private response',headers,None)
        self.addCleanup(error.close)
        with self.assertRaisesRegex(ClamShieldError,'server cooldown'):
            self.updates.run('core',Mock(side_effect=error))
        status=self.updates.status();self.assertEqual(deadline,status['next_allowed'])
        self.assertNotIn('private',json.dumps(status))
        self.updates.save({'interval_minutes':60})
        with self.assertRaises(ClamShieldError):self.updates.check_due()

    def test_http_date_cooldown_and_invalid_rate_limit_headers(self):
        from email.utils import formatdate
        deadline=int(time.time())+172800
        headers=Message();headers['Retry-After']=formatdate(deadline,usegmt=True);headers['X-RateLimit-Reset']='nan'
        error=HTTPError('https://example.test/rules',403,'forbidden',headers,None)
        self.addCleanup(error.close)
        self.assertEqual(deadline,RuleUpdates.http_deadline(error))
        headers.replace_header('Retry-After','invalid');headers.replace_header('X-RateLimit-Reset','inf')
        self.assertIsNone(RuleUpdates.http_deadline(error))

    def test_invalid_persisted_interval_and_symlink_fail_closed(self):
        self.settings.prepare();self.updates.policy_path.write_text('{"interval_minutes":1}')
        with self.assertRaises(ClamShieldError):self.updates.run('core',Mock())
        self.updates.policy_path.unlink();target=self.settings.state/'foreign';target.write_text('{}')
        self.updates.policy_path.symlink_to(target)
        with self.assertRaises(ClamShieldError):self.updates.status()

    def test_automatic_profile_excludes_pending_edits_disabled_sources_and_uninstalled_rules(self):
        manager=RuleManager(self.settings)
        config={'sources':{'forge':{'enabled':True,'profile':'extended'}},'disabled':[]}
        active={'configured':True,'profile':'extended','config_sha256':revision(config)}
        with patch.object(manager,'read',return_value=config),patch.object(manager.rules,'status',return_value=active):
            payload=manager.automatic_update();self.assertEqual('extended',payload['profile'])
            self.assertEqual(revision(config),payload['revision'])
            config['disabled']=['forge:One'];self.assertIsNone(manager.automatic_update())
            config['disabled']=[];config['sources']['forge']['enabled']=False
            self.assertIsNone(manager.automatic_update())
            config['sources']['forge']['enabled']=True;active['configured']=False
            self.assertIsNone(manager.automatic_update())
            active['configured']=True;self.updates.save({'automatic':False})
            self.assertIsNone(manager.automatic_update())
