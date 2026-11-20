import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, call

from clamshield.application import Application
from clamshield.errors import AccessDenied, EngineError
from clamshield.mail_protection import MailProtection
from clamshield.maintenance import Maintenance
from clamshield.settings import Settings
from clamshield.store import Store


class MailProtectionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.settings=Settings(state=Path(temp.name)/'state');self.store=Store(self.settings.database)
        self.context=dict(actor='admin',owner='admin',identity='generation',admin=True)
        self.native=Mock();self.native.authorize.return_value=self.context
        self.protection=MailProtection(self.settings,self.store,self.native)
        self.app=Application(self.settings,self.store,self.native)
        self.signatures=self.enterContext(patch('clamshield.mail_protection.Signatures')).return_value
        self.rules=self.enterContext(patch('clamshield.mail_protection.RuleManager')).return_value
        self.integration=self.enterContext(patch('clamshield.mail_protection.MailIntegration')).return_value
        self.policies=self.enterContext(patch('clamshield.mail_protection.MailPolicies')).return_value
        self.connected=self.enterContext(patch('clamshield.mail_protection.transport_active',return_value=True))
        self.enterContext(patch('clamshield.mail_protection.configuration',return_value={'yara_enabled':True}))
        self.integration.enable.return_value={'enabled':True}
        self.integration.status.return_value={'phase':'active','transition':None}
        self.policies.server_defaults.return_value={'enabled':True}

    def test_enable_prepares_missing_data_then_verifies_before_enabling_defaults(self):
        self.signatures.manifest.return_value=None;phases=[]
        self.policies.enable_server_defaults.side_effect=lambda context:self.connected.assert_called_once_with()
        result=self.protection.enable(self.context,progress=phases.append)
        self.assertTrue(result['enabled']);self.signatures.update.assert_called_once_with('all')
        self.rules.install.assert_called_once_with('core');self.integration.enable.assert_called_once_with()
        self.policies.enable_server_defaults.assert_called_once_with(self.context)
        self.assertEqual(['signatures','rules','preparing','verifying','policies'],phases)

    def test_enable_keeps_existing_data_and_choices(self):
        self.settings.rules.parent.mkdir(parents=True,exist_ok=True);self.settings.rules.write_bytes(b'fixture')
        self.signatures.manifest.return_value={'generation':'existing'}
        self.protection.enable(self.context)
        self.signatures.update.assert_not_called();self.rules.install.assert_not_called()

    def test_no_success_or_default_policy_write_when_connection_fails(self):
        self.connected.return_value=False
        with self.assertRaises(EngineError):self.protection.enable(self.context)
        self.policies.enable_server_defaults.assert_not_called()
        self.integration.enable.side_effect=EngineError('Verification failed')
        with self.assertRaises(EngineError):self.protection.enable(self.context)
        self.policies.enable_server_defaults.assert_not_called()

    def test_status_requires_verified_connection_active_lifecycle_and_defaults(self):
        self.assertTrue(self.protection.status()['enabled'])
        for change in ('connection','defaults','transition','phase'):
            with self.subTest(change=change):
                self.connected.return_value=change!='connection'
                self.policies.server_defaults.return_value={'enabled':change!='defaults'}
                self.integration.status.return_value={'phase':'disabled' if change=='phase' else 'active','transition':'preparing' if change=='transition' else None}
                self.assertFalse(self.protection.status()['enabled'])

    def test_disable_delegates_safe_drain_and_retains_policies(self):
        self.integration.disable.return_value={'disabled':True}
        self.assertEqual({'disabled':True},self.protection.disable())
        self.integration.disable.assert_called_once_with();self.policies.enable_server_defaults.assert_not_called()

    def test_api_queues_one_deduplicated_task_under_actor_generation(self):
        request=dict(actor='admin',owner='tenant',action='mail-protection-enable',policy={'enabled':False})
        first=self.app.dispatch(request);second=self.app.dispatch(request)
        self.assertEqual(first,second);task=self.store.claim_task('worker')
        self.assertEqual('admin',task['owner']);self.assertEqual({},task['payload'])
        self.assertIn(call('admin','admin'),self.native.authorize.call_args_list)
        self.integration.enable.assert_not_called()

    def test_api_rejects_tenant_even_if_browser_claims_admin(self):
        self.native.authorize.return_value=self.context|{'admin':False}
        for action in ('mail-protection-enable','mail-protection-disable','mail-protection-status'):
            with self.subTest(action=action),self.assertRaises(AccessDenied):
                self.app.dispatch(dict(actor='admin',action=action,admin=True))

    def test_progress_and_failures_are_generation_scoped(self):
        self.store.enqueue_task(self.context,'mail-protection-enable',{})
        task=self.store.claim_task('worker');self.store.task_progress(task,'verifying')
        self.assertEqual('verifying',self.store.mail_protection_status(self.context)['latest']['phase'])
        self.store.task_progress(task|{'worker':'foreign'},'policies')
        self.assertEqual('verifying',self.store.mail_protection_status(self.context)['latest']['phase'])
        self.assertEqual({'pending':False,'latest':None},self.store.mail_protection_status(self.context|{'identity':'replacement'}))
        self.store.finish_task(task,error='Could not verify')
        status=self.app.dispatch(dict(actor='admin',action='mail-protection-status'))
        self.assertFalse(status['pending']);self.assertEqual('failed',status['latest']['status'])

    def worker(self,enable):
        resources=Mock();resources.journal.exists.return_value=False;resources.website_journal.exists.return_value=False
        integration=Mock();integration.journal.exists.return_value=False
        coordinator=Mock();coordinator.enable.side_effect=enable
        with patch('clamshield.resources.Resources',return_value=resources),patch('clamshield.mail_integration.MailIntegration',return_value=integration),patch('clamshield.mail_protection.MailProtection',return_value=coordinator):
            Maintenance(self.settings,self.store,self.native).once()

    def test_worker_marks_complete_only_after_coordinator_verification(self):
        self.store.enqueue_task(self.context,'mail-protection-enable',{})
        def enable(context,progress):
            for phase in ('signatures','preparing','verifying','policies'):
                progress(phase);current=self.store.mail_protection_status(context)
                self.assertTrue(current['pending']);self.assertEqual('running',current['latest']['status'])
                self.assertEqual(phase,current['latest']['phase'])
            return {'enabled':True}
        self.worker(enable)
        self.assertEqual('completed',self.store.mail_protection_status(self.context)['latest']['status'])

    def test_worker_failure_is_reported_and_retryable(self):
        self.store.enqueue_task(self.context,'mail-protection-enable',{})
        self.worker(Mock(side_effect=EngineError('Scanner verification failed')))
        status=self.store.mail_protection_status(self.context)
        self.assertFalse(status['pending']);self.assertEqual('failed',status['latest']['status'])
        self.assertEqual('Scanner verification failed',status['latest']['error'])
        self.assertTrue(self.app.dispatch(dict(actor='admin',action='mail-protection-enable'))['queued'])
