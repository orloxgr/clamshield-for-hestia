import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError
from clamshield.maintenance import Maintenance
from clamshield.settings import Settings
from clamshield.store import Store


class RuleInstallation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name)/'state')
        self.store = Store(self.settings.database)
        self.context = dict(actor='operator', owner='operator', identity='native-generation', admin=True)
        self.hestia = Mock(); self.hestia.authorize.return_value = self.context
        self.app = Application(self.settings, self.store, self.hestia)

    def test_install_is_one_scoped_deduplicated_task_with_validated_profile(self):
        request = dict(actor='operator', owner='tenant', action='rules-install', profile='core', generation='untrusted')
        first = self.app.dispatch(request); second = self.app.dispatch(request)
        self.assertEqual(first['task_id'], second['task_id'])
        task = self.store.claim_task('worker')
        self.assertEqual('rules-install', task['action'])
        self.assertEqual({'profile':'core', 'release':None}, task['payload'])
        self.assertEqual('operator', task['owner'])
        self.assertIn(unittest.mock.call('operator','operator'), self.hestia.authorize.call_args_list)
        with self.assertRaises(ClamShieldError):
            self.app.dispatch(request | {'profile':'invalid'})

    def test_install_and_status_require_real_administrator_authority(self):
        self.hestia.authorize.return_value = self.context | {'admin':False}
        for action in ('rules-install','rules-status'):
            with self.subTest(action=action), self.assertRaises(AccessDenied):
                self.app.dispatch(dict(actor='operator', action=action, admin=True, profile='core'))

    def test_progress_and_latest_status_are_account_generation_scoped(self):
        task_id = self.store.enqueue_task(self.context,'rules-install',{'profile':'core'})
        task = self.store.claim_task('worker')
        self.store.task_progress(task,'checking')
        status = self.store.rule_install_status(self.context)
        self.assertTrue(status['pending']); self.assertEqual('checking',status['latest']['phase'])
        self.assertEqual(task_id,status['latest']['id'])
        for other in (self.context | {'identity':'replacement'}, self.context | {'owner':'other'}):
            self.assertEqual({'pending':False,'latest':None},self.store.rule_install_status(other))
        self.store.task_progress(task | {'worker':'foreign-worker'},'activating')
        self.assertEqual('checking',self.store.rule_install_status(self.context)['latest']['phase'])
        self.store.finish_task(task,result={'generation':'generation-one','activated':True})
        self.store.task_progress(task,'downloading')
        status=self.store.rule_install_status(self.context)
        self.assertFalse(status['pending']); self.assertTrue(status['latest']['activated'])

    def worker(self, install):
        resources=Mock(); resources.journal.exists.return_value=False; resources.website_journal.exists.return_value=False
        integration=Mock(); integration.journal.exists.return_value=False
        manager=Mock(); manager.install.side_effect=install
        with patch('clamshield.resources.Resources',return_value=resources), patch('clamshield.mail_integration.MailIntegration',return_value=integration), patch('clamshield.rule_manager.RuleManager',return_value=manager):
            Maintenance(self.settings,self.store,self.hestia).once()

    def test_worker_reports_completion_only_after_install_and_activation_return(self):
        self.store.enqueue_task(self.context,'rules-install',{'profile':'extended','release':None})
        def install(profile,release,progress):
            self.assertEqual('extended',profile)
            for phase in ('downloading','checking','activating'):
                progress(phase)
                current=self.store.rule_install_status(self.context)['latest']
                self.assertEqual('running',current['status']); self.assertFalse(current['activated'])
                self.assertEqual(phase,current['phase'])
            return {'generation':'generation-installed','activated':True}
        self.worker(install)
        self.assertEqual('completed',self.store.rule_install_status(self.context)['latest']['status'])
        self.assertTrue(self.store.rule_install_status(self.context)['latest']['activated'])

    def test_worker_validation_failure_is_retryable_and_never_reports_activation(self):
        self.store.enqueue_task(self.context,'rules-install',{'profile':'core'})
        def install(_profile,_release,progress):
            progress('checking'); raise ClamShieldError('Invalid rule package')
        self.worker(install)
        status=self.store.rule_install_status(self.context)
        self.assertFalse(status['pending']); self.assertEqual('failed',status['latest']['status'])
        self.assertFalse(status['latest']['activated']); self.assertEqual('Invalid rule package',status['latest']['error'])
        self.assertTrue(self.app.dispatch(dict(actor='operator',action='rules-install',profile='core'))['queued'])

    def test_status_finds_pending_work_beyond_bounded_history_and_excludes_old_build_errors(self):
        self.store.enqueue_task(self.context,'rules-build',{'revision':'old'})
        for n in range(105): self.store.enqueue_task(self.context,'other',{'number':n})
        with patch('clamshield.application.Rules') as rules:
            rules.return_value.status.return_value={'configured':False,'config':{'private':'omitted'}}
            status=self.app.dispatch(dict(actor='operator',owner='tenant',action='rules-status'))
        self.assertTrue(status['pending']); self.assertIsNone(status['latest'])
        self.assertEqual({'configured':False},status['active'])
