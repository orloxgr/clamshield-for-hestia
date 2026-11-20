"""Global scope follows native accounts and never trusts browser role/scope."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.hestia import Hestia
from clamshield.mail_inventory import resolve
from clamshield.mail_policy import MailPolicies, PERMISSIONS
from clamshield.remediation import Remediation
from clamshield.scheduler import Scheduler
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.website_permissions import WebsitePermissions, DEFAULTS as WEBSITE_PERMISSIONS


class GlobalAdministration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.settings=Settings(state=self.base/'state');self.settings.prepare()
        self.store=Store(self.settings.database);self.ids={name:name+'-generation' for name in ('admin','alice','bob')}
        self.hestia=Hestia();self.hestia.identity=lambda owner:self.ids[owner]
        self.hestia.call=Mock(side_effect=self.call)
        for owner in self.ids:(self.base/owner).mkdir()
        self.admin=self.hestia.authorize('admin');self.alice=self.hestia.authorize('alice')
        self.app=Application(self.settings,self.store,self.hestia);self.mail=MailPolicies(self.store,self.hestia)

    def call(self,command,*args):
        if command=='v-list-user':return {args[0]:dict(ROLE='admin' if args[0]=='admin' else 'user',SUSPENDED='no')}
        if command=='v-list-users':return {owner:dict(ROLE='admin' if owner=='admin' else 'user',SUSPENDED='no') for owner in self.ids}
        if command=='v-list-web-domains':return {} if args[0]=='admin' else {args[0]+'.test':dict(DOCUMENT_ROOT=str(self.base/args[0]))}
        if command=='v-list-mail-domains':return {} if args[0]=='admin' else {args[0]+'.test':{}}
        if command=='v-list-mail-accounts':return {'inbox':{}}
        raise AssertionError(command)

    def request(self,action,actor='admin',**values):return self.app.dispatch(dict(actor=actor,action=action,**values))

    def server_mail(self,defaults=None,permissions=None):
        current=self.request('mail-server-get')
        value=dict(defaults=defaults or {},permissions=dict(PERMISSIONS) if permissions is None else permissions)
        return self.request('mail-server-save',policy=value,revision=current['revision'])

    def dashboard(self,**values):
        # Infrastructure status is independent of account aggregation.
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.app,'engine_status',return_value={}))
            for target in ('resources.Resources','spamassassin.SpamAssassinControls','mail_adapter.MailAdapter','mail_integration.MailIntegration'):
                stack.enter_context(patch('clamshield.'+target+'.status',return_value={}))
            return self.request('dashboard',**values)

    def test_global_dashboard_collects_live_generations_and_deduplicates_server_events(self):
        for owner in ('alice','bob'):
            context=self.hestia.authorize(owner);site=self.hestia.sites(owner)[0]
            job_id=self.store.enqueue(context,site);job=self.store.claim('fixture')
            self.store.add_finding(job,'inert.php',{'sha256':'a'*64},dict(engine='yara',signature='Inert.Fixture',provider='local'))
            self.store.finish(job,'completed',{})
        self.store.notify('@admin','','health.problem','fixture',{})
        global_view=self.dashboard(scope='auto')
        self.assertEqual('server',global_view['context']['view_scope'])
        self.assertEqual({'alice','bob'},{row['owner'] for row in global_view['sites']})
        self.assertEqual(2,global_view['summary']['open_findings'])
        self.assertTrue(all(row['site_availability']['available'] for row in global_view['findings']))
        self.assertEqual(1,len(global_view['notifications']))
        selected=self.dashboard(owner='alice',scope='account')
        self.assertEqual(['alice'],[row['owner'] for row in selected['sites']])
        self.ids['alice']='recreated'
        recreated=self.dashboard(scope='server')
        self.assertEqual(1,recreated['summary']['open_findings'])
        self.assertEqual(['bob'],[row['owner'] for row in recreated['findings']])

    def test_global_totals_do_not_use_preview_lengths(self):
        context=self.hestia.authorize('alice');site=self.hestia.sites('alice')[0]
        for _ in range(205):self.store.enqueue(context,site)
        view=self.dashboard(scope='server')
        self.assertEqual(205,view['summary']['active_scans']);self.assertEqual(200,len(view['jobs']))

    def test_tenant_cannot_enter_global_scope_or_control_any_server_service(self):
        requests=[('dashboard',dict(scope='server')),('mail-server-get',{}),('mail-server-save',{}),
            ('mail-server-activity',{}),('mail-account-save',{}),('mail-account-reset',{}),
            ('mail-protection-enable',{}),('mail-protection-disable',{}),('mail-integration-enable',{}),
            ('mail-integration-disable',{}),('mail-integration-refresh',{}),('mail-adapter-build',{}),
            ('spamassassin-save',{}),('website-engine-start',{}),('website-engine-stop',{}),
            ('resources-save',{}),('rules-install',{}),('providers-save',{}),
            ('policy-defaults-save',dict(scope='server',policy={})),
            ('website-permissions-save',dict(scope='server',policy=WEBSITE_PERMISSIONS)),
            ('remediation-policy-save',dict(scope='server',policy=dict(mode='report'))),
            ('wordpress-recovery-list',dict(scope='server'))]
        for action,fields in requests:
            with self.subTest(action=action),self.assertRaises(AccessDenied):self.request(action,actor='alice',admin=True,**fields)
        self.assertEqual('account',self.dashboard(actor='alice',scope='auto')['context']['view_scope'])

    def test_mail_defaults_and_permissions_inherit_to_all_accounts_and_new_domains(self):
        self.assertFalse(any(self.mail.permissions(self.alice).values()))
        with self.assertRaises(AccessDenied):self.mail.save(self.alice,'alice.test','',dict(spam_threshold=7))
        self.server_mail(dict(spam_threshold=7,spam_action='quarantine'),dict(PERMISSIONS,manage_policy=True))
        for owner in ('alice','bob'):
            context=self.hestia.authorize(owner)
            self.assertEqual(7,self.mail.get(context,owner+'.test')['effective']['spam_threshold'])
            self.assertTrue(self.mail.permissions(context)['manage_policy'])
        self.ids['future']='future-generation';(self.base/'future').mkdir()
        self.assertEqual(7,self.mail.get(self.hestia.authorize('future'),'future.test')['effective']['spam_threshold'])
        self.mail.save(self.alice,'alice.test','',dict(spam_threshold=9))
        self.server_mail(dict(spam_threshold=8),dict(PERMISSIONS,manage_policy=True))
        self.assertEqual(9,self.mail.get(self.alice,'alice.test')['effective']['spam_threshold'])
        self.assertEqual(8,self.mail.get(self.hestia.authorize('bob'),'bob.test')['effective']['spam_threshold'])
        for enabled in (True,False):
            with self.assertRaises(AccessDenied):self.mail.save(self.alice,'alice.test','',dict(enabled=enabled))
        self.mail.save(self.alice,'alice.test','',None,reset=True)
        self.assertEqual(8,self.mail.get(self.alice,'alice.test')['effective']['spam_threshold'])

    def test_account_mail_defaults_reset_and_recreated_accounts_follow_global(self):
        self.server_mail(dict(spam_threshold=6),dict(PERMISSIONS,manage_policy=True))
        current=self.request('mail-account-get',owner='alice')
        self.request('mail-account-save',owner='alice',revision=current['revision'],policy=dict(defaults=dict(spam_threshold=9),permissions=dict(PERMISSIONS)))
        self.assertEqual(9,self.mail.get(self.alice,'alice.test','inbox')['effective']['spam_threshold'])
        self.assertFalse(self.mail.permissions(self.alice)['manage_policy'])
        current=self.request('mail-account-get',owner='alice')
        self.request('mail-account-reset',owner='alice',revision=current['revision'])
        self.assertEqual(6,self.mail.get(self.alice,'alice.test')['effective']['spam_threshold'])
        self.assertTrue(self.mail.permissions(self.alice)['manage_policy'])
        self.mail.save_permissions(self.hestia.authorize('admin','alice'),dict(PERMISSIONS))
        self.ids['alice']='recreated'
        self.assertTrue(self.mail.permissions(self.hestia.authorize('alice'))['manage_policy'])

    def test_server_policy_cas_rejects_stale_edits_and_invalid_inherited_thresholds(self):
        stale=self.request('mail-server-get')
        self.server_mail(dict(spam_threshold=7))
        with self.assertRaises(Conflict):self.request('mail-server-save',revision=stale['revision'],policy=dict(defaults={},permissions=PERMISSIONS))
        admin_alice=self.hestia.authorize('admin','alice')
        self.mail.save(admin_alice,'alice.test','inbox',dict(spam_high_threshold=8))
        with self.assertRaises(ClamShieldError):self.server_mail(dict(spam_threshold=9))
        self.assertEqual(7,self.mail.get(self.alice,'alice.test')['effective']['spam_threshold'])
        for key in ('enabled','exceptions'):
            with self.assertRaises(ClamShieldError):self.server_mail({key:True if key=='enabled' else []})

    def test_global_mail_activity_includes_other_accounts_when_admin_has_no_domains(self):
        for owner in ('alice','bob'):
            context=self.hestia.authorize(owner);recipient='inbox@'+owner+'.test'
            target=resolve(self.mail.targets(context),recipient)
            self.mail.record(context,target,SimpleNamespace(message_id='fixture-'+owner,sender='remote@sender.test',recipients=(recipient,)),'a'*64,dict(action='deliver',classification='clean'))
        view=self.request('mail-server-activity')
        self.assertEqual(dict(domains=2,decisions=2,quarantine=0),view['totals'])
        self.assertEqual({'alice','bob'},{row['owner'] for row in view['decisions']})
        self.ids['alice']='replacement'
        self.assertEqual(1,self.request('mail-server-activity')['totals']['decisions'])

    def test_global_schedule_is_inherited_without_freezing_new_sites(self):
        scheduler=Scheduler(self.settings,self.store,self.hestia)
        self.request('policy-defaults-save',scope='server',policy=dict(frequency='daily',time='02:00',watch=True))
        site=self.hestia.sites('alice')[0]
        self.assertTrue(scheduler.policy(self.alice,site)['watch'])
        scheduler.site(self.alice,site,'fixture',datetime.now(timezone.utc))
        self.request('policy-defaults-save',scope='server',policy=dict(frequency='weekly',watch=False))
        self.assertEqual('weekly',scheduler.policy(self.alice,site)['frequency'])
        self.request('policy-defaults-save',owner='alice',policy=dict(frequency='monthly'))
        self.assertEqual('monthly',scheduler.policy(self.alice,site)['frequency'])
        self.request('policy-save',owner='alice',domain='alice.test',policy=dict(frequency='never'))
        self.request('policy-reset',owner='alice',domain='alice.test')
        self.assertEqual('monthly',scheduler.policy(self.alice,site)['frequency'])
        self.request('policy-defaults-reset',owner='alice')
        self.assertEqual('weekly',scheduler.policy(self.alice,site)['frequency'])

    def test_global_website_permissions_and_automatic_actions_keep_admin_authority(self):
        self.request('website-permissions-save',scope='server',policy=dict.fromkeys(WEBSITE_PERMISSIONS,False))
        permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        self.assertFalse(permissions.get(self.alice)['effective']['scan'])
        self.request('website-permissions-save',owner='alice',policy=WEBSITE_PERMISSIONS)
        self.assertTrue(permissions.get(self.alice)['effective']['scan'])
        self.request('website-permissions-reset',owner='alice')
        self.assertFalse(permissions.get(self.alice)['effective']['scan'])
        self.request('remediation-policy-save',scope='server',policy=dict(mode='quarantine'))
        automatic=Remediation(self.settings,self.store,self.hestia)
        value,_=automatic.effective(self.alice,'alice.test')
        self.assertEqual('quarantine',value['mode']);self.assertEqual('administrator',value['authority'])
        self.request('remediation-policy-save',owner='alice',scope='account',policy=dict(mode='report'))
        self.assertEqual('report',automatic.effective(self.alice,'alice.test')[0]['mode'])
        self.request('remediation-policy-save',owner='alice',scope='account',policy=dict(mode='inherit'))
        self.assertEqual('quarantine',automatic.effective(self.alice,'alice.test')[0]['mode'])


if __name__=='__main__':unittest.main()
