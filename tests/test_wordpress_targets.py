"""Account/server integrity queueing uses the same native scope as manual scans."""
import unittest
from unittest.mock import Mock

import test_review as fixtures
from clamshield.errors import AccessDenied,ClamShieldError


class WordPressTargets(unittest.TestCase):
    setUp=fixtures.ReviewTests.setUp

    def test_account_checks_skip_suspended_sites_and_reuse_pending_jobs(self):
        site=dict(owner='alice',identity=self.ids['alice'],domain='alice.test',root=str(self.base/'alice'),suspended=False)
        self.hestia.sites=Mock(return_value=[site,site|dict(domain='suspended.test',suspended=True)])
        request=dict(actor='alice',action='wordpress-scan',scope='account')
        first=self.app.dispatch(request);second=self.app.dispatch(request)
        self.assertEqual(first['jobs'],second['jobs']);self.assertEqual(1,len(first['jobs']))
        self.assertEqual(('alice','alice.test','queued'),tuple(first['checks'][0][key] for key in ('owner','domain','status')))
        job=self.store.job(self.alice,first['jobs'][0]);self.assertEqual(('wordpress-integrity',''),(job['source'],job['target']))
        self.assertNotIn('root',first['checks'][0]);self.assertNotIn('identity',first['checks'][0])

    def test_server_checks_use_native_accounts_and_skip_suspended_accounts_and_sites(self):
        inventory=self.hestia.inventory()
        for account in inventory:
            if account['owner']=='bob':account['suspended']=True
            if account['owner']=='alice':account['sites'].append(account['sites'][0]|dict(domain='suspended.test',suspended=True))
        self.hestia.inventory=Mock(return_value=inventory)
        value=self.app.dispatch(dict(actor='admin',owner='admin',action='wordpress-scan',scope='server'))
        self.assertEqual({'admin','alice'},{check['owner'] for check in value['checks']});self.assertEqual(2,len(value['jobs']))
        with self.store.connection() as db:
            self.assertEqual({'admin'},{row[0] for row in db.execute('SELECT actor FROM jobs')})
            self.assertEqual(2,db.execute("SELECT count(*) FROM jobs WHERE source='wordpress-integrity' AND target=''").fetchone()[0])

    def test_tenants_cannot_forge_global_or_foreign_scope_or_apply_one_path_to_all_sites(self):
        for values in (dict(scope='server',admin=True),dict(owner='bob',scope='account'),dict(scope='unknown'),dict(scope='account',path='blog')):
            with self.subTest(values=values),self.assertRaises(AccessDenied):
                self.app.dispatch(dict(actor='alice',action='wordpress-scan')|values)
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM jobs').fetchone()[0])

    def test_denied_scan_permission_and_recreated_account_cannot_queue_checks(self):
        from clamshield.website_permissions import DEFAULTS,WebsitePermissions
        WebsitePermissions(self.settings,self.store,self.hestia).save(self.hestia.authorize('admin','alice'),DEFAULTS|dict(scan=False))
        with self.assertRaises(AccessDenied):self.app.dispatch(dict(actor='alice',action='wordpress-scan',scope='account'))
        old=self.hestia.sites('alice');self.ids['alice']='replacement';self.hestia.sites=Mock(return_value=old)
        with self.assertRaises(AccessDenied):self.app.dispatch(dict(actor='admin',owner='alice',action='wordpress-scan',scope='account'))
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM jobs').fetchone()[0])

    def test_empty_selection_and_missing_site_return_errors_without_queuing(self):
        self.hestia.sites=Mock(return_value=[])
        for values in (dict(scope='account'),dict(scope='site',domain='missing.test')):
            with self.assertRaises(ClamShieldError):self.app.dispatch(dict(actor='alice',action='wordpress-scan')|values)
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM jobs').fetchone()[0])
