import json
import time
import unittest
from unittest.mock import Mock

import test_mail_custody as fixtures
from clamshield.application import Application
from clamshield.errors import AccessDenied,ClamShieldError,Conflict
from clamshield.scan_status import ScanStatus


class ScanStatusTests(unittest.TestCase):
    setUp=fixtures.MailCustodyTests.setUp
    request_for=fixtures.MailCustodyTests.request_for

    def scans(self):return ScanStatus(self.store,self.native)
    def queue(self,context=None):
        context=context or self.alice
        return self.store.enqueue(context,dict(owner=context['owner'],identity=context['identity'],domain=context['owner']+'.test',root='/private/fixture-root'))

    def test_account_generation_scoped_snapshot_and_minimal_fields(self):
        own=self.queue();foreign=self.queue(self.bob)
        before=self.scans().list(self.alice)
        self.assertEqual(1,before['total']);self.assertEqual(own,before['jobs'][0]['id'])
        self.assertEqual(dict(recorded=1,queued=1,running=0),before['summary'])
        self.assertTrue(before['jobs'][0]['can_cancel'])
        self.assertFalse(set(before['jobs'][0])&{'root','identity','worker','actor','generation'})
        self.ids['alice']='recreated'
        with self.assertRaises(AccessDenied):self.scans().list(self.alice)
        self.assertEqual(0,self.scans().list(self.native.authorize('alice'))['total'])

    def test_admin_server_view_and_native_scope_derived_cancel(self):
        own=self.queue();foreign=self.queue(self.bob);admin=self.native.authorize('admin','alice')
        result=self.scans().list(admin,'server')
        self.assertEqual(2,result['total']);self.assertEqual({'alice','bob'},{row['owner'] for row in result['jobs']})
        self.assertEqual(1,result['account_active'])
        self.scans().cancel(admin,foreign,'server')
        self.assertEqual('cancelled',self.store.job(self.bob,foreign)['status'])
        with self.store.connection() as db:
            event=db.execute("SELECT actor,owner,identity FROM audit WHERE action='scan.cancel_requested' AND subject=?",(foreign,)).fetchone()
        self.assertEqual(('admin','bob',self.ids['bob']),tuple(event))

    def test_tenant_cannot_select_server_or_cancel_another_account(self):
        foreign=self.queue(self.bob)
        for method in (lambda:self.scans().list(self.alice,'server'),lambda:self.scans().cancel(self.alice,foreign,'server'),lambda:self.scans().cancel(self.alice,foreign)):
            with self.assertRaises(AccessDenied):method()
        app=Application(self.settings,self.store,self.native)
        with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',owner='alice',admin=True,action='scans-status',scope='server'))
        self.assertEqual('queued',self.store.job(self.bob,foreign)['status'])

    def test_server_cancel_of_recreated_owner_retains_old_job(self):
        foreign=self.queue(self.bob);self.ids['bob']='recreated'
        admin=self.native.authorize('admin')
        self.assertEqual(1,self.scans().list(admin,'server')['total'])
        with self.assertRaisesRegex(AccessDenied,'account was replaced'):self.scans().cancel(admin,foreign,'server')
        with self.store.connection() as db:self.assertEqual('queued',db.execute('SELECT status FROM jobs WHERE id=?',(foreign,)).fetchone()[0])

    def test_running_cancel_waits_for_worker_and_never_reports_complete(self):
        job=self.queue()
        with self.store.connection(True) as db:
            db.execute("UPDATE jobs SET status='running',counters=?,heartbeat=? WHERE id=?",(json.dumps(dict(seen=10,scanned=7,errors=1,skipped=2)),time.time(),job))
        self.scans().cancel(self.alice,job)
        result=self.scans().list(self.alice)['jobs'][0]
        self.assertEqual('running',result['status']);self.assertEqual(1,result['cancel_requested']);self.assertFalse(result['can_cancel'])
        self.assertEqual(7,result['counters']['scanned']);self.assertEqual(1,result['counters']['errors'])

    def test_active_first_search_and_bounded_pagination(self):
        active=self.queue()
        for index in range(102):
            job=self.queue()
            with self.store.connection(True) as db:db.execute("UPDATE jobs SET status='completed',finished=? WHERE id=?",(time.time(),job))
        page=self.scans().list(self.alice)
        self.assertEqual(103,page['total']);self.assertEqual(100,len(page['jobs']));self.assertEqual(active,page['jobs'][0]['id'])
        self.assertEqual(3,len(self.scans().list(self.alice,offset=page['next_offset'])['jobs']))
        self.assertEqual(1,self.scans().list(self.alice,kind='active')['total'])
        self.assertEqual(active,self.scans().list(self.alice,search=active)['jobs'][0]['id'])

    def test_invalid_filters_and_terminal_cancel_are_nonmutating(self):
        job=self.queue();self.scans().cancel(self.alice,job)
        with self.assertRaises(Conflict):self.scans().cancel(self.alice,job)
        for values in (dict(scope='foreign'),dict(search='x'*301),dict(offset=True),dict(offset=-1),dict(kind='unknown')):
            with self.assertRaises(ClamShieldError):self.scans().list(self.alice,**values)
        with self.assertRaises(AccessDenied):self.scans().cancel(self.alice,'../../foreign')

    def test_snapshot_does_not_probe_engines_or_build_native_site_inventory(self):
        self.queue();app=Application(self.settings,self.store,self.native)
        app.engine_status=Mock(side_effect=AssertionError('Unexpected engine probe'))
        self.native.sites=Mock(side_effect=AssertionError('Unexpected site inventory'))
        self.native.inventory=Mock(side_effect=AssertionError('Unexpected server inventory'))
        result=app.dispatch(dict(actor='alice',owner='alice',action='scans-status'))
        self.assertEqual(1,result['total']);app.engine_status.assert_not_called();self.native.sites.assert_not_called();self.native.inventory.assert_not_called()
