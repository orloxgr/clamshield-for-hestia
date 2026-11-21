import fcntl
import json
import os
import unittest
from unittest.mock import patch

from clamshield.application import Application
from clamshield.errors import AccessDenied,ClamShieldError
from clamshield.remediation import Remediation
from clamshield.website_permissions import WebsitePermissions,DEFAULTS,ACTIONS
from clamshield.worker import Worker
import test_cleanup as fixtures


class WebsiteDelegation(unittest.TestCase):
    def setUp(self):
        fixtures.TargetedCleaning.setUp(self)
        self.permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        self.app=Application(self.settings,self.store,self.hestia)
        self.automatic=Remediation(self.settings,self.store,self.hestia)
        self.admin=self.context|dict(actor='operator_fixture',admin=True)

    def save(self,**changes):
        values=dict(DEFAULTS)|changes
        with patch.object(self.hestia,'authorize',return_value=self.admin):self.permissions.save(self.admin,values)
        return values

    def request(self,action,**values):
        return self.app.dispatch(dict(actor='alice',action=action,**values))

    def scan(self):
        job_id=self.request('scan',scope='site',domain=self.site['domain'],path=self.path)['jobs'][0]
        Worker(self.settings,self.store,self.hestia,self.engines).once();return job_id

    def action(self,job_id):return next(row for row in self.automatic.history(self.context) if row['job_id']==job_id)

    def test_default_all_actions_available_and_native_admin_bypasses_restrictions(self):
        self.assertEqual(DEFAULTS,self.permissions.get(self.context)['effective'])
        self.save(**dict.fromkeys(DEFAULTS,False))
        with patch.object(self.hestia,'authorize',return_value=self.admin):
            self.assertEqual(DEFAULTS,self.permissions.get(self.admin)['effective'])
            self.assertFalse(any(self.permissions.get(self.admin)['permissions'].values()))
            self.permissions.require(self.admin,'quarantine')

    def test_only_fresh_native_admin_can_save_and_unknown_or_nonboolean_fields_fail(self):
        with self.assertRaises(AccessDenied):self.permissions.save(self.context|{'admin':True},dict(DEFAULTS))
        for values in ({},dict(DEFAULTS)|{'unknown':True},dict(DEFAULTS)|{'scan':1}):
            with self.assertRaises(ClamShieldError):self.permissions.save(self.admin,values)
        self.assertEqual(DEFAULTS,self.permissions.get(self.context)['permissions'])

    def test_account_generation_replacement_does_not_inherit_permissions(self):
        self.save(quarantine=False)
        with patch.object(self.hestia,'authorize',return_value=self.context|{'identity':'recreated'}):
            with self.assertRaises(AccessDenied):self.permissions.get(self.context)
            self.assertEqual(DEFAULTS,self.permissions.get(self.context|{'identity':'recreated'})['permissions'])

    def test_every_mapped_root_api_action_rejects_revoked_capability(self):
        self.save(**dict.fromkeys(DEFAULTS,False))
        for action,capability in ACTIONS.items():
            if action=='repair-apply':continue
            with self.subTest(action=action):
                with self.assertRaisesRegex(AccessDenied,'disabled by the administrator'):
                    self.request(action,admin=True,owner='alice',policy={'mode':'quarantine'})

    def test_explicit_resume_is_scoped_and_cannot_bypass_schedule_permission(self):
        from clamshield.initial_monitoring import InitialMonitoring
        job=self.store.enqueue(self.context,self.site,source='watch-initial',generation='rules')
        self.store.cancel(self.context,job)
        self.save(schedule=False)
        with self.assertRaisesRegex(AccessDenied,'disabled by the administrator'):
            self.request('initial-monitoring-resume',domain=self.site['domain'])
        self.assertTrue(InitialMonitoring.status(self.store,self.context,self.site))
        self.save(schedule=True)
        result=self.request('initial-monitoring-resume',domain=self.site['domain'])
        self.assertFalse(result['initial_monitoring_paused'])
        self.assertFalse(InitialMonitoring.status(self.store,self.context,self.site))

    def test_apply_checks_actual_frozen_plan_kind_instead_of_browser_capability(self):
        cleanup=self.repairs.queue(self.context,self.finding,cleanup=True)
        self.save(cleanup=False)
        with self.assertRaisesRegex(AccessDenied,'cleaning.*disabled'):
            self.request('repair-apply',plan_id=cleanup,capability='repair',cleanup=False)
        self.save(repair=False)
        Worker(self.settings,self.store,self.hestia,self.engines).once()
        (self.root/'backup.php').write_bytes(self.after)
        backup=self.repairs.queue(self.context,self.finding,backup_path='backup.php')
        with self.assertRaisesRegex(AccessDenied,'replacements.*disabled'):
            self.request('repair-apply',plan_id=backup,capability='cleanup')

    def test_manual_job_revalidates_delegation_after_queueing(self):
        job_id=self.request('scan',scope='site',domain=self.site['domain'])['jobs'][0]
        self.save(scan=False);Worker(self.settings,self.store,self.hestia,self.engines).once()
        job=self.store.job(self.context,job_id)
        self.assertEqual('failed',job['status']);self.assertIn('disabled',job['error']);self.assertEqual(self.before,self.file.read_bytes())

    def test_admin_queued_scan_is_not_revoked_with_tenant_delegation(self):
        with patch.object(self.hestia,'authorize',return_value=self.admin):
            job_id=self.app.dispatch(dict(actor='operator_fixture',owner='alice',action='scan',scope='site',domain=self.site['domain']))['jobs'][0]
        self.save(scan=False)
        with patch.object(self.hestia,'authorize',side_effect=lambda actor,*args:self.admin if actor=='operator_fixture' else self.context):
            Worker(self.settings,self.store,self.hestia,self.engines).once()
        self.assertEqual('completed',self.store.job(self.context,job_id)['status'])

    def test_revoked_manual_preview_is_failed_in_both_job_and_plan(self):
        plan=self.request('cleanup-preview',finding_id=self.finding)['plan_id']
        self.save(cleanup=False);Worker(self.settings,self.store,self.hestia,self.engines).once()
        self.assertEqual('failed',self.store.job(self.context,plan)['status'])
        self.assertEqual('failed',self.repairs.get(self.context,plan)['status'])

    def test_mode_requires_each_delegated_mutation_permission(self):
        self.save(quarantine=False)
        for mode in ('quarantine','cleanup-or-quarantine'):
            with self.assertRaises(AccessDenied):self.automatic.save(self.context,dict(mode=mode))
        self.automatic.save(self.context,dict(mode='cleanup'))
        self.save(cleanup=False)
        with self.assertRaises(AccessDenied):self.automatic.save(self.context,dict(mode='cleanup'))
        self.automatic.save(self.context,dict(mode='report'))

    def test_inherit_cannot_bypass_revoked_mode_permission(self):
        self.automatic.save(self.context,dict(mode='quarantine'))
        self.save(quarantine=False)
        with self.assertRaises(AccessDenied):self.automatic.save(self.context,dict(mode='inherit'),self.site['domain'])

    def test_revocation_stops_pending_user_automation_and_regrant_needs_new_scan(self):
        self.automatic.save(self.context,dict(mode='quarantine'));job_id=self.scan()
        self.save(quarantine=False);policy=self.automatic.policy(self.context,self.site['domain'])['effective']
        self.assertEqual('report',policy['mode']);self.assertIn('disabled',policy['blocked_reason'])
        self.automatic.once();self.assertEqual('needs_review',self.action(job_id)['status']);self.assertTrue(self.file.exists())
        self.save();self.automatic.once();self.assertEqual('needs_review',self.action(job_id)['status']);self.assertTrue(self.file.exists())
        new=self.scan();self.automatic.once();self.assertEqual('quarantined',self.action(new)['status'])

    def test_administrator_automatic_policy_survives_revoked_tenant_capabilities(self):
        self.save(**dict.fromkeys(DEFAULTS,False))
        with patch.object(self.hestia,'authorize',return_value=self.admin):
            self.automatic.save(self.admin,dict(mode='quarantine'),self.site['domain'])
        from clamshield.generations import current
        job_id=self.store.enqueue(self.context,self.site,self.path,source='watch',generation=current(self.settings))
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.automatic.once()
        self.assertEqual('quarantined',self.action(job_id)['status']);self.assertFalse(self.file.exists())

    def test_user_cannot_change_administrator_policy_after_manage_permission_revoked(self):
        with patch.object(self.hestia,'authorize',return_value=self.admin):self.automatic.save(self.admin,dict(mode='quarantine'))
        self.save(automatic=False)
        with self.assertRaises(AccessDenied):self.automatic.save(self.context,dict(mode='report'))
        self.assertEqual('quarantine',self.automatic.policy(self.context,self.site['domain'])['effective']['mode'])

    def test_cancel_remains_available_after_permission_revocation(self):
        self.automatic.save(self.context,dict(mode='quarantine'));job_id=self.scan();row=self.action(job_id)
        self.save(**dict.fromkeys(DEFAULTS,False));self.request('remediation-cancel',operation_id=row['id'])
        self.assertEqual('cancelled',self.action(job_id)['status'])
        queued=self.store.enqueue(self.context,self.site)
        self.request('cancel',job_id=queued);self.assertTrue(self.store.cancelled(queued))

    def test_completed_capture_recovery_finishes_even_if_user_permission_revoked(self):
        self.automatic.save(self.context,dict(mode='quarantine'));job_id=self.scan()
        update=self.automatic.update
        def interrupted(row,status,error=None):
            if status=='quarantined':raise KeyboardInterrupt()
            return update(row,status,error)
        with patch.object(self.automatic,'update',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.automatic.once()
        self.save(**dict.fromkeys(DEFAULTS,False));self.automatic.once()
        self.assertEqual('quarantined',self.action(job_id)['status']);self.assertFalse(self.file.exists())

    def test_permissions_writer_is_excluded_until_mutation_guard_releases(self):
        fd=os.open(self.settings.state/'website-permissions.lock',os.O_CREAT|os.O_RDWR,0o600)
        try:
            with self.permissions.guard(self.context,'scan',{}):
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(fd,fcntl.LOCK_UN)
        finally:os.close(fd)
