from pathlib import Path
import json
import unittest
from unittest.mock import patch

from clamshield.cleanup import RECIPES
from clamshield.errors import AccessDenied,Conflict,EngineError
from clamshield.exceptions import Exceptions
from clamshield.generations import current as generation
from clamshield.quarantine import Quarantine
from clamshield.remediation import Remediation
from clamshield.worker import Worker
import test_cleanup as cleaning_fixtures


class AutomaticActions(unittest.TestCase):
    def setUp(self):
        cleaning_fixtures.TargetedCleaning.setUp(self);self.auto=Remediation(self.settings,self.store,self.hestia)
        self.yara.scan.side_effect=lambda path:[self.hit] if RECIPES[0]['prefix'] in Path(path).read_bytes() or b'UNSUPPORTED_INFECTION' in Path(path).read_bytes() else []

    def scan(self,mode=None,engines=None,source='manual'):
        if mode is not None:self.auto.save(self.context,{'mode':mode})
        job_id=self.store.enqueue(self.context,self.site,self.path,source=source,generation=generation(self.settings))
        Worker(self.settings,self.store,self.hestia,self.engines if engines is None else engines).once()
        return job_id

    def only(self):
        rows=self.auto.history(self.context);self.assertEqual(1,len(rows));return rows[0]

    def test_report_and_old_scan_enabling_do_not_mutate_or_backfill(self):
        self.scan();self.assertEqual([],self.auto.history(self.context))
        self.auto.save(self.context,{'mode':'quarantine'});self.auto.once()
        self.assertEqual([],self.auto.history(self.context));self.assertEqual(self.before,self.file.read_bytes())

    def test_review_only_heuristics_do_not_trigger_automatic_quarantine(self):
        self.hit=dict(self.hit,review_only=True)
        self.scan('quarantine');self.auto.once()
        self.assertEqual([],self.auto.history(self.context));self.assertEqual(self.before,self.file.read_bytes())
        finding=self.store.list_findings(self.context)[0]
        self.assertTrue(finding['detail']['review_only']);self.assertEqual('open',finding['status'])

    def test_independent_strong_finding_can_still_trigger_automatic_policy(self):
        self.yara.scan.side_effect=None;self.yara.scan.return_value=[dict(self.hit,review_only=True),dict(self.hit,signature='IndependentStrong')]
        self.scan('quarantine');self.auto.once()
        self.assertEqual('quarantined',self.only()['status']);self.assertFalse(self.file.exists())

    def legacy_advisory(self):
        return dict(engine='clamav',provider='securiteinfo',signature='Existing.Software.Advisory',severity='review',
                    category='malware',source_id='securiteinfo--securiteinfo-pua-app-and-vulnerabilities.ndb')

    def test_legacy_unflagged_clamav_advisory_is_excluded_from_automatic_discovery(self):
        self.clam.scan.return_value=[self.legacy_advisory()];self.yara.scan.side_effect=None;self.yara.scan.return_value=[]
        self.scan('quarantine');self.auto.once()
        self.assertEqual([],self.auto.history(self.context));self.assertEqual(self.before,self.file.read_bytes())
        self.assertNotIn('review_only',self.store.list_findings(self.context)[0]['detail'])

    def test_pending_legacy_advisory_is_revalidated_before_any_mutation(self):
        self.scan('quarantine');pending=self.only()
        with self.store.connection(True) as db:
            db.execute("UPDATE findings SET engine='clamav',detail=? WHERE id=?",(json.dumps(self.legacy_advisory()),pending['finding_id']))
        self.auto.once();self.assertEqual('needs_review',self.only()['status']);self.assertEqual(self.before,self.file.read_bytes())

    def test_legacy_clamav_advisory_does_not_hide_a_separate_strong_finding(self):
        self.clam.scan.return_value=[self.legacy_advisory()]
        self.scan('quarantine');self.auto.once()
        self.assertEqual('quarantined',self.only()['status']);self.assertFalse(self.file.exists())

    def test_account_default_site_override_and_replaced_root_binding(self):
        self.auto.save(self.context,{'mode':'quarantine'});self.assertEqual('quarantine',self.auto.policy(self.context,self.site['domain'])['effective']['mode'])
        self.auto.save(self.context,{'mode':'report'},self.site['domain']);self.assertEqual('report',self.auto.policy(self.context,self.site['domain'])['effective']['mode'])
        self.auto.save(self.context,{'mode':'inherit'},self.site['domain']);self.assertEqual('quarantine',self.auto.policy(self.context,self.site['domain'])['effective']['mode'])
        self.root.rename(self.base/'old-site');self.root.mkdir()
        self.assertEqual('report',self.auto.policy(self.context,self.site['domain'])['effective']['mode'])
        with self.assertRaises(AccessDenied):self.auto.policy(self.context|{'identity':'new'},self.site['domain'])

    def test_native_automatic_quarantine_restore_preserves_private_original_and_no_loop(self):
        self.scan('quarantine');self.assertEqual('queued',self.only()['status']);self.auto.once();row=self.only()
        self.assertEqual('quarantined',row['status']);self.assertFalse(self.file.exists())
        q=Quarantine(self.settings,self.store,self.hestia);q.restore(self.context,row['detail']['operation_id'])
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual(self.before,(self.settings.quarantine/row['detail']['operation_id']).read_bytes())
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
        self.assertEqual(1,len(self.auto.history(self.context)));self.assertTrue(self.file.exists())
        self.assertEqual('restored',self.only()['operation_status'])

    def test_automatic_cleaning_requires_preview_and_exact_postcheck_and_supports_undo(self):
        self.scan('cleanup');self.auto.once();row=self.only();self.assertEqual('preparing',row['status']);self.assertEqual(self.before,self.file.read_bytes())
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once();self.assertEqual('verifying',self.only()['status']);self.assertEqual(self.after,self.file.read_bytes())
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once();row=self.only();self.assertEqual('cleaned',row['status'])
        self.repairs.undo(self.context,row['detail']['plan_id']);Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
        self.assertEqual(self.before,self.file.read_bytes());self.assertEqual(1,len(self.auto.history(self.context)))
        self.assertEqual('undone',self.only()['plan_status'])

    def test_unknown_cleaning_only_falls_back_when_explicit_combined_mode_selected(self):
        self.file.write_bytes(b'<?php /* UNSUPPORTED_INFECTION */')
        self.scan('cleanup-or-quarantine');self.auto.once();Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
        row=self.only();self.assertEqual('quarantined',row['status']);self.assertEqual('unsupported-cleanup',row['detail']['fallback']);self.assertFalse(self.file.exists())

    def test_unknown_strict_cleaning_and_engine_preview_failure_leave_file_for_review(self):
        self.file.write_bytes(b'<?php /* UNSUPPORTED_INFECTION */');before=self.file.read_bytes()
        self.scan('cleanup');self.auto.once();Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
        self.assertEqual('needs_review',self.only()['status']);self.assertEqual(before,self.file.read_bytes())

    def test_policy_revocation_exception_and_explicit_cancel_stop_pending_mutations(self):
        self.scan('quarantine');row=self.only();self.auto.save(self.context,{'mode':'report'});self.auto.once()
        self.assertEqual('needs_review',self.only()['status']);self.assertEqual(self.before,self.file.read_bytes())
        self.scan('quarantine');rows=self.auto.history(self.context);current=next(r for r in rows if r['status']=='queued')
        Exceptions(self.store).add(self.context,current['finding_id'],'file');self.auto.once()
        self.assertEqual('needs_review',self.auto.get(self.context,current['id'])['status']);self.assertEqual(self.before,self.file.read_bytes())
        self.scan('quarantine');self.assertFalse(any(r['status']=='queued' for r in self.auto.history(self.context)))

    def test_cancel_and_cross_generation_history_are_scoped(self):
        self.scan('quarantine');row=self.only();self.auto.cancel(self.context,row['id']);self.auto.once()
        self.assertEqual('cancelled',self.only()['status']);self.assertEqual(self.before,self.file.read_bytes())
        with self.assertRaises(AccessDenied):self.auto.get(self.context|{'identity':'other'},row['id'])
        with self.assertRaises(AccessDenied):self.auto.cancel(self.context|{'owner':'bob','identity':'other'},row['id'])

    def test_partial_and_single_engine_jobs_never_queue_automatic_actions(self):
        self.scan('quarantine',[self.yara]);self.assertEqual([],self.auto.history(self.context))
        self.clam.scan.side_effect=EngineError('Unavailable');self.scan()
        self.assertEqual([],self.auto.history(self.context));self.assertEqual(self.before,self.file.read_bytes())

    def test_restore_recheck_and_rule_trial_sources_never_trigger_actions(self):
        self.scan('quarantine',source='quarantine-restore-recheck');self.auto.once()
        self.assertEqual([],self.auto.history(self.context));self.assertEqual(self.before,self.file.read_bytes())

    def test_changed_bytes_cannot_be_quarantined_automatically(self):
        self.scan('quarantine');self.file.write_bytes(b'Later account edit');self.auto.once()
        self.assertEqual('needs_review',self.only()['status']);self.assertEqual(b'Later account edit',self.file.read_bytes())

    def test_signature_generation_change_revokes_pending_automatic_action(self):
        self.scan('quarantine')
        with patch('clamshield.remediation.generation',return_value='replaced-signature-generation'):self.auto.once()
        self.assertEqual('needs_review',self.only()['status']);self.assertEqual(self.before,self.file.read_bytes())

    def test_combined_mode_does_not_fallback_after_engine_error_or_flagged_candidate(self):
        for reason in ('error','flagged'):
            with self.subTest(reason=reason):
                self.scan('cleanup-or-quarantine');self.auto.once()
                if reason=='error':self.clam.scan.side_effect=EngineError('Scanner unavailable')
                else:self.clam.scan.return_value=[dict(engine='clamav',signature='Other threat',provider='local')]
                Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
                self.assertFalse(any(row['status']=='quarantined' for row in self.auto.history(self.context)))
                self.assertEqual('needs_review',self.auto.history(self.context)[0]['status']);self.assertEqual(self.before,self.file.read_bytes())
                self.clam.scan.side_effect=None;self.clam.scan.return_value=[]

    def test_interruption_after_quarantine_commit_reconciles_without_duplicate_capture(self):
        self.scan('quarantine');original=self.auto.update
        def interrupted(row,status,error=None):
            if status=='quarantined':raise KeyboardInterrupt()
            return original(row,status,error)
        with patch.object(self.auto,'update',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.auto.once()
        self.assertEqual('applying',self.only()['status']);self.auto.once()
        self.assertEqual('quarantined',self.only()['status']);self.assertEqual(1,len(self.repairs.quarantine.list(self.context)))

    def test_discovery_pages_and_replay_keep_one_record_per_file(self):
        self.auto.save(self.context,{'mode':'quarantine'})
        for i in range(55):(self.root/('sample-'+str(i)+'.php')).write_bytes(self.before)
        job_id=self.store.enqueue(self.context,self.site,generation=generation(self.settings))
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.assertEqual(50,len(self.auto.history(self.context)))
        self.auto.discover(job_id);self.auto.discover(job_id)
        self.assertEqual(56,len(self.auto.history(self.context)));self.assertTrue(self.file.exists())

    def test_waiting_previews_do_not_starve_newer_quarantines(self):
        self.auto.save(self.context,{'mode':'cleanup'})
        for i in range(11):(self.root/('sample-'+str(i)+'.php')).write_bytes(self.before)
        job_id=self.store.enqueue(self.context,self.site,generation=generation(self.settings))
        Worker(self.settings,self.store,self.hestia,self.engines).once()
        self.auto.once();self.auto.once()
        self.assertTrue(all(row['status']=='preparing' for row in self.auto.history(self.context)))

    def test_dashboard_policies_use_one_native_authorization_without_relisting_sites(self):
        self.auto.save(self.context,{'mode':'quarantine'})
        sites=[dict(self.site)]
        with patch.object(self.hestia,'sites',side_effect=AssertionError('Repeated inventory')):
            self.auto.site_policies(self.context,sites)
        self.assertEqual('quarantine',sites[0]['remediation']['effective']['mode'])

    def test_policy_cancelled_during_cleaning_preview_never_applies(self):
        self.scan('cleanup');self.auto.once();self.auto.cancel(self.context,self.only()['id'])
        Worker(self.settings,self.store,self.hestia,self.engines).once();self.auto.once()
        self.assertEqual('cancelled',self.only()['status']);self.assertEqual(self.before,self.file.read_bytes())
