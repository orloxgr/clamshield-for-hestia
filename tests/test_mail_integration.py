import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.application import Application
from clamshield.atomic import write,write_json
from clamshield.errors import AccessDenied,Conflict,EngineError
from clamshield.mail_adapter import MailAdapter,sha
from clamshield.mail_integration import MailIntegration,UNITS
from clamshield.mail_runtime import state,mode
from clamshield.settings import Settings
from clamshield.store import Store


class Controller(MailIntegration):
    def __init__(self,*args):
        super().__init__(*args)
        self.units={u:{'active':False,'enabled':False} for u in UNITS}
        self.restarts=0;self.bad_ready=False;self.bad_drain=False;self.bad_restart=0
        self.release='fixture-release-1';self.version='fixture';self.selected=None

    def code_identity(self):return self.release

    def unit_states(self):return {key:dict(value) for key,value in self.units.items()}

    def system(self,*args,**kwargs):
        if args[0] in ('start','stop','enable','disable') and args[1] in self.units:
            self.units[args[1]]['active' if args[0] in ('start','stop') else 'enabled']=args[0] in ('start','enable')
        return subprocess.CompletedProcess(args,0,b'',b'')

    def restart_native(self):
        self.restarts+=1
        if self.bad_restart:
            self.bad_restart-=1;raise EngineError('Native restart failed')

    def stop_native(self):pass

    def preflight(self):
        base=self.settings.mail_adapters/'adapter-fixture';base.mkdir(parents=True,exist_ok=True)
        write(base/'local_scan.so','verified new adapter',0o644)
        self.selected=dict(generation=base.name,library_sha256=sha(base/'local_scan.so'),
                    source_sha256=hashlib.sha256(MailAdapter(self.settings).source.read_bytes()).hexdigest(),native={'version':self.version})
        return self.selected

    def verified_refresh_candidate(self,target):
        if target['adapter']!=self.selected or target['code_generation']!=self.release:raise Conflict('Changed candidate')
        return self.selected

    def ready(self):
        if self.bad_ready:raise EngineError('Scanner readiness failed')

    def wait_connected(self):pass

    def guard(self):
        import clamshield.mail_integration as module
        from clamshield.mail_runtime import fingerprint
        return dict(guarded=True,runtime={str(p):fingerprint(p) for p in (module.LIBRARY,module.MACRO,Path('/usr/sbin/exim4'))})

    def drain(self,**kwargs):
        if self.bad_drain:raise Conflict('Live handoff could not drain')


class IntegrationTests(unittest.TestCase):
    def test_native_restart_targets_exim_and_checks_resulting_service_health(self):
        controller=MailIntegration(Settings(),None,None)
        success=subprocess.CompletedProcess([],0,b'',b'')
        with patch('clamshield.mail_integration.subprocess.run',side_effect=[success,success]) as run:
            controller.restart_native()
        self.assertEqual(['/usr/local/hestia/bin/v-restart-service','exim4','yes'],run.call_args_list[0].args[0])
        self.assertEqual(['/usr/bin/systemctl','is-active','--quiet','exim4'],run.call_args_list[1].args[0])
        for replies in ([subprocess.CompletedProcess([],1,b'',b'')],[success,subprocess.CompletedProcess([],1,b'',b'')]):
            with patch('clamshield.mail_integration.subprocess.run',side_effect=replies):
                with self.assertRaises(EngineError):controller.restart_native()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.library=root/'owned-mail/local_scan.so';self.library.parent.mkdir()
        write(self.library.parent/'.clamshield-owner','clamshield\n',0o644);write(self.library,'old adapter',0o644)
        self.macro=root/'native/localmacros';self.macro.parent.mkdir()
        self.guard=root/'systemd/exim4.service.d/clamshield-mail.conf'
        self.guard.parent.mkdir(parents=True)
        self.settings=Settings(state=root/'state');self.settings.prepare()
        self.store=Store(self.settings.database)
        # This controller fixture already simulates native version/restarts.
        # Bind its runtime identity to a private fixture inode as well, instead
        # of requiring or fingerprinting the host's actual Exim installation.
        executable=root/'native/exim4';write(executable,'fixture native executable',0o755)
        from clamshield.mail_runtime import fingerprint as real_fingerprint
        def fixture_fingerprint(path):
            return real_fingerprint(executable if Path(path)==Path('/usr/sbin/exim4') else path)
        patches=[patch('clamshield.mail_integration.LIBRARY',self.library),patch('clamshield.mail_integration.MACRO',self.macro),
                 patch('clamshield.mail_integration.fingerprint',side_effect=fixture_fingerprint),
                 patch('clamshield.mail_runtime.fingerprint',side_effect=fixture_fingerprint),
                 patch('clamshield.mail_integration.GUARD',self.guard),
                 patch('clamshield.mail_integration.MACRO_TEXT','# Managed by clamshield\nlocal_scan_path = '+str(self.library)+'\n')]
        for value in patches:value.start();self.addCleanup(value.stop)
        self.controller=Controller(self.settings,self.store,Mock())
        source=root/'source.c';write(source,MailAdapter(self.settings).source.read_bytes(),0o644)
        for value in (patch('clamshield.mail_integration.native',side_effect=lambda:dict(version=self.controller.version)),
                      patch('clamshield.mail_integration.MailAdapter',return_value=Mock(source=source))):
            value.start();self.addCleanup(value.stop)

    def test_enable_disable_are_repeatable_and_disable_retains_owned_adapter(self):
        result=self.controller.enable();self.assertTrue(result['enabled'])
        self.assertEqual('active',state(self.settings)['phase'])
        self.assertTrue(self.controller.enable()['unchanged'])
        self.assertTrue(all(v['active'] and v['enabled'] for v in self.controller.units.values()))
        self.assertFalse(self.controller.disable()['enabled'])
        self.assertEqual('disabled',state(self.settings)['phase'])
        self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())
        self.assertEqual(b'verified new adapter',self.library.read_bytes())
        self.assertTrue(all(not v['active'] and not v['enabled'] for v in self.controller.units.values()))
        self.assertTrue(self.controller.disable()['unchanged'])

    def test_readiness_failure_restores_prior_files_and_units_without_native_restart(self):
        self.controller.bad_ready=True
        with self.assertRaises(EngineError):self.controller.enable()
        self.assertEqual(b'old adapter',self.library.read_bytes())
        self.assertIsNone(state(self.settings));self.assertFalse(self.controller.journal.exists())
        self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())
        self.assertEqual(0,self.controller.restarts)
        self.assertTrue(all(not v['active'] and not v['enabled'] for v in self.controller.units.values()))

    def test_failed_native_restart_removes_new_hook_and_preserves_old_adapter(self):
        self.controller.bad_restart=1
        with self.assertRaises(EngineError):self.controller.enable()
        self.assertEqual(2,self.controller.restarts)
        self.assertIsNone(state(self.settings));self.assertEqual(b'old adapter',self.library.read_bytes())
        self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())

    def test_failed_drain_keeps_active_services_without_restarting_native(self):
        self.controller.enable();before=self.controller.restarts
        self.controller.bad_drain=True
        with self.assertRaises(Conflict):self.controller.disable()
        self.assertEqual(before,self.controller.restarts)
        self.assertEqual('active',state(self.settings)['phase'])
        self.assertTrue(all(v['active'] and v['enabled'] for v in self.controller.units.values()))
        self.assertFalse(self.controller.journal.exists())

    def test_foreign_native_prefix_is_never_replaced_or_adopted(self):
        write(self.macro,'foreign administrator macros',0o644)
        with self.assertRaises(Conflict):self.controller.enable()
        self.assertEqual('foreign administrator macros',self.macro.read_text())
        self.assertFalse(self.controller.journal.exists());self.assertEqual(0,self.controller.restarts)

    def test_crash_after_later_write_intent_can_restore_prior_intermediate_bytes(self):
        import clamshield.mail_integration as module
        real=module.write;calls=0
        def interrupt(path,*args,**kwargs):
            nonlocal calls
            if path==self.controller.state:
                calls+=1
                if calls==2:raise KeyboardInterrupt('Simulated stopped worker after durable intent')
            return real(path,*args,**kwargs)
        with patch('clamshield.mail_integration.write',side_effect=interrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.enable()
        self.assertTrue(self.controller.journal.exists())
        self.assertTrue(self.controller.recover()['recovered'])
        self.assertIsNone(state(self.settings));self.assertFalse(self.controller.journal.exists())
        self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())
        self.assertEqual(b'old adapter',self.library.read_bytes())

    def test_changed_owned_file_blocks_rollback_instead_of_clobbering_it(self):
        transaction=self.controller.begin('enable')
        self.controller.put(transaction,self.macro,'owned intended bytes')
        write(self.macro,'concurrent changed configuration',0o644)
        with self.assertRaises(Conflict):self.controller.recover()
        self.assertEqual('concurrent changed configuration',self.macro.read_text())
        self.assertTrue(self.controller.journal.exists())

    def test_committed_enable_finishes_after_interruption_instead_of_rolling_back(self):
        with patch.object(self.controller,'finish_active',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.enable()
        self.assertTrue(self.controller.transaction()['committed'])
        self.assertEqual('starting',mode(self.settings))
        self.assertEqual({'recovered':True,'completed':'enable'},self.controller.recover())
        self.assertEqual('active',state(self.settings)['phase'])
        self.assertTrue(self.macro.exists());self.assertTrue(self.guard.exists())
        self.assertTrue(all(v['active'] and v['enabled'] for v in self.controller.units.values()))
        self.assertFalse(self.controller.journal.exists())

    def test_committed_disable_finishes_before_or_after_hook_detach(self):
        for boundary in ('before','after'):
            with self.subTest(boundary=boundary):
                self.controller.enable()
                real=self.controller.put
                def interrupt(transaction,path,content,*args):
                    result=real(transaction,path,content,*args)
                    if path==self.macro and content is None:raise KeyboardInterrupt
                    return result
                target='finish_disabled' if boundary=='before' else 'put'
                with patch.object(self.controller,target,side_effect=KeyboardInterrupt if boundary=='before' else interrupt),self.assertRaises(KeyboardInterrupt):
                    self.controller.disable()
                self.assertTrue(self.controller.transaction()['committed'])
                self.assertEqual('starting',mode(self.settings))
                self.assertEqual(self.macro.exists(),boundary=='before')
                self.assertEqual({'recovered':True,'completed':'disable'},self.controller.recover())
                self.assertEqual('disabled',state(self.settings)['phase'])
                self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())
                self.assertTrue(all(not v['active'] and not v['enabled'] for v in self.controller.units.values()))

    def test_uncommitted_interrupted_drain_restores_active_without_native_restart(self):
        self.controller.enable();before=self.controller.restarts
        with patch.object(self.controller,'drain',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.disable()
        self.assertEqual('draining',mode(self.settings))
        self.assertEqual({'recovered':True,'rolled_back':'disable'},self.controller.recover())
        self.assertEqual('active',state(self.settings)['phase'])
        self.assertEqual(before,self.controller.restarts)
        self.assertTrue(all(v['active'] and v['enabled'] for v in self.controller.units.values()))

    def test_committed_enable_readiness_failure_keeps_recoverable_intent(self):
        with patch.object(self.controller,'finish_active',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.enable()
        self.controller.bad_ready=True
        with self.assertRaises(EngineError):self.controller.recover()
        self.assertTrue(self.controller.transaction()['committed']);self.assertTrue(self.macro.exists())
        self.controller.bad_ready=False
        self.assertEqual('enable',self.controller.recover()['completed'])

    def test_recovery_rejects_wrong_committed_target(self):
        transaction=self.controller.begin('enable')
        transaction.update(committed=True,target=dict(owner='clamshield',schema=1,phase='disabled'))
        write_json(self.controller.journal,transaction)
        with self.assertRaises(EngineError):self.controller.recover()

    def test_recovery_rejects_foreign_unit_names_and_bad_snapshot_hashes(self):
        transaction=self.controller.begin('enable')
        transaction['units']['ssh.service']={'active':True,'enabled':True};write_json(self.controller.journal,transaction)
        with self.assertRaises(EngineError):self.controller.recover()
        transaction['units'].pop('ssh.service');transaction['files'][str(self.library)]['sha256']='0'*64
        write_json(self.controller.journal,transaction)
        with self.assertRaises(EngineError):self.controller.recover()

    def test_runtime_marked_missing_or_changed_state_is_not_treated_as_legacy(self):
        self.assertEqual('legacy',mode(self.settings))
        write_json(self.controller.owner,{'owner':'clamshield','schema':1})
        with self.assertRaises(EngineError):mode(self.settings)
        write_json(self.controller.state,{'owner':'clamshield','schema':1,'phase':'active','runtime':{}})
        with self.assertRaises(EngineError):mode(self.settings)
        write_json(self.controller.state,{'owner':'clamshield','schema':1,'phase':'disabled','runtime':{}})
        self.assertEqual('disabled',mode(self.settings))

    def test_journal_gate_defers_normal_work_and_stops_new_sends_after_detach(self):
        self.assertEqual('legacy',mode(self.settings))
        write_json(self.controller.journal,{'action':'enable','phase':'prepared'})
        self.assertEqual('starting',mode(self.settings))
        write_json(self.controller.journal,{'action':'disable','phase':'draining'})
        self.assertEqual('draining',mode(self.settings))
        write_json(self.controller.journal,{'action':'disable','phase':'detaching'})
        self.assertEqual('starting',mode(self.settings))

    def test_tenant_cannot_query_or_control_server_integration(self):
        class Hestia:
            def authorize(self,*_args):return dict(admin=False,actor='tenant',owner='tenant')
        app=Application(self.settings,self.store,Hestia())
        for action in ('mail-integration-status','mail-integration-enable','mail-integration-disable','mail-integration-refresh','mail-integration-recover'):
            with self.subTest(action=action),self.assertRaises(AccessDenied):
                app.dispatch(dict(actor='tenant',action=action,admin=True))

    def test_new_code_generation_and_native_package_are_automatically_refreshed(self):
        self.controller.enable();before=self.controller.restarts
        self.assertFalse(self.controller.reconcile()['refreshed'])
        self.controller.release='fixture-release-2';self.controller.version='updated'
        self.assertTrue(self.controller.reconcile()['refreshed'])
        self.assertEqual(before+1,self.controller.restarts)
        current=state(self.settings)
        self.assertEqual('fixture-release-2',current['code_generation'])
        self.assertEqual('updated',current['adapter']['native']['version'])
        self.assertEqual('active',current['phase']);self.assertFalse(self.controller.journal.exists())

    def test_uncommitted_refresh_drains_without_submitting_pending_work_and_recovers_prior_state(self):
        self.controller.enable();before=self.controller.restarts
        with patch.object(self.controller,'drain',side_effect=KeyboardInterrupt) as drain,self.assertRaises(KeyboardInterrupt):
            self.controller.refresh()
        drain.assert_called_once_with(inflight_only=True)
        self.assertEqual('starting',mode(self.settings))
        self.assertEqual('refresh',self.controller.recover()['rolled_back'])
        self.assertEqual(before,self.controller.restarts);self.assertEqual('active',state(self.settings)['phase'])

    def test_committed_refresh_failure_remains_gated_and_recoverable(self):
        self.controller.enable();self.controller.release='fixture-release-2'
        self.controller.bad_ready=True
        with self.assertRaises(EngineError):self.controller.refresh()
        self.assertTrue(self.controller.transaction()['committed'])
        self.assertEqual('refresh',self.controller.transaction()['action']);self.assertEqual('starting',mode(self.settings))
        self.controller.bad_ready=False
        self.assertEqual('refresh',self.controller.recover()['completed'])
        self.assertEqual('fixture-release-2',state(self.settings)['code_generation'])

    def test_explicit_disable_supersedes_failed_refresh_without_discarding_history(self):
        self.controller.enable();self.controller.bad_ready=True
        with self.assertRaises(EngineError):self.controller.refresh()
        self.assertFalse(self.controller.disable()['enabled'])
        self.assertEqual('disabled',state(self.settings)['phase']);self.assertFalse(self.controller.journal.exists())
        self.assertFalse(self.macro.exists());self.assertFalse(self.guard.exists())

    def test_foreign_library_or_guard_never_gets_blessed_by_refresh(self):
        self.controller.enable();before=self.controller.restarts
        write(self.guard,'# Managed by clamshield\nforeign edited hook',0o644)
        with self.assertRaises(Conflict):self.controller.refresh()
        self.assertEqual(before,self.controller.restarts);self.assertFalse(self.controller.journal.exists())
        self.assertTrue(self.controller.reconcile()['review_required'])
        self.assertTrue(self.controller.reconcile()['retry_pending'])

    def test_same_byte_file_replacement_requires_runtime_reverification(self):
        self.controller.enable()
        write(self.library,self.library.read_bytes(),0o644)
        self.assertIn('runtime-identity',self.controller.refresh_reasons(state(self.settings)))
        self.assertTrue(self.controller.reconcile()['refreshed'])
        self.assertFalse(self.controller.reconcile()['refreshed'])

    def test_idle_installed_maintenance_refreshes_changed_code(self):
        from clamshield.maintenance import Maintenance
        self.controller.enable();self.controller.release='fixture-release-2'
        with patch('clamshield.mail_integration.MailIntegration',return_value=self.controller):
            result=Maintenance(self.settings,self.store,Mock()).once()
        self.assertFalse(result['worked']);self.assertTrue(result['mail_refresh']['refreshed'])

    def test_queued_authorized_disable_can_escape_failed_refresh_recovery(self):
        from clamshield.maintenance import Maintenance
        self.controller.enable();self.controller.bad_ready=True
        with self.assertRaises(EngineError):self.controller.refresh()
        context=dict(actor='admin',owner='admin',identity='native-admin-generation',admin=True)
        native_hestia=Mock();native_hestia.authorize.return_value=context
        task=self.store.enqueue_task(context,'mail-integration-disable',{})
        with patch('clamshield.mail_integration.MailIntegration',return_value=self.controller):
            result=Maintenance(self.settings,self.store,native_hestia).once()
        self.assertEqual(task,result['task_id']);native_hestia.authorize.assert_called_once_with('admin','admin')
        with self.store.connection() as db:row=dict(db.execute('SELECT * FROM maintenance WHERE id=?',(task,)).fetchone())
        self.assertEqual('completed',row['status']);self.assertEqual('disabled',state(self.settings)['phase'])

    def pending_refresh(self):
        self.controller.enable()
        with patch.object(self.controller,'finish_refresh',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.refresh()
        self.assertTrue(self.controller.transaction()['committed'])

    def test_pending_refresh_rebases_to_newer_code_and_native_package_before_activation(self):
        self.pending_refresh();self.controller.release='fixture-release-2';self.controller.version='updated'
        self.assertEqual('refresh',self.controller.recover()['completed'])
        current=state(self.settings)
        self.assertEqual('fixture-release-2',current['code_generation'])
        self.assertEqual('updated',current['adapter']['native']['version']);self.assertEqual(1,current['last_refresh_rebases'])
        self.assertEqual('active',current['phase']);self.assertFalse(self.controller.journal.exists())

    def test_interrupted_rebase_commit_preserves_history_and_can_follow_another_update(self):
        self.pending_refresh();self.controller.release='fixture-release-2';self.controller.version='updated'
        commit=self.controller.commit
        def interrupt(transaction,target):
            result=commit(transaction,target)
            if transaction.get('rebases'):raise KeyboardInterrupt
            return result
        with patch.object(self.controller,'commit',side_effect=interrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.recover()
        saved=self.controller.transaction()
        self.assertEqual(1,len(saved['rebases']));self.assertEqual('fixture-release-2',saved['target']['code_generation'])
        self.assertEqual('fixture-release-1',saved['rebases'][0]['code_generation']);self.assertEqual('starting',mode(self.settings))
        self.controller.release='fixture-release-3';self.controller.version='updated-again'
        self.controller.recover();current=state(self.settings)
        self.assertEqual('fixture-release-3',current['code_generation']);self.assertEqual(2,current['last_refresh_rebases'])

    def test_failed_new_target_preparation_preserves_existing_durable_intent(self):
        self.pending_refresh();before=self.controller.journal.read_bytes();restarts=self.controller.restarts
        self.controller.release='fixture-release-2'
        with patch.object(self.controller,'preflight',side_effect=EngineError('Unavailable exact SDK')),self.assertRaises(EngineError):
            self.controller.recover()
        self.assertEqual(before,self.controller.journal.read_bytes());self.assertEqual(restarts,self.controller.restarts)
        self.assertEqual('starting',mode(self.settings))

    def test_rebase_never_adopts_runtime_bytes_outside_original_or_recorded_intents(self):
        self.pending_refresh();self.controller.release='fixture-release-2'
        write(self.library,'foreign concurrent library bytes',0o644)
        with patch.object(self.controller,'preflight') as preflight,self.assertRaises(Conflict):
            self.controller.recover()
        preflight.assert_not_called();self.assertEqual(b'foreign concurrent library bytes',self.library.read_bytes())
        self.assertTrue(self.controller.journal.exists())

    def test_recovery_rejects_unbounded_or_malformed_superseded_target_history(self):
        self.pending_refresh();transaction=self.controller.transaction();transaction['rebases']=[{}]*17
        write_json(self.controller.journal,transaction)
        with self.assertRaises(EngineError):self.controller.recover()
        transaction['rebases']=[dict(adapter='../outside',code_generation='untrusted',native={},source_sha256='0'*64,superseded_at=1)]
        write_json(self.controller.journal,transaction)
        with self.assertRaises(EngineError):self.controller.recover()

    def test_rebase_audit_is_durable_and_not_duplicated_after_interrupted_finalization(self):
        self.pending_refresh();self.controller.release='fixture-release-2';self.controller.version='updated'
        record=self.controller.record_rebases
        def interrupt(*args):
            record(*args);raise KeyboardInterrupt
        with patch.object(self.controller,'record_rebases',side_effect=interrupt),self.assertRaises(KeyboardInterrupt):
            self.controller.recover()
        with self.store.connection() as db:
            self.assertEqual(1,db.execute("SELECT count(*) FROM audit WHERE action='mail.refresh_rebased'").fetchone()[0])
        self.controller.recover()
        with self.store.connection() as db:
            self.assertEqual(1,db.execute("SELECT count(*) FROM audit WHERE action='mail.refresh_rebased'").fetchone()[0])
        self.assertFalse(self.controller.journal.exists());self.assertEqual('active',state(self.settings)['phase'])
