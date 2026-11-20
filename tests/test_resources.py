from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.application import Application
from clamshield.atomic import write_json
from clamshield.errors import AccessDenied,ClamShieldError,Conflict,EngineError
from clamshield.resources import DEFAULTS,SERVICES,Resources,quota,render,validate
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker
from clamshield.website_policy import website_policy


class Controls(Resources):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.effective=deepcopy(DEFAULTS);self.active={key:False for key in SERVICES};self.enabled=dict(self.active)
        self.used={key:0 for key in SERVICES};self.operations=[];self.bad_effective=False;self.bad_ready=False

    def inspect(self,key):
        row=self.effective[key]
        values=dict(cpu_percent=row['cpu_percent'],memory_bytes=row['memory_mib']*1024**2,io_weight=row['io_weight'])
        return values|dict(active=self.active[key],enabled=self.enabled[key],pid=123 if self.active[key] else 0,
                           memory_current=self.used[key],cgroup=dict(values) if self.active[key] else None)

    def system(self,*args,**kwargs):
        self.operations.append(args)
        if args[0]=='daemon-reload':
            self.effective=deepcopy(DEFAULTS)
            for key in SERVICES:
                path=self.config_path(key)
                if path.exists():
                    lines=path.read_text().splitlines()
                    self.effective[key]=dict(cpu_percent=int(lines[2].split('=')[1][:-1]),memory_mib=int(lines[3].split('=')[1][:-1]),io_weight=int(lines[4].split('=')[1]))
            if self.bad_effective:self.effective['website_worker']['io_weight']=1
        elif args[0] in ('start','stop','enable','disable'):
            key=next(key for key,row in SERVICES.items() if row[0]==args[1])
            (self.active if args[0] in ('start','stop') else self.enabled)[key]=args[0] in ('start','enable')
        return subprocess.CompletedProcess(args,0,'','')

    def website_ready(self):
        if self.bad_ready:raise EngineError('Wrong active database generation')


class ResourceControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.units=self.root/'units';self.units.mkdir()
        for row in SERVICES.values():(self.units/row[0]).write_text('# Managed by clamshield\n[Service]\n')
        self.settings=Settings(state=self.root/'state');self.settings.prepare();self.store=Store(self.settings.database)
        self.controls=Controls(self.settings,unit_dir=self.units)
        self.policy=deepcopy(DEFAULTS);self.policy['website_worker'].update(cpu_percent=75,memory_mib=768,io_weight=250)

    def test_only_fixed_services_bounded_integers_and_supported_fields_are_accepted(self):
        for field,value in [('cpu_percent',True),('cpu_percent',0),('cpu_percent','100%\nExecStart=evil'),('memory_mib',float('inf')),('memory_mib',127),('io_weight',10001)]:
            policy=deepcopy(DEFAULTS);policy['website_worker'][field]=value
            with self.assertRaises(ClamShieldError):validate(policy)
        with self.assertRaises(ClamShieldError):validate(DEFAULTS|{'exim4':DEFAULTS['mail_broker']})
        with self.assertRaises(ClamShieldError):validate(DEFAULTS|{'website_worker':DEFAULTS['website_worker']|{'raw':'evil'}})

    def test_cpu_quota_systemd_timespans_are_exact_and_invalid_data_is_denied(self):
        for text,percent in [('750ms',75),('1s 500ms',150),('1min 4s',6400),('10ms',1),('infinity',None)]:self.assertEqual(percent,quota(text))
        with self.assertRaises(EngineError):quota('100; reboot')

    def test_apply_is_persistent_live_and_only_owned_paths_are_written(self):
        self.controls.active['website_clamav']=True
        before_pid=self.controls.inspect('website_clamav')['pid'];result=self.controls.apply(self.policy)
        self.assertFalse(result['restarted']);self.assertEqual(self.policy,self.controls.configured()['policy'])
        self.assertEqual(before_pid,self.controls.inspect('website_clamav')['pid'])
        self.assertFalse(any(row[0] in ('start','stop','restart') for row in self.controls.operations))
        for key in SERVICES:self.assertEqual(render(self.policy[key]),self.controls.config_path(key).read_text())
        self.assertFalse(self.controls.journal.exists())

    def test_memory_below_live_use_is_refused_before_any_write(self):
        self.controls.used['website_worker']=800*1024**2
        with self.assertRaises(Conflict):self.controls.apply(self.policy)
        self.assertFalse(self.controls.metadata.exists());self.assertFalse(self.controls.journal.exists())
        self.assertTrue(all(not self.controls.config_path(key).exists() for key in SERVICES))

    def test_effective_mismatch_rolls_back_all_owned_overrides(self):
        self.controls.bad_effective=True
        with self.assertRaises(EngineError):self.controls.apply(self.policy)
        self.assertFalse(self.controls.metadata.exists());self.assertFalse(self.controls.journal.exists())
        self.assertTrue(all(not self.controls.config_path(key).exists() for key in SERVICES))

    def test_uncommitted_interruption_restores_old_policy_and_preserves_other_dropins(self):
        self.controls.prepare();other=self.controls.config_path('website_worker').parent/'other.conf';other.write_text('Other administrator setting')
        with patch.object(self.controls,'verify',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.apply(self.policy)
        self.assertFalse(self.controls.record()['committed']);self.assertTrue(self.controls.recover_limits())
        self.assertEqual(DEFAULTS,self.controls.effective);self.assertFalse(self.controls.metadata.exists())
        self.assertEqual('Other administrator setting',other.read_text())

    def test_committed_interruption_finishes_desired_policy_idempotently(self):
        with patch.object(self.controls,'finish',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.apply(self.policy)
        self.assertTrue(self.controls.record()['committed']);recovered=self.controls.recover_limits()
        self.assertTrue(recovered['committed']);self.assertEqual(self.policy,recovered['policy'])
        self.assertEqual(self.policy,self.controls.configured()['policy']);self.assertFalse(self.controls.recover_limits())

    def test_foreign_change_after_interruption_is_not_overwritten(self):
        with patch.object(self.controls,'verify',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.apply(self.policy)
        path=self.controls.config_path('website_worker');path.write_text('Foreign operator data')
        with self.assertRaises(Conflict):self.controls.recover_limits()
        self.assertEqual('Foreign operator data',path.read_text());self.assertTrue(self.controls.journal.exists())

    def test_malformed_saved_directives_cannot_be_replayed_as_recovery(self):
        with patch.object(self.controls,'verify',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.apply(self.policy)
        value=self.controls.record();value['files']['website_worker']={'text':'[Service]\nExecStart=evil','mode':0o644,'gid':os.getegid()};write_json(self.controls.journal,value)
        with self.assertRaises(EngineError):self.controls.recover_limits()
        self.assertEqual(render(self.policy['website_worker']),self.controls.config_path('website_worker').read_text())

    def test_foreign_or_symlink_dropin_and_unmanaged_main_unit_are_refused(self):
        self.controls.prepare();path=self.controls.config_path('website_worker');path.write_text('Foreign')
        with self.assertRaises(Conflict):self.controls.apply(self.policy)
        path.unlink();path.symlink_to(self.units/SERVICES['website_worker'][0])
        with self.assertRaises(EngineError):self.controls.apply(self.policy)
        path.unlink();(self.units/SERVICES['website_worker'][0]).write_text('Unmanaged unit')
        with self.assertRaises(EngineError):self.controls.apply(self.policy)

    def test_verified_website_start_stop_are_persistent_and_do_not_touch_mail(self):
        self.assertTrue(self.controls.website(True)['verified']);self.assertTrue(self.controls.active['website_clamav']);self.assertTrue(self.controls.enabled['website_clamav'])
        self.assertTrue(website_policy(self.settings)['enabled'])
        self.controls.website(False);self.assertFalse(self.controls.active['website_clamav']);self.assertFalse(self.controls.enabled['website_clamav'])
        self.assertFalse(website_policy(self.settings)['enabled'])
        self.assertTrue(all(row[0] not in ('start','stop','enable','disable') or row[1]==SERVICES['website_clamav'][0] for row in self.controls.operations))

    def test_failed_readiness_restores_prior_service_state(self):
        self.controls.bad_ready=True
        with self.assertRaises(EngineError):self.controls.website(True)
        self.assertFalse(self.controls.active['website_clamav']);self.assertFalse(self.controls.enabled['website_clamav']);self.assertFalse(self.controls.website_journal.exists())

    def test_interrupted_start_rolls_back_and_committed_start_finishes(self):
        with patch.object(self.controls,'website_ready',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.website(True)
        self.controls.recover_website();self.assertFalse(self.controls.active['website_clamav'])
        self.assertIsNone(website_policy(self.settings))
        unlink=Path.unlink
        def stop(path,*args,**kwargs):
            if path==self.controls.website_journal:raise KeyboardInterrupt()
            return unlink(path,*args,**kwargs)
        with patch.object(Path,'unlink',stop):
            with self.assertRaises(KeyboardInterrupt):self.controls.website(True)
        self.assertTrue(self.controls.website_record()['committed']);self.controls.recover_website()
        self.assertTrue(self.controls.active['website_clamav']);self.assertTrue(self.controls.enabled['website_clamav'])
        self.assertTrue(website_policy(self.settings)['enabled'])

    def test_website_recovery_preserves_exact_prior_policy_or_refuses_foreign_change(self):
        self.controls.website(False);before=self.controls.snapshot(self.controls.website_metadata)
        with patch.object(self.controls,'website_ready',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.website(True)
        self.controls.recover_website();self.assertEqual(before,self.controls.snapshot(self.controls.website_metadata))
        with patch.object(self.controls,'website_ready',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.controls.website(True)
        write_json(self.controls.website_metadata,dict(owner='clamshield',schema=1,enabled=True,changed_at=42))
        with self.assertRaises(Conflict):self.controls.recover_website()
        self.assertTrue(self.controls.website_journal.exists());self.assertEqual(42,website_policy(self.settings)['changed_at'])

    def test_policy_validation_rejects_unsafe_types_links_and_permissions(self):
        path=self.controls.website_metadata
        for value in (dict(owner='clamshield',schema=1,enabled=1,changed_at=0),dict(owner='clamshield',schema=True,enabled=False,changed_at=0),dict(owner='clamshield',schema=1,enabled=False,changed_at=float('nan'))):
            write_json(path,value)
            with self.assertRaises(EngineError):website_policy(self.settings)
        write_json(path,dict(owner='clamshield',schema=1,enabled=False,changed_at=0));path.chmod(0o644)
        with self.assertRaises(EngineError):website_policy(self.settings)
        path.unlink();path.symlink_to(self.units/SERVICES['website_clamav'][0])
        with self.assertRaises(EngineError):website_policy(self.settings)

    def test_explicit_stop_supersedes_a_failed_committed_start_recovery(self):
        self.controls.active['website_clamav']=self.controls.enabled['website_clamav']=True;self.controls.bad_ready=True
        write_json(self.controls.website_journal,dict(owner='clamshield',schema=1,committed=True,before=dict(active=False,enabled=False),target=dict(active=True,enabled=True)))
        with self.assertRaises(EngineError):self.controls.recover_website()
        self.controls.website(False);self.assertFalse(self.controls.active['website_clamav']);self.assertFalse(self.controls.website_journal.exists())

    def test_pending_transition_gates_new_website_jobs_and_tenants_cannot_control_server(self):
        context=dict(actor='alice',owner='alice',identity='generation',admin=False)
        hestia=Mock();hestia.authorize.return_value=context;site=dict(owner='alice',identity='generation',domain='site.test',root=str(self.root),suspended=False)
        app=Application(self.settings,self.store,hestia)
        for action in ('resources-status','resources-save','website-engine-status','website-engine-start','website-engine-stop','resources-recover'):
            with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',action=action,policy=self.policy))
        job_id=self.store.enqueue(context,site);write_json(self.controls.journal,{'pending':True})
        self.assertFalse(Worker(self.settings,self.store,hestia,[]).once());self.assertEqual('queued',self.store.job(context,job_id)['status'])

    def test_native_admin_api_queues_validated_global_policy_without_browser_paths(self):
        context=dict(actor='alice',owner='alice',identity='generation',admin=True);hestia=Mock();hestia.authorize.return_value=context
        result=Application(self.settings,self.store,hestia).dispatch(dict(actor='alice',action='resources-save',policy=self.policy,path='/etc/shadow'))
        task=self.store.claim_task('fixture');self.assertEqual(result['task_id'],task['id']);self.assertEqual({'policy':self.policy},task['payload'])
        self.assertTrue(any(row['action']=='resources.queued' for row in self.store.history(context)))
        self.assertFalse(any(row['action']=='resources.queued' for row in self.store.history(context|{'admin':False})))

    def test_dashboard_engine_status_uses_native_admin_scope_and_reads_live_engine(self):
        context=dict(actor='alice',owner='selected',identity='selected-generation',admin=True)
        own=dict(context,owner='alice',identity='admin-generation')
        hestia=Mock();hestia.authorize.side_effect=[context,own,context,own]
        app=Application(self.settings,self.store,hestia)
        foreign=self.store.enqueue_task(context,'website-engine-start',{})
        task_id=self.store.enqueue_task(own,'website-engine-start',{})
        with patch.object(app,'engine_status',return_value={'clamav':{'available':False}}):
            result=app.dispatch(dict(actor='alice',owner='selected',action='website-engine-status'))
        self.assertTrue(result['pending']);self.assertFalse(result['engine']['available'])
        self.assertEqual(task_id,result['latest']['id']);self.assertNotEqual(foreign,result['latest']['id'])
        foreign_task=self.store.claim_task('fixture');self.store.finish_task(foreign_task,{})
        task=self.store.claim_task('fixture');self.store.finish_task(task,{'verified':True})
        with patch.object(app,'engine_status',return_value={'clamav':{'available':True,'version':'ClamAV fixture'}}):
            result=app.dispatch(dict(actor='alice',owner='selected',action='website-engine-status'))
        self.assertFalse(result['pending']);self.assertEqual('completed',result['latest']['status'])
        self.assertEqual('ClamAV fixture',result['engine']['version'])
