import fcntl
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write_json
from clamshield.errors import Conflict
from clamshield.installation import Installation,UNITS,TIMERS,CONTROLLERS
from clamshield.resources import DEFAULTS,render,revision
from clamshield.settings import Settings


class FixtureInstallation(Installation):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.calls=[]
    def system(self,*args,**kwargs):
        self.calls.append(args)
        output=b'inactive\n'*len(CONTROLLERS) if args[:3]==('show','--property=ActiveState','--value') else b''
        return subprocess.CompletedProcess(args,0,output,b'')
    def detach_mail(self):self.calls.append(('detach-mail',))
    def recover_operations(self):self.calls.append(('recover-operations',))
    def unload_profile(self,path):self.calls.append(('unload-profile',str(path)))


class InstalledLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.settings=Settings(state=self.root/'var/lib/clamshield');self.settings.prepare()
        self.installation=FixtureInstallation(self.settings,root=self.root)
        self.release=self.root/'opt/clamshield.releases/release-test';self.release.mkdir(parents=True)
        (self.release/'.clamshield-owner').write_text('clamshield\n')
        self.contents={}
        for path in self.installation.files():
            path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# Managed by clamshield\n'+path.name+'\n');self.contents[path]=path.read_bytes()
        self.installation.target.symlink_to(self.release)
        self.installation.register(self.release)
        self.custody=self.settings.quarantine/'original';self.custody.write_bytes(b'Preserved quarantine original')
        self.config=self.root/'etc/clamshield/admin.json';self.config.parent.mkdir(parents=True);self.config.write_text('Preserved administrator settings')

    def test_removal_is_repeatable_and_retains_custody_config_code_and_foreign_extensions(self):
        foreign=self.root/'usr/local/hestia/web/js/custom_scripts/other.js';foreign.write_text('Other addon')
        result=self.installation.uninstall()
        self.assertTrue(result['uninstalled']);self.assertFalse(result['packages_removed'])
        self.assertTrue(all(not path.exists() for path in self.contents));self.assertFalse(self.installation.target.is_symlink())
        self.assertEqual(b'Preserved quarantine original',self.custody.read_bytes());self.assertTrue(self.config.exists());self.assertTrue(self.release.exists());self.assertEqual('Other addon',foreign.read_text())
        self.assertIn(('disable','--now',*TIMERS),self.installation.calls)
        self.assertLess(self.installation.calls.index(('detach-mail',)),self.installation.calls.index(('stop',*(name for name in UNITS if name.endswith('.service')))))
        self.assertTrue(self.installation.uninstall()['unchanged'])
        with self.assertRaises(Conflict):self.installation.available()

    def test_foreign_changed_linked_or_writable_integrations_are_refused_before_services_stop(self):
        path=next(iter(self.contents));before=path.read_bytes()
        for kind in ('content','symlink','mode'):
            with self.subTest(kind=kind):
                if kind=='content':path.write_bytes(b'Foreign content')
                elif kind=='symlink':path.unlink();path.symlink_to(self.custody)
                else:path.chmod(0o666)
                with self.assertRaises(Conflict):self.installation.uninstall()
                self.assertEqual([],self.installation.calls);self.assertFalse(self.installation.journal.exists())
                if path.is_symlink():path.unlink()
                path.write_bytes(before);path.chmod(0o644)

    def test_changed_code_pointer_is_rejected_before_any_removal(self):
        self.installation.target.unlink();self.installation.target.symlink_to(self.root/'foreign-target')
        with self.assertRaises(Conflict):self.installation.uninstall()
        self.assertTrue(all(path.exists() for path in self.contents));self.assertEqual([],self.installation.calls)

    def test_process_interruption_during_removal_is_resumable_without_restarting_services(self):
        original=self.installation.remove_file;count=0
        def interrupted(path,expected):
            nonlocal count
            original(path,expected);count+=1
            if count==3:raise KeyboardInterrupt()
        with patch.object(self.installation,'remove_file',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.installation.uninstall()
        self.assertEqual('removing',json.loads(self.installation.journal.read_text())['phase'])
        with self.assertRaises(Conflict):self.installation.available()
        self.installation.calls=[];self.assertTrue(self.installation.uninstall()['uninstalled'])
        self.assertNotIn(('detach-mail',),self.installation.calls);self.assertTrue(self.custody.exists())

    def test_interruption_after_pointer_removal_and_manifest_commit_is_idempotent(self):
        unlink=Path.unlink
        def interrupted(path,*args,**kwargs):
            if path==self.installation.journal:raise KeyboardInterrupt()
            return unlink(path,*args,**kwargs)
        with patch.object(Path,'unlink',new=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.installation.uninstall()
        self.assertFalse(self.installation.target.is_symlink());self.assertEqual('removed',self.installation.inventory()['phase'])
        self.assertTrue(self.installation.uninstall()['uninstalled']);self.assertFalse(self.installation.journal.exists())

    def test_interrupted_removal_preserves_later_foreign_bytes_for_review(self):
        original=self.installation.remove_file;paths=list(self.contents)
        def changed(path,expected):
            if path==paths[1]:path.write_bytes(b'Later foreign content')
            return original(path,expected)
        with patch.object(self.installation,'remove_file',side_effect=changed):
            with self.assertRaises(Conflict):self.installation.uninstall()
        self.assertEqual(b'Later foreign content',paths[1].read_bytes());self.assertTrue(self.installation.journal.exists());self.assertTrue(self.custody.exists())

    def test_unexpected_metadata_paths_cannot_expand_deletion_scope(self):
        manifest=self.installation.inventory();manifest['files'][str(self.custody)]='0'*64;write_json(self.installation.manifest,manifest)
        with self.assertRaises(Conflict):self.installation.uninstall()
        self.assertTrue(self.custody.exists());self.assertEqual([],self.installation.calls)

    def test_incomplete_inventory_or_nonobject_metadata_cannot_enable_runtime_or_remove_files(self):
        manifest=self.installation.inventory()
        for value in (manifest|{'files':{}},manifest|{'release':None},{},[],None):
            with self.subTest(value=value):
                write_json(self.installation.manifest,value)
                with self.assertRaises(Conflict):self.installation.available()
                with self.assertRaises(Conflict):self.installation.uninstall()
                self.assertEqual([],self.installation.calls);self.assertTrue(all(path.exists() for path in self.contents))

    def test_removal_journal_cannot_change_the_recorded_static_inventory(self):
        manifest=self.installation.inventory()
        value=dict(owner='clamshield',schema=1,phase='removing',release=str(self.release),files={})
        write_json(self.installation.journal,value)
        with self.assertRaises(Conflict):self.installation.uninstall()
        self.assertEqual([],self.installation.calls);self.assertTrue(all(path.exists() for path in self.contents))

    def test_owned_resource_profiles_are_removed_but_retained_metadata_and_foreign_dropins_survive(self):
        metadata=dict(owner='clamshield',schema=1,policy=DEFAULTS,revision=revision(DEFAULTS),applied_at=1)
        write_json(self.settings.state/'resources.json',metadata)
        path=self.root/'etc/systemd/system/clamshield-worker.service.d/clamshield-resources.conf';path.parent.mkdir();path.write_text(render(DEFAULTS['website_worker']))
        foreign=path.with_name('other.conf');foreign.write_text('[Service]\nNice=5\n')
        self.installation.uninstall();self.assertFalse(path.exists());self.assertTrue(foreign.exists());self.assertEqual(metadata,json.loads((self.settings.state/'resources.json').read_text()))

    def test_unknown_resource_bytes_are_not_claimed_by_removal(self):
        path=self.root/'etc/systemd/system/clamshield-worker.service.d/clamshield-resources.conf';path.parent.mkdir();path.write_text('Foreign override')
        with self.assertRaises(Conflict):self.installation.uninstall()
        self.assertEqual('Foreign override',path.read_text());self.assertEqual([],self.installation.calls)

    def test_install_pending_blocks_runtime_and_removal_until_successful_resume(self):
        self.installation.begin_install(self.release)
        with self.assertRaises(Conflict):self.installation.available()
        with self.assertRaises(Conflict):self.installation.uninstall()
        self.installation.begin_install(self.release);self.installation.register(self.release);self.installation.finish_install()
        self.installation.available();self.assertTrue(self.custody.exists())

    def test_reinstall_reuses_retained_data_after_complete_removal(self):
        self.installation.uninstall();self.installation.begin_install(self.release)
        for path,content in self.contents.items():path.write_bytes(content)
        self.installation.target.symlink_to(self.release);self.installation.register(self.release);self.installation.finish_install()
        self.installation.available();self.assertEqual(b'Preserved quarantine original',self.custody.read_bytes());self.assertTrue(self.config.exists())

    def test_exclusive_lifecycle_gate_waits_for_an_existing_request(self):
        path=self.settings.state/'installation.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
        try:
            with self.installation.runtime():
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(fd,fcntl.LOCK_UN)
        finally:os.close(fd)

    def controller_process(self,ignore_term=False,release_lock=False):
        fd=os.open(self.settings.state/'installation.lock',os.O_CREAT|os.O_RDWR,0o600);os.close(fd)
        script='''import fcntl,signal,sys,time
lock=open(sys.argv[1],'a+b');fcntl.flock(lock,fcntl.LOCK_SH)
if sys.argv[2]=='ignore':signal.signal(signal.SIGTERM,signal.SIG_IGN)
if sys.argv[2]=='release':signal.signal(signal.SIGTERM,lambda *_:fcntl.flock(lock,fcntl.LOCK_UN))
print('ready',flush=True)
time.sleep(60)
'''
        child=subprocess.Popen([sys.executable,'-c',script,str(self.settings.state/'installation.lock'),
                                'release' if release_lock else 'ignore' if ignore_term else 'normal'],stdout=subprocess.PIPE,text=True)
        def cleanup():
            if child.poll() is None:child.kill()
            child.wait(timeout=5);child.stdout.close()
        self.addCleanup(cleanup)
        self.assertEqual('ready',child.stdout.readline().strip())
        return child

    def test_update_closes_admission_and_stops_real_lock_holder_before_publishing(self):
        child=self.controller_process();system=self.installation.system
        def stop(*args,**kwargs):
            self.assertTrue(self.installation.install_journal.exists())
            with self.assertRaises(Conflict):self.installation.available()
            if args==('stop','--no-block',*CONTROLLERS):child.terminate()
            if args[0]=='show':
                return subprocess.CompletedProcess(args,0,(b'inactive\n' if child.poll() is not None else b'deactivating\n')*len(CONTROLLERS),b'')
            return system(*args,**kwargs)
        started=time.monotonic()
        with patch.object(self.installation,'system',side_effect=stop):
            with self.installation.update(self.release,grace=1,timeout=1):
                child.wait(timeout=1)
                self.assertTrue(self.installation.install_journal.exists())
                self.assertEqual(b'Preserved quarantine original',self.custody.read_bytes())
                self.installation.finish_install()
        self.assertLess(time.monotonic()-started,5)
        self.assertEqual(('stop',*TIMERS),self.installation.calls[0])
        self.assertEqual(('stop','--no-block',*CONTROLLERS),self.installation.calls[1])
        self.installation.available()

    def test_update_escalates_only_recorded_controllers_when_they_ignore_stop(self):
        child=self.controller_process(ignore_term=True,release_lock=True);system=self.installation.system
        def stop(*args,**kwargs):
            if args==('stop','--no-block',*CONTROLLERS):child.terminate()
            if args[0]=='kill':child.kill()
            if args[0]=='show':
                return subprocess.CompletedProcess(args,0,(b'inactive\n' if child.poll() is not None else b'deactivating\n')*len(CONTROLLERS),b'')
            return system(*args,**kwargs)
        with patch.object(self.installation,'system',side_effect=stop):
            with self.installation.update(self.release,grace=.1,timeout=1):pass
        self.assertIn(('kill','--kill-whom=all','--signal=SIGKILL',*CONTROLLERS),self.installation.calls)
        self.assertTrue(self.installation.install_journal.exists())

    def test_update_lock_timeout_retains_gate_and_never_kills_an_arbitrary_request(self):
        with self.installation.runtime():
            with self.assertRaises(TimeoutError):
                with self.installation.update(self.release,grace=0,timeout=0):
                    self.fail('No publication while an active request holds the lock')
        self.assertTrue(self.installation.install_journal.exists())
        self.assertTrue(all('exim4' not in arg and 'hestia' not in arg for call in self.installation.calls for arg in call))

    def test_foreign_controller_is_refused_before_admission_or_services_change(self):
        path=self.root/'etc/systemd/system/clamshield-worker.service';path.write_text('Foreign controller')
        with self.assertRaises(Conflict):
            with self.installation.update(self.release):pass
        self.assertFalse(self.installation.install_journal.exists());self.assertEqual([],self.installation.calls)

    def test_partial_publication_retry_accepts_exact_owned_new_unit_only(self):
        self.installation.begin_install(self.release)
        units=self.release/'systemd';units.mkdir()
        name='clamshield-worker.service';content='# Managed by clamshield\nNew owned version\n'
        (units/name).write_text(content)
        (self.root/'etc/systemd/system'/name).write_text(content)
        with self.installation.update(self.release,grace=0,timeout=0):pass
        self.assertIn(('stop','--no-block',*CONTROLLERS),self.installation.calls)

    def test_fresh_install_opens_gate_without_stopping_foreign_system_services(self):
        self.installation.target.unlink();self.installation.manifest.unlink()
        with self.installation.update(self.release):
            self.assertTrue(self.installation.install_journal.exists())
        self.assertEqual([],self.installation.calls)

    def legacy_bell_inventory(self):
        value=self.installation.read(self.installation.manifest)
        paths=[self.root/'etc/systemd/system'/name for name in ('clamshield-notifications.service','clamshield-notifications.timer')]
        for path in paths:value['files'].pop(str(path));path.unlink()
        write_json(self.installation.manifest,value)
        return paths

    def test_pre_bell_upgrade_admits_only_the_old_inventory_and_registers_new_owned_units(self):
        paths=self.legacy_bell_inventory()
        with self.assertRaises(Conflict):self.installation.inventory()
        with self.installation.update(self.release):
            for path in paths:path.write_bytes(self.contents[path])
            self.installation.register(self.release)
            self.installation.finish_install()
        self.installation.available()
        self.assertTrue(all(str(path) in self.installation.inventory()['files'] for path in paths))
        for call in self.installation.calls:
            self.assertFalse(any(name in call for name in ('clamshield-notifications.service','clamshield-notifications.timer')))

    def test_pre_bell_upgrade_never_stops_a_foreign_file_at_the_new_service_path(self):
        paths=self.legacy_bell_inventory();paths[0].write_text('Foreign service')
        with self.assertRaises(Conflict):
            with self.installation.update(self.release):pass
        self.assertEqual([],self.installation.calls);self.assertFalse(self.installation.install_journal.exists())
        self.assertEqual('Foreign service',paths[0].read_text())

    def test_current_release_cannot_masquerade_as_pre_bell_inventory(self):
        self.legacy_bell_inventory()
        source=self.release/'src/clamshield/notification_preferences.py';source.parent.mkdir(parents=True);source.write_text('Current release')
        with self.assertRaises(Conflict):
            with self.installation.update(self.release):pass
        self.assertEqual([],self.installation.calls)

    def resource_fixture(self,enabled=None,active=False):
        if enabled is not None:write_json(self.settings.state/'website-engine.json',dict(owner='clamshield',schema=1,enabled=enabled,changed_at=1))
        resource=Mock();resource.locked.side_effect=lambda:nullcontext();resource.worker_lock.side_effect=lambda:nullcontext()
        resource.journal=self.settings.state/'resources-activation.json';resource.website_journal=self.settings.state/'website-engine-activation.json'
        resource.inspect.return_value=dict(active=active)
        return resource

    def test_legacy_and_explicit_stop_do_not_start_website_engine(self):
        for enabled in (None,False):
            resource=self.resource_fixture(enabled)
            with patch('clamshield.resources.Resources',return_value=resource):self.installation.restore_website()
            self.assertNotIn(('start','clamshield-clamd.service'),self.installation.calls);resource.website_ready.assert_not_called()
        self.assertIn(('disable','clamshield-clamd.service'),self.installation.calls)

    def test_saved_start_restarts_an_inactive_engine_and_preserves_exact_intent(self):
        resource=self.resource_fixture(True);before=(self.settings.state/'website-engine.json').read_bytes()
        with patch('clamshield.resources.Resources',return_value=resource):result=self.installation.restore_website()
        self.assertEqual(dict(started=True,verified=True),result);self.assertIn(('start','clamshield-clamd.service'),self.installation.calls)
        resource.website_ready.assert_called_once();self.assertEqual(before,(self.settings.state/'website-engine.json').read_bytes())

    def test_healthy_active_start_is_verified_without_service_restart(self):
        resource=self.resource_fixture(True,active=True)
        with patch('clamshield.resources.Resources',return_value=resource):result=self.installation.restore_website()
        self.assertFalse(result['started']);self.assertNotIn(('start','clamshield-clamd.service'),self.installation.calls);resource.website_ready.assert_called_once()

    def test_newly_started_engine_is_stopped_if_readiness_fails_and_install_stays_pending(self):
        resource=self.resource_fixture(True);resource.website_ready.side_effect=Conflict('Wrong scanning data');self.installation.begin_install(self.release)
        with patch('clamshield.resources.Resources',return_value=resource):
            with self.assertRaises(Conflict):self.installation.restore_website()
        self.assertIn(('stop','clamshield-clamd.service'),self.installation.calls);self.assertTrue(self.installation.install_journal.exists())

    def test_pending_scanner_recovery_prevents_starting_unverified_data(self):
        resource=self.resource_fixture(True);(self.settings.state/'signature-activation.json').write_text('{}')
        with patch('clamshield.resources.Resources',return_value=resource):
            with self.assertRaises(Conflict):self.installation.restore_website()
        self.assertEqual([],self.installation.calls);resource.website_ready.assert_not_called()

    def test_fresh_install_without_journals_does_not_need_previous_code_or_scanner_controllers(self):
        self.installation.target.unlink()
        with patch('clamshield.resources.Resources') as resources:
            self.assertEqual({},self.installation.recover_configuration())
        resources.assert_not_called()

    def test_installer_recovers_limits_signatures_spam_then_website_before_publication(self):
        names=('resources-activation.json','signature-activation.json','spamassassin-activation.json','website-engine-activation.json')
        for name in names:write_json(self.settings.state/name,{})
        self.installation.begin_install(self.release);order=[]
        def recover(name):
            order.append(name);(self.settings.state/name).unlink();return dict(recovered=True)
        resources=Mock();resources.recover_limits.side_effect=lambda:recover(names[0]);resources.recover_website.side_effect=lambda:recover(names[3])
        signatures=Mock();signatures.recover.side_effect=lambda:recover(names[1])
        spam=Mock();spam.recover.side_effect=lambda:recover(names[2])
        with patch('clamshield.resources.Resources',return_value=resources),patch('clamshield.signatures.Signatures',return_value=signatures),patch('clamshield.spamassassin.SpamAssassinControls',return_value=spam):
            result=self.installation.recover_configuration()
        self.assertEqual(list(names),order);self.assertEqual(set(names),set(result))
        self.assertTrue(self.installation.install_journal.exists());self.assertTrue(all(path.exists() for path in self.contents))
        from clamshield.store import Store
        with Store(self.settings.database).connection() as db:
            self.assertEqual(4,db.execute("SELECT count(*) FROM audit WHERE action='installation.configuration_recovered' AND owner='@admin'").fetchone()[0])

    def test_configuration_recovery_failure_preserves_original_journal_and_integration(self):
        path=self.settings.state/'resources-activation.json';write_json(path,{'retained':'original intent'})
        before=path.read_bytes();resources=Mock();resources.recover_limits.side_effect=Conflict('Foreign drop-in retained')
        with patch('clamshield.resources.Resources',return_value=resources):
            with self.assertRaises(Conflict):self.installation.recover_configuration()
        self.assertEqual(before,path.read_bytes());self.assertEqual(self.release,self.installation.target.resolve());self.assertTrue(all(path.exists() for path in self.contents))

    def test_false_recovery_success_cannot_clear_installer_gate(self):
        write_json(self.settings.state/'resources-activation.json',{});self.installation.begin_install(self.release)
        resource=Mock();resource.recover_limits.return_value=True
        with patch('clamshield.resources.Resources',return_value=resource):
            with self.assertRaisesRegex(Conflict,'did not finish'):self.installation.recover_configuration()
        self.assertTrue(self.installation.install_journal.exists());self.assertTrue((self.settings.state/'resources-activation.json').exists())

    def test_interrupted_mail_transition_is_recovered_before_code_publication(self):
        path=self.settings.state/'mail-integration-journal.json';write_json(path,{})
        package=self.release/'src/clamshield';package.mkdir(parents=True)
        (package/'__init__.py').write_text('')
        (package/'settings.py').write_text('class Settings:\n def __init__(self,state,hestia):self.state,self.hestia,self.database=state,hestia,state/"state.sqlite3"\n')
        (package/'store.py').write_text('class Store:\n def __init__(self,path):pass\n')
        (package/'hestia.py').write_text('class Hestia:\n def __init__(self,path):pass\n')
        (package/'mail_integration.py').write_text('''class MailIntegration:
 def __init__(self,settings,store,hestia):self.settings=settings
 def recover(self):
  (self.settings.state/'mail-integration-journal.json').unlink()
  return {'recovered':True,'source':__file__}
''')
        result=self.installation.recover_mail_configuration()
        self.assertEqual(str(package/'mail_integration.py'),result['source'])
        self.assertFalse(path.exists());self.assertEqual(self.release,self.installation.target.resolve())
        self.assertEqual([],self.installation.calls)

    def test_mail_recovery_cannot_report_success_while_its_journal_remains(self):
        path=self.settings.state/'mail-integration-journal.json';write_json(path,{})
        with patch('clamshield.installation.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{"recovered":true}',b'')):
            with self.assertRaises(Conflict):self.installation.recover_mail_configuration()
        self.assertTrue(path.exists());self.assertEqual([],self.installation.calls)

    def test_linked_or_writable_recovery_metadata_is_refused_before_controllers(self):
        path=self.settings.state/'resources-activation.json';path.symlink_to(self.custody)
        with patch('clamshield.resources.Resources') as resources:
            with self.assertRaises(Conflict):self.installation.recover_configuration()
            path.unlink();write_json(path,{});path.chmod(0o666)
            with self.assertRaises(Conflict):self.installation.recover_configuration()
        resources.assert_not_called();self.assertEqual(b'Preserved quarantine original',self.custody.read_bytes())


    def test_signature_migration_is_audited_and_notified_once_before_install_gate_clears(self):
        from clamshield.store import Store
        self.installation.begin_install(self.release)
        result=dict(previous='generation-legacy',generation='generation-new',catalog_policy='fixture')
        manager=Mock();manager.migrate_current.return_value=result;manager.manifest.return_value=None
        with patch('clamshield.signatures.Signatures',return_value=manager):
            self.assertEqual(result,self.installation.migrate_signatures());self.installation.migrate_signatures()
        self.assertTrue(self.installation.install_journal.exists())
        with Store(self.settings.database).connection() as db:
            self.assertEqual(1,db.execute("SELECT count(*) FROM audit WHERE owner='@admin' AND action='signatures.catalog_migrated'").fetchone()[0])
            self.assertEqual(1,db.execute("SELECT count(*) FROM notifications WHERE owner='@admin' AND event='signatures.catalog_migrated'").fetchone()[0])

    def test_migration_failure_preserves_pending_install_and_retained_custody(self):
        self.installation.begin_install(self.release);manager=Mock();manager.migrate_current.side_effect=Conflict('Data migration failed')
        with patch('clamshield.signatures.Signatures',return_value=manager):
            with self.assertRaises(Conflict):self.installation.migrate_signatures()
        self.assertTrue(self.installation.install_journal.exists());self.assertEqual(b'Preserved quarantine original',self.custody.read_bytes())

    def test_committed_migration_can_finish_missing_audit_after_installer_retry(self):
        manager=Mock();manager.migrate_current.return_value=None
        manager.manifest.return_value=dict(rebuilt_from='generation-legacy',generation='generation-new',catalog=dict(policy='fixture'))
        with patch('clamshield.signatures.Signatures',return_value=manager):
            result=self.installation.migrate_signatures()
        self.assertEqual('generation-legacy',result['previous']);self.assertEqual('generation-new',result['generation'])
