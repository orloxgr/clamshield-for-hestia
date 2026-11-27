from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write,write_json
from clamshield.errors import AccessDenied,Conflict,EngineError
from clamshield.settings import Settings
from clamshield.signature_memory import SignatureMemory,METHOD,MAX_SECONDS,configurations,selection,summarize,validate_report


def report():
    return dict(schema=1,method=METHOD,selection='a'*64,engine=dict(version='ClamAV fixture',binary_sha256='b'*64,packages='clamav\tfixture\tinstalled'),
        measured=1000,rows=[dict(case=case,repeat=repeat,peak_rss_bytes=(100 if case=='case-0' else 160)*1024**2+repeat*1024,elapsed_seconds=1) for repeat in range(3) for case in ('case-0','case-1')],
        aliases={'baseline':'case-0','all':'case-1','without-securiteinfo':'case-0'},limits=dict(memory_bytes=2*1024**3,cpu_percent=50,runtime_seconds=MAX_SECONDS),machine='x86_64')


class MemoryCalculationTests(unittest.TestCase):
    def test_configuration_union_is_deduplicated_and_provider_costs_are_marginal(self):
        rows=[dict(name='official',provider='official'),dict(name='native',provider='native'),dict(name='si',provider='securiteinfo')]
        cases,aliases=configurations(rows)
        self.assertEqual(2,len(cases));self.assertEqual(aliases['baseline'],aliases['without-securiteinfo'])
        self.assertEqual({'official','native'},set(row['name'] for row in cases[0]['files']))
        rows += [dict(name='sane',provider='sanesecurity'),dict(name='local',provider='local')]
        cases,aliases=configurations(rows);self.assertEqual(5,len(cases));self.assertEqual(5,len(aliases))
        current=report();validate_report(current);value=summarize(current['rows'],current['aliases'])
        self.assertEqual(60*1024**2,value['providers'][0]['delta_bytes']);self.assertEqual(100*1024**2+1024,value['baseline']['median_bytes'])

    def test_complete_three_sample_sets_are_required_and_unbounded_or_forged_values_rejected(self):
        for change in (lambda v:v['rows'].pop(),lambda v:v['rows'].append(v['rows'][0]),
                       lambda v:v['rows'][0].update(peak_rss_bytes=True),lambda v:v['rows'][0].update(peak_rss_bytes=0),
                       lambda v:v['rows'][0].update(elapsed_seconds=float('nan')),lambda v:v.update(schema=True),
                       lambda v:v['engine'].update(binary_sha256=[]),lambda v:v['aliases'].update(all='../../private'),
                       lambda v:v['limits'].update(memory_bytes=2**60),lambda v:v.update(method='disk-size-estimate')):
            value=report();change(value)
            with self.subTest(value=value),self.assertRaises(EngineError):validate_report(value)

    def test_selection_ignores_generation_and_purpose_split_but_not_loaded_data_or_attribution(self):
        manifest=dict(files=[dict(name='test.hdb',provider='local',sha256='a'*64,size=10)],generation='old')
        token=selection(manifest);self.assertEqual(token,selection(manifest|dict(generation='new',profiles={'mail':[],'website':['test.hdb']})))
        changed=deepcopy(manifest);changed['files'][0]['sha256']='b'*64;self.assertNotEqual(token,selection(changed))
        changed=deepcopy(manifest);changed['files'][0]['provider']='native';self.assertNotEqual(token,selection(changed))

    def test_negative_or_overlapping_observed_differences_are_not_fabricated_as_additive_savings(self):
        current=report()
        for row in current['rows']:
            if row['case']=='case-1':row['peak_rss_bytes']=95*1024**2
        value=summarize(current['rows'],current['aliases']);self.assertLess(value['providers'][0]['delta_bytes'],0)
        self.assertLess(value['providers'][0]['minimum_delta_bytes'],value['providers'][0]['maximum_delta_bytes'])

    def test_unknown_observation_handle_is_not_misclassified_as_stopped(self):
        record={'unit':'fixture.service','token':'a'*32}
        with patch('clamshield.signature_memory.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','D-Bus unavailable')):
            with self.assertRaisesRegex(EngineError,'inspect'):SignatureMemory.unit_live(record)
        with patch('clamshield.signature_memory.subprocess.run',return_value=subprocess.CompletedProcess([],1,'LoadState=not-found\n','')):
            self.assertFalse(SignatureMemory.unit_live(record))


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root-owned measurement metadata and staging')
class SignatureMemoryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='cs-memory-',dir='/root');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare();self.memory=SignatureMemory(self.settings)
        self.snapshots=self.root/'snapshots';self.snapshots.mkdir()
        replacement=patch('clamshield.native_integration.SNAPSHOTS',self.snapshots);replacement.start();self.addCleanup(replacement.stop)
        self.identity=report()['engine'];self.memory.engine=Mock(return_value=self.identity)
        self.stage=self.root/'signatures/generation-test';self.stage.mkdir(parents=True);(self.stage.parent/'current').symlink_to(self.stage)
        self.files=[]
        for name,provider in (('official.hdb','official'),('si.hdb','securiteinfo')):
            data=('Inert '+name).encode();(self.stage/name).write_bytes(data)
            self.files.append(dict(name=name,provider=provider,sha256=hashlib.sha256(data).hexdigest(),size=len(data)))
        (self.stage/'clamshield-generation.hdb').write_text('Fixture')
        self.manifest=dict(files=self.files,engine_mode='native-shared',canary=dict(payload='Canary',signature='Fixture'))
        self.manager=Mock(base=self.stage.parent);self.manager.manifest.side_effect=lambda:self.manifest;self.manager.locked.side_effect=nullcontext
        self.native=Mock(snapshots=self.snapshots);self.patches=[patch('clamshield.native_integration.enabled',return_value=True),patch('clamshield.signatures.Signatures',return_value=self.manager),patch('clamshield.native_integration.NativeIntegration',return_value=self.native)]
        for value in self.patches:value.start();self.addCleanup(value.stop)
        self.memory.allowed=Mock();self.memory.unit_live=Mock(return_value=False)

    def workspace(self):
        token='c'*32;folder=self.snapshots/('memory-'+token);folder.mkdir();write(folder/'.owner',token+'\n')
        info=folder.stat();record=dict(owner='clamshield',schema=1,token=token,unit='clamshield-signature-memory-'+token+'.service',directory=str(folder),device=info.st_dev,inode=info.st_ino)
        write_json(self.memory.work,record);return folder,record

    def save(self):
        value=report();value['selection']=selection(self.manifest);write_json(self.memory.path,value);return value

    def runner(self,command,stdout,stderr,timeout):
        self.assertIn('User=clamav',command);self.assertIn('BindsTo=clamshield-maintenance.service',command)
        self.assertNotIn('After=clamshield-maintenance.service',command) # oneshot would deadlock waiting for itself.
        self.assertIn('MemorySwapMax=0',command);self.assertIn('PrivateNetwork=yes',command)
        self.assertIn('RuntimeMaxSec=180',command);self.assertLessEqual(timeout,200)
        plan=json.loads(Path(command[-1]).read_text());self.assertEqual(2,len(plan['cases']))
        self.assertEqual(0o750,stat.S_IMODE(Path(command[-1]).parent.stat().st_mode))
        for case in plan['cases']:
            self.assertEqual(0o750,stat.S_IMODE(Path(case['directory']).stat().st_mode))
            for path in Path(case['directory']).iterdir():self.assertEqual(0,path.stat().st_mode&0o022)
        stdout.write(json.dumps({'complete':True,'rows':report()['rows']}).encode()+b'\n')
        return subprocess.CompletedProcess(command,0)

    def test_completed_bounded_measurement_publishes_only_complete_results_and_cleans_workspace(self):
        phases=[]
        with patch('clamshield.signature_memory.subprocess.run',side_effect=self.runner):value=self.memory.measure(phases.append)
        self.assertEqual(6,value['samples']);self.assertEqual(['preparing','measuring'],phases)
        self.assertFalse(self.memory.work.exists());self.assertEqual([],list(self.snapshots.iterdir()))
        self.assertFalse(self.memory.status()['report']['stale']);self.assertEqual(60*1024**2,self.memory.status()['report']['providers'][0]['delta_bytes'])

    def test_strict_maintenance_umask_still_allows_clamav_to_traverse_prepared_data(self):
        old=os.umask(0o077)
        try:
            with patch('clamshield.signature_memory.subprocess.run',side_effect=self.runner):value=self.memory.measure()
        finally:os.umask(old)
        self.assertEqual(6,value['samples']);self.assertFalse(self.memory.work.exists())

    def test_failed_or_partial_probe_retains_previous_measurement(self):
        self.save();before=self.memory.path.read_bytes()
        for response in (subprocess.CompletedProcess([],1),subprocess.CompletedProcess([],0)):
            def failed(command,stdout,stderr,timeout):
                stdout.write(b'{"complete":true,"rows":[]}\n');return response
            with patch('clamshield.signature_memory.subprocess.run',side_effect=failed),self.assertRaises(EngineError):self.memory.measure()
            self.assertEqual(before,self.memory.path.read_bytes());self.assertFalse(self.memory.work.exists())

    def test_concurrent_signature_content_change_cannot_publish_a_current_measurement(self):
        self.save();before=self.memory.path.read_bytes();self.manager.verify_data.side_effect=[None,EngineError('Active data changed')]
        with patch('clamshield.signature_memory.subprocess.run',side_effect=self.runner),self.assertRaisesRegex(EngineError,'Active data changed'):
            self.memory.measure()
        self.assertEqual(before,self.memory.path.read_bytes())

    def test_low_available_memory_fails_before_a_new_process_is_started(self):
        original=Path.read_text
        def read_text(path,*args,**kwargs):return 'MemAvailable: 1048576 kB\n' if path==Path('/proc/meminfo') else original(path,*args,**kwargs)
        with patch.object(Path,'read_text',read_text),patch('clamshield.signature_memory.subprocess.run') as run,self.assertRaisesRegex(EngineError,'available RAM'):
            self.memory.measure()
        run.assert_not_called();self.assertFalse(self.memory.work.exists())

    def test_changed_data_or_engine_marks_previous_results_stale_without_erasing_them(self):
        self.save();self.files[1]['sha256']='d'*64;self.assertTrue(self.memory.status()['report']['stale'])
        self.save();self.memory.engine.return_value=self.identity|{'packages':'changed'};self.assertTrue(self.memory.status()['report']['stale'])
        self.assertTrue(self.memory.path.exists())

    def test_corrupt_or_incomplete_metadata_does_not_display_a_memory_estimate(self):
        value=self.save();value['rows'].pop();write_json(self.memory.path,value)
        current=self.memory.status();self.assertIsNone(current['report']);self.assertIn('error',current)

    def test_live_unit_is_observed_without_cleanup_or_restarting(self):
        folder,record=self.workspace();self.memory.unit_live.return_value=True
        self.assertEqual({'running':True},self.memory.recover());self.assertTrue(folder.exists());self.assertTrue(self.memory.work.exists())
        with self.assertRaisesRegex(Conflict,'still running'):self.memory.measure()

    def test_terminal_unit_workspace_is_cleaned_but_foreign_replacement_is_preserved(self):
        folder,record=self.workspace();(folder/'temporary').write_text('Owned')
        self.assertTrue(self.memory.recover()['recovered']);self.assertFalse(folder.exists())
        folder,record=self.workspace();folder.rename(folder.with_name('old'));folder.mkdir();(folder/'foreign').write_text('Preserve')
        with self.assertRaises(Conflict):self.memory.recover()
        self.assertEqual('Preserve',(folder/'foreign').read_text())

    def test_symlink_and_hardlink_in_workspace_block_cleanup(self):
        folder,record=self.workspace();target=self.root/'foreign';target.write_text('Preserve');(folder/'unsafe').symlink_to(target)
        with self.assertRaises(EngineError):self.memory.recover()
        (folder/'unsafe').unlink();os.link(target,folder/'unsafe')
        with self.assertRaises(EngineError):self.memory.recover()
        self.assertEqual('Preserve',target.read_text())

    def test_browser_paths_are_ignored_and_actor_scope_deduplicates_pending_measurements(self):
        from clamshield.application import Application
        from clamshield.store import Store
        store=Store(self.settings.database);hestia=Mock();context=dict(actor='admin',owner='tenant',identity='tenant-generation',admin=True)
        actor=dict(actor='admin',owner='admin',identity='admin-generation',admin=True)
        hestia.authorize.side_effect=lambda caller,owner=None:actor if owner=='admin' else context
        app=Application(self.settings,store,hestia)
        one=app.dispatch(dict(actor='admin',owner='tenant',action='signature-memory-measure',path='/etc/shadow',unit='foreign.service'))
        two=app.dispatch(dict(actor='admin',owner='tenant',action='signature-memory-measure'))
        self.assertEqual(one['task_id'],two['task_id']);self.assertEqual([],store.list_tasks(context))
        self.assertEqual({},store.list_tasks(actor)[0]['payload'])
        hestia.authorize.side_effect=None;hestia.authorize.return_value=context|{'admin':False}
        for action in ('signature-memory-status','signature-memory-measure'):
            with self.assertRaises(AccessDenied):app.dispatch(dict(actor='tenant',action=action))
