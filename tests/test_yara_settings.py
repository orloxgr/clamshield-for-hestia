from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.application import Application
from clamshield.engines import ClamAV,Yara
from clamshield.errors import AccessDenied,ClamShieldError,EngineError
from clamshield.generations import current
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker
from clamshield.yara_settings import DEFAULTS,YaraSettings


class WebsiteYaraSettings(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        base=Path(folder.name);self.root=base/'site';self.root.mkdir();(self.root/'sample.php').write_text('inert fixture')
        self.settings=Settings(state=base/'state');self.settings.prepare();self.store=Store(self.settings.database)
        self.context=dict(actor='alice',owner='alice',identity='native-generation',admin=True)
        self.site=dict(owner='alice',identity='native-generation',domain='site.test',root=str(self.root),suspended=False)
        self.hestia=Mock();self.hestia.authorize.return_value=self.context;self.hestia.sites.return_value=[self.site]
        self.policy=YaraSettings(self.settings)

    def test_validated_settings_persist_and_change_scan_generation_without_changing_clamav_suffix(self):
        before=current(self.settings)
        for value in (DEFAULTS|{'enabled':1},DEFAULTS|{'timeout_seconds':0},DEFAULTS|{'max_file_mib':True},DEFAULTS|{'max_file_mib':51},DEFAULTS|{'extra':True}):
            with self.assertRaises(ClamShieldError):self.policy.apply(value)
        self.policy.apply(DEFAULTS|{'enabled':False})
        after=current(self.settings);self.assertNotEqual(before,after)
        self.assertEqual(before.partition('|clamav:')[2],after.partition('|clamav:')[2])
        self.assertFalse(YaraSettings(self.settings).read()['enabled'])
        self.policy.path.unlink();target=self.settings.state/'foreign';target.write_text(json.dumps(DEFAULTS));self.policy.path.symlink_to(target)
        with self.assertRaises(ClamShieldError):self.policy.read()

    def test_only_real_admin_can_queue_settings_or_source_changes(self):
        app=Application(self.settings,self.store,self.hestia)
        for action in ('yara-settings-save','rules-options-save','yara-settings-status'):
            self.hestia.authorize.return_value=self.context|{'admin':False}
            with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',action=action,policy=DEFAULTS,admin=True))
        self.hestia.authorize.return_value=self.context
        queued=app.dispatch(dict(actor='alice',action='yara-settings-save',policy=DEFAULTS|{'enabled':False}))
        self.assertTrue(queued['queued']);self.assertTrue(self.policy.read()['enabled'])
        status=app.dispatch(dict(actor='alice',action='yara-settings-status'))
        self.assertTrue(status['pending']);self.assertEqual('queued',status['task']['status'])

    def run_scan(self):
        job_id=self.store.enqueue(self.context,self.site)
        with patch.object(ClamAV,'scan',return_value=[]),patch('clamshield.website_generation.pinned',side_effect=lambda settings,engine,generation:nullcontext(engine)):
            Worker(self.settings,self.store,self.hestia).once()
        return self.store.job(self.context,job_id)

    def test_disabled_yara_is_omitted_from_real_worker_and_reported_as_selected_clamav_coverage(self):
        self.policy.apply(DEFAULTS|{'enabled':False})
        with patch.object(Yara,'scan',side_effect=AssertionError('Disabled YARA must not run')):
            job=self.run_scan()
        self.assertEqual('completed',job['status'])
        with self.store.connection() as db:detail=json.loads(db.execute('SELECT detail FROM file_results WHERE job_id=?',(job['id'],)).fetchone()[0])
        self.assertEqual(['clamav'],detail['engines']);self.assertFalse(detail['failures'])
        from clamshield.readiness import WebsiteReadiness
        self.assertEqual('disabled',WebsiteReadiness(self.settings).yara()['state'])

    def test_enabled_yara_receives_saved_timeout_and_size_limits(self):
        self.policy.apply(DEFAULTS|{'timeout_seconds':7,'max_file_mib':2})
        seen=[]
        def scan(engine,path,*args,**kwargs):seen.append((engine.timeout,engine.max_file_bytes));return []
        with patch.object(Yara,'scan',autospec=True,side_effect=scan):job=self.run_scan()
        self.assertEqual('completed',job['status']);self.assertEqual([(7,2*1024**2)],seen)

    def test_size_limit_does_not_silently_report_a_clean_complete_scan(self):
        (self.root/'sample.php').write_bytes(b'x'*(1024**2+1))
        self.policy.apply(DEFAULTS|{'max_file_mib':1})
        job=self.run_scan()
        self.assertEqual('partial',job['status']);self.assertEqual(1,job['counters']['errors'])

    def test_repair_validation_keeps_both_engines_when_ordinary_yara_scanning_is_disabled(self):
        self.policy.apply(DEFAULTS|{'enabled':False})
        job_id=self.store.enqueue(self.context,self.site,source='repair-recheck')
        job=self.store.claim('fixture');worker=Worker(self.settings,self.store,self.hestia)
        with patch.object(worker,'validate'),patch.object(worker,'_run') as run,patch('clamshield.website_generation.pinned',side_effect=lambda settings,engine,generation:nullcontext(engine)):
            worker.run(job|{'source':'manual'})
            self.assertEqual({'clamav'},{engine.name for engine in run.call_args.args[1]})
            run.reset_mock()
            worker.run(job)
        self.assertEqual({'clamav','yara'},{engine.name for engine in run.call_args.args[1]})
