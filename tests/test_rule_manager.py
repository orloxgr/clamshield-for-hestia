import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.engines import Yara
from clamshield.errors import AccessDenied,ClamShieldError,Conflict,EngineError
from clamshield.rule_catalog import analyze
from clamshield.rule_manager import RuleManager,revision
from clamshield.rule_trials import RuleTrials
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.worker import Worker

AVAILABLE=Path('/usr/bin/yarac').is_file() and importlib.util.find_spec('plyara') is not None


@unittest.skipUnless(AVAILABLE,'Ubuntu YARA and plyara integration')
class ManagedRules(unittest.TestCase):
    @staticmethod
    def hosting():
        content=b'rule PHPHeuristic {strings:$a="RuleTestMarker" condition:$a}'
        metadata=dict(commit='a'*40,version='a'*40,source_url='https://github.com/example/pinned',
            license='LGPL upstream notice',license_url='https://github.com/example/LICENSE',license_sha256='b'*64,
            dependencies=[],review_only=True,scope='website')
        return content,metadata

    def test_managed_hosting_is_staged_with_provenance_review_only_and_mail_scope(self):
        self.source()
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):candidate=self.manager.php_hosting()
        self.assertFalse(self.manager.rules.status()['configured'])
        self.assertEqual('a'*40,self.manager.read()['sources']['php_hosting']['commit'])
        self.manager.activate(candidate['generation'])
        sample=self.base/'php';sample.write_bytes(b'RuleTestMarker')
        hits=Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac').scan(sample)
        # Independent identical rules may collapse; retain only review-only
        # source to prove the standalone heuristic and email scope explicitly.
        self.manager.toggle_source('local',False);candidate=self.manager.build();self.manager.activate(candidate['generation'])
        hits=Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac').scan(sample)
        self.assertEqual(1,len(hits));self.assertTrue(hits[0]['review_only']);self.assertEqual('a'*40,hits[0]['commit'])
        self.assertEqual('b'*64,hits[0]['license_sha256'])
        self.assertEqual([],Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac',purpose='mail').scan(sample))
        with self.assertRaises(Conflict):self.source('php_hosting')

    def test_hosting_update_preserves_disabled_state_and_refuses_concurrent_configuration(self):
        self.source()
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):self.manager.php_hosting()
        self.manager.toggle_source('php_hosting',False)
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):self.manager.fetch('php_hosting')
        self.assertFalse(self.manager.read()['sources']['php_hosting']['enabled'])
        def change():
            self.manager.toggle_source('local',False);return self.hosting()
        with patch('clamshield.php_hosting_rules.fetch',side_effect=change),self.assertRaises(Conflict):self.manager.php_hosting()

    def test_independent_strong_alias_remains_eligible_and_visible_in_mail(self):
        self.source('zstrong',content=self.hosting()[0].decode())
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):candidate=self.manager.php_hosting()
        self.manager.activate(candidate['generation'])
        hits=Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac').scan(self.sample)
        self.assertEqual(1,len(hits));self.assertFalse(hits[0].get('review_only',False))
        mail=Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac',purpose='mail').scan(self.sample)
        self.assertEqual(1,len(mail));self.assertEqual('zstrong',mail[0]['source_id'])

    def test_review_mode_is_explicit_staged_and_preserved_by_updates(self):
        self.source()
        self.manager.toggle_source('local',False)
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):first=self.manager.php_hosting()
        self.manager.activate(first['generation'])
        self.manager.review_mode('php_hosting',False)
        self.assertTrue(self.manager.read()['sources']['php_hosting']['scope']=='website')
        active=self.manager.metadata(first['generation'])[1]
        self.assertTrue(active['config']['sources']['php_hosting']['review_only'])
        with patch('clamshield.php_hosting_rules.fetch',return_value=self.hosting()):second=self.manager.php_hosting()
        self.assertFalse(self.manager.metadata(second['generation'])[1]['config']['sources']['php_hosting']['review_only'])
        self.manager.activate(second['generation'])
        hits=self.scan();self.assertEqual(1,len(hits));self.assertTrue(hits[0]['heuristic'])
        self.assertFalse(hits[0].get('review_only',False));self.assertEqual('a'*40,hits[0]['commit'])
        self.assertEqual([],Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac',purpose='mail').scan(self.sample))
        with self.assertRaises(ClamShieldError):self.manager.review_mode('php_hosting','false')
        with self.assertRaises(ClamShieldError):self.manager.review_mode('local',False)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.settings=Settings(state=self.base/'state');self.settings.prepare()
        self.manager=RuleManager(self.settings)
        self.sample=self.base/'sample';self.sample.write_bytes(b'RuleTestMarker')

    def source(self,source_id='local',content='rule Local {strings:$a="RuleTestMarker" condition:$a}',kind='local',url=None):
        return self.manager.save_source(dict(id=source_id,name='Local source',kind=kind,version='1',license='MIT test fixture',content=content,**({'url':url} if url else {})))

    def scan(self,name=None):
        return Yara('/usr/bin/yara',self.manager.rules.base/(name or 'current')/'rules.yarac').scan(self.sample)

    def forge_fixture(self, content=b'rule ForgeFixture {strings:$a="RuleTestMarker" condition:$a}'):
        return (content,dict(version='fixture-release',source_url='https://example.test/rules.zip',
                             archive_sha256='a'*64,licenses='MIT fixture notice'))

    def test_one_install_validates_and_activates_distro_rules_with_rollback_retained(self):
        stages=[]
        with patch.object(self.manager.rules,'fetch_forge',return_value=self.forge_fixture()):
            active=self.manager.install('core',progress=stages.append)
        self.assertEqual(['downloading','checking','activating'],stages)
        self.assertTrue(active['activated']);self.assertEqual(active['generation'],self.manager.rules.status()['generation'])
        self.assertEqual(1,len(self.scan()))
        with patch.object(self.manager.rules,'fetch_forge',return_value=self.forge_fixture(b'rule NewFixture {condition:false}')):
            self.manager.install('extended')
        self.assertEqual([],self.scan());self.manager.rollback()
        self.assertEqual(active['generation'],self.manager.rules.status()['generation'])

    def test_one_install_failure_keeps_previous_active_generation(self):
        with patch.object(self.manager.rules,'fetch_forge',return_value=self.forge_fixture()):
            active=self.manager.install('core')
        with patch.object(self.manager.rules,'fetch_forge',return_value=self.forge_fixture(b'not valid YARA')),self.assertRaises(ClamShieldError):
            self.manager.install('extended')
        self.assertEqual(active['generation'],self.manager.rules.status()['generation'])
        self.assertEqual(1,len(self.scan()))

    def test_one_install_refuses_source_changes_before_automatic_activation(self):
        with patch.object(self.manager.rules,'fetch_forge',return_value=self.forge_fixture()):
            active=self.manager.install('core')
            def change(phase):
                if phase=='activating':self.manager.toggle_source('forge',False)
            with self.assertRaises(Conflict):self.manager.install('extended',progress=change)
        self.assertEqual(active['generation'],self.manager.rules.status()['generation'])

    def test_candidate_is_not_active_and_preserves_source_notices_and_provenance(self):
        content='/* MIT original notice */\nrule Local {strings:$a="RuleTestMarker" condition:$a}'
        self.source(content=content);candidate=self.manager.build()
        self.assertFalse(self.manager.rules.status()['configured'])
        release=self.manager.rules.base/candidate['generation']
        self.assertEqual(content,(release/'original-local.yar').read_text())
        self.assertEqual(content,(release/'source-local.yar').read_text())
        self.manager.activate(candidate['generation']);hits=self.scan()
        self.assertEqual('local:Local',hits[0]['signature']);self.assertEqual('local:Local',hits[0]['rule_id'])
        self.assertEqual('MIT test fixture',hits[0]['license'])

    def test_lexer_spans_preserve_braces_strings_comments_and_same_line_rules(self):
        source='/* notice */ rule One {strings:$a="} rule Fake {" condition:$a} rule Two {condition:true}'
        result=analyze({'sources':[dict(id='local',namespace='local',content=source)],'disabled':['local:Two']})
        self.assertIn('/* notice */',result['selected']['local'])
        self.assertIn('rule One {strings:$a="} rule Fake {" condition:$a}',result['selected']['local'])
        self.assertNotIn('rule Two',result['selected']['local'])
        self.assertEqual(2,len(result['catalog']))

    def test_namespaces_allow_equal_names_and_matching_duplicates_retain_aliases(self):
        self.source('one');self.source('two')
        candidate=self.manager.build();self.manager.activate(candidate['generation']);hits=self.scan()
        self.assertEqual(1,len(hits));self.assertEqual(1,len(hits[0]['also_matched']))
        self.assertEqual({'one','two'},{hits[0]['source_id'],hits[0]['also_matched'][0]['source_id']})
        self.assertEqual(['two'],[n['source_id'] for n in self.manager.catalog(candidate['generation'],'source:two')['rules']])

    def test_same_name_conflict_rejected_but_exact_duplicate_removed(self):
        self.source(content='rule Same {condition:true} rule Same {condition:false}')
        with self.assertRaises(EngineError):self.manager.build()
        self.source(content='rule Same {condition:true} rule Same {condition:true}')
        candidate=self.manager.build();self.assertEqual(1,candidate['rules'])
        self.assertEqual(1,candidate['sources'][0]['duplicates_removed'])

    def test_private_dependencies_prevent_unsafe_disable_and_old_active_survives(self):
        self.source(content='private rule Helper {condition:true} rule Public {condition:Helper}')
        first=self.manager.build();self.manager.activate(first['generation'])
        self.manager.toggle_rule('local:Helper',False)
        with self.assertRaises(EngineError):self.manager.build()
        helper=next(n for n in self.manager.catalog()['rules'] if n['name']=='Helper')
        self.assertTrue(helper['enabled']);self.assertFalse(helper['selected'])
        self.assertEqual(first['generation'],self.manager.rules.status()['generation'])
        self.assertEqual('local:Public',self.scan()[0]['signature'])
        self.manager.toggle_rule('local:Public',False)
        # Both disabled would produce an empty policy, which is rejected.
        with self.assertRaises(Conflict):self.manager.build()

    def test_wildcard_dependencies_are_catalogued(self):
        self.source(content='rule Family1 {condition:true} rule Family2 {condition:false} rule Public {condition:any of (Family*)}')
        candidate=self.manager.build();catalog=self.manager.catalog(candidate['generation'])['rules']
        public=next(n for n in catalog if n['name']=='Public')
        self.assertEqual(['local:Family1','local:Family2'],public['dependencies'])
        self.manager.toggle_rule('local:Family2',False)
        with self.assertRaises(EngineError):self.manager.build()

    def test_cascade_disable_closes_transitive_references_and_keeps_other_sources(self):
        self.source(content='private rule Helper {condition:true} rule Public {condition:Helper} rule Top {condition:Public}')
        self.source('side',content='rule Side {condition:true}')
        self.manager.build()
        result=self.manager.toggle_rule('local:Helper',False,cascade=True)
        self.assertEqual(3,result['affected_rules'])
        candidate=self.manager.build();self.manager.activate(candidate['generation'])
        self.assertEqual(['side:Side'],[hit['signature'] for hit in self.scan()])
        self.assertEqual({'local:Helper','local:Public','local:Top'},set(self.manager.read()['disabled']))

    def test_disabling_global_rule_removes_gate_instead_of_making_every_rule_false(self):
        self.source(content='global rule Gate {condition:false} rule Public {strings:$a="RuleTestMarker" condition:$a}')
        first=self.manager.build();self.manager.activate(first['generation']);self.assertEqual([],self.scan())
        self.manager.toggle_rule('local:Gate',False);second=self.manager.build();self.manager.activate(second['generation'])
        self.assertEqual('local:Public',self.scan()[0]['signature'])

    def test_stale_candidate_cannot_overwrite_newer_source_settings(self):
        self.source();candidate=self.manager.build();self.source(content='rule Changed {condition:true}')
        with self.assertRaises(Conflict):self.manager.activate(candidate['generation'])
        self.assertFalse(self.manager.rules.status()['configured'])

    def test_rollback_restores_compiled_rules_and_policy_snapshot(self):
        self.source();first=self.manager.build();self.manager.activate(first['generation']);old=self.manager.read()
        self.source('second',content='rule New {condition:true}');second=self.manager.build();self.manager.activate(second['generation'])
        self.manager.rollback()
        self.assertEqual(old,self.manager.read());self.assertEqual(first['generation'],self.manager.rules.status()['generation'])

    def test_corrupt_catalog_rejects_activation_without_changing_active(self):
        self.source();first=self.manager.build();self.manager.activate(first['generation'])
        self.source('second',content='rule Other {condition:true}');second=self.manager.build()
        (self.manager.rules.base/second['generation']/'catalog.json').write_text('[]')
        with self.assertRaises(EngineError):self.manager.activate(second['generation'])
        self.assertEqual(first['generation'],self.manager.rules.status()['generation'])

    def test_disabled_source_keeps_its_rule_overrides_without_stale_failure(self):
        self.source('one');self.source('two',content='rule Other {condition:true}');first=self.manager.build()
        self.manager.toggle_rule('one:Local',False);self.manager.toggle_source('one',False)
        second=self.manager.build();self.assertEqual([],second['stale_overrides']);self.manager.activate(second['generation'])
        self.assertEqual('two:Other',self.scan()[0]['signature'])

    def test_source_update_preserves_package_disabled_state(self):
        self.source('one');self.source('two',content='rule Other {condition:true}')
        self.manager.toggle_source('one',False)
        self.source('one',content='rule Updated {condition:true}')
        self.assertFalse(self.manager.read()['sources']['one']['enabled'])

    def test_includes_and_remote_ssrf_targets_are_rejected(self):
        self.source(content='include "/etc/passwd"\nrule Test {condition:true}')
        with self.assertRaises(EngineError):self.manager.build()
        for url in ['http://raw.githubusercontent.com/o/r/main/file.yar','https://127.0.0.1/file.yar',
                    'https://user@raw.githubusercontent.com/o/r/main/file.yar','https://raw.githubusercontent.com:444/o/r/main/file.yar']:
            with self.assertRaises(ClamShieldError):self.source(kind='remote',url=url)

    def test_stable_uuid_identity_survives_rule_rename(self):
        identity='de305d54-75b4-431b-adb2-eb6b9e546014'
        self.source(content='rule Name {meta:id="'+identity+'" condition:true}')
        first=self.manager.build();node=self.manager.catalog(first['generation'])['rules'][0]
        self.assertEqual('local:'+identity,node['id'])
        self.manager.toggle_rule(node['id'],False)
        self.source(content='rule Renamed {meta:id="'+identity+'" condition:true} rule Other {condition:true}')
        second=self.manager.build();self.assertFalse(next(n for n in self.manager.catalog(second['generation'])['rules'] if n['name']=='Renamed')['enabled'])

    def test_shared_upstream_uuid_does_not_merge_distinct_rules_or_reject_valid_package(self):
        identity='de305d54-75b4-431b-adb2-eb6b9e546014'
        self.source(content='rule One {meta:id="'+identity+'" condition:true} rule Two {meta:id="'+identity+'" condition:false}')
        candidate=self.manager.build();nodes=self.manager.catalog(candidate['generation'])['rules']
        self.assertEqual({'local:'+identity+':One','local:'+identity+':Two'},{n['id'] for n in nodes})
        self.manager.activate(candidate['generation']);self.assertEqual('local:One',self.scan()[0]['signature'])

    def test_reactivating_same_generation_keeps_previous_rollback_target(self):
        self.source();first=self.manager.build();self.manager.activate(first['generation'])
        self.source('two',content='rule Other {condition:true}');second=self.manager.build();self.manager.activate(second['generation'])
        self.manager.activate(second['generation']);self.manager.rollback()
        self.assertEqual(first['generation'],self.manager.rules.status()['generation'])


@unittest.skipUnless(AVAILABLE,'Ubuntu YARA and plyara integration')
class ScopedRuleTrials(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'site';self.root.mkdir()
        self.settings=Settings(state=self.base/'state');self.settings.prepare();self.store=Store(self.settings.database)
        self.context=dict(actor='alice',owner='alice',identity='generation',admin=False)
        self.site=dict(owner='alice',identity='generation',domain='site.test',root=str(self.root),suspended=False)
        self.hestia=Mock();self.hestia.sites.return_value=[self.site];self.hestia.authorize.return_value=self.context
        self.manager=RuleManager(self.settings)
        self.manager.save_source(dict(id='local',name='Local',version='1',license='MIT',content='rule Old {condition:false}'))
        self.active=self.manager.build();self.manager.activate(self.active['generation'])
        self.manager.save_source(dict(id='extra',name='Extra',version='1',license='MIT',content='rule New {strings:$a="RuleTestMarker" condition:$a}'))
        self.candidate=self.manager.build()
        (self.root/'clean.php').write_text('<?php echo "Hello";')
        (self.root/'fixture.txt').write_text('RuleTestMarker')
        self.trials=RuleTrials(self.settings,self.store,self.hestia)

    def test_trial_compares_actual_ubuntu_engines_without_live_findings_or_activation(self):
        job_id=self.trials.queue(self.context,'site.test')
        Worker(self.settings,self.store,self.hestia).once()
        job=self.store.job(self.context,job_id)
        self.assertEqual('completed',job['status']);self.assertEqual(2,job['counters']['scanned'])
        self.assertEqual(1,job['counters']['new_signatures']);self.assertEqual(0,job['counters']['infected'])
        self.assertEqual(self.candidate['generation'],job['generation'])
        self.assertEqual(self.active['generation'],self.manager.rules.status()['generation'])
        self.assertEqual([],self.store.list_findings(self.context))
        report=self.trials.report(self.context,job_id)
        self.assertEqual(2,len(report['files']));self.assertGreater(job['counters']['candidate_seconds'],0)
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM observations').fetchone()[0])

    def test_trial_reports_and_paths_are_owner_generation_scoped(self):
        job_id=self.trials.queue(self.context,'site.test')
        foreign=self.context|dict(owner='bob',identity='bob-generation')
        self.assertEqual([],self.trials.list(foreign))
        with self.assertRaises(AccessDenied):self.trials.report(foreign,job_id)
        with self.assertRaises(AccessDenied):self.trials.queue(self.context,'site.test','../outside')
        with self.assertRaises(AccessDenied):self.trials.queue(self.context,'foreign.test')

    def test_trial_symlink_is_partial_instead_of_clean(self):
        (self.root/'link').symlink_to('/etc/passwd');job_id=self.trials.queue(self.context,'site.test')
        Worker(self.settings,self.store,self.hestia).once()
        self.assertEqual('partial',self.store.job(self.context,job_id)['status'])
        self.assertEqual(1,self.store.job(self.context,job_id)['counters']['skipped'])

    def test_admin_can_compare_retained_generations_but_tenant_requires_published_choice(self):
        self.manager.activate(self.candidate['generation'])
        self.manager.save_source(dict(id='latest',name='Latest',version='1',license='MIT',content='rule Latest {condition:false}'))
        self.manager.build()
        with self.assertRaises(AccessDenied):self.trials.queue(self.context,'site.test',name=self.active['generation'])
        job_id=self.trials.queue(self.context|{'admin':True},'site.test',name=self.active['generation'])
        self.assertEqual(self.active['generation'],self.store.job(self.context,job_id)['generation'])
