import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from clamshield.engines import Yara
from clamshield.errors import ClamShieldError,Conflict
from clamshield.rule_manager import RuleManager
from clamshield.settings import Settings
from clamshield.web_hosting_rules import fetch,EXTRA,INDEX


class WebHostingData(unittest.TestCase):
    def files(self):
        return {INDEX:b'/* generated original index */\ninclude "./exploit_kits/EK_Test.yar"\n',
            'exploit_kits/EK_Test.yar':b'/* original EK notice */\nrule Exploit {condition:false}',
            EXTRA[0]:b'rule Phishing {condition:false}',EXTRA[1]:b'rule Javascript {condition:false}',
            'LICENSE':b'GNU GENERAL PUBLIC LICENSE\nVersion 2\n'}

    def fixture(self,files=None,*,commit='a'*40,truncated=False,corrupt=None,node_change=None,duplicate=False):
        files=self.files() if files is None else files
        nodes=[dict(path=p,type='blob',mode='100644',size=len(b),sha=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()) for p,b in files.items()]
        if node_change:
            next(x for x in nodes if x['path']=='exploit_kits/EK_Test.yar').update(node_change)
        if duplicate:nodes.append(dict(nodes[0]))
        calls=[]
        def download(url,maximum):
            calls.append(url)
            if '/commits/' in url:return json.dumps(dict(sha=commit)).encode()
            if '/git/trees/' in url:return json.dumps(dict(tree=nodes,truncated=truncated)).encode()
            name=url.split('/'+commit+'/',1)[1]
            return corrupt if corrupt is not None and name=='exploit_kits/EK_Test.yar' else files[name]
        return download,calls

    def test_original_conditions_notices_index_and_full_license_are_preserved(self):
        download,calls=self.fixture();content,metadata=fetch(download)
        self.assertIn(b'/* original EK notice */',content);self.assertIn(b'rule Exploit {condition:false}',content)
        self.assertIn(b'rule Phishing {condition:false}',content);self.assertIn(b'rule Javascript {condition:false}',content)
        self.assertEqual(self.files()['LICENSE'].decode(),metadata['license']);self.assertEqual(5,len(metadata['dependencies']))
        self.assertEqual('a'*40,metadata['commit']);self.assertEqual('website',metadata['scope']);self.assertTrue(metadata['review_only'])
        self.assertEqual(hashlib.sha256(self.files()['LICENSE']).hexdigest(),metadata['license_sha256'])
        self.assertTrue(all('raw.githubusercontent.com/Yara-Rules/rules/'+('a'*40)+'/' in url for url in calls if '/commits/' not in url and '/git/trees/' not in url))

    def test_commit_tree_duplicate_and_blob_identity_fail_closed(self):
        for options in (dict(commit='master'),dict(truncated=True),dict(duplicate=True),dict(corrupt=b'changed body'),dict(node_change=dict(mode='120000')),dict(node_change=dict(size=0)),dict(node_change=dict(sha='not-a-blob'))):
            with self.subTest(options=options),self.assertRaises(ClamShieldError):fetch(self.fixture(**options)[0])

    def test_index_must_stay_in_original_tree_and_account_for_every_directive(self):
        for target in ('/etc/shadow','../secret.yar','exploit_kits/../x.yar','https://evil.invalid/a.yar','exploit_kits/missing.yar','exploit_kits/a\\b.yar'):
            files=self.files();files[INDEX]=('include "'+target+'"\n').encode()
            with self.subTest(target=target),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])
        for body in (b'include "./exploit_kits/EK_Test.yar"\ninclude "exploit_kits/EK_Test.yar"',b'include "exploit_kits/EK_Test.yar"\nrule Unexpected {condition:true}',b'/* never closed',b'// empty index'):
            files=self.files();files[INDEX]=body
            with self.subTest(body=body),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])

    def test_changed_global_include_nul_and_encoding_context_are_not_silently_rewritten(self):
        for body in (b'global rule Context {condition:true}',b'include "unknown.yar"\nrule Bad {condition:true}',b'rule Null {condition:true}\0',b'\xff'):
            files=self.files();files['exploit_kits/EK_Test.yar']=body
            with self.subTest(body=body),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])

    def test_required_fixed_sources_and_license_must_exist(self):
        for missing in ('LICENSE',EXTRA[0],EXTRA[1]):
            files=self.files();del files[missing]
            with self.subTest(missing=missing),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])
        files=self.files();files['LICENSE']=b'GNU GENERAL PUBLIC LICENSE Version 3'
        with self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])

    def test_metadata_and_total_bounds_apply_before_source_activation(self):
        with self.assertRaises(ClamShieldError):fetch(lambda *_:b'x'*(4*1024**2+1))
        files=self.files();files['exploit_kits/EK_Test.yar']=b'x'*(1024**2+1)
        with self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])


AVAILABLE=Path('/usr/bin/yarac').is_file() and importlib.util.find_spec('plyara') is not None


@unittest.skipUnless(AVAILABLE,'Ubuntu YARA and plyara integration')
class ManagedWebHosting(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.settings=Settings(state=self.base/'state');self.settings.prepare();self.manager=RuleManager(self.settings)
        self.sample=self.base/'sample';self.sample.write_bytes(b'WebRuleTestMarker')

    def source(self,source_id='strong',content='rule Strong {strings:$a="WebRuleTestMarker" condition:$a}'):
        return self.manager.save_source(dict(id=source_id,name=source_id,kind='local',license='CC0',version='1',content=content))

    @staticmethod
    def hosting():
        # Full trusted managed notices can exceed the ordinary upload form limit.
        notice='GPL-2.0 original notice\n'+'x'*17000
        return b'rule WebHeuristic {strings:$a="WebRuleTestMarker" condition:$a}',dict(commit='c'*40,version='c'*40,source_url='https://github.com/Yara-Rules/rules/tree/'+('c'*40),license=notice,license_url='https://github.com/Yara-Rules/rules/LICENSE',license_sha256=hashlib.sha256(notice.encode()).hexdigest(),dependencies=[],review_only=True,scope='website')

    def stage(self):
        with patch('clamshield.web_hosting_rules.fetch',return_value=self.hosting()):return self.manager.web_hosting()

    def engine(self,purpose='website'):
        return Yara('/usr/bin/yara',self.manager.rules.base/'current/rules.yarac',purpose=purpose)

    def test_stage_requires_activation_and_keeps_source_provenance_review_and_mail_scope(self):
        candidate=self.stage();self.assertFalse(self.manager.rules.status()['configured'])
        source=self.manager.read()['sources']['web_hosting'];self.assertEqual('web-hosting',source['kind']);self.assertTrue(source['review_only'])
        self.assertEqual(self.hosting()[1]['license'],source['license'])
        self.manager.activate(candidate['generation']);hits=self.engine().scan(self.sample)
        self.assertEqual(1,len(hits));hit=hits[0]
        self.assertTrue(hit['review_only']);self.assertTrue(hit['heuristic']);self.assertEqual('web_hosting',hit['source_id']);self.assertEqual('c'*40,hit['commit'])
        self.assertEqual(source['license_sha256'],hit['license_sha256']);self.assertEqual([],self.engine('mail').scan(self.sample))
        with self.assertRaises(Conflict):self.source('web_hosting')

    def test_explicit_eligibility_is_staged_and_disabled_choice_survives_refresh(self):
        first=self.stage();self.manager.activate(first['generation']);self.manager.review_mode('web_hosting',False)
        self.assertTrue(self.manager.metadata(first['generation'])[1]['config']['sources']['web_hosting']['review_only'])
        second=self.stage();self.manager.activate(second['generation']);self.assertFalse(self.engine().scan(self.sample)[0].get('review_only',False))
        self.manager.toggle_source('web_hosting',False)
        with patch('clamshield.web_hosting_rules.fetch',return_value=self.hosting()),self.assertRaises(ClamShieldError):self.manager.fetch('web_hosting')
        # A source-only disabled configuration has no rules to compile; its
        # saved disabled/eligibility intent must still survive that refusal.
        self.assertFalse(self.manager.read()['sources']['web_hosting']['enabled']);self.assertFalse(self.manager.read()['sources']['web_hosting']['review_only'])
        with self.assertRaises(ClamShieldError):self.manager.review_mode('web_hosting','false')

    def test_independent_identical_strong_rule_remains_eligible_in_website_and_mail(self):
        self.source('zstrong',self.hosting()[0].decode());candidate=self.stage();self.manager.activate(candidate['generation'])
        website=self.engine().scan(self.sample);self.assertEqual(1,len(website));self.assertFalse(website[0].get('review_only',False))
        mail=self.engine('mail').scan(self.sample);self.assertEqual(1,len(mail));self.assertEqual('zstrong',mail[0]['source_id']);self.assertNotIn('also_matched',mail[0])

    def test_collision_and_download_race_cannot_overwrite_unrelated_configuration(self):
        self.source('web_hosting')
        with patch('clamshield.web_hosting_rules.fetch') as download,self.assertRaises(Conflict):self.manager.web_hosting()
        download.assert_not_called()
        self.source('strong');before=self.manager.read()['sources']['web_hosting']
        # Use an independent fresh manager with a legitimate nonmanaged source.
        other=RuleManager(Settings(state=self.base/'other-state'));other.settings.prepare()
        other.save_source(dict(id='strong',name='Strong',kind='local',license='CC0',version='1',content='rule S {condition:false}'))
        def race():other.toggle_source('strong',False);return self.hosting()
        with patch('clamshield.web_hosting_rules.fetch',side_effect=race),self.assertRaises(Conflict):other.web_hosting()
        self.assertNotIn('web_hosting',other.read()['sources']);self.assertEqual(before,self.manager.read()['sources']['web_hosting'])

    def test_invalid_update_keeps_the_original_active_compiled_generation(self):
        self.source();first=self.manager.build();self.manager.activate(first['generation']);path=self.manager.rules.base/'current'
        before=path.resolve();digest=hashlib.sha256((before/'rules.yarac').read_bytes()).hexdigest();_,metadata=self.hosting()
        with patch('clamshield.web_hosting_rules.fetch',return_value=(b'rule invalid {',metadata)),self.assertRaises(ClamShieldError):self.manager.web_hosting()
        self.assertEqual(before,path.resolve());self.assertEqual(digest,hashlib.sha256((before/'rules.yarac').read_bytes()).hexdigest())
        self.assertEqual(1,len(self.engine().scan(self.sample)))
