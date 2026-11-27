import hashlib
import json
import re
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.errors import EngineError
from clamshield.providers import Providers
from clamshield.readiness import WebsiteReadiness
from clamshield.settings import Settings
from clamshield.signature_catalog import SignatureCatalog
from clamshield.signatures import Signatures
from clamshield import signature_profiles as profiles
from clamshield.website_generation import AttributedClamAV
from clamshield.mail_scanners import MailScanner


@unittest.skipUnless(Path('/usr/bin/clamscan').is_file() and Path('/usr/bin/sigtool').is_file(), 'Ubuntu ClamAV')
class SignatureProfiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o755)
        self.settings = Settings(state=self.base/'state'); self.settings.prepare()
        self.manager = Signatures(self.settings); self.manager.base.mkdir(mode=0o755)
        self.stage = self.manager.base/'generation-profiles'; self.stage.mkdir(mode=0o755)
        files = []
        for provider, name, content in [('official', 'official.ndb', 'Shared.Malware:0:*:494e4552545f4d414c574152455f46495854555245\n'),
                ('securiteinfo', 'securiteinfo--spam_marketing.ndb', 'Mail.Spam:0:*:494e4552545f5350414d5f46495854555245\n')]:
            path=self.stage/name; path.write_text(content); path.chmod(0o644)
            files.append(dict(provider=provider, name=name, size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        self.manifest=dict(generation=self.stage.name, providers=['official','securiteinfo'], files=files,
            profiles={'website':['official.ndb'], 'mail':sorted(row['name'] for row in files)})
        self.manager.complete_stage(self.stage, self.manifest)

    def scan(self, profile, payload):
        sample=self.base/'input';sample.write_bytes(payload); sample.chmod(0o644)
        result=subprocess.run(['/usr/bin/clamscan','--no-summary','--database='+str(self.stage/profile), str(sample)],capture_output=True,text=True,timeout=30)
        self.assertIn(result.returncode, (0,1), result.stderr)
        return result

    def test_real_engine_loads_spam_only_for_mail_and_malware_for_both(self):
        self.assertEqual(0,self.scan('website',b'INERT_SPAM_FIXTURE').returncode)
        self.assertIn('Mail.Spam',self.scan('mail',b'INERT_SPAM_FIXTURE').stdout)
        for profile in profiles.PROFILES:
            self.assertIn('Shared.Malware',self.scan(profile,b'INERT_MALWARE_FIXTURE').stdout)
            own=profiles.canary(self.manifest,profile)
            self.assertIn(own['signature'],self.scan(profile,own['payload'].encode()).stdout)
            other=profiles.canary(self.manifest,'mail' if profile=='website' else 'website')
            self.assertEqual(0,self.scan(profile,other['payload'].encode()).returncode)

    def test_profile_tampering_and_extra_databases_fail_before_activation(self):
        self.manager.verify_data(self.stage,self.manifest)
        extra=self.stage/'website'/'unexpected.ndb';extra.write_text('unexpected')
        with self.assertRaises(EngineError):self.manager.verify_data(self.stage,self.manifest)
        extra.unlink();target=self.stage/'mail'/'securiteinfo--spam_marketing.ndb'
        original=target.read_bytes();target.write_bytes(original.replace(b'Mail.Spam',b'Fail.Spam'))
        with self.assertRaises(EngineError):self.manager.verify_data(self.stage,self.manifest)

    def test_same_name_from_an_excluded_database_does_not_affect_attribution(self):
        with SignatureCatalog(self.stage,self.manifest) as catalog:
            self.assertEqual('spam',catalog.resolve('Mail.Spam.UNOFFICIAL',sources=profiles.sources(self.manifest,'mail'))['category'])
            self.assertEqual('unclassified',catalog.resolve('Mail.Spam.UNOFFICIAL',sources=profiles.sources(self.manifest,'website'))['provider'])

    def test_shared_generation_loads_one_union_and_applies_website_and_mail_selections(self):
        stage=self.manager.base/'generation-native-shared';stage.mkdir(mode=0o755)
        for row in self.manifest['files']:shutil.copyfile(self.stage/row['name'],stage/row['name'])
        manifest={key:self.manifest[key] for key in ('files','profiles','providers')}
        manifest.update(generation=stage.name,engine_mode='native-shared')
        self.manager.complete_stage(stage,manifest)
        self.manager.verify_data(stage,manifest)
        self.assertFalse((stage/'website').exists());self.assertFalse((stage/'mail').exists())
        self.assertEqual(profiles.directory(stage,manifest,'website'),profiles.directory(stage,manifest,'mail'))
        self.assertEqual(profiles.canary(manifest,'website'),profiles.canary(manifest,'mail'))
        sample=self.base/'shared-payload';sample.write_bytes(b'INERT_SPAM_FIXTURE INERT_MALWARE_FIXTURE')
        result=subprocess.run(['/usr/bin/clamscan','--allmatch','--no-summary','--database='+str(stage),str(sample)],
                              capture_output=True,text=True,check=False)
        self.assertEqual(1,result.returncode,result.stderr)
        names=re.findall(r': (.+) FOUND',result.stdout)
        self.assertEqual({'Mail.Spam.UNOFFICIAL','Shared.Malware.UNOFFICIAL'},set(names))
        names.sort(key=lambda name:0 if name.startswith('Mail.') else 1)
        with SignatureCatalog(stage,manifest) as catalog:
            website=AttributedClamAV(Mock(scan=Mock(return_value=[dict(engine='clamav',signature=name) for name in names])),
                lambda name:catalog.selected(name,sources=profiles.sources(manifest,'website')),stage.name,manifest['content_sha256'])
            hits=website.scan(sample)
            self.assertEqual(['Shared.Malware.UNOFFICIAL'],[hit['signature'] for hit in hits])
            mail=MailScanner(Mock(scan=Mock(return_value=names)),
                Mock(scan=Mock(return_value=dict(score=0,threshold=5,symbols=[]))),
                resolve_signature=lambda name:catalog.selected(name,sources=profiles.sources(manifest,'mail')))
            import os,fcntl
            from clamshield.mail_bridge import SEALS
            fd=os.memfd_create('shared-mail-test',os.MFD_ALLOW_SEALING)
            try:
                os.write(fd,sample.read_bytes());fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
                report=mail.scan(fd)
                self.assertTrue(report['complete']);self.assertEqual(2,len(report['detections']))
                self.assertEqual(['spam','malware'],[hit['category'] for hit in report['detections']])
            finally:os.close(fd)
        extra=stage/'unexpected.ign2';extra.write_text('Shared.Malware\n')
        with self.assertRaisesRegex(EngineError,'unexpected or missing'):
            self.manager.verify_data(stage,manifest)

    def test_shared_engine_rejects_incompatible_global_lists_instead_of_silently_suppressing_matches(self):
        manifest=json.loads(json.dumps(self.manifest));manifest['engine_mode']='native-shared'
        manifest['files'].append(dict(provider='local',name='local--global.ign2',sha256='a'*64,size=1))
        manifest['profiles']['mail'].append('local--global.ign2')
        manifest['profiles']['mail'].sort()
        with self.assertRaisesRegex(EngineError,'engine-wide databases'):
            profiles.validate_selection(manifest)

    def test_selection_only_change_changes_generation_identity_and_readiness(self):
        before=profiles.identity(self.manifest,1)
        changed=json.loads(json.dumps(self.manifest));changed['profiles']['website']=changed['profiles']['mail']
        self.assertNotEqual(before,profiles.identity(changed,1))
        providers=Providers(self.settings)
        providers.save({'securiteinfo':dict(enabled=True,key='a'*128,plan='professional',website_databases=[],mail_databases=['spam_marketing.ndb']),
                        'local':{'enabled':False}})
        # Add its required companion to the advertised retained selection.
        config=providers.read();record=dict(self.manifest, providers=['official','securiteinfo'])
        record['files']=self.manifest['files']+[dict(provider='securiteinfo',name='securiteinfo--securiteinfo.ign2')]
        record['profiles']={'website':['official.ndb','securiteinfo--securiteinfo.ign2'],
                            'mail':['official.ndb','securiteinfo--securiteinfo.ign2','securiteinfo--spam_marketing.ndb']}
        readiness=WebsiteReadiness(self.settings);self.assertTrue(readiness.selected_signatures(record))
        providers.save({'securiteinfo':{'website_databases':['spam_marketing.ndb']}})
        self.assertFalse(readiness.selected_signatures(record))

    def test_activation_rollback_and_recovery_preserve_both_daemon_directories(self):
        for name in ('website_config','mail_config'):
            path=self.base/name;path.write_text('# Managed by clamshield\nDatabaseDirectory /var/lib/clamav\n');path.chmod(0o644)
            setattr(self.manager,name,path)
        self.manager.mail_active=Mock(return_value=True);self.manager.daemon_ready=Mock();self.manager.mail_ready=Mock()
        self.manager.restart_mail=Mock()
        self.manager.validate=Mock()  # The real engine validated both profiles in setUp.
        with patch('clamshield.signatures.subprocess.run'):
            self.manager.activate(self.stage,self.manifest)
            for profile, name in [('website','website_config'),('mail','mail_config')]:
                self.assertIn(str(self.stage/profile)+'\n',getattr(self.manager,name).read_text())
            old=self.stage;self.manager.pointer('previous',old)
            self.manager.rollback()
            for profile,name in [('website','website_config'),('mail','mail_config')]:
                self.assertIn(str(old/profile)+'\n',getattr(self.manager,name).read_text())
            self.manager.mail_ready.side_effect=KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):self.manager.activate(self.stage,self.manifest)
            self.manager.mail_ready.side_effect=None
            self.assertTrue(self.manager.recover())
            self.assertIn(str(old/'mail')+'\n',self.manager.mail_config.read_text())
