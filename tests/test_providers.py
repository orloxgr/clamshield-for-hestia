import json
import os
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from clamshield.errors import ClamShieldError, EngineError
from clamshield.provider_catalog import SANE_FINGERPRINT, SANE, recommended
from clamshield.provider_fetch import Fetch, regular_copy
from clamshield.providers import Providers, DEFAULTS, UPDATE_POLICIES
from clamshield.settings import Settings
from clamshield.signatures import Signatures


class ProviderConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name) / 'state')
        self.providers = Providers(self.settings)

    def test_secret_never_appears_in_public_settings_and_masked_save_preserves_it(self):
        secret = 'a' * 128
        value = self.providers.save({'securiteinfo': {'key': secret, 'enabled': True}})
        self.assertNotIn(secret, json.dumps(value))
        self.assertTrue(value['securiteinfo']['has_key'])
        self.providers.save({'securiteinfo': {'key': ''}})
        self.assertEqual(secret, self.providers.read()['securiteinfo']['key'])
        self.assertEqual(0o600, self.providers.path.stat().st_mode & 0o777)

    def test_paid_databases_cannot_be_selected_with_basic_plan(self):
        with self.assertRaises(ClamShieldError):
            self.providers.save({'securiteinfo': {'databases': ['securiteinfo0hour.hdb']}})
        self.assertFalse(self.providers.path.exists())
        self.providers.save({'securiteinfo': {'plan': 'professional', 'databases': ['securiteinfo0hour.hdb']}})
        self.assertIn('securiteinfo.ign2', self.providers.read()['securiteinfo']['databases'])

    def test_new_installation_gets_scoped_defaults_only_once(self):
        value = self.providers.initialize(existing=False)
        self.assertNotIn('spam.ldb', value['sanesecurity']['website_databases'])
        self.assertIn('spam.ldb', value['sanesecurity']['mail_databases'])
        self.providers.save({'sanesecurity': {'website_databases': ['rogue.hdb'], 'mail_databases': ['junk.ndb']}})
        saved = self.providers.path.read_bytes()
        self.providers.initialize(existing=True); self.providers.initialize(existing=False)
        self.assertEqual(saved, self.providers.path.read_bytes())

    def test_upgrade_preserves_legacy_custom_selections_in_both_profiles(self):
        self.settings.prepare()
        legacy = {'automatic': False, 'securiteinfo': {'plan': 'professional', 'key': 'a'*128,
            'enabled': True, 'databases': ['securiteinfo.ign2', 'spam_marketing.ndb', 'securiteinfo-pua-app-and-vulnerabilities.ndb']},
            'sanesecurity': {'enabled': True, 'databases': ['sanesecurity.ftm', 'sigwhitelist.ign2', 'badmacro.ndb']}}
        self.providers.path.write_text(json.dumps(legacy)); before = self.providers.path.read_bytes()
        value = self.providers.initialize(existing=True)
        self.assertEqual(before, self.providers.path.read_bytes())
        for name in ('securiteinfo', 'sanesecurity'):
            for profile in ('website', 'mail'):
                self.assertEqual(legacy[name]['databases'], value[name][profile+'_databases'])
        self.providers.save({'official': {'interval_minutes': 120}})
        self.assertEqual(set(legacy['securiteinfo']['databases']), set(self.providers.read()['securiteinfo']['website_databases']))

    def test_existing_installation_without_provider_file_keeps_old_defaults(self):
        self.settings.prepare(); self.settings.database.touch()
        before = self.providers.read()
        self.assertEqual(before['sanesecurity']['website_databases'], before['sanesecurity']['mail_databases'])
        self.assertNotIn('spam.ldb', before['sanesecurity']['mail_databases'])
        self.assertEqual(before, self.providers.initialize(existing=True))

    def test_paid_presets_exclude_pua_and_high_risk_but_keep_malware_in_both_profiles(self):
        with patch.dict(SANE, {'future-high.ndb': ('High-risk fixture', 'high', 'malware')}):
            for plan in ('basic', 'professional', 'gold', 'reseller'):
                value = recommended(plan)
                for name, section in value.items():
                    for names in section.values():
                        self.assertNotIn('future-high.ndb', names)
                        self.assertNotIn('securiteinfo-pua-app-and-vulnerabilities.ndb', names)
                if plan != 'basic':
                    self.assertIn('javascript.ndb', value['securiteinfo']['website_databases'])
                    self.assertIn('javascript.ndb', value['securiteinfo']['mail_databases'])
                    self.assertNotIn('spam_marketing.ndb', value['securiteinfo']['website_databases'])
                    self.assertIn('spam_marketing.ndb', value['securiteinfo']['mail_databases'])

    def test_profile_saves_download_union_and_validate_each_selection(self):
        self.providers.save({'securiteinfo': {'plan': 'professional', 'website_databases': ['javascript.ndb'],
                                            'mail_databases': ['spam_marketing.ndb']}})
        section = self.providers.read()['securiteinfo']
        self.assertEqual(['javascript.ndb', 'securiteinfo.ign2'], section['website_databases'])
        self.assertEqual(['securiteinfo.ign2', 'spam_marketing.ndb'], section['mail_databases'])
        self.assertEqual(['javascript.ndb', 'securiteinfo.ign2', 'spam_marketing.ndb'], section['databases'])
        for key in ('website_databases', 'mail_databases'):
            for invalid in (['../../outside.ndb'], 'spam_marketing.ndb', [True]):
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ClamShieldError):
                    self.providers.save({'securiteinfo': {key: invalid}})

    def test_server_wide_choices_are_explicit_and_existing_conflicts_never_normalize_on_read_or_schedule_save(self):
        self.providers.initialize(existing=False)
        value=self.providers.read();value['securiteinfo']['plan']='professional'
        value['securiteinfo']['mail_databases'].append('securiteinfo.pdb')
        self.providers.path.write_text(json.dumps(value));before=self.providers.path.read_bytes()
        self.assertEqual(['securiteinfo.pdb'],self.providers.public()['selection_conflicts']['securiteinfo'])
        self.providers.initialize(existing=True);self.assertEqual(before,self.providers.path.read_bytes())
        self.providers.save({'securiteinfo':{'interval_minutes':120}})
        self.assertNotIn('securiteinfo.pdb',self.providers.read()['securiteinfo']['website_databases'])
        with self.assertRaises(ClamShieldError):
            self.providers.save({'securiteinfo':{'mail_databases':['securiteinfo.pdb']}})
        self.providers.save({'securiteinfo':{'shared_databases':['securiteinfo.ign2','securiteinfo.pdb']}})
        for purpose in ('website','mail'):
            self.assertIn('securiteinfo.pdb',self.providers.read()['securiteinfo'][purpose+'_databases'])
        self.assertEqual([],self.providers.public()['selection_conflicts']['securiteinfo'])
        with self.assertRaises(ClamShieldError):self.providers.save({'securiteinfo':{'shared_databases':['javascript.ndb']}})

    def test_recommended_new_defaults_have_compatible_shared_databases(self):
        from clamshield.provider_catalog import server_wide
        for plan in ('basic','professional','gold','reseller'):
            for section in recommended(plan).values():
                self.assertFalse(any(server_wide(item) for item in set(section['website_databases'])^set(section['mail_databases'])))

    def test_separate_update_and_provider_forms_preserve_each_others_saved_fields(self):
        self.providers.save({'automatic':False,'official':{'interval_minutes':180},
                             'securiteinfo':{'interval_minutes':120},'sanesecurity':{'interval_minutes':90}})
        self.providers.save({'securiteinfo':{'plan':'professional','key':'a'*128,'enabled':True,
            'website_databases':['javascript.ndb'],'mail_databases':['spam_marketing.ndb']}})
        value=self.providers.read()
        self.assertFalse(value['automatic']);self.assertEqual(120,value['securiteinfo']['interval_minutes'])
        choices=value['securiteinfo'].copy()
        self.providers.save({'automatic':True,'official':{'interval_minutes':60},'securiteinfo':{'interval_minutes':240}})
        after=self.providers.read()
        self.assertTrue(after['automatic']);self.assertEqual(240,after['securiteinfo']['interval_minutes'])
        choices['interval_minutes']=240
        self.assertEqual(choices,after['securiteinfo']);self.assertEqual(90,after['sanesecurity']['interval_minutes'])

    def test_catalog_does_not_invent_risk_ratings(self):
        catalog = self.providers.public()['catalog']
        self.assertTrue(all(row['risk'] in ('not-rated', 'not-applicable') for row in catalog['securiteinfo']))
        self.assertTrue(all(row['risk_url'] for row in catalog['sanesecurity']))

    def test_explicit_high_risk_selection_survives_updates_without_reapplying_presets(self):
        with patch.dict(SANE, {'future-high.ndb': ('High-risk fixture', 'high', 'malware')}):
            self.providers.save({'sanesecurity': {'website_databases': ['future-high.ndb'], 'mail_databases': []}})
            before = self.providers.path.read_bytes()
            self.providers.initialize(existing=True)
            for _ in range(3):
                value = self.providers.public()
                self.assertIn('future-high.ndb', value['sanesecurity']['website_databases'])
            self.assertEqual(before, self.providers.path.read_bytes())

    def test_database_names_and_credentials_cannot_inject_updater_configuration(self):
        for incoming in ({'key': 'a' * 64 + '\nOnUpdateExecute bad'}, {'databases': ['../../evil.ndb']}):
            with self.assertRaises(ClamShieldError):
                self.providers.save({'securiteinfo': incoming})

    def test_required_sane_companion_files_cannot_be_omitted(self):
        self.providers.save({'sanesecurity': {'databases': ['phish.ndb']}})
        self.assertEqual(['phish.ndb','sanesecurity.ftm','sigwhitelist.ign2'], self.providers.read()['sanesecurity']['databases'])

    def test_local_signature_path_cannot_escape_owned_storage(self):
        for name in ('../bad.hdb', '/tmp/bad.hdb', 'bad.cbc', 'bad.hdb\n'):
            with self.subTest(name=name), self.assertRaises(ClamShieldError):
                self.providers.save_local(name, 'fixture')
        self.providers.save_local('hosting.hdb', 'fixture')
        self.assertEqual(['hosting.hdb'], self.providers.public()['local']['files'])

    def test_interval_validation_never_accepts_a_faster_provider_check(self):
        for name in UPDATE_POLICIES:
            for value in (0, 59, -1, True, 60.0, '60', 525601):
                with self.subTest(name=name,value=value), self.assertRaises(ClamShieldError):
                    self.providers.save({name:{'interval_minutes':value}})
            self.providers.save({name:{'interval_minutes':90}})
            self.assertEqual(90,self.providers.public()[name]['interval_minutes'])
        for plan in ('basic','professional','gold','reseller'):
            self.providers.save({'securiteinfo':{'plan':plan,'interval_minutes':60}})
            self.assertEqual(60,self.providers.public()['schedule']['securiteinfo']['minimum_minutes'])

    def test_legacy_settings_gain_intervals_without_losing_key_database_selection_or_switches(self):
        self.settings.prepare();old=json.loads(json.dumps(DEFAULTS))
        for name in ('securiteinfo','sanesecurity'):
            old[name].pop('website_databases');old[name].pop('mail_databases')
        for name in UPDATE_POLICIES:old[name].pop('interval_minutes')
        old['automatic']=False;old['securiteinfo'].update(key='b'*128,plan='professional',databases=['securiteinfo.ign2','securiteinfo0hour.hdb'])
        self.providers.path.write_text(json.dumps(old))
        value=self.providers.public();self.assertFalse(value['automatic'])
        self.assertEqual(['securiteinfo.ign2','securiteinfo0hour.hdb'],value['securiteinfo']['databases'])
        self.assertEqual('b'*128,self.providers.read()['securiteinfo']['key']);self.assertNotIn('b'*128,json.dumps(value))
        self.assertTrue(all(value[name]['interval_minutes']==60 for name in UPDATE_POLICIES))

    def test_next_allowed_uses_saved_interval_last_success_and_longer_upstream_cooldown(self):
        self.providers.save({'securiteinfo':{'interval_minutes':120}})
        self.providers.status('securiteinfo',last_attempt=1000,last_success=1100)
        self.assertFalse(self.providers.due('securiteinfo',8299));self.assertTrue(self.providers.due('securiteinfo',8300))
        self.providers.status('securiteinfo',retry_after=20000)
        self.providers.save({'securiteinfo':{'interval_minutes':60}})
        self.assertFalse(self.providers.due('securiteinfo',19999));self.assertTrue(self.providers.due('securiteinfo',20000))
        self.assertEqual(20000,self.providers.public()['schedule']['securiteinfo']['next_allowed'])

    def test_invalid_persisted_interval_fails_closed(self):
        self.settings.prepare();value=json.loads(json.dumps(DEFAULTS));value['official']['interval_minutes']=1
        self.providers.path.write_text(json.dumps(value))
        with self.assertRaises(ClamShieldError):self.providers.due('official')

    def test_concurrent_manual_updates_share_the_persisted_interval_gate(self):
        manager=Signatures(self.settings);manager.seed_official=Mock();manager.stage=Mock(return_value=(None,{'generation':'fixture'}))
        manager.fetch.freshclam=Mock()
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:manager.update(provider='official'),range(8)))
        self.assertEqual(1,manager.fetch.freshclam.call_count)
        restarted=Fetch(self.settings,Providers(self.settings));restarted.freshclam=Mock()
        self.assertTrue(restarted.refresh('official',self.providers.read()['official'])['used_cache'])
        restarted.freshclam.assert_not_called()

    def test_interrupted_download_still_consumes_the_interval(self):
        fetch=Fetch(self.settings,self.providers);fetch.freshclam=Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):fetch.refresh('official',DEFAULTS['official'])
        fetch.freshclam=Mock();self.assertTrue(fetch.refresh('official',DEFAULTS['official'])['used_cache']);fetch.freshclam.assert_not_called()

    def test_freshclam_cooldown_is_persisted_without_exposing_credential_output(self):
        self.providers.save({'securiteinfo':{'key':'c'*128,'plan':'professional'}})
        fetch=Fetch(self.settings,self.providers);cache=Path(self.temp.name)/'cache';cache.mkdir();fetch.cache=Mock(return_value=cache)
        raw=b'private https://www.securiteinfo.com/'+b'c'*128+b'\nWARNING: You are still on cool-down until after: 2099-01-02 03:04:05\n'
        with patch('clamshield.provider_fetch.subprocess.run',return_value=Mock(returncode=17,stdout=raw,stderr=b'')) as run:
            with self.assertRaises(ClamShieldError) as error:fetch.refresh('securiteinfo',self.providers.read()['securiteinfo'])
        self.assertNotIn('c'*128,str(error.exception));self.assertEqual('UTC',run.call_args.kwargs['env']['TZ'])
        deadline=datetime(2099,1,2,3,4,5,tzinfo=timezone.utc).timestamp()
        self.assertEqual(deadline,self.providers.public()['schedule']['securiteinfo']['next_allowed'])
        self.assertNotIn('c'*128,json.dumps(self.providers.public()));self.assertNotIn('https:',json.dumps(self.providers.public()['status']))
        self.providers.save({'securiteinfo':{'interval_minutes':60}})
        fetch.freshclam=Mock();self.assertTrue(fetch.refresh('securiteinfo',self.providers.read()['securiteinfo'])['used_cache']);fetch.freshclam.assert_not_called()


class Verification(unittest.TestCase):
    def test_generation_canary_is_readable_under_private_service_umask(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o755)
            settings = Settings(state=root / 'state')
            manager = Signatures(settings)
            cache = root / 'official'; cache.mkdir()
            for name in ('main.cvd','daily.cvd','bytecode.cvd'):
                (cache / name).write_text('fixture')
            manager.fetch.cache = Mock(return_value=cache)
            def check_permissions(stage, manifest):
                self.assertEqual(0o644, (stage / 'clamshield-generation.hdb').stat().st_mode & 0o777)
                self.assertEqual(0o755, stage.stat().st_mode & 0o777)
            manager.validate = check_permissions
            previous = os.umask(0o077)
            try:
                with manager.locked():
                    manager.stage(manager.providers.read())
            finally:
                os.umask(previous)

    def test_only_pinned_primary_or_signing_fingerprint_is_accepted(self):
        settings = Settings()
        fetch = Fetch(settings, Mock())
        fields = '[GNUPG:] VALIDSIG ' + SANE_FINGERPRINT + ' 2026-11-18 0 0 0 4 0 1 10 00 ' + SANE_FINGERPRINT
        fetch.gpg = Mock(return_value=Mock(returncode=0, stdout=fields.encode()))
        fetch.verify_sane(Path('/fixture'), Path('/fixture.sig'), Path('/gpg'))
        fetch.gpg.return_value = Mock(returncode=0, stdout=fields.replace(SANE_FINGERPRINT,'F'*40).encode())
        with self.assertRaises(ClamShieldError):
            fetch.verify_sane(Path('/fixture'), Path('/fixture.sig'), Path('/gpg'))

    def test_bad_signature_and_multiple_valid_records_are_rejected(self):
        fetch = Fetch(Settings(), Mock())
        fetch.gpg = Mock(return_value=Mock(returncode=1, stdout=b'[GNUPG:] BADSIG test'))
        with self.assertRaises(ClamShieldError):
            fetch.verify_sane(Path('/fixture'), Path('/fixture.sig'), Path('/gpg'))
        valid = ('[GNUPG:] VALIDSIG ' + SANE_FINGERPRINT + ' 2026-11-18 0 0 0 4 0 1 10 00 ' + SANE_FINGERPRINT).encode()
        for output in (valid + b'\n' + valid, b'[GNUPG:] VALIDSIG'):
            fetch.gpg.return_value = Mock(returncode=0, stdout=output)
            with self.subTest(output=output), self.assertRaises(ClamShieldError):
                fetch.verify_sane(Path('/fixture'), Path('/fixture.sig'), Path('/gpg'))

    def test_cache_symlink_is_never_copied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'real').write_text('fixture'); (root / 'link').symlink_to(root / 'real')
            with self.assertRaises(OSError):
                regular_copy(root / 'link', root / 'output')

    def test_securiteinfo_urls_are_only_given_to_freshclam_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(state=Path(temp) / 'state')
            providers = Providers(settings)
            fetch = Fetch(settings, providers)
            config = providers.read()['securiteinfo'] | {'key': 'b' * 128}
            text = fetch.freshclam_config('securiteinfo', config, Path('/var/lib/clamshield-cache/securiteinfo'))
            self.assertIn('DatabaseCustomURL https://www.securiteinfo.com/get/signatures/' + 'b'*128 + '/securiteinfoold.hdb', text)
            self.assertNotIn('OnUpdateExecute', text)


@unittest.skipUnless(Path('/usr/bin/clamscan').is_file(), 'Ubuntu ClamAV validation')
class ActualDatabaseValidation(unittest.TestCase):
    def test_age_warning_does_not_hide_validation_failure(self):
        from clamshield.signatures import STALE_WARNING
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);settings=Settings(state=root/'state');settings.prepare()
            stage=root/'generation-fixture';stage.mkdir()
            clean=stage/'.validation-clean';canary=stage/'.validation-canary'
            output=(str(clean)+': OK\n'+str(canary)+': Fixture.UNOFFICIAL FOUND\n').encode()
            result=Mock(returncode=1,stdout=output,stderr=STALE_WARNING)
            with patch('clamshield.signatures.subprocess.run',return_value=result):
                manifest={'canary':{'payload':'fixture','signature':'Fixture'}}
                Signatures(settings).validate(stage,manifest)
                self.assertIn('official_database_age',manifest['validation_warnings'])
                for changed in (dict(stderr=STALE_WARNING+b'LibClamAV Error: invalid database\n'),
                                dict(stdout=output.replace(b': OK',b': ERROR')),dict(returncode=2)):
                    failed=Mock(returncode=1,stdout=output,stderr=STALE_WARNING)
                    for key,value in changed.items():setattr(failed,key,value)
                    with patch('clamshield.signatures.subprocess.run',return_value=failed),self.assertRaises(EngineError):
                        Signatures(settings).validate(stage,{'canary':{'payload':'fixture','signature':'Fixture'}})

    def test_invalid_local_database_cannot_pass_staging_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o755)
            settings = Settings(state=root / 'state')
            stage = root / 'generation-invalid'; stage.mkdir(mode=0o755)
            (stage / 'broken.hdb').write_text('this is not a ClamAV database\n')
            manifest = {'canary': {'payload': 'fixture', 'signature': 'ClamShield.Test'}}
            with self.assertRaises(EngineError):
                Signatures(settings).validate(stage, manifest)
