import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.errors import ClamShieldError, EngineError
from clamshield.provider_catalog import SANE_FINGERPRINT
from clamshield.provider_fetch import Fetch, regular_copy
from clamshield.providers import Providers
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
    def test_invalid_local_database_cannot_pass_staging_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o755)
            settings = Settings(state=root / 'state')
            stage = root / 'generation-invalid'; stage.mkdir(mode=0o755)
            (stage / 'broken.hdb').write_text('this is not a ClamAV database\n')
            manifest = {'canary': {'payload': 'fixture', 'signature': 'ClamShield.Test'}}
            with self.assertRaises(EngineError):
                Signatures(settings).validate(stage, manifest)
