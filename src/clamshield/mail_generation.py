"""Hold the mail generation stable through readiness, scanning and attribution."""
import fcntl
import os
from pathlib import Path
import re
import stat
import time

from .errors import ClamShieldError, EngineError
from .mail_bridge import SEALS
from .mail_scanners import MailScanner, digest_snapshot
from .providers import Providers
from .signature_catalog import SignatureCatalog, engine_lock
from .signatures import Signatures
from . import signature_profiles as profiles


class GenerationMailScanner:
    def __init__(self, settings, clamav, spamassassin, *, yara=None, timeout=25):
        self.settings, self.clamav, self.spamassassin = settings, clamav, spamassassin
        self.yara, self.timeout = yara, timeout

    def _canary(self, manifest, deadline):
        manifest = dict(manifest, canary=profiles.canary(manifest, 'mail'))
        fd = os.memfd_create('clamshield-mail-generation', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            os.write(fd, manifest['canary']['payload'].encode())
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
            hits = self.clamav.scan(fd, deadline=deadline)
            if manifest['canary']['signature'] + '.UNOFFICIAL' not in hits:
                raise EngineError('Mail daemon has not loaded the pinned signature generation')
        finally:
            os.close(fd)

    def _legacy_official(self):
        """Existing official-only lab installs remain explicit, never a fallback."""
        path = Path('/etc/clamshield/mail-clamd.conf'); info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise EngineError('Mail ClamAV configuration is not trusted')
        config = path.read_text()
        if '# Managed by clamshield' not in config or re.findall(r'^DatabaseDirectory\s+(.+)$', config, re.M) != ['/var/lib/clamav']:
            raise EngineError('Mail generation is not configured')
        providers = Providers(self.settings).read()
        if providers['sanesecurity']['enabled'] or providers['securiteinfo']['enabled'] or any((self.settings.state / 'local-signatures').glob('*')):
            raise EngineError('Additional signatures require an activated catalog generation')

    def scan(self, fd):
        deadline = time.monotonic() + self.timeout
        try:
            with engine_lock(self.settings):
                from .spamassassin import SpamAssassinControls
                controls = SpamAssassinControls(self.settings)
                if controls.journal.exists():
                    raise EngineError('SpamAssassin configuration recovery is pending')
                spam_config = controls.configured()
                spamassassin = self.spamassassin
                if spam_config:
                    from .spamassassin_binding import BoundSpamAssassin
                    spamassassin = BoundSpamAssassin(spamassassin, controls, spam_config['policy'])
                if (self.settings.state / 'signature-activation.json').exists():
                    raise EngineError('Signature generation recovery is pending')
                manager = Signatures(self.settings); current = manager.base / 'current'
                if current.exists() or current.is_symlink():
                    manifest = manager.manifest()
                    if not manifest:
                        raise EngineError('Invalid current signature generation')
                    if profiles.shared(manifest) and getattr(self.clamav,'all_matches',False) is not True:
                        raise EngineError('Shared native mail databases require complete all-match scan results')
                    with SignatureCatalog(current.resolve(strict=True), manifest) as catalog:
                        self._canary(manifest, deadline)
                        lookup=catalog.selected if profiles.shared(manifest) else catalog.resolve
                        result = MailScanner(self.clamav, spamassassin, yara=self.yara,
                            resolve_signature=lambda signature: lookup(signature, sources=profiles.sources(manifest, 'mail')),
                            timeout=max(.001, deadline-time.monotonic())).scan(fd)
                        result['signature_generation'] = manifest['generation']
                        result['signature_content_sha256'] = manifest['content_sha256']
                        if spam_config:
                            result['spamassassin_revision'] = spam_config['revision']
                        return result
                self._legacy_official()
                def official_only(signature):
                    if signature.endswith('.UNOFFICIAL'):
                        raise EngineError('Unofficial detection has no pinned provenance generation')
                    phishing = signature.startswith(('Heuristics.Phishing.', 'Phishing.Heuristics.')) or signature.split('.')[1:2] == ['Phishing']
                    return dict(provider='clamav', category='phishing' if phishing else 'malware', source_id='official-databases',
                                attribution='official-only-native-data', source_version='native-freshclam')
                result = MailScanner(self.clamav, spamassassin, yara=self.yara, resolve_signature=official_only,
                                     timeout=max(.001, deadline-time.monotonic())).scan(fd)
                if spam_config:
                    result['spamassassin_revision'] = spam_config['revision']
                return result
        except (OSError, ClamShieldError, ValueError, KeyError) as exc:
            return dict(complete=False, sha256=digest_snapshot(fd), spam_score=None, spam_symbols=[], detections=[], errors=[type(exc).__name__])
