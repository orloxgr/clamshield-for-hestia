"""Pinned website ClamAV attribution; the caller holds the worker lock."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile

from .errors import ClamShieldError, EngineError
from .providers import Providers
from .signature_catalog import SignatureCatalog, validate_origin
from .signatures import Signatures
from . import signature_profiles as profiles


def advisory_kind(origin):
    """Use verified source identities, never a vendor-looking signature name."""
    kinds=set()
    for source in origin.get('origins') or [origin]:
        if source.get('category')=='spam':kinds.add('spam')
        elif (source.get('provider')=='securiteinfo' and
              source.get('source_id')=='securiteinfo--securiteinfo-pua-app-and-vulnerabilities.ndb'):
            kinds.add('software')
        else:return None  # A separate malware/phishing origin stays actionable.
    return next(iter(kinds)) if len(kinds)==1 else 'mixed'


class AttributedClamAV:
    name = 'clamav'

    def __init__(self, engine, resolver, generation, content):
        self.engine, self.resolver = engine, resolver
        self.generation, self.content = generation, content

    def scan(self, path):
        detections = []
        for hit in self.engine.scan(path):
            origin = validate_origin(self.resolver(hit['signature']))
            detection=dict(hit, **origin, signature_generation=self.generation,
                           signature_content_sha256=self.content)
            kind=advisory_kind(origin)
            if kind:detection.update(review_only=True,advisory_kind=kind)
            detections.append(detection)
        return detections


@contextmanager
def pinned(settings, engine, job_generation):
    """A job cannot attribute a daemon from another generation or use guesses.

    The worker lock excludes update/recovery for the full context lifetime.
    Catalog connections live only within this job; stored detections retain all
    origin fields independently of later updates, rollback and data retention.
    """
    manager = Signatures(settings)
    entered = False
    try:
        if (settings.state/'signature-activation.json').exists():
            raise EngineError('Signature generation recovery is pending')
        _yara, separator, expected = job_generation.partition('|clamav:')
        if not separator:
            raise EngineError('Website job has no pinned ClamAV generation')
        current = manager.base/'current'
        if current.exists() or current.is_symlink():
            manifest = manager.manifest()
            if not manifest or expected != manifest['generation']:
                raise EngineError('Website signature generation changed after job pinning')
            with SignatureCatalog(current.resolve(strict=True), manifest) as catalog:
                with tempfile.NamedTemporaryFile(dir=settings.snapshots) as sample:
                    canary = profiles.canary(manifest, 'website')
                    sample.write(canary['payload'].encode()); sample.flush()
                    hits = engine.scan(Path(sample.name))
                if not any(hit['signature'] == canary['signature']+'.UNOFFICIAL' for hit in hits):
                    raise EngineError('Website daemon has not loaded the pinned signature generation')
                from .website_coverage import verify
                verify(engine,settings)
                entered = True
                resolver = lambda signature: catalog.resolve(signature, sources=profiles.sources(manifest, 'website'))
                yield AttributedClamAV(engine, resolver, manifest['generation'], manifest['content_sha256'])
                return
        if expected != 'ubuntu-native':
            raise EngineError('Website pinned signature generation is unavailable')
        content = manager.read_daemon_config(manager.website_config)
        import re
        if re.findall(r'^DatabaseDirectory\s+(.+)$', content, re.M) != ['/var/lib/clamav']:
            raise EngineError('Website official-only configuration is not explicit')
        providers = Providers(settings).read()
        if providers['sanesecurity']['enabled'] or providers['securiteinfo']['enabled'] or any((settings.state/'local-signatures').glob('*')):
            raise EngineError('Additional website signatures require a catalog generation')
        def official_only(signature):
            if signature.endswith('.UNOFFICIAL'):
                raise EngineError('Website unofficial detection has no provenance catalog')
            phishing = signature.startswith(('Heuristics.Phishing.', 'Phishing.Heuristics.')) or signature.split('.')[1:2] == ['Phishing']
            return dict(category='phishing' if phishing else 'malware', provider='clamav',
                        source_id='official-databases', source_version='native-freshclam',
                        attribution='official-only-native-data')
        from .website_coverage import verify
        verify(engine,settings)
        entered = True
        yield AttributedClamAV(engine, official_only, 'ubuntu-native', 'native-freshclam')
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        if entered:
            raise
        raise EngineError('Website signature provenance is unavailable or changed') from exc
