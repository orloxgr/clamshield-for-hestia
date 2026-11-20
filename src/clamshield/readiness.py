"""Read-only website readiness against the actual loaded data, not VERSION."""
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .engines import ClamAV
from .errors import ClamShieldError, EngineError
from .generations import current
from .providers import Providers
from .rule_manager import revision
from .rules import Rules
from .signatures import Signatures
from .website_generation import pinned


class WebsiteReadiness:
    def __init__(self, settings):
        self.settings = settings

    @contextmanager
    def lock(self, path):
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_nlink != 1 or info.st_mode & 0o022):
                raise EngineError('Readiness lock is not protected')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def selected_signatures(self, manifest):
        config = Providers(self.settings).read()
        if {key for key in ('official', 'securiteinfo', 'sanesecurity', 'local') if config[key]['enabled']} != set(manifest['providers']):
            return False
        for provider in ('securiteinfo', 'sanesecurity'):
            expected = {provider + '--' + name for name in config[provider]['databases']} if config[provider]['enabled'] else set()
            if expected != {row['name'] for row in manifest['files'] if row['provider'] == provider}:
                return False
        expected = {}
        folder = self.settings.state / 'local-signatures'
        if config['local']['enabled'] and folder.exists():
            if folder.is_symlink():
                raise EngineError('Local signature storage is not protected')
            for path in folder.iterdir():
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                            info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 4 * 1024**2):
                        raise EngineError('Local signature data is not protected')
                    data = stream.read(4 * 1024**2 + 1)
                    if len(data) > 4 * 1024**2:
                        raise EngineError('Local signature data exceeds its allowance')
                expected['local--' + path.name] = hashlib.sha256(data).hexdigest()
        return expected == {row['name']: row['sha256'] for row in manifest['files'] if row['provider'] == 'local'}

    def clamav(self):
        try:
            engine = ClamAV(self.settings.clamd_socket, timeout=3)
            with pinned(self.settings, engine, current(self.settings)) as bound:
                with tempfile.NamedTemporaryFile(dir=self.settings.snapshots) as sample:
                    sample.write(b'ClamShield inert website readiness input.'); sample.flush()
                    if bound.scan(Path(sample.name)):
                        raise EngineError('The readiness input was detected')
                generation = bound.generation
            manifest = Signatures(self.settings).manifest()
            if manifest and not self.selected_signatures(manifest):
                return dict(state='pending', message='Saved signature selection needs activation.', generation=generation)
            return dict(state='ready', message='Loaded signatures and provenance verified.', generation=generation)
        except (OSError, ValueError, KeyError, TypeError, ClamShieldError):
            return dict(state='unavailable', message='Website signatures could not be verified; review activation and scanner status.')

    def yara(self):
        from .yara_settings import YaraSettings
        if not YaraSettings(self.settings).read()['enabled']:
            return dict(state='disabled',message='YARA website scanning is disabled by the administrator.')
        try:
            rules = Rules(self.settings); pointer = rules.base / 'current'
            if not pointer.is_symlink() or not self.settings.rules.is_file():
                return dict(state='missing', message='No validated YARA rules are active.')
            generation = pointer.resolve().name
            if pointer.resolve().parent != rules.base or self.settings.rules.resolve() != pointer.resolve() / 'rules.yarac':
                raise EngineError('Website YARA rules differ from the managed generation')
            _path, metadata = rules.validate_generation(generation)
            config_path = self.settings.state / 'rules-config.json'
            if config_path.exists() or config_path.is_symlink():
                if config_path.is_symlink():
                    raise EngineError('Rule configuration is not protected')
                config = json.loads(config_path.read_text())
                desired = revision(config)
                pending = (metadata['config_sha256'] != desired) if 'config_sha256' in metadata else bool(config['sources'] or config['disabled'])
                if pending:
                    return dict(state='pending', message='Saved YARA selection needs building and activation.', generation=generation)
            return dict(state='ready', message='Active YARA data loaded and verified.', generation=generation)
        except (OSError, ValueError, KeyError, TypeError, ClamShieldError):
            return dict(state='unavailable', message='Active YARA rules could not be verified; review the rule candidate and scanner status.')

    def check(self):
        """None means busy: never refresh an old verification time in that case."""
        try:
            self.settings.prepare()
            with ExitStack() as stack:
                stack.enter_context(self.lock(self.settings.state / 'worker.lock'))
                if any((self.settings.state / name).exists() for name in ('install-pending.json', 'uninstall.json', 'resources-activation.json', 'website-engine-activation.json')):
                    return dict(state='incomplete', message='Website scanner maintenance or recovery is pending.')
                rules = self.settings.state / 'rules'
                rules.mkdir(mode=0o700, exist_ok=True)
                info = rules.lstat()
                if rules.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise EngineError('Rule storage is not protected')
                stack.enter_context(self.lock(rules / 'update.lock'))
                clamav, yara = self.clamav(), self.yara()
                ready = clamav['state'] == 'ready' and yara['state'] in ('ready','disabled')
                return dict(state='healthy' if ready else 'incomplete', clamav=clamav, yara=yara,
                            message='Website engines and selected scanning data are ready.' if ready else 'Website coverage needs attention. ' + ' '.join(row['message'] for row in (clamav, yara) if row['state'] != 'ready'))
        except BlockingIOError:
            return None
        except (OSError, ValueError, KeyError, TypeError, ClamShieldError):
            return dict(state='unavailable', message='Website readiness could not be verified.')


def public_status(value, now):
    """A cached successful probe is not a current assurance after 90 seconds."""
    if not isinstance(value, dict) or not value:
        return dict(state='unknown', message='Website readiness has not been verified yet.', checked=None)
    result = dict(value)
    checked = result.get('checked')
    if type(checked) not in (int, float) or not 0 <= checked <= now:
        result.update(state='unknown', message='Website readiness needs a fresh check.', checked=None)
    elif now - checked > 90:
        result.update(state='unknown', message='Website readiness needs a fresh check.')
    elif result.get('verification_deferred'):
        result.update(state='checking', message='Readiness verification waits for an active scan or update.')
    return result
