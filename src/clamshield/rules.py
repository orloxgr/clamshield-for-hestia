"""Stage and locally compile rule data using only Ubuntu's yarac executable."""
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen
import uuid
import zipfile

from .engines import engine_identity, sealed_file, Yara
from .errors import ClamShieldError, Conflict, EngineError
from .store import encode


def download(url, maximum):
    request = Request(url, headers={'User-Agent': 'ClamShield-for-Hestia/0.1'})
    with urlopen(request, timeout=45) as response:
        result = response.read(maximum + 1)
    if len(result) > maximum:
        raise ClamShieldError('Rules download exceeds the allowed size')
    return result


class Rules:
    def __init__(self, settings):
        self.settings = settings
        self.base = settings.state / 'rules'

    @contextmanager
    def locked(self):
        self.settings.prepare()
        self.base.mkdir(exist_ok=True, mode=0o700)
        if self.base.is_symlink():
            raise ClamShieldError('Unexpected rules directory')
        with (self.base / 'update.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def compile(self, source, destination):
        return self.compile_many({'default': source}, destination)

    def compile_many(self, sources, destination):
        if not 1 <= len(sources) <= 16 or any(not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,31}', n) for n in sources):
            raise ClamShieldError('Invalid compilation namespace')
        output = os.memfd_create('clamshield-compiled', os.MFD_ALLOW_SEALING)
        try:
            options = engine_identity()
            if options:
                os.fchown(output, options['user'], options['group'])
            os.fchmod(output, 0o600)
            with ExitStack() as stack:
                inputs = {namespace: stack.enter_context(sealed_file(source)) for namespace, source in sources.items()}
                def limits():
                    import resource
                    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
                    resource.setrlimit(resource.RLIMIT_CPU, (240, 240))
                    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2, 512 * 1024**2))
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                argv = [namespace + ':/proc/self/fd/' + str(fd) for namespace, fd in inputs.items()]
                result = subprocess.run(['/usr/bin/yarac', '-w', *argv, '/proc/self/fd/' + str(output)],
                                        pass_fds=(*inputs.values(), output), preexec_fn=limits, **options,
                                        capture_output=True, timeout=245,
                                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                if result.returncode:
                    raise EngineError('Rules are incompatible with the installed Ubuntu YARA')
            os.lseek(output, 0, os.SEEK_SET)
            with Path(destination).open('xb') as stream:
                while chunk := os.read(output, 1024 * 1024):
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EngineError('Rules compilation failed or timed out') from exc
        finally:
            os.close(output)

    def publish(self, content, metadata):
        with self.locked():
            release = self.base / ('generation-' + uuid.uuid4().hex)
            release.mkdir(mode=0o700)
            try:
                source = release / 'rules.yar'
                source.write_bytes(content)
                self.compile(source, release / 'rules.yarac')
                # Smoke-test loading and execution in the actual installed engine.
                empty = release / 'smoke-test'
                empty.write_bytes(b'ClamShield ruleset compatibility test')
                Yara('/usr/bin/yara', release / 'rules.yarac', timeout=20).scan(empty)
                empty.unlink()
                metadata = dict(metadata, sha256=hashlib.sha256(content).hexdigest(),
                                activated=time.time(), generation=release.name)
                (release / 'metadata.json').write_text(encode(metadata))
                for path in release.iterdir():
                    with path.open('rb') as stream:
                        os.fsync(stream.fileno())
                release_fd = os.open(release, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(release_fd)
                finally:
                    os.close(release_fd)
                current, previous = self.base / 'current', self.base / 'previous'
                for pointer in (current, previous):
                    if pointer.exists() and (not pointer.is_symlink() or pointer.resolve().parent != self.base):
                        raise ClamShieldError('Unexpected rules generation pointer')
                if current.is_symlink():
                    self.pointer(previous, current.resolve())
                self.pointer(current, release)
                return metadata
            except BaseException:
                # Only this newly created, fixed child of the owned rules folder.
                if not (self.base / 'current').is_symlink() or (self.base / 'current').resolve() != release:
                    shutil.rmtree(release)
                raise

    def pointer(self, path, target):
        temp = self.base / ('.pointer-' + uuid.uuid4().hex)
        temp.symlink_to(target.name)
        os.replace(temp, path)
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def fetch_forge(self, profile='core', release=None):
        if profile not in ('core', 'extended', 'full'):
            raise ClamShieldError('Invalid YARA Forge profile')
        if release is None:
            data = json.loads(download('https://api.github.com/repos/YARAHQ/yara-forge/releases/latest', 1024**2))
            release = data['tag_name']
        if not isinstance(release, str) or not re.fullmatch(r'\d{8}', release):
            raise ClamShieldError('Invalid YARA Forge release')
        url = f'https://github.com/YARAHQ/yara-forge/releases/download/{release}/yara-forge-rules-{profile}.zip'
        archive = download(url, 16 * 1024**2)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            path = f'packages/{profile}/yara-rules-{profile}.yar'
            members = [i for i in zipped.infolist() if i.filename == path]
            if len(members) != 1 or members[0].file_size > 64 * 1024**2:
                raise ClamShieldError('Invalid YARA Forge archive')
            # Read one canonical member; never extract arbitrary archive paths.
            content = zipped.read(members[0])
        if b'YARA-Forge YARA Rule Package' not in content[:1024]:
            raise ClamShieldError('Rules package header is missing')
        return content, {'provider': 'yara-forge', 'profile': profile,
                                      'version': release, 'source_url': url,
                                      'archive_sha256': hashlib.sha256(archive).hexdigest(),
                                      'licenses': 'Upstream license notices retained in original source'}

    def forge(self, profile='core', release=None):
        from .rule_updates import RuleUpdates
        def operation():
            content, metadata = self.fetch_forge(profile, release)
            return self.publish(content, metadata)
        return RuleUpdates(self.settings).run(profile, operation)

    def validate_generation(self, name):
        if not isinstance(name, str) or not re.fullmatch('generation-[a-zA-Z0-9_-]{1,80}', name):
            raise ClamShieldError('Invalid rules generation')
        release = self.base / name
        if release.is_symlink() or release.resolve().parent != self.base or not release.is_dir():
            raise ClamShieldError('Rules generation unavailable')
        metadata = json.loads((release / 'metadata.json').read_text())
        for filename, expected in metadata.get('files', {'rules.yar': metadata['sha256']}).items():
            if '/' in filename or '\\' in filename or filename.startswith('.'):
                raise ClamShieldError('Invalid rules generation manifest')
            path = release / filename
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise EngineError('Rules generation content verification failed')
        with tempfile.NamedTemporaryFile(dir=self.base) as sample:
            sample.write(b'ClamShield generation compatibility test'); sample.flush()
            Yara('/usr/bin/yara', release / 'rules.yarac', timeout=20).scan(Path(sample.name))
        return release, metadata

    def activate(self, name):
        with self.locked():
            release, metadata = self.validate_generation(name)
            current = self.base / 'current'
            if current.is_symlink():
                if current.resolve().parent != self.base:
                    raise ClamShieldError('Unexpected rules generation pointer')
                if current.resolve() == release:
                    return metadata
                self.pointer(self.base / 'previous', current.resolve())
            elif current.exists():
                raise ClamShieldError('Unexpected rules generation pointer')
            self.pointer(current, release)
            return metadata

    def rollback(self):
        with self.locked():
            current, previous = self.base / 'current', self.base / 'previous'
            if not current.is_symlink() or not previous.is_symlink():
                raise Conflict('No previous rules generation is available')
            old, new = current.resolve(), previous.resolve()
            if old.parent != self.base or new.parent != self.base:
                raise ClamShieldError('Unexpected rules generation pointer')
            new, metadata = self.validate_generation(new.name)
            self.pointer(current, new)
            self.pointer(previous, old)
            return metadata

    def status(self):
        current = self.base / 'current'
        if not current.is_symlink():
            return {'configured': False}
        actual = current.resolve()
        if actual.parent != self.base:
            raise ClamShieldError('Unexpected rules generation pointer')
        metadata=json.loads((actual / 'metadata.json').read_text())
        return {'configured': True, **{k:v for k,v in metadata.items() if k not in ('config','files')}}
