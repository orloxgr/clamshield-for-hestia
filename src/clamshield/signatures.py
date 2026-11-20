"""Validated immutable data generations shared by the owned website/mail daemons."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

from .atomic import sync_directory, write, write_json
from .engines import ClamAV, engine_identity
from .errors import ClamShieldError, Conflict, EngineError
from .provider_fetch import Fetch, regular_copy
from .providers import Providers
from .provider_catalog import MAX_DATABASE_BYTES
from .signature_catalog import build as build_catalog, POLICY as CATALOG_POLICY, SignatureCatalog, engine_lock


class Signatures:
    website_config = Path('/etc/clamshield/clamd.conf')
    mail_config = Path('/etc/clamshield/mail-clamd.conf')

    def __init__(self, settings):
        self.settings = settings
        self.base = settings.signatures
        self.providers = Providers(settings)
        self.fetch = Fetch(settings, self.providers)

    @contextmanager
    def locked(self):
        self.settings.prepare()
        if self.base.is_symlink():
            raise ClamShieldError('Unexpected signatures directory')
        self.base.mkdir(mode=0o755, exist_ok=True)
        with (self.settings.state / 'signature-update.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @contextmanager
    def activation_lock(self):
        # A website job can be long. Keep mail on its current generation while
        # waiting for that job, then acquire mail exclusion immediately before
        # changing engines/data. No mail request takes the website worker lock.
        fd = os.open(self.settings.state / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
                raise EngineError('Website engine lock is not trusted')
            fcntl.flock(fd, fcntl.LOCK_EX)
            with engine_lock(self.settings, exclusive=True, blocking=True):
                yield
        finally:
            os.close(fd)

    def seed_official(self):
        cache = self.fetch.cache('official')
        if any(cache.glob('main.c[vl]d')):
            return
        import pwd
        identity = pwd.getpwnam('clamav')
        for source in Path('/var/lib/clamav').iterdir():
            if re.fullmatch(r'(?:main|daily|bytecode)(?:-\d+)?\.(?:cvd|cld)(?:\.sign)?', source.name):
                destination = cache / source.name
                if not destination.exists():
                    regular_copy(source, destination)
                    os.chown(destination, identity.pw_uid, identity.pw_gid)

    def stage(self, config, *, reuse_current=False):
        stage = Path(tempfile.mkdtemp(prefix='generation-', dir=self.base))
        stage.chmod(0o755)
        manifest = {'files': [], 'providers': [], 'generation': stage.name, 'created': time.time()}
        try:
            for name in ('official', 'securiteinfo', 'sanesecurity', 'local'):
                if not config[name]['enabled']:
                    continue
                if name == 'official':
                    cache = self.fetch.cache(name)
                    files = []
                    for stem in ('main', 'daily', 'bytecode'):
                        chosen = next((p for ext in ('.cld', '.cvd') if (p := cache / (stem + ext)).is_file()), None)
                        if chosen is None:
                            raise ClamShieldError('Official ClamAV databases have not been downloaded')
                        files.append(chosen.name)
                    files.extend(p.name for p in cache.iterdir() if re.fullmatch(r'(main|daily|bytecode)-\d+\.cvd\.sign', p.name))
                elif name == 'local':
                    cache = self.settings.state / 'local-signatures'
                    files = sorted(p.name for p in cache.iterdir()) if cache.exists() else []
                else:
                    cache = self.fetch.cache(name)
                    files = config[name]['databases']
                for filename in files:
                    if '/' in filename or '\\' in filename or filename.startswith('.'):
                        raise ClamShieldError('Invalid signature filename')
                    destination = stage / (filename if name == 'official' else name + '--' + filename)
                    digest = regular_copy(cache / filename, destination)
                    if name == 'sanesecurity':
                        signature = stage / (destination.name + '.sig')
                        regular_copy(cache / (filename + '.sig'), signature, maximum=1024**2)
                        self.fetch.verify_sane(destination, signature)
                    manifest['files'].append({'provider': name, 'name': destination.name, 'sha256': digest,
                                              'size': destination.stat().st_size})
                manifest['providers'].append(name)
            if not any(row['provider'] == 'official' for row in manifest['files']):
                raise ClamShieldError('Official signatures are required')
            return self.complete_stage(stage, manifest, reuse_current=reuse_current)
        except BaseException:
            shutil.rmtree(stage)
            raise

    def complete_stage(self, stage, manifest, *, reuse_current=False):
        identity = json.dumps({'files': manifest['files'], 'catalog_policy': CATALOG_POLICY}, sort_keys=True, separators=(',', ':')).encode()
        manifest['content_sha256'] = hashlib.sha256(identity).hexdigest()
        payload = b'ClamShield generation validation ' + stage.name.encode()
        signature_name = 'ClamShield.Generation.' + stage.name.removeprefix('generation-')
        (stage / 'clamshield-generation.hdb').write_text(
            hashlib.md5(payload).hexdigest() + ':' + str(len(payload)) + ':' + signature_name + '\n')
        (stage / 'clamshield-generation.hdb').chmod(0o644)
        manifest['canary'] = {'payload': payload.decode(), 'signature': signature_name}
        self.validate(stage, manifest)
        # Always validate freshly captured data with the installed engine. Only
        # the expensive name/catalog build can be reused, after verifying both
        # active data and its immutable catalog. Never mutate an old generation.
        if reuse_current:
            previous=self.manifest()
            if (previous and previous.get('content_sha256')==manifest['content_sha256'] and
                    previous.get('catalog',{}).get('policy')==CATALOG_POLICY):
                active=(self.base/'current').resolve()
                self.verify_data(active,previous)
                with SignatureCatalog(active,previous):pass
                shutil.rmtree(stage)
                return None,previous
        manifest['catalog'] = build_catalog(stage, manifest)
        write_json(stage / 'manifest.json', manifest, 0o644)
        for path in stage.iterdir():
            path.chmod(0o644)
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        sync_directory(stage)
        return stage, manifest

    def upgrade_archive(self, stage, manifest):
        """Rebuild old retained data without changing an immutable generation."""
        target = Path(tempfile.mkdtemp(prefix='generation-', dir=self.base)); target.chmod(0o755)
        rebuilt = json.loads(json.dumps(manifest)); rebuilt.pop('catalog', None)
        rebuilt.update(generation=target.name, created=time.time(), rebuilt_from=stage.name)
        try:
            for row in manifest['files']:
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', row['name']):
                    raise EngineError('Invalid archived signature filename')
                if regular_copy(stage / row['name'], target / row['name']) != row['sha256']:
                    raise EngineError('Archived signature generation changed')
                if row['provider'] == 'sanesecurity':
                    regular_copy(stage / (row['name'] + '.sig'), target / (row['name'] + '.sig'), maximum=1024**2)
                    self.fetch.verify_sane(target / row['name'], target / (row['name'] + '.sig'))
            return self.complete_stage(target, rebuilt)
        except BaseException:
            shutil.rmtree(target); raise

    def validate(self, stage, manifest):
        clean, canary = stage / '.validation-clean', stage / '.validation-canary'
        clean.write_bytes(b'ClamShield clean database compatibility fixture')
        canary.write_text(manifest['canary']['payload'])
        clean.chmod(0o644); canary.chmod(0o644)
        try:
            def limits():
                import resource
                resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
                resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            result = subprocess.run(['/usr/bin/clamscan', '--stdout', '--no-summary',
                '--database=' + str(stage), str(clean), str(canary)], **engine_identity(),
                preexec_fn=limits, capture_output=True, timeout=150,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            detections = [line for line in result.stdout.decode(errors='replace').splitlines() if line.endswith(' FOUND')]
            if result.returncode != 1 or len(detections) != 1 or manifest['canary']['signature'] not in detections[0] or result.stderr.strip():
                # Private diagnostics contain only validation fixture output,
                # never freshclam's credential-bearing provider URLs.
                if self.settings.state.is_dir():
                    write(self.settings.state / 'signature-validation.private.txt',
                          result.stderr[-16384:] + b'\n' + result.stdout[-16384:])
                raise EngineError('ClamAV rejected the staged databases or their validation scan')
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EngineError('ClamAV database validation failed or timed out') from exc
        finally:
            clean.unlink(missing_ok=True)
            canary.unlink(missing_ok=True)

    def manifest(self, path=None):
        pointer = path or self.base / 'current'
        if not pointer.is_symlink():
            return None
        target = pointer.resolve()
        if target.parent != self.base or not target.name.startswith('generation-'):
            raise ClamShieldError('Unexpected signatures generation pointer')
        return json.loads((target / 'manifest.json').read_text())

    def pointer(self, name, target):
        path = self.base / name
        if path.exists() and not path.is_symlink():
            raise ClamShieldError('Unexpected signatures generation pointer')
        temporary = self.base / ('.pointer-' + uuid.uuid4().hex)
        temporary.symlink_to(target.name)
        os.replace(temporary, path)
        sync_directory(self.base)

    def daemon_ready(self, manifest, timeout=60):
        with tempfile.NamedTemporaryFile(dir=self.settings.snapshots) as sample:
            sample.write(manifest['canary']['payload'].encode()); sample.flush()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    hits = ClamAV(self.settings.clamd_socket, timeout=3).scan(Path(sample.name))
                    if any(h['signature'].removesuffix('.UNOFFICIAL') == manifest['canary']['signature'] for h in hits):
                        return
                except EngineError:
                    pass
                time.sleep(0.5)
        raise EngineError('Website ClamAV did not load the selected database generation')

    def daemon_version_ready(self, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            try:
                ClamAV(self.settings.clamd_socket, timeout=3).version()
                return
            except EngineError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    def mail_ready(self, manifest, timeout=60):
        # Readiness must work even while the broker is stopped and its protected
        # ALLMATCH scan directory is absent. Stream only the owned canary bytes.
        client = ClamAV('/run/clamshield-mail-clamd/clamd.sock', timeout=3)
        with tempfile.NamedTemporaryFile(dir=self.settings.snapshots) as sample:
            sample.write(manifest['canary']['payload'].encode()); sample.flush()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if any(hit['signature'] == manifest['canary']['signature'] + '.UNOFFICIAL' for hit in client.scan(Path(sample.name))):
                        return
                except EngineError:
                    pass
                time.sleep(.5)
        raise EngineError('Mail ClamAV did not load the selected database generation')

    def mail_version_ready(self, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            try:
                ClamAV('/run/clamshield-mail-clamd/clamd.sock').version()
                return
            except EngineError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.5)

    @staticmethod
    def mail_active():
        return subprocess.run(['/usr/bin/systemctl', 'is-active', 'clamshield-mail-clamd.service'],
                              capture_output=True, timeout=10).returncode == 0

    @staticmethod
    def restart_mail():
        subprocess.run(['/usr/bin/systemctl', 'restart', 'clamshield-mail-clamd.service'],
                       capture_output=True, check=True, timeout=120)

    @staticmethod
    def stop_owned(mail_active):
        # Stop before changing a pointer: a legacy daemon may still watch that
        # pointer with SelfCheck and start a concurrent, memory-heavy reload.
        units = ['clamshield-clamd.service']
        if mail_active:
            units.append('clamshield-mail-clamd.service')
        for unit in units:
            subprocess.run(['/usr/bin/systemctl', 'stop', unit], capture_output=True, check=True, timeout=120)

    def daemon_config(self, content, stage=None):
        matches = re.findall(r'^DatabaseDirectory\s+(.+)$', content, re.M)
        if len(matches) != 1 or '# Managed by clamshield' not in content:
            raise ClamShieldError('Owned ClamAV configuration ownership or database directory is invalid')
        return re.sub(r'^DatabaseDirectory\s+.+$', 'DatabaseDirectory ' + str(stage or self.base / 'current'), content, flags=re.M)

    def read_daemon_config(self, path):
        if path.parent.resolve(strict=True) != path.parent:
            raise ClamShieldError('Unexpected ClamAV configuration directory')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                info.st_mode & 0o022 or info.st_size > 65536):
                raise ClamShieldError('ClamAV configuration is not trusted')
            content = os.pread(fd, 65537, 0).decode('utf-8')
            self.daemon_config(content)
            return content
        finally:
            os.close(fd)

    def verify_data(self, stage, manifest):
        if (stage.parent != self.base or stage.is_symlink() or not stage.name.startswith('generation-') or
            manifest.get('generation') != stage.name):
            raise EngineError('Unexpected signature data generation')
        folder = stage.stat()
        if not stat.S_ISDIR(folder.st_mode) or folder.st_uid != os.geteuid() or folder.st_mode & 0o022:
            raise EngineError('Signature generation directory is untrusted')
        identity = json.dumps({'files': manifest['files'], 'catalog_policy': CATALOG_POLICY}, sort_keys=True, separators=(',', ':')).encode()
        if hashlib.sha256(identity).hexdigest() != manifest['content_sha256']:
            raise EngineError('Signature generation manifest identity changed')
        names = set()
        for row in manifest['files']:
            name = row['name']
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', name) or name in names:
                raise EngineError('Invalid signature data filename')
            names.add(name); fd = os.open(stage / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or
                    before.st_mode & 0o022 or before.st_size != row['size'] or before.st_size > MAX_DATABASE_BYTES):
                    raise EngineError('Signature data identity changed')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                after = os.fstat(fd)
                if (digest != row['sha256'] or
                    (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) !=
                    (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
                    raise EngineError('Signature data changed after validation')
            finally:
                os.close(fd)

    def activate(self, stage, manifest, *, legacy_website_active=True):
        from .website_policy import website_policy
        if type(legacy_website_active) is not bool:raise EngineError('Invalid retained website service state')
        self.verify_data(stage, manifest)
        with SignatureCatalog(stage, manifest):
            pass
        config_path = self.website_config
        before = self.read_daemon_config(config_path)
        mail_before = self.read_daemon_config(self.mail_config) if self.mail_config.exists() or self.mail_config.is_symlink() else None
        mail_active = self.mail_active() if mail_before is not None else False
        if mail_before is not None:
            self.daemon_config(mail_before)  # Ownership and exactly one directory.
        current = self.base / 'current'
        previous = current.resolve() if current.is_symlink() else None
        journal = self.settings.state / 'signature-activation.json'
        # Scan workers hold the same lock through every engine request, so a
        # database switch cannot interrupt a currently running website scan.
        with self.activation_lock():
            policy=website_policy(self.settings)
            website_active=legacy_website_active if policy is None else policy['enabled']
            write_json(journal, {'previous': str(previous) if previous else None,
                                 'candidate': str(stage), 'configuration': before,
                                 'mail_configuration': mail_before, 'mail_active': mail_active,
                                 'website_active':website_active})
            try:
                self.stop_owned(mail_active)
                self.pointer('current', stage)
                write(config_path, self.daemon_config(before, stage), 0o644)
                if mail_before is not None:
                    write(self.mail_config, self.daemon_config(mail_before, stage), 0o644)
                if website_active:
                    subprocess.run(['/usr/bin/systemctl', 'restart', 'clamshield-clamd.service'], check=True,
                                   capture_output=True, timeout=120)
                if mail_active:
                    self.restart_mail()
                if website_active:self.daemon_ready(manifest)
                if mail_active:
                    self.mail_ready(manifest)
                if previous:
                    self.pointer('previous', previous)
                journal.unlink(); sync_directory(journal.parent)
                return manifest
            except Exception as failure:
                try:
                    self.stop_owned(mail_active)
                    if previous:
                        self.pointer('current', previous)
                    else:
                        current.unlink(missing_ok=True)
                    write(config_path, before, 0o644)
                    if mail_before is not None:
                        write(self.mail_config, mail_before, 0o644)
                    if website_active:
                        subprocess.run(['/usr/bin/systemctl', 'restart', 'clamshield-clamd.service'],
                                       capture_output=True, check=True, timeout=120)
                    if mail_active:
                        self.restart_mail()
                    if website_active:
                        if previous:self.daemon_ready(self.manifest())
                        else:self.daemon_version_ready()
                    if mail_active:
                        if previous:
                            self.mail_ready(self.manifest())
                        else:
                            self.mail_version_ready()
                    journal.unlink(missing_ok=True)
                except Exception:
                    raise EngineError('Database activation failed; the durable recovery journal requires attention') from None
                if isinstance(failure, ClamShieldError):
                    raise failure
                raise EngineError('Database activation failed; the previous database generation was restored') from None

    def migrate_current(self):
        """Rebuild a retained legacy generation without downloads or in-place edits."""
        with self.locked():
            if (self.settings.state/'signature-activation.json').exists():
                raise Conflict('Recover interrupted database activation before catalog migration')
            manifest=self.manifest()
            if manifest is None or manifest.get('catalog',{}).get('policy')==CATALOG_POLICY:return None
            original=(self.base/'current').resolve()
            stage,rebuilt=self.upgrade_archive(original,manifest)
            active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','clamshield-clamd.service'],capture_output=True,timeout=30).returncode==0
            self.activate(stage,rebuilt,legacy_website_active=active)
            self.providers.status('activation',state='active',last_success=time.time(),generation=stage.name,error=None,migrated_from=original.name)
            return dict(previous=original.name,generation=stage.name,catalog_policy=CATALOG_POLICY)

    def update(self, provider='all', acquire=True):
        if provider not in ('all', 'official', 'securiteinfo', 'sanesecurity', 'local'):
            raise ClamShieldError('Unknown signature provider')
        with self.locked():
            if (self.settings.state / 'signature-activation.json').exists():
                raise Conflict('An interrupted database activation requires recovery')
            config = self.providers.read()
            self.seed_official()
            if acquire:
                for name in ('official', 'securiteinfo', 'sanesecurity'):
                    if config[name]['enabled'] and provider in ('all', name):
                        self.fetch.refresh(name, config[name])
            stage, manifest = self.stage(config, reuse_current=True)
            if stage is None:
                return {'changed': False, 'catalog_reused': True, **manifest}
            result = self.activate(stage, manifest)
            self.providers.status('activation', state='active', last_success=time.time(), generation=stage.name, error=None)
            return {'changed': True, **result}

    def rollback(self):
        with self.locked():
            previous = self.base / 'previous'
            manifest = self.manifest(previous)
            if manifest is None:
                raise Conflict('No previous database generation is available')
            stage = previous.resolve()
            if manifest.get('catalog', {}).get('policy') != CATALOG_POLICY:
                stage, manifest = self.upgrade_archive(stage, manifest)
            self.verify_data(stage, manifest)
            with SignatureCatalog(stage, manifest):
                pass
            self.validate(stage, manifest)
            return self.activate(stage, manifest)

    def recover(self):
        journal = self.settings.state / 'signature-activation.json'
        if not journal.exists():
            return False
        with self.locked(), self.activation_lock():
            if journal.is_symlink():
                raise ClamShieldError('Unexpected activation recovery journal')
            record = json.loads(journal.read_text())
            website_active=record.get('website_active',True)
            if type(website_active) is not bool:raise EngineError('Invalid website recovery service state')
            previous = Path(record['previous']) if record['previous'] else None
            candidate = Path(record['candidate'])
            if candidate.parent != self.base or (previous and previous.parent != self.base):
                raise ClamShieldError('Unexpected activation recovery generation')
            config = record['configuration']
            if not isinstance(config, str) or '# Managed by clamshield' not in config:
                raise ClamShieldError('Invalid activation recovery configuration')
            self.stop_owned(record.get('mail_active', False))
            if previous:
                self.pointer('current', previous)
            else:
                (self.base / 'current').unlink(missing_ok=True)
            write(self.website_config, config, 0o644)
            mail_config = record.get('mail_configuration')
            if mail_config is not None:
                self.daemon_config(mail_config)
                write(self.mail_config, mail_config, 0o644)
            if website_active:
                subprocess.run(['/usr/bin/systemctl', 'restart', 'clamshield-clamd.service'],
                               capture_output=True, check=True, timeout=120)
            if record.get('mail_active'):
                self.restart_mail()
            if website_active:
                if previous:self.daemon_ready(self.manifest())
                else:self.daemon_version_ready()
            if record.get('mail_active'):
                if previous:
                    self.mail_ready(self.manifest())
                else:
                    self.mail_version_ready()
            journal.unlink(); sync_directory(journal.parent)
            return True

    def status(self):
        manifest = self.manifest()
        return {'configured': bool(manifest), **(manifest or {})}
