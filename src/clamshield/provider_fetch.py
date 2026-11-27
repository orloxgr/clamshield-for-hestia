"""Upstream-specific acquisition; never downloads SecuriteInfo using a custom HTTP client."""
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import tempfile
import time

from .atomic import write
from .engines import engine_identity
from .errors import ClamShieldError
from .provider_catalog import SANE_FINGERPRINT, SANE_KEY_URL, SANE_MIRROR, SECURITEINFO_BASE, MAX_DATABASE_BYTES
from .rules import download


def regular_copy(source, destination, maximum=MAX_DATABASE_BYTES):
    """Copy a bounded regular file without following cache-controlled symlinks."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ClamShieldError('Provider cache contains an unsafe file')
        digest = hashlib.sha256()
        with Path(destination).open('xb') as stream:
            total = 0
            while chunk := os.read(fd, 1024**2):
                total += len(chunk)
                if total > maximum:
                    raise ClamShieldError('Provider file exceeds its size allowance')
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or total != before.st_size:
            raise ClamShieldError('Provider data changed during capture')
        Path(destination).chmod(0o644)
        return digest.hexdigest()
    finally:
        os.close(fd)


class Fetch:
    def __init__(self, settings, providers):
        self.settings, self.providers = settings, providers

    def cache(self, name):
        root = self.settings.provider_cache
        if root.is_symlink():
            raise ClamShieldError('Unexpected provider cache directory')
        root.mkdir(mode=0o755, exist_ok=True)
        path = root / name
        if path.is_symlink():
            raise ClamShieldError('Unexpected provider cache directory')
        path.mkdir(mode=0o700, exist_ok=True)
        identity = pwd.getpwnam('clamav')
        os.chown(path, identity.pw_uid, identity.pw_gid)
        return path

    def due(self, name):
        return self.providers.due(name)

    def freshclam_config(self, name, config, cache):
        lines = ['# Managed by clamshield', 'DatabaseOwner clamav',
                 'DatabaseDirectory ' + str(cache), 'DatabaseMirror database.clamav.net',
                 'TestDatabases yes', 'MaxAttempts 1', 'ConnectTimeout 20',
                 'ReceiveTimeout 120', 'LogTime no', 'LogSyslog no',
                 'ScriptedUpdates yes', 'Bytecode yes']
        if name == 'securiteinfo':
            lines.extend('DatabaseCustomURL ' + SECURITEINFO_BASE + '/' + config['key'] + '/' + filename
                         for filename in config['databases'])
        return '\n'.join(lines) + '\n'

    def freshclam(self, name, config):
        cache = self.cache(name)
        self.settings.prepare()
        folder = self.settings.state / 'freshclam-config'
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink():
            raise ClamShieldError('Unexpected updater configuration directory')
        path = folder / (name + '.conf')
        write(path, self.freshclam_config(name, config, cache))
        argv = ['/usr/bin/freshclam', '--config-file=' + str(path), '--stdout']
        if name == 'securiteinfo':
            # Supported by current ClamAV; does not fetch the official bases.
            argv.append('--update-db=custom')
        apparmor = Path('/sys/module/apparmor/parameters/enabled')
        if apparmor.exists() and apparmor.read_text().strip() == 'Y':
            argv = ['/usr/bin/aa-exec', '-p', 'clamshield-freshclam', '--', *argv]
        result = subprocess.run(argv, capture_output=True, timeout=600,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        # Freshclam diagnostics can contain credential-bearing URLs. Do not
        # return, log, persist or attach raw stdout/stderr to an exception.
        # Retain only a strictly parsed UTC deadline; raw output may contain keys.
        output = (result.stdout or b'') + b'\n' + (result.stderr or b'')
        deadlines = []
        for value in re.findall(rb'cool-down until after: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', output):
            try: deadlines.append(datetime.strptime(value.decode('ascii'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
            except ValueError: pass
        if deadlines and max(deadlines) > time.time():
            self.providers.status(name, retry_after=max(deadlines))
            raise ClamShieldError('Freshclam postponed the update until its provider cooldown expires')
        if result.returncode:
            raise ClamShieldError('Freshclam update failed; check provider credentials, entitlement and network access')
        return cache

    def sane_key(self):
        cache = self.cache('gnupg')
        key = cache / 'sanesecurity-public.gpg'
        if not key.exists():
            write(key, download(SANE_KEY_URL, 1024**2))
            identity = pwd.getpwnam('clamav')
            os.chown(key, identity.pw_uid, identity.pw_gid)
        result = self.gpg(cache, '--with-colons', '--import-options', 'show-only', '--import', str(key))
        primary = []
        want_fingerprint = False
        for line in result.stdout.decode(errors='replace').splitlines():
            fields = line.split(':')
            if fields[0] == 'pub':
                want_fingerprint = True
            elif fields[0] == 'fpr' and want_fingerprint:
                primary.append(fields[9].upper())
                want_fingerprint = False
        if result.returncode or primary != [SANE_FINGERPRINT]:
            raise ClamShieldError('SaneSecurity signing key fingerprint does not match the pinned provider key')
        imported = self.gpg(cache, '--import', str(key))
        if imported.returncode:
            raise ClamShieldError('SaneSecurity signing key could not be imported')
        return cache

    def gpg(self, home, *args):
        return subprocess.run(['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart',
                               '--homedir', str(home), *args], **engine_identity(),
                              capture_output=True, timeout=45,
                              env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})

    def verify_sane(self, path, signature, home=None):
        home = home or self.sane_key()
        result = self.gpg(home, '--status-fd', '1', '--verify', str(signature), str(path))
        valid = []
        for line in result.stdout.decode(errors='replace').splitlines():
            fields = line.split()
            if len(fields) >= 11 and fields[:2] == ['[GNUPG:]', 'VALIDSIG']:
                valid.append(fields)
        if result.returncode or len(valid) != 1 or SANE_FINGERPRINT not in (valid[0][2], valid[0][-1]):
            raise ClamShieldError('SaneSecurity database signature verification failed')

    def sane(self, config):
        self.sane_key()
        cache = self.cache('sanesecurity')
        files = [name for database in config['databases'] for name in (database, database + '.sig')]
        include = cache / 'download-files.txt'
        write(include, '\n'.join(files) + '\n')
        identity = pwd.getpwnam('clamav')
        os.chown(include, identity.pw_uid, identity.pw_gid)
        # Try the round-robin's individual IPv4 mirrors as well, without an
        # unbounded retry loop. No compression or bulk directory mirroring.
        try:
            addresses = sorted({row[4][0] for row in socket.getaddrinfo('rsync.sanesecurity.net', 873, socket.AF_INET)})[:4]
        except OSError:
            addresses = []
        mirrors = [SANE_MIRROR] + ['rsync://' + ip + '/sanesecurity/' for ip in addresses]
        for mirror in mirrors:
            result = subprocess.run(['/usr/bin/rsync', '--no-motd', '--times',
                '--timeout=45', '--contimeout=15', '--no-links', '--no-specials', '--no-devices',
                '--max-size=128m', '--files-from=' + str(include), mirror, str(cache) + '/'],
                **engine_identity(), capture_output=True, timeout=180,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            if result.returncode == 0 and all((cache / name).is_file() and not (cache / name).is_symlink() for name in files):
                return cache
        raise ClamShieldError('SaneSecurity download failed; check rsync TCP port 873 and provider mirror availability')

    def refresh(self, name, config):
        if not self.due(name):
            return {'provider': name, 'used_cache': True, 'next_allowed': self.providers.public()['schedule'][name]['next_allowed']}
        from .native_integration import enabled
        native_official=name=='official' and enabled(self.settings)
        self.providers.status(name, state='updating', error=None,**({} if native_official else {'last_attempt':time.time()}))
        try:
            if native_official:
                from .native_updates import NativeUpdates
                result=NativeUpdates(self.settings).check(on_attempt=lambda:self.providers.status(name,last_attempt=time.time()))
                status=dict(state=result['state'],error=None)
                if result['check_completed']:status.update(last_success=time.time(),retry_after=None)
                self.providers.status(name,**status)
                return dict(provider=name,used_cache=not result['check_completed'],**result)
            if name in ('official', 'securiteinfo'):
                self.freshclam(name, config)
            elif name == 'sanesecurity':
                self.sane(config)
            else:
                raise ClamShieldError('Unknown provider')
            self.providers.status(name, last_success=time.time(), state='downloaded', error=None, retry_after=None)
            return {'provider': name, 'used_cache': False}
        except (OSError, subprocess.SubprocessError, ClamShieldError) as exc:
            message = str(exc) if isinstance(exc, ClamShieldError) else 'Provider update failed or timed out'
            self.providers.status(name, state='error', error=message)
            raise ClamShieldError(message) from None
