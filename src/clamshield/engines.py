"""Scan one captured file using Ubuntu's engines, with bounded execution."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess

from .errors import EngineError, EncryptedContent


@contextmanager
def sealed_file(path):
    """An inherited anonymous file, readable after dropping engine privileges."""
    fd = os.memfd_create('clamshield-readonly', os.MFD_ALLOW_SEALING)
    try:
        with open(path, 'rb') as stream:
            while chunk := stream.read(1024 * 1024):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        os.fchmod(fd, 0o444)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield fd
    finally:
        os.close(fd)


def engine_identity():
    if os.geteuid() != 0:
        return {}
    import pwd
    identity = pwd.getpwnam('clamav')
    return dict(user=identity.pw_uid, group=identity.pw_gid, extra_groups=[])


def provider(signature):
    name = signature.lower()
    if name.startswith('clamshield.local.'):
        return 'local'
    if 'securiteinfo' in name:
        return 'securiteinfo'
    if name.startswith(('sanesecurity', 'sane.', 'foxhole', 'winnow', 'bofhland')):
        return 'sanesecurity'
    return 'unofficial' if name.endswith('.unofficial') else 'clamav'


class ClamAV:
    name = 'clamav'

    def __init__(self, socket_path, timeout=45, maximum=50 * 1024 * 1024):
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self.maximum = maximum

    def scan(self, path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.socket_path)
                connection.sendall(b'zINSTREAM\0')
                total = 0
                with open(path, 'rb') as stream:
                    while chunk := stream.read(65536):
                        total += len(chunk)
                        if total > self.maximum:
                            raise EngineError('ClamAV stream size limit exceeded')
                        connection.sendall(struct.pack('!I', len(chunk)) + chunk)
                connection.sendall(b'\0\0\0\0')
                response = bytearray()
                while b'\0' not in response:
                    chunk = connection.recv(4096)
                    if not chunk or len(response) + len(chunk) > 65536:
                        raise EngineError('ClamAV returned an incomplete response')
                    response.extend(chunk)
        except OSError as exc:
            raise EngineError('ClamAV is unavailable or timed out') from exc
        verdict = bytes(response).split(b'\0', 1)[0].decode('utf-8', errors='replace')
        if verdict == 'stream: OK':
            return []
        match = re.fullmatch(r'stream: (.+) FOUND', verdict)
        if match:
            signature = match[1]
            if not signature.endswith('.UNOFFICIAL') and signature.startswith('Heuristics.Limits.Exceeded'):
                raise EngineError('ClamAV scan limits were exceeded')
            if not signature.endswith('.UNOFFICIAL') and signature.startswith('Heuristics.Encrypted.'):
                raise EncryptedContent('ClamAV could not inspect encrypted archive or document contents')
            return [{'engine': 'clamav', 'signature': signature,
                     'provider': provider(signature), 'severity': 'review'}]
        raise EngineError('ClamAV did not complete the scan')

    def version(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(self.socket_path)
                connection.sendall(b'zVERSION\0')
                value = connection.recv(4096).split(b'\0', 1)[0].decode(errors='replace')
                if not value.startswith('ClamAV '):
                    raise EngineError('ClamAV version unavailable')
                return value
        except OSError as exc:
            raise EngineError('ClamAV is unavailable') from exc


class Yara:
    name = 'yara'

    def __init__(self, binary, rules, timeout=45, purpose='website'):
        self.binary, self.rules, self.timeout = binary, Path(rules), timeout
        self.purpose=purpose
        self._catalog_key, self._catalog, self._sources = None, {}, {}

    def catalog(self):
        key = str(self.rules.resolve())
        if key == self._catalog_key:
            return self._catalog
        path = self.rules.resolve().parent / 'catalog.json'
        self._catalog, self._sources = {}, {}
        if path.is_file():
            try:
                data = path.read_bytes()
                metadata_path = path.parent/'metadata.json'
                metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
                expected = metadata.get('files',{}).get('catalog.json')
                if expected and hashlib.sha256(data).hexdigest() != expected:
                    raise EngineError('YARA rule provenance verification failed')
                self._catalog = {(n['namespace']+':'+n['name']):n for n in json.loads(data)}
                self._sources = metadata.get('config',{}).get('sources',{})
            except (OSError,ValueError,KeyError,TypeError) as exc:
                raise EngineError('YARA rule provenance is unavailable') from exc
        self._catalog_key = key
        return self._catalog

    def scan(self, path, timeout=None):
        if getattr(self,'max_file_bytes',None) and Path(path).stat().st_size > self.max_file_bytes:
            raise EngineError('File exceeds the configured YARA size limit')
        # A mail transaction may have less time left than the website default.
        timeout = self.timeout if timeout is None else min(self.timeout, max(1, int(timeout)))
        if not self.rules.is_file():
            raise EngineError('No validated YARA ruleset is active')
        catalog = self.catalog()
        try:
            # Inherit read-only handles to the private snapshot and active rules.
            # The parser never needs root access to tenant or system paths.
            with sealed_file(self.rules) as rules_fd, sealed_file(path) as target_fd:
                rule_arg = '/proc/self/fd/' + str(rules_fd)
                target_arg = '/proc/self/fd/' + str(target_fd)
                options = engine_identity()
                def limits():
                    import resource
                    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
                    resource.setrlimit(resource.RLIMIT_CPU, (timeout + 1, timeout + 1))
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                compiled = ['-C'] if self.rules.suffix == '.yarac' else []
                result = subprocess.run([self.binary, *compiled, '-q', '-w', '-e', '-l', '1001', '-a', str(timeout),
                                         rule_arg, target_arg], pass_fds=(rules_fd, target_fd),
                                        preexec_fn=limits, **options,
                                        capture_output=True, timeout=timeout + 3,
                                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EngineError('YARA is unavailable or timed out') from exc
        if result.returncode != 0 or result.stderr.strip():
            raise EngineError('YARA did not complete the scan')
        detections, grouped = [], {}
        for line in result.stdout.decode('utf-8', errors='replace').splitlines():
            rule, separator, scanned = line.partition(' ')
            if not separator or scanned != target_arg or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', rule):
                raise EngineError('YARA returned an invalid result')
            node = catalog.get(rule, {})
            source = self._sources.get(node.get('source_id'), {})
            if source.get('scope')=='website' and self.purpose=='mail':continue
            detection = {'engine': 'yara', 'signature': rule.removeprefix('default:'),
                         'provider': 'yara-forge' if node.get('source_id')=='forge' else source.get('kind','yara'),
                         'severity':'review'}
            if node:
                detection.update(rule_id=node['id'],source_id=node['source_id'],
                    source_version=source.get('version'),
                    rule_sha256=node['sha256'],
                    source_url=str(node['metadata'].get('source_url',source.get('source_url','')))[:1000],
                    license=str(node['metadata'].get('license',source.get('license','Unknown')))[:1000])
            if source.get('kind') in ('php-hosting','web-hosting'):
                detection['heuristic']=True
                for field in ('commit','license_url','license_sha256'):
                    if source.get(field):detection[field]=source[field]
            if source.get('review_only') is True:detection['review_only']=True
            # Only collapse rules proven independent of rule/global context,
            # and only after both have actually matched this same snapshot.
            group = node.get('context_hash') if node.get('dedup_safe') else None
            if group and group in grouped:
                alias=dict(rule_id=node['id'],signature=detection['signature'],source_id=node['source_id'])
                if detection.get('review_only'):alias['review_only']=True
                else:grouped[group].pop('review_only',None)
                grouped[group].setdefault('also_matched',[]).append(alias)
            else:
                detections.append(detection)
                if group: grouped[group] = detection
            if len(detections)+sum(len(d.get('also_matched',[])) for d in detections)>1000:
                raise EngineError('YARA match limit exceeded; coverage is incomplete')
        return detections

    def version(self):
        try:
            result = subprocess.run([self.binary, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode:
                raise EngineError('YARA version unavailable')
            return result.stdout.strip()
        except OSError as exc:
            raise EngineError('YARA is unavailable') from exc
