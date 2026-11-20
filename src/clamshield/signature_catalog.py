"""Bounded, immutable exact-name provenance for a validated ClamAV generation.

The APT sigtool reads data formats; this module does not implement an engine.
Mixed feeds and name collisions never downgrade an ambiguous match to spam.
"""
import hashlib
from contextlib import contextmanager
from collections import OrderedDict
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile
import threading

from .engines import engine_identity
from .errors import EngineError
from .store import encode
from .provider_catalog import MAX_DATABASE_BYTES


@contextmanager
def engine_lock(settings, *, exclusive=False, blocking=False):
    settings.prepare()
    fd = os.open(settings.state / 'mail-engine.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise EngineError('Mail engine generation lock is not trusted')
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def _hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

POLICY = 1
FILENAME = 'signature-catalog.sqlite3'
MAX_NAMES = 8_000_000
MAX_OUTPUT = 256 * 1024**2
NAMED = {'.hdb', '.hsb', '.mdb', '.msb', '.ndb', '.ldb', '.cdb'}
SUPPORT = {'.ftm', '.ign2', '.fp', '.sfp', '.wdb', '.pdb'}
FIELDS = {'category', 'provider', 'source_id', 'source_version', 'classification_basis'}
PRIORITY = {'spam': 0, 'phishing': 1, 'malware': 2}
_verified = OrderedDict()
_verification_lock = threading.Lock()


def _fingerprint(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                                               'st_uid', 'st_gid', 'st_mode', 'st_nlink'))


def _verify_index(fd, info, record, manifest):
    # Immutable generations are root-owned and not writable by another account.
    # Reuse a hash only for the same complete inode/change-time/ownership recipe.
    # Replacement, writes, chmod/chown and extra hardlinks invalidate this key.
    key = (*_fingerprint(info), record['sha256'], record['policy'], manifest['generation'], manifest['content_sha256'])
    with _verification_lock:
        if key not in _verified:
            with os.fdopen(os.dup(fd), 'rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != record['sha256']:
                    raise EngineError('Signature catalog content changed')
            if _fingerprint(os.fstat(fd)) != _fingerprint(info):
                raise EngineError('Signature catalog changed during verification')
            _verified[key] = True
            while len(_verified) > 8:
                _verified.popitem(last=False)
        _verified.move_to_end(key)


def classify(provider, filename, name):
    """Use the verified feed plus its documented named groups, never name alone.

    References: sanesecurity.com/usage/signatures/ and /support/documentation/.
    junk/phish/shelter/blurl are mixed; unknown groups remain malware.
    """
    if provider == 'securiteinfo' and filename == 'spam_marketing.ndb':
        return 'spam', 'provider-spam-feed'
    if provider == 'sanesecurity':
        if filename in {'lott.ndb', 'scam.ndb', 'spam.ldb', 'spamimg.hdb', 'spamattach.hdb', 'jurlbl.ndb', 'jurlbla.ndb'}:
            return 'spam', 'provider-spam-feed'
        if filename in {'spear.ndb', 'spearl.ndb'}:
            return 'phishing', 'provider-phishing-feed'
        if filename in {'phish.ndb', 'shelter.ldb', 'junk.ndb', 'blurl.ndb'}:
            if re.match(r'Sanesecurity\.(?:Phishing(?:\.|$)|PhishingTestSig(?:\.|$)|Doc\.|Fake\.)', name, re.I):
                return 'phishing', 'documented-provider-group'
            return 'malware', 'mixed-feed-conservative'
    return 'malware', 'malware-or-unclassified-feed'


def validate_origin(value):
    if (not isinstance(value, dict) or set(value) - (FIELDS | {'attribution', 'origins'}) or
        value.get('category', 'malware') not in PRIORITY or
        any(not isinstance(item, str) or len(item) > 512 for key, item in value.items() if key != 'origins')):
        raise EngineError('Signature provenance is invalid')
    origins = value.get('origins', [])
    if (not isinstance(origins, list) or len(origins) > 32 or
        any(not isinstance(item, dict) or set(item) != FIELDS or item.get('category') not in PRIORITY or
            any(not isinstance(v, str) or len(v) > 512 for v in item.values()) for item in origins)):
        raise EngineError('Signature origin list is invalid')
    return value


def _names(path):
    """Pass the optional argument with '='; separate argv would list all DBs."""
    def limits():
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            result = subprocess.run(['/usr/bin/sigtool', '--list-sigs=' + str(path)],
                **engine_identity(), stdout=output, stderr=error, timeout=90, preexec_fn=limits,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            if result.returncode or output.tell() > MAX_OUTPUT or error.tell():
                raise EngineError('APT sigtool could not list the selected signature database')
            output.seek(0)
            while line := output.readline(4097):
                if not line.endswith(b'\n'):
                    raise EngineError('Signature name is incomplete or oversized')
                yield line[:-1].decode('utf-8')
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise EngineError('Signature catalog extraction failed or timed out') from exc


def build(stage, manifest):
    stage = Path(stage)
    destination = stage / FILENAME
    if destination.exists() or destination.is_symlink():
        raise EngineError('Signature catalog destination already exists')
    db = sqlite3.connect(destination)
    count = 0; categories = {name: 0 for name in PRIORITY}
    try:
        db.executescript('''PRAGMA journal_mode=DELETE;
          CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE signatures(name TEXT NOT NULL,source_id TEXT NOT NULL,detail TEXT NOT NULL,
            PRIMARY KEY(name,source_id)) WITHOUT ROWID;''')
        db.executemany('INSERT INTO metadata VALUES(?,?)',
            [('policy', str(POLICY)), ('generation', manifest['generation']), ('content_sha256', manifest['content_sha256'])])
        for row in manifest['files']:
            if row['provider'] == 'official':
                continue  # Official names retain their signed-engine provenance.
            name = row['name']; provider = row['provider']
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', name):
                raise EngineError('Unsafe generation database filename')
            filename = name.removeprefix(provider + '--'); path = stage / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or
                info.st_size > MAX_DATABASE_BYTES or _hash(path) != row['sha256']):
                raise EngineError('Generation data changed before catalog extraction')
            if path.suffix in SUPPORT:
                continue  # URL databases produce shared engine heuristics, not named matches.
            if path.suffix in ('.yar', '.yara'):
                import plyara
                if info.st_size > 8 * 1024**2:
                    raise EngineError('ClamAV YARA provenance exceeds its parsing allowance')
                try:
                    names = ['YARA.' + rule['rule_name'] for rule in plyara.Plyara().parse_string(path.read_text())]
                except Exception as exc:
                    raise EngineError('ClamAV YARA provenance could not be parsed') from exc
            elif path.suffix in NAMED:
                names = _names(path)
            else:
                raise EngineError('Generation contains an unsupported provenance format')
            batch = []
            for signature in names:
                # Legacy upstream names can contain punctuation outside the
                # current naming guideline. ClamAV validation is authoritative;
                # names are bounded data/SQL parameters, never shell fragments.
                if not 1 <= len(signature) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in signature):
                    raise EngineError('Database contains an invalid signature name')
                category, basis = classify(provider, filename, signature)
                origin = dict(provider=provider, source_id=name, source_version=row['sha256'],
                              category=category, classification_basis=basis)
                batch.append((signature, name, encode(origin))); categories[category] += 1; count += 1
                if count > MAX_NAMES:
                    raise EngineError('Signature catalog exceeds its bounded name allowance')
                if len(batch) == 1000:
                    db.executemany('INSERT OR IGNORE INTO signatures VALUES(?,?,?)', batch); batch = []
            db.executemany('INSERT OR IGNORE INTO signatures VALUES(?,?,?)', batch)
        db.commit()
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise EngineError('Signature catalog integrity check failed')
    except BaseException:
        db.close(); destination.unlink(missing_ok=True)
        raise
    else:
        db.close()
    destination.chmod(0o644)
    with destination.open('rb') as stream:
        os.fsync(stream.fileno()); digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(name=FILENAME, sha256=digest, size=destination.stat().st_size, policy=POLICY,
                listed_names=count, categories=categories)


class SignatureCatalog:
    def __init__(self, stage, manifest):
        self.stage, self.manifest = Path(stage), manifest
        record = manifest.get('catalog', {})
        if record.get('name') != FILENAME or record.get('policy') != POLICY:
            raise EngineError('Database generation needs a compatible provenance catalog')
        self.fd = os.open(self.stage / FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.db = None
        try:
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                info.st_mode & 0o022 or info.st_size != record['size']):
                raise EngineError('Signature catalog is not a trusted immutable file')
            _verify_index(self.fd, info, record, manifest)
            self.db = sqlite3.connect('file:/proc/self/fd/' + str(self.fd) + '?mode=ro&immutable=1', uri=True)
            self.db.execute('PRAGMA query_only=ON')
            metadata = dict(self.db.execute('SELECT key,value FROM metadata'))
            if metadata != dict(policy=str(POLICY), generation=manifest['generation'], content_sha256=manifest['content_sha256']):
                raise EngineError('Signature catalog belongs to another generation')
            current = (self.stage / FILENAME).lstat()
            for checked in (os.fstat(self.fd), current):
                if _fingerprint(checked) != _fingerprint(info):
                    raise EngineError('Signature catalog changed while opening')
        except BaseException:
            self.close(); raise

    def close(self):
        if self.db is not None:
            self.db.close(); self.db = None
        if self.fd is not None:
            os.close(self.fd); self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def resolve(self, signature):
        if not isinstance(signature, str) or not 1 <= len(signature) <= 512:
            raise EngineError('Invalid signature lookup')
        if signature.endswith('.UNOFFICIAL'):
            name = signature.removesuffix('.UNOFFICIAL')
            rows = list(self.db.execute('SELECT detail FROM signatures WHERE name=? ORDER BY source_id LIMIT 33', (name,)))
            if len(rows) > 32:
                raise EngineError('Signature provenance collision limit exceeded')
            origins = [json.loads(row[0]) for row in rows]
            if len(origins) == 1:
                return validate_origin(origins[0] | {'attribution': 'exact-database-name', 'origins': origins})
            if origins:
                category = max((origin['category'] for origin in origins), key=PRIORITY.get)
                return validate_origin(dict(provider='multiple', source_id='ambiguous-signature-name',
                    source_version=self.manifest['content_sha256'], category=category,
                    classification_basis='conservative-name-collision', attribution='ambiguous-name', origins=origins))
            return validate_origin(dict(provider='unclassified', source_id='uncatalogued-unofficial-name',
                source_version=self.manifest['content_sha256'], category='malware', attribution='unresolved', origins=[]))
        heuristic = signature.startswith(('Heuristics.', 'Phishing.Heuristics.'))
        phishing = signature.startswith(('Heuristics.Phishing.', 'Phishing.Heuristics.')) or signature.split('.')[1:2] == ['Phishing']
        return validate_origin(dict(provider='clamav', source_id='shared-engine-heuristic' if heuristic else 'official-databases',
            source_version=self.manifest['content_sha256'], category='phishing' if phishing else 'malware',
            attribution='engine-heuristic' if heuristic else 'official-engine-name', origins=[]))
