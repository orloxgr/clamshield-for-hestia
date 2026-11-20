"""Separate daemon database directories inside one atomic update generation."""
import hashlib
import json
import os
from pathlib import Path
import stat

from .errors import EngineError
from .provider_fetch import regular_copy

PROFILES = ('website', 'mail')


def identity(manifest, catalog_policy):
    value = {'files': manifest['files'], 'catalog_policy': catalog_policy}
    if 'profiles' in manifest:
        value['profiles'] = manifest['profiles']
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def canary(manifest, profile):
    if 'profiles' not in manifest:
        return manifest['canary']
    if profile not in PROFILES:
        raise EngineError('Unknown signature profile')
    name = manifest['generation'].removeprefix('generation-')
    return {'payload': 'ClamShield profile validation ' + name + ' ' + profile,
            'signature': 'ClamShield.Profile.' + name + '.' + profile}


def canary_bytes(manifest, profile):
    value = canary(manifest, profile); payload = value['payload'].encode()
    return (hashlib.md5(payload).hexdigest() + ':' + str(len(payload)) + ':' + value['signature'] + '\n').encode()


def directory(stage, manifest, profile):
    return Path(stage) / profile if 'profiles' in manifest else Path(stage)


def sources(manifest, profile):
    return manifest.get('profiles', {}).get(profile)


def validate_selection(manifest):
    if 'profiles' not in manifest:
        return
    profiles = manifest['profiles']
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise EngineError('Invalid signature profiles')
    files = {row['name']: row for row in manifest['files']}
    official = {row['name'] for row in manifest['files'] if row['provider'] == 'official'}
    for names in profiles.values():
        if (not isinstance(names, list) or any(not isinstance(n, str) or n not in files for n in names)
                or names != sorted(set(names)) or not official <= set(names)):
            raise EngineError('Invalid signature profile selection')
    if set().union(*map(set, profiles.values())) != set(files):
        raise EngineError('Signature profile union differs from staged data')


def materialize(stage, manifest):
    validate_selection(manifest)
    for profile in manifest.get('profiles', {}):
        folder = directory(stage, manifest, profile); folder.mkdir(mode=0o755); folder.chmod(0o755)
        for name in manifest['profiles'][profile]:
            regular_copy(stage / name, folder / name)
            if (stage / (name + '.sig')).is_file():
                regular_copy(stage / (name + '.sig'), folder / (name + '.sig'), maximum=1024**2)
        path = folder / 'clamshield-generation.hdb'
        path.write_bytes(canary_bytes(manifest, profile)); path.chmod(0o644)


def verify(stage, manifest):
    validate_selection(manifest)
    files = {row['name']: row for row in manifest['files']}
    for profile, names in manifest.get('profiles', {}).items():
        folder = directory(stage, manifest, profile); info = folder.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise EngineError('Untrusted signature profile directory')
        expected = set(names) | {'clamshield-generation.hdb'}
        expected |= {name + '.sig' for name in names if files[name]['provider'] == 'sanesecurity'}
        if {p.name for p in folder.iterdir()} != expected:
            raise EngineError('Signature profile contains unexpected or missing files')
        for name in names + ['clamshield-generation.hdb']:
            fd = os.open(folder / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                expected_size = files[name]['size'] if name in files else len(canary_bytes(manifest, profile))
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                        or before.st_mode & 0o022 or before.st_size != expected_size):
                    raise EngineError('Signature profile file identity changed')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                expected_hash = files[name]['sha256'] if name in files else hashlib.sha256(canary_bytes(manifest, profile)).hexdigest()
                after = os.fstat(fd)
                if digest != expected_hash or (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                    raise EngineError('Signature profile data changed after validation')
            finally:
                os.close(fd)
