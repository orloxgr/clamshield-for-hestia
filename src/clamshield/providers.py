"""Private provider settings and safe public status. Data acquisition is separate."""
from copy import deepcopy
import fcntl
import json
import re
import time

from .atomic import write, write_json
from .errors import ClamShieldError
from .provider_catalog import SI, SI_BASIC, SANE, SANE_REQUIRED, catalog

DEFAULTS = {
    'automatic': True,
    'official': {'enabled': True, 'interval_minutes': 60},
    'securiteinfo': {'enabled': False, 'plan': 'basic', 'key': '', 'databases': list(SI_BASIC), 'interval_minutes': 60},
    'sanesecurity': {'enabled': False, 'databases': list(SANE_REQUIRED) + ['phish.ndb', 'rogue.hdb'], 'interval_minutes': 60},
    'local': {'enabled': True},
}
UPDATE_POLICIES = {
    'official': {'minimum_minutes': 60, 'note': 'Conservative hourly floor for ClamAV CDN access',
                 'url': 'https://docs.clamav.net/faq/faq-troubleshoot.html'},
    'securiteinfo': {'minimum_minutes': 60, 'note': 'Provider permits one download per hour, for all plans',
                    'url': 'https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml'},
    'sanesecurity': {'minimum_minutes': 60, 'note': 'Conservative hourly floor; provider forbids excessive mirror requests',
                    'url': 'https://sanesecurity.com/usage/linux-scripts/'},
}


def validate_interval(name, value):
    minimum = UPDATE_POLICIES[name]['minimum_minutes']
    if type(value) is not int or not minimum <= value <= 525600:
        raise ClamShieldError(f'{name} update interval must be a whole number from {minimum} to 525600 minutes')
    return value


def timing(name, config, status):
    interval = validate_interval(name, config[name].get('interval_minutes', 60))
    record = status.get(name, {})
    anchor = max(record.get('last_attempt') or 0, record.get('last_success') or 0)
    permitted = max(anchor + interval*60 if anchor else 0, record.get('retry_after') or 0)
    return dict(UPDATE_POLICIES[name], interval_minutes=interval, next_allowed=permitted,
                last_attempt=record.get('last_attempt'), last_success=record.get('last_success'),
                retry_after=record.get('retry_after'))
LOCAL_SUFFIXES = ('.hdb', '.hsb', '.ndb', '.ldb', '.ign2', '.fp', '.sfp', '.ftm', '.cdb', '.mdb', '.pdb', '.wdb', '.yar', '.yara')


class Providers:
    def __init__(self, settings):
        self.settings = settings
        self.path = settings.state / 'providers.json'

    def read(self):
        if self.path.is_symlink():
            raise ClamShieldError('Unexpected provider configuration path')
        if not self.path.exists():
            return deepcopy(DEFAULTS)
        saved = json.loads(self.path.read_text())
        if not isinstance(saved, dict): raise ClamShieldError('Invalid provider settings')
        result = deepcopy(DEFAULTS)
        result.update(saved)
        for name in ('official', 'securiteinfo', 'sanesecurity', 'local'):
            if not isinstance(saved.get(name, {}), dict): raise ClamShieldError('Invalid provider settings')
            result[name] = deepcopy(DEFAULTS[name]) | saved.get(name, {})
        for name in UPDATE_POLICIES: validate_interval(name, result[name]['interval_minutes'])
        return result

    def save(self, value):
        self.settings.prepare()
        if not isinstance(value, dict) or set(value) - set(DEFAULTS):
            raise ClamShieldError('Invalid provider settings')
        with (self.settings.state / 'providers-config.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.read()
            if 'automatic' in value:
                if type(value['automatic']) is not bool:
                    raise ClamShieldError('Invalid automatic-update setting')
                result['automatic'] = value['automatic']
            for name in ('official', 'securiteinfo', 'sanesecurity', 'local'):
                if name not in value:
                    continue
                incoming = value[name]
                if not isinstance(incoming, dict) or set(incoming) - set(DEFAULTS[name]):
                    raise ClamShieldError('Invalid provider settings')
                current = result[name]
                for key, item in incoming.items():
                    if key == 'enabled' and type(item) is not bool:
                        raise ClamShieldError('Invalid provider toggle')
                    if key == 'interval_minutes': validate_interval(name, item)
                    if key == 'key':
                        # Empty masked fields preserve the saved credential.
                        if item == '':
                            continue
                        if not isinstance(item, str) or not re.fullmatch(r'[a-fA-F0-9]{64,256}', item):
                            raise ClamShieldError('SecuriteInfo requires the hexadecimal account key from its installation page')
                    current[key] = item
                if name == 'official' and not current['enabled']:
                    raise ClamShieldError('Official ClamAV protection must remain enabled')
            si, sane = result['securiteinfo'], result['sanesecurity']
            if si['plan'] not in ('basic', 'professional', 'gold', 'reseller'):
                raise ClamShieldError('Invalid SecuriteInfo plan')
            for section, allowed, required in ((si, SI, ('securiteinfo.ign2',)), (sane, SANE, SANE_REQUIRED)):
                files = section['databases']
                if not isinstance(files, list) or any(not isinstance(n, str) or n not in allowed for n in files):
                    raise ClamShieldError('Invalid provider database selection')
                section['databases'] = sorted(set(files) | set(required))
            if si['plan'] == 'basic' and any(n not in SI_BASIC for n in si['databases']):
                raise ClamShieldError('Selected SecuriteInfo databases require a paid plan')
            if si['enabled'] and not si['key']:
                raise ClamShieldError('Enter a SecuriteInfo account key before enabling the provider')
            write_json(self.path, result)
        return self.public()

    def public(self):
        result = self.read()
        key = result['securiteinfo'].pop('key', '')
        result['securiteinfo']['has_key'] = bool(key)
        status_path = self.settings.state / 'provider-status.json'
        result['status'] = json.loads(status_path.read_text()) if status_path.exists() else {}
        result['schedule'] = {name: timing(name, result, result['status']) for name in UPDATE_POLICIES}
        result['catalog'] = catalog()
        local = self.settings.state / 'local-signatures'
        result['local']['files'] = sorted(p.name for p in local.iterdir() if p.is_file() and not p.is_symlink()) if local.exists() else []
        return result

    def due(self, name, now=None):
        if name not in UPDATE_POLICIES: raise ClamShieldError('Unknown provider')
        current = self.public()
        return (time.time() if now is None else now) >= current['schedule'][name]['next_allowed']

    def save_local(self, name, content):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', name) or not name.endswith(LOCAL_SUFFIXES):
            raise ClamShieldError('Use a supported local ClamAV signature filename')
        if not isinstance(content, str) or not content.strip() or len(content.encode()) > 4 * 1024**2 or '\0' in content:
            raise ClamShieldError('Local signature content is empty or exceeds 4 MiB')
        self.settings.prepare()
        folder = self.settings.state / 'local-signatures'
        folder.mkdir(exist_ok=True, mode=0o700)
        if folder.is_symlink():
            raise ClamShieldError('Unexpected local signature directory')
        write(folder / name, content)
        return {'name': name, 'activation_required': True}

    def delete_local(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', name) or not name.endswith(LOCAL_SUFFIXES):
            raise ClamShieldError('Invalid local signature filename')
        path = self.settings.state / 'local-signatures' / name
        if path.is_symlink() or not path.is_file():
            raise ClamShieldError('Local signature file unavailable')
        path.unlink()
        return {'name': name, 'activation_required': True}

    def status(self, name, **changes):
        self.settings.prepare()
        path = self.settings.state / 'provider-status.json'
        with (self.settings.state / 'providers-config.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            value = json.loads(path.read_text()) if path.exists() else {}
            value[name] = value.get(name, {}) | changes
            write_json(path, value)
