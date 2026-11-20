"""Durable server-wide Forge update timing, separate from Ubuntu engine updates."""
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import fcntl
import json
import math
import time
from urllib.error import HTTPError

from .atomic import write_json
from .errors import ClamShieldError

DEFAULTS = {'automatic': True, 'interval_minutes': 1440, 'profile': None}
MINIMUM_MINUTES = 60  # Our conservative polling floor, not an upstream quota.
SOURCE_URL = 'https://github.com/YARAHQ/yara-forge#readme'


class RuleUpdates:
    def __init__(self, settings):
        self.settings = settings
        self.policy_path = settings.state / 'rule-updates.json'
        self.state_path = settings.state / 'rule-update-status.json'

    @contextmanager
    def locked(self, name='rule-update-settings.lock'):
        self.settings.prepare()
        path = self.settings.state / name
        if path.is_symlink():
            raise ClamShieldError('Unexpected YARA update lock')
        with path.open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @staticmethod
    def load(path):
        if path.is_symlink():
            raise ClamShieldError('Unexpected YARA update settings path')
        return json.loads(path.read_text()) if path.is_file() else {}

    @staticmethod
    def validate(value):
        if not isinstance(value, dict) or set(value) - set(DEFAULTS):
            raise ClamShieldError('Invalid YARA update settings')
        value = DEFAULTS | value
        if type(value['automatic']) is not bool:
            raise ClamShieldError('Invalid automatic YARA update toggle')
        interval = value['interval_minutes']
        if value['profile'] is not None and value['profile'] not in ('core','extended','full'):
            raise ClamShieldError('Choose Core, Extended or Full')
        if type(interval) is not int or not MINIMUM_MINUTES <= interval <= 525600:
            raise ClamShieldError('YARA update interval must be 60 to 525600 whole minutes')
        return value

    def status(self):
        with self.locked():
            policy = self.validate(self.load(self.policy_path))
            state = self.load(self.state_path)
        if policy['profile'] is None:
            from .rules import Rules
            installed=Rules(self.settings).status().get('profile')
            policy['profile']=installed if installed in ('core','extended','full') else 'core'
        anchor = max(state.get('last_attempt') or 0, state.get('last_success') or 0)
        return state | policy | dict(minimum_minutes=MINIMUM_MINUTES, source_url=SOURCE_URL,
            next_allowed=max(anchor + policy['interval_minutes'] * 60 if anchor else 0, state.get('retry_after') or 0))

    def save(self, value):
        with self.locked():
            policy = self.validate(value)
            write_json(self.policy_path, policy)
        return self.status()

    def record(self, **changes):
        with self.locked():
            write_json(self.state_path, self.load(self.state_path) | changes)

    def check_due(self):
        status = self.status()
        if time.time() < status['next_allowed']:
            deadline = datetime.fromtimestamp(status['next_allowed'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            raise ClamShieldError('Next permitted YARA Forge update: ' + deadline)

    def run(self, profile, operation):
        if profile not in ('core', 'extended', 'full'):
            raise ClamShieldError('Invalid YARA Forge profile')
        # Serialize the complete operation across workers, CLI calls and profiles.
        with self.locked('rule-download.lock'):
            self.check_due()
            self.record(last_attempt=time.time(), profile=profile, state='updating', error=None)
            try:
                result = operation()
            except HTTPError as exc:
                deadline = self.http_deadline(exc)
                message = 'YARA Forge download was refused by GitHub'
                if deadline:
                    self.record(retry_after=deadline)
                    message += '; the server cooldown is being respected'
                self.record(state='failed', error=message)
                raise ClamShieldError(message) from exc
            except BaseException as exc:
                message = str(exc) if isinstance(exc, ClamShieldError) else 'YARA update failed or was interrupted; active rules were retained'
                self.record(state='failed', error=message)
                raise
            self.record(last_success=time.time(), state='completed', error=None, retry_after=None)
            return result

    @staticmethod
    def http_deadline(error):
        deadlines = []
        retry = error.headers.get('Retry-After', '') if error.headers else ''
        try:
            deadlines.append(time.time() + int(retry) if retry.isdigit() else parsedate_to_datetime(retry).timestamp())
        except (ValueError, TypeError, OverflowError):
            pass
        if error.code in (403, 429) and error.headers:
            try:
                deadlines.append(float(error.headers.get('X-RateLimit-Reset', '')))
            except ValueError:
                pass
        deadlines = [value for value in deadlines if math.isfinite(value)]
        return max([time.time(), *deadlines]) if deadlines else None
