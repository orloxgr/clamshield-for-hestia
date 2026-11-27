"""Server health state transitions: unchanged checks do not generate new alerts."""
from datetime import datetime, timezone
import json
from pathlib import Path
import time

from .atomic import write_json
from .engines import ClamAV, Yara
from .errors import ClamShieldError
from .providers import Providers


class Health:
    def __init__(self, settings, store):
        self.settings, self.store = settings, store

    def observe(self, components, deferred=(), *, partial=False):
        path = self.settings.state / 'health.json'
        before = json.loads(path.read_text()) if path.exists() else {}
        now = time.time()
        result = dict(before) if partial else {}
        for name, state in components.items():
            old = before.get(name)
            changed = old is None or old.get('state') != state['state']
            result[name] = state | {'checked': now, 'changed': now if changed else old['changed']}
            if changed and (state['state'] != 'healthy' or old is not None and old.get('checked') is not None):
                event = 'health.recovered' if state['state'] == 'healthy' else 'health.problem'
                self.store.notify('@admin', '', event, name,
                                  {'component': name, **state}, str(now) + ':' + name)
        for name in deferred:
            # Waiting on a live worker/update is not a failure or recovery.
            # Keep the real observation time and previous state for deduplication.
            result[name] = dict(before.get(name) or {'state': 'unknown', 'checked': None, 'changed': now},
                                verification_deferred=True)
        write_json(path, result)
        return result

    def website_check(self):
        from .readiness import WebsiteReadiness
        value = WebsiteReadiness(self.settings).check()
        result = self.observe({'website-coverage': value} if value is not None else {},
                              ('website-coverage',) if value is None else (), partial=True)
        return result['website-coverage'], value is None

    def check(self, extra=None):
        components = dict(extra or {})
        from .readiness import WebsiteReadiness
        readiness = WebsiteReadiness(self.settings).check()
        if readiness is not None:
            components['website-coverage'] = readiness
        engine=ClamAV(self.settings.clamd_socket)
        from .native_integration import enabled,ManagedNativeClamAV
        if enabled(self.settings):engine=ManagedNativeClamAV(self.settings)
        for engine in (engine, Yara(self.settings.yara_binary, self.settings.rules)):
            try:
                version = engine.version()
                components[engine.name] = {'state': 'healthy', 'version': version}
            except ClamShieldError:
                components[engine.name] = {'state': 'unavailable', 'message': 'Engine health check failed'}
        components['yara-rules'] = {'state': 'healthy' if self.settings.rules.is_file() else 'missing',
                                    'message': 'Validated rules are active' if self.settings.rules.is_file() else 'No validated YARA rules are active'}
        from .yara_settings import YaraSettings
        if not YaraSettings(self.settings).read()['enabled']:
            components['yara-rules']={'state':'healthy','message':'YARA website scanning is disabled by the administrator'}
        providers = Providers(self.settings).public()
        now = time.time()
        for name in ('official', 'securiteinfo', 'sanesecurity'):
            if not providers[name]['enabled']:
                continue
            status = providers['status'].get(name, {})
            if status.get('state') == 'error':
                components['provider-' + name] = {'state': 'error', 'message': status.get('error', 'Provider update failed')}
            elif not status.get('last_success') or now - status['last_success'] > 48 * 3600:
                components['provider-' + name] = {'state': 'stale', 'message': 'No successful provider check in the last 48 hours'}
            else:
                components['provider-' + name] = {'state': 'healthy', 'last_success': status['last_success']}
        if components.get('clamav', {}).get('state') == 'healthy':
            # VERSION reports the loaded daily database publication date. A
            # successful HTTP check alone is not proof of fresh signature data.
            value = components['clamav']['version'].split('/', 2)
            try:
                published = datetime.strptime(value[2], '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
                age = now - published.timestamp()
                components['clamav-database-age'] = {'state': 'healthy' if age <= 72 * 3600 else 'stale',
                                                     'published': published.isoformat(), 'age_hours': round(age / 3600, 1)}
            except (ValueError, IndexError):
                components['clamav-database-age'] = {'state': 'unknown', 'message': 'Loaded database publication time could not be verified'}
        return self.observe(components, ('website-coverage',) if readiness is None else ())

    def status(self):
        path = self.settings.state / 'health.json'
        return json.loads(path.read_text()) if path.exists() else {}
