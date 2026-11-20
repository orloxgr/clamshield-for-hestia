"""Persistent schedules, changed-file scans and generation-aware full rescans."""
from datetime import datetime, timedelta, timezone
import calendar
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import AccessDenied, ClamShieldError
from .paths import attributes, file_handle, walk
from .store import encode
from .providers import Providers
from .generations import current as current_generation
from .health import Health

DEFAULTS = {'watch': False, 'frequency': 'never', 'time': '02:00',
            'timezone': 'UTC', 'weekday': 0, 'monthday': 1, 'rescan_updates': True}


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ClamShieldError('Invalid scan policy')
    result = DEFAULTS | value
    if any(type(result[k]) is not bool for k in ('watch', 'rescan_updates')):
        raise ClamShieldError('Invalid scan policy toggle')
    if result['frequency'] not in ('never', 'daily', 'weekly', 'monthly'):
        raise ClamShieldError('Invalid schedule frequency')
    if not isinstance(result['time'], str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', result['time']):
        raise ClamShieldError('Invalid schedule time')
    if type(result['weekday']) is not int or not 0 <= result['weekday'] <= 6:
        raise ClamShieldError('Invalid weekday')
    if type(result['monthday']) is not int or not 1 <= result['monthday'] <= 31:
        raise ClamShieldError('Invalid day of month')
    try:
        ZoneInfo(result['timezone'])
    except (ZoneInfoNotFoundError, TypeError, ValueError) as exc:
        raise ClamShieldError('Invalid schedule timezone') from exc
    return result


def schedule_slot(policy, now):
    """Most recent due calendar slot; DST fallback executes a date only once."""
    local = now.astimezone(ZoneInfo(policy['timezone']))
    hour, minute = map(int, policy['time'].split(':'))
    due = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
    frequency = policy['frequency']
    if frequency == 'never':
        return None
    if frequency == 'daily':
        if due > local:
            due -= timedelta(days=1)
    elif frequency == 'weekly':
        due -= timedelta(days=(due.weekday() - policy['weekday']) % 7)
        if due > local:
            due -= timedelta(days=7)
    else:
        due = due.replace(day=min(policy['monthday'], calendar.monthrange(local.year, local.month)[1]))
        if due > local:
            previous = due.replace(day=1) - timedelta(days=1)
            due = previous.replace(day=min(policy['monthday'], calendar.monthrange(previous.year, previous.month)[1]),
                                   hour=hour, minute=minute, second=0, microsecond=0)
    return frequency + ':' + due.strftime('%Y-%m-%d')


class Scheduler:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia

    def policy(self, context, site):
        with self.store.connection() as db:
            row = db.execute('SELECT settings,root FROM policies WHERE owner=? AND identity=? AND domain=?',
                             (*self.store.scope(context), site['domain'])).fetchone()
        return validate_policy(json.loads(row['settings'])) if row and row['root'] == site['root'] else dict(DEFAULTS)

    def save(self, context, site, settings, now=None):
        if (site['owner'], site['identity']) != self.store.scope(context):
            raise AccessDenied('Site unavailable')
        policy = validate_policy(settings)
        # Saving a schedule starts from now, rather than immediately running a
        # missed slot from before the user enabled it.
        slot = schedule_slot(policy, now or datetime.now(timezone.utc))
        with self.store.connection(True) as db:
            db.execute('''INSERT INTO policies VALUES(?,?,?,?,?,?)
              ON CONFLICT(owner,identity,domain) DO UPDATE SET root=excluded.root,
              settings=excluded.settings,last_slot=excluded.last_slot''',
              (*self.store.scope(context), site['domain'], site['root'], encode(policy), slot))
            self.store.audit(context, 'policy.saved', site['domain'], policy, db)
        return policy

    def pending(self, context, domain):
        with self.store.connection() as db:
            return [dict(row) for row in db.execute('''SELECT target,source FROM jobs WHERE owner=? AND identity=?
              AND domain=? AND status IN ('queued','running')''', (*self.store.scope(context), domain)).fetchall()]

    def tick(self, now=None):
        now = now or datetime.now(timezone.utc)
        try:
            inventory = self.hestia.inventory()
        except (OSError, ClamShieldError):
            Health(self.settings, self.store).check({'hestia-inventory': {'state': 'unavailable', 'message': 'Native account inventory failed'}})
            return {'queued': [], 'failures': [{'error': 'Native Hestia inventory is unavailable; no account state was changed'}]}
        Health(self.settings, self.store).check({'hestia-inventory': {'state': 'healthy'}})
        generation = current_generation(self.settings)
        queued, failures = [], []
        # Provider downloads are separate maintenance tasks; the monitor never
        # blocks website discovery while waiting for a network transfer.
        providers = Providers(self.settings).public()
        if providers['automatic']:
            enabled = [name for name in ('official', 'securiteinfo', 'sanesecurity') if providers[name]['enabled']]
            stale = any(now.timestamp() - providers['status'].get(name, {}).get('last_attempt', 0) >= 3600 for name in enabled)
            admin = next((a for a in inventory if a['role'] == 'admin' and not a['suspended']), None)
            if stale and admin:
                admin_context = dict(actor=admin['owner'], owner=admin['owner'], identity=admin['identity'])
                self.store.enqueue_task(admin_context, 'signatures-update', {'provider': 'all'})
        for account in inventory:
            if account['suspended']:
                continue
            context = dict(actor=account['owner'], owner=account['owner'], identity=account['identity'])
            for site in account['sites']:
                if site['suspended']:
                    continue
                try:
                    queued.extend(self.site(context, site, generation, now))
                except (OSError, ClamShieldError):
                    failures.append({'owner': account['owner'], 'domain': site['domain'], 'error': 'Monitoring could not inspect this site'})
        return {'queued': queued, 'failures': failures}

    def site(self, context, site, generation, now):
        policy = self.policy(context, site)
        pending = [row for row in self.pending(context, site['domain']) if row['source'] not in ('wordpress-integrity', 'repair-preview','yara-trial')]
        if any(row['target'] == '' for row in pending):
            return []
        with self.store.connection() as db:
            row = db.execute('SELECT last_slot FROM policies WHERE owner=? AND identity=? AND domain=?',
                             (*self.store.scope(context), site['domain'])).fetchone()
            last = db.execute('''SELECT generation FROM jobs WHERE owner=? AND identity=? AND domain=?
              AND root=? AND target='' AND source NOT IN ('wordpress-integrity','repair-preview','yara-trial') AND status='completed' ORDER BY finished DESC LIMIT 1''',
              (*self.store.scope(context), site['domain'], site['root'])).fetchone()
            observations = {row['path']: json.loads(row['fingerprint']) for row in db.execute(
                'SELECT path,fingerprint FROM observations WHERE owner=? AND identity=? AND domain=? AND root=?',
                (*self.store.scope(context), site['domain'], site['root'])).fetchall()}
        slot = schedule_slot(policy, now)
        if row and slot and slot != row['last_slot']:
            # The durable job key also covers a crash before last_slot commits.
            job_id = self.store.enqueue(context, site, source='scheduled', generation=generation, dedup_key=slot)
            with self.store.connection() as db:
                db.execute('UPDATE policies SET last_slot=? WHERE owner=? AND identity=? AND domain=?',
                           (slot, *self.store.scope(context), site['domain']))
            return [job_id]
        if last and policy['rescan_updates'] and last['generation'] != generation:
            return [self.store.enqueue(context, site, source='signature-update', generation=generation)]
        if not policy['watch']:
            return []
        if not observations and not pending:
            return [self.store.enqueue(context, site, source='watch-initial', generation=generation)]
        queued = []
        for relative, state, detail in walk(site['root']):
            if state != 'regular':
                continue
            if any(p['target'] == relative or (p['target'] and relative.startswith(p['target'] + '/')) for p in pending):
                continue
            with file_handle(site['root'], relative) as (_, info):
                current = attributes(info)
            before = observations.get(relative)
            if before is None or any(before.get(key) != value for key, value in current.items()):
                queued.append(self.store.enqueue(context, site, relative, source='watch', generation=generation))
            if len(queued) >= 100:
                break
        return queued

    def once(self):
        import fcntl
        self.settings.prepare()
        with (self.settings.state / 'scheduler.lock').open('a+b') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'busy': True}
            return self.tick()
