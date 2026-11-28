"""Bounded, passive collection of fixed native delivery fallback log markers.

Runs in maintenance, never in SMTP. An observed broker reply is communication
evidence only; neither a quiet log nor a successful reply establishes clean mail.
"""
from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
from zoneinfo import ZoneInfo

from .errors import EngineError

LIMIT = 256 * 1024
STATE_LIMIT = 65536
MAX_PENDING = 32
MAX_MESSAGES = 128
FALLBACK = 'ClamShield native delivery fallback; check incomplete'
PREFIX = r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: (?P<zone>[+-]\d{4}))? (?P<id>[A-Za-z0-9]{6}-[A-Za-z0-9]{6,16}-[A-Za-z0-9]{2,8}) '
# Only the fixed owned log record, not subjects, addresses or arbitrary suffixes.
DIRECT = re.compile(PREFIX + re.escape(FALLBACK))
WARNING = re.compile(PREFIX + r'(?:H=[^\s()\[\]]{1,255}(?: \([^\s()\[\]]{1,255}\))? \[[0-9a-fA-F:.]{1,64}\](?: U=[A-Za-z0-9_.-]{1,64})? )?Warning: ' + re.escape(FALLBACK))
REPLY = re.compile(PREFIX + r'ClamShield decision=(?P<decision>[0-4]) event=[0-9a-f]{32}')


@contextmanager
def parent(path):
    """Hold every directory without following links; check the named parent too."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise EngineError('Unexpected native diagnostic path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        before = os.fstat(fd)
        yield fd
        after = path.parent.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise EngineError('Native diagnostic directory changed during observation')
    finally:
        os.close(fd)


def trusted(info, owners, *, private=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in owners or
            info.st_mode & (0o077 if private else 0o022)):
        raise EngineError('Unsafe native diagnostic file')


class NativeMailHealth:
    def __init__(self, settings, store=None):
        self.settings, self.store = settings, store
        self.path = settings.state / 'native-mail-observations.json'

    @staticmethod
    def empty():
        return dict(version=1, cursor=None, checked=None, collection='not-observed',
                    history_limited=False, backlog=False, recent=[], incidents=[],
                    fallbacks=0, last_fallback=None, last_response=None, watermark=0, error=None, messages=[])

    def read(self):
        with parent(self.path) as directory:
            try: fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError: return self.empty()
            try:
                trusted(os.fstat(fd), {os.geteuid()}, private=True)
                before = os.fstat(fd)
                raw = os.read(fd, STATE_LIMIT + 1)
                if len(raw) > STATE_LIMIT: raise EngineError('Native mail observation storage exceeds its limit')
                after = os.fstat(fd)
                if raw != os.pread(fd, len(raw), 0) or any(getattr(before, key) != getattr(after, key) for key in
                        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                    raise EngineError('Native mail observation storage changed during reading')
                named = os.stat(self.path.name, dir_fd=directory, follow_symlinks=False)
                if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
                    raise EngineError('Native mail observation storage was replaced during reading')
            finally: os.close(fd)
        value = json.loads(raw)
        # Preserve the existing collector cursor/incidents. Individual message
        # receipts start with new observations; old scores are never invented.
        if isinstance(value,dict) and set(value)==set(self.empty())-{'messages'}:
            value['messages']=[]
        self.validate(value)
        return value

    @staticmethod
    def validate(value):
        def number(v): return type(v) in (int, float) and 0 <= v < 10**12
        if (not isinstance(value, dict) or set(value) != set(NativeMailHealth.empty()) or
                type(value['version']) is not int or value['version'] != 1 or
                not isinstance(value['collection'], str) or value['collection'] not in ('not-observed', 'observed', 'unavailable') or
                any(type(value[k]) is not bool for k in ('history_limited', 'backlog')) or
                any(value[k] is not None and not number(value[k]) for k in ('checked', 'last_fallback', 'last_response')) or
                not number(value['watermark']) or type(value['fallbacks']) is not int or value['fallbacks'] < 0 or
                value['error'] not in (None, 'Native delivery log could not be observed. Review native logging and diagnostic storage.') or
                not isinstance(value['recent'], list) or len(value['recent']) > 512 or
                any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in value['recent']) or
                not isinstance(value['incidents'], list) or len(value['incidents']) > MAX_PENDING or
                not isinstance(value['messages'],list) or len(value['messages'])>MAX_MESSAGES):
            raise EngineError('Invalid native mail observation storage')
        c = value['cursor']
        if c is not None and (not isinstance(c, dict) or set(c) != {'path', 'dev', 'ino', 'offset', 'discard'} or
                not isinstance(c['path'], str) or len(c['path']) > 4096 or not c['path'].startswith('/') or
                any(type(c[k]) is not int or c[k] < 0 for k in ('dev', 'ino', 'offset')) or type(c['discard']) is not bool):
            raise EngineError('Invalid native mail log cursor')
        for row in value['incidents']:
            if (not isinstance(row, dict) or set(row) != {'id', 'first', 'last', 'count', 'response', 'published'} or
                    not isinstance(row['id'], str) or not re.fullmatch('[0-9a-f]{32}', row['id']) or
                    not number(row['first']) or not number(row['last']) or row['last'] < row['first'] or
                    type(row['count']) is not int or row['count'] < 1 or type(row['published']) is not bool or
                    (row['response'] is not None and (not number(row['response']) or row['response'] < row['last']))):
                raise EngineError('Invalid native mail fallback incident')
        if len({row['id'] for row in value['incidents']}) != len(value['incidents']):
            raise EngineError('Duplicate native mail fallback incident')
        for row in value['messages']:
            if (not isinstance(row,dict) or set(row)!={'id','native_id','created'} or
                    not isinstance(row['native_id'],str) or not re.fullmatch(r'[A-Za-z0-9]{6}-[A-Za-z0-9]{6,16}-[A-Za-z0-9]{2,8}',row['native_id']) or
                    row['id']!=hashlib.sha256(('fallback:'+row['native_id']).encode()).hexdigest() or not number(row['created'])):
                raise EngineError('Invalid native message observation')
        if len({row['id'] for row in value['messages']})!=len(value['messages']):
            raise EngineError('Duplicate pending native message observation')

    def save(self, value):
        self.validate(value)
        # Keep the ordinary on-disk receipt compatible with the existing
        # collector when there is no pending message evidence to preserve.
        stored=value if value['messages'] else {k:v for k,v in value.items() if k!='messages'}
        raw = json.dumps(stored, sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > STATE_LIMIT: raise EngineError('Native mail observation storage exceeds its limit')
        with parent(self.path) as directory:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise EngineError('Unsafe native mail observation directory')
            name = '.native-mail-' + os.urandom(16).hex()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try: os.unlink(name, dir_fd=directory)
                except FileNotFoundError: pass

    @staticmethod
    def source():
        result = subprocess.run(['/usr/sbin/exim4', '-bP', 'log_file_path', 'timezone'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True)
        lines = result.stdout.decode('utf-8', errors='strict').splitlines()
        values = dict(line.split(' = ', 1) for line in lines if ' = ' in line)
        pattern = values.get('log_file_path', '')
        if (not pattern.startswith('/') or ':' in pattern or pattern.count('%s') != 1 or
                '%' in pattern.replace('%s', '') or len(pattern) > 4096):
            raise EngineError('Native log destination is unsupported')
        zone = values.get('timezone', '')
        return Path(pattern.replace('%s', 'main')), ZoneInfo(zone) if zone else None

    @staticmethod
    def parse(raw, timezone):
        if len(raw) > 8192: return None
        try: line = raw.decode('ascii')
        except UnicodeDecodeError: return None
        match = DIRECT.fullmatch(line) or WARNING.fullmatch(line)
        kind = 'fallback'
        if match is None: match = REPLY.fullmatch(line); kind = 'response'
        if match is None: return None
        try:
            moment = datetime.strptime(match['time'], '%Y-%m-%d %H:%M:%S')
            if match['zone']:
                moment = datetime.strptime(match['time'] + match['zone'], '%Y-%m-%d %H:%M:%S%z')
            elif timezone is not None: moment = moment.replace(tzinfo=timezone)
            observed = moment.timestamp()
            if observed < 0 or observed > time.time() + 300: return None
        except (ValueError, OverflowError): return None
        digest = hashlib.sha256((kind + ':' + match['id']).encode()).hexdigest()
        return kind, observed, digest

    def scan(self, value, path, timezone):
        uid = pwd.getpwnam('Debian-exim').pw_uid
        with parent(path) as directory:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                before = os.fstat(fd); trusted(before, {0, uid})
                c = value['cursor']
                same = c and c['path'] == str(path) and (c['dev'], c['ino']) == (before.st_dev, before.st_ino) and c['offset'] <= before.st_size
                offset = c['offset'] if same else max(0, before.st_size - LIMIT)
                discard = c['discard'] if same else offset > 0
                if not same and (c is not None or offset): value['history_limited'] = True
                raw = os.pread(fd, LIMIT, offset)
                if raw != os.pread(fd, len(raw), offset): raise EngineError('Native delivery log changed during observation')
                after = os.fstat(fd); named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                trusted(after, {0, uid})
                if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino) or after.st_size < before.st_size:
                    raise EngineError('Native delivery log was replaced during observation')
                consumed = 0
                parts = raw.split(b'\n')
                for index, part in enumerate(parts):
                    if index == len(parts) - 1:
                        if discard or len(part) > 8192:
                            consumed += len(part); discard = True; value['history_limited'] = True
                        break
                    if discard:
                        discard = False; value['history_limited'] = True
                    else:
                        event = self.parse(part, timezone)
                        if event:
                            match=(DIRECT.fullmatch(part.decode('ascii')) or WARNING.fullmatch(part.decode('ascii'))) if event[0]=='fallback' else None
                            if not self.record(value,event,native_id=match['id'] if match else None):break
                        if len(part) > 8192: value['history_limited'] = True
                    consumed += len(part) + 1
                value['cursor'] = dict(path=str(path), dev=before.st_dev, ino=before.st_ino, offset=offset + consumed, discard=discard)
                value['backlog'] = offset + consumed < after.st_size
            finally: os.close(fd)

    @staticmethod
    def record(value, event, *, native_id=None):
        kind, observed, digest = event
        if digest in value['recent']: return True
        if native_id is not None and not any(row['id']==digest for row in value['messages']):
            # Stop before consuming the next log line when the durable outbox is
            # full. Maintenance can publish it after recovery, then resume this
            # same cursor. No SMTP work or native mail submission occurs here.
            if len(value['messages'])>=MAX_MESSAGES:return False
            value['messages'].append(dict(id=digest,native_id=native_id,created=observed))
        # Rotation/clock changes cannot turn old replies into current recovery.
        if observed < value['watermark']:
            value['history_limited'] = True
            return True
        rows = value['incidents']; current = rows[-1] if rows and rows[-1]['response'] is None else None
        if kind == 'fallback':
            if current is None:
                if len(rows) == MAX_PENDING:
                    if not rows[0]['published']: return False
                    rows.pop(0)
                current = dict(id=digest[:32], first=observed, last=observed, count=0, response=None, published=False)
                rows.append(current)
            current['last'] = observed; current['count'] += 1
            value['fallbacks'] += 1; value['last_fallback'] = observed
        else:
            value['last_response'] = observed
            if current: current['response'] = observed
        value['watermark'] = observed
        value['recent'] = (value['recent'] + [digest])[-512:]
        return True

    def collect(self):
        # Maintenance prepares owned storage. Never create/chmod a path before
        # resolving its directory chain without symbolic links here.
        with parent(self.path) as directory:
            fd = os.open('native-mail-observations.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            try:
                trusted(os.fstat(fd), {os.geteuid()}, private=True)
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: return {'busy': True}
                value = self.read()
                # Do not commit partial parsing when an input changes underneath us.
                candidate = json.loads(json.dumps(value))
                try:
                    self.scan(candidate, *self.source())
                    candidate.update(collection='observed', checked=time.time(), error=None)
                    value = candidate
                except (OSError, ValueError, KeyError, EngineError, subprocess.SubprocessError):
                    value.update(collection='unavailable', checked=time.time(), history_limited=True,
                        error='Native delivery log could not be observed. Review native logging and diagnostic storage.')
                self.save(value)
                self.publish(value)
                return self.summary(value)
            finally: os.close(fd)

    def publish(self, value):
        if self.store is None: return
        if value['messages']:
            with self.store.connection(True) as db:
                db.executemany('INSERT OR IGNORE INTO native_mail_messages VALUES(?,?,?)',
                    [(row['id'][:32],row['native_id'],row['created']) for row in value['messages']])
            value['messages']=[]
            self.save(value)
        for row in value['incidents']:
            if row['published']: continue
            detail = dict(message='Native delivery fallback was recorded. The ClamShield check was incomplete; this is not a clean verdict.',
                          first_observed=row['first'], last_observed=row['last'], observed_fallbacks=row['count'],
                          action='Review Email settings / Mail integration and the native mail logs.')
            with self.store.connection(True) as db:
                changed = db.execute('INSERT OR IGNORE INTO native_mail_alerts VALUES(?,?)', (row['id'], time.time())).rowcount
                if changed:
                    self.store.audit(dict(actor='clamshield-maintenance', owner='@admin', identity=''),
                                     'mail.native_fallback', 'mail-integration', detail, db)
                    self.store.notify('@admin', '', 'mail.native_fallback', 'mail-integration', detail, 'native-mail:' + row['id'], db)
            row['published'] = True
            self.save(value)

    @staticmethod
    def summary(value):
        return {k: value[k] for k in ('collection', 'checked', 'history_limited', 'backlog', 'fallbacks', 'last_fallback', 'last_response', 'error')}

    def status(self):
        if not self.settings.state.exists(): return self.summary(self.empty())
        return self.summary(self.read())
