"""Structured, linted controls for our isolated daemon; native files stay intact."""
from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import time

from .atomic import write, write_json, sync_directory
from .errors import ClamShieldError, EngineError
from .mail_bridge import SEALS
from .mail_scanners import SpamAssassin
from .signature_catalog import engine_lock

DEFAULTS = dict(required_score=5.0, rbl_enabled=True, uribl_enabled=True,
                blocked_zones=[], scores={})
UNIT = 'clamshield-mail-spamd.service'
BASE = Path('/etc/clamshield/spamassassin')
MARKER = '# Managed by clamshield\n'
# Administrative responses describe lookup availability, never message content.
# Keep these independent of optional per-rule overrides and upstream defaults.
INFRASTRUCTURE_RULES = (
    'RCVD_IN_VALIDITY_CERTIFIED_BLOCKED', 'RCVD_IN_VALIDITY_RPBL_BLOCKED',
    'RCVD_IN_VALIDITY_SAFE_BLOCKED', 'URIBL_BLOCKED', 'RCVD_IN_DNSWL_BLOCKED',
)
SAFETY_VERSION = 1
REPORTER = Path('/opt/clamshield/tools/spamassassin-report.pm')


def validate(value, *, legacy=False):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ClamShieldError('Invalid SpamAssassin settings')
    result = deepcopy(value)
    score = result['required_score']
    if (type(score) not in (int, float) or not math.isfinite(score) or not 0.1 <= score <= 100 or
            abs(round(score * 10) - score * 10) > 1e-8):
        raise ClamShieldError('Required score must be 0.1 to 100, in steps of 0.1')
    result['required_score'] = float(score)
    for key in ('rbl_enabled', 'uribl_enabled'):
        if type(result[key]) is not bool:
            raise ClamShieldError('Invalid DNS blocklist toggle')
    zones = result['blocked_zones']
    if not isinstance(zones, list) or len(zones) > 100:
        raise ClamShieldError('Use up to 100 blocked DNS zones')
    for zone in zones:
        if (not isinstance(zone, str) or len(zone) > 253 or '.' not in zone or
                not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in zone.split('.'))):
            raise ClamShieldError('Use lowercase DNS zone names without wildcards or credentials')
    result['blocked_zones'] = sorted(set(zones))
    scores = result['scores']
    if not isinstance(scores, dict) or len(scores) > 250:
        raise ClamShieldError('Use up to 250 rule score overrides')
    for name, amount in scores.items():
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,126}', name) or
                name.startswith('CLAMSHIELD_CONFIG_') or type(amount) not in (int, float) or
                not math.isfinite(amount) or not -100 <= amount <= 100):
            raise ClamShieldError('Invalid rule name or score; scores must be -100 to 100')
        decimal = Decimal(str(amount))
        if decimal != decimal.quantize(Decimal('0.000001')):
            raise ClamShieldError('Rule scores support up to six decimal places')
        if not legacy and name in INFRASTRUCTURE_RULES and amount != 0:
            raise ClamShieldError('DNS blocklist access failures must have a zero spam score')
    return result


def revision(policy, *, legacy=False):
    value = policy if legacy else dict(policy=policy, safety_version=SAFETY_VERSION, report_version=1)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def render(policy, *, legacy=False):
    policy = validate(policy, legacy=legacy); token = revision(policy, legacy=legacy)
    lines = [MARKER.rstrip(), 'bayes_auto_learn 0', 'use_bayes 0',
             'ifplugin Mail::SpamAssassin::Plugin::Pyzor', 'use_pyzor 0', 'endif',
             'ifplugin Mail::SpamAssassin::Plugin::Razor2', 'use_razor2 0', 'endif',
             'ifplugin Mail::SpamAssassin::Plugin::DCC', 'use_dcc 0', 'endif',
             'required_score %.1f' % policy['required_score'],
             'skip_rbl_checks ' + str(int(not policy['rbl_enabled'])),
             'skip_uribl_checks ' + str(int(not policy['uribl_enabled']))]
    lines += ['dns_query_restriction deny ' + zone for zone in policy['blocked_zones']]
    lines += ['score %s %.6f' % (name, amount) for name, amount in sorted(policy['scores'].items())]
    if not legacy:
        lines += ['score %s 0' % name for name in INFRASTRUCTURE_RULES]
        reporter = REPORTER
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(reporter)):
            raise EngineError('Unsupported SpamAssassin report plugin path')
        lines += ['loadplugin ClamShield::Report ' + str(reporter), 'clear_report_template',
                  'report CLAMSHIELD/1 ' + token, 'report _CLAMSHIELDREPORT_']
    # A non-executable inert message proves which configuration the daemon loaded.
    lines += ['header CLAMSHIELD_CONFIG_%s X-ClamShield-Config =~ /^%s$/' % (token[:16], token),
              'score CLAMSHIELD_CONFIG_%s 0.001' % token[:16]]
    return '\n'.join(lines) + '\n'


class SpamAssassinControls:
    def __init__(self, settings, *, base=BASE):
        self.settings, self.base = settings, Path(base)
        self.active = self.base / 'active.cf'
        self.metadata = settings.state / 'spamassassin.json'
        self.journal = settings.state / 'spamassassin-activation.json'
        self.proof = settings.state / 'spamassassin-daemon.json'

    def runtime_stamp(self):
        result = {}
        reporter = REPORTER.resolve(strict=True)
        for name in ('/etc/clamshield/spamd.env', '/etc/systemd/system/' + UNIT, str(reporter)):
            path = Path(name); self._trusted(path)
            if path.stat().st_size > 65536:
                raise EngineError('SpamAssassin runtime configuration exceeds its limit')
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def read_proof(self):
        if not self.proof.exists() and not self.proof.is_symlink():
            return None
        self._trusted(self.proof)
        return json.loads(self.proof.read_text())

    def discard_proof(self):
        self.proof.unlink(missing_ok=True); sync_directory(self.settings.state)

    @staticmethod
    def verify_contributions(report, stamp):
        if report.get('reporter_sha256') != stamp.get(str(REPORTER.resolve(strict=True))):
            raise EngineError('SpamAssassin process has not loaded the installed report plugin')
        if any(rule['name'] in INFRASTRUCTURE_RULES and rule['score'] != 0 for rule in report.get('rules', [])):
            raise EngineError('SpamAssassin assigned points to a DNS blocklist access failure')

    def verify_report(self, report, policy, *, deadline=None):
        """Called under mail's shared engine lock, after releasing its SA socket.

        A second incoming message must not hold a daemon worker while waiting for
        a configuration probe. Verdicts are never cached, only process readiness.
        """
        from .spamassassin_binding import process
        configured = self.configured()
        if configured is None or configured['revision'] != revision(policy):
            raise EngineError('SpamAssassin configured policy changed before its score could be used')
        if report.get('revision') != revision(policy):
            raise EngineError('SpamAssassin report uses an unexpected configuration revision')
        identity = process(report.get('_peer')); stamp = self.runtime_stamp()
        self.verify_contributions(report, stamp)
        wanted = dict(revision=revision(policy), identity=identity, runtime=stamp)
        if abs(report['threshold'] - policy['required_score']) > .051:
            raise EngineError('SpamAssassin score threshold differs from validated settings')
        if self.read_proof() == wanted:
            return
        fd = os.open(self.settings.state/'spamassassin-proof.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        try:
            self._trusted(self.settings.state/'spamassassin-proof.lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EngineError('SpamAssassin process verification is already running') from exc
            if self.read_proof() != wanted:
                self.probe(policy, deadline=deadline)
            if self.read_proof() != wanted or process(report['_peer']) != identity or self.runtime_stamp() != stamp:
                raise EngineError('SpamAssassin process changed before its score could be used')
        finally:
            os.close(fd)

    @staticmethod
    def _trusted(path, *, directory=False):
        info = path.lstat()
        import stat
        if (path.resolve() != path or info.st_uid != os.geteuid() or info.st_mode & 0o022 or
                (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)) or
                (directory and not stat.S_ISDIR(info.st_mode))):
            raise EngineError('Untrusted SpamAssassin storage')

    def prepare(self):
        self.settings.prepare()
        self.base.mkdir(mode=0o755, parents=True, exist_ok=True)
        self._trusted(self.base, directory=True)

    @contextmanager
    def locked(self):
        self.prepare()
        fd = os.open(self.settings.state / 'spamassassin.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            self._trusted(self.settings.state / 'spamassassin.lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def configured(self, *, allow_legacy=False):
        if not self.metadata.exists() and not self.metadata.is_symlink():
            return None
        self._trusted(self.metadata)
        value = json.loads(self.metadata.read_text())
        policy = validate(value['policy'], legacy=allow_legacy)
        self._trusted(self.active)
        if value['revision'] != revision(policy) or self.active.read_text() != render(policy):
            if (allow_legacy and value['revision'] == revision(policy, legacy=True) and
                    self.active.read_text() == render(policy, legacy=True)):
                return value
            raise EngineError('SpamAssassin configuration changed or requires safety activation')
        return value

    @staticmethod
    def verify_infrastructure_scores(parsed):
        """Inspect all installed score sets, not just the selected lint mode."""
        for rule in parsed['rules']:
            if rule['name'] not in INFRASTRUCTURE_RULES:
                continue
            scores = rule.get('scores')
            if (not isinstance(scores, list) or len(scores) != 4 or
                    any(type(score) not in (int, float) or score != 0 for score in scores) or
                    rule.get('score') != 0):
                raise EngineError('A DNS blocklist access failure still contributes to spam scoring')

    def upgrade_safety(self):
        """Only rewrite an exactly recognized owned configuration; retain policy."""
        with self.locked():
            saved = self.configured(allow_legacy=True)
            if saved is None:
                self._trusted(self.active)
                before = self.active.read_text()
                old_initial = (MARKER + '# Initial isolated daemon defaults. Structured UI activation adds a verified revision.\n' +
                               '\n'.join(render(DEFAULTS, legacy=True).splitlines()[1:-2]) + '\n')
                if before != old_initial:
                    return False
                policy, expected = deepcopy(DEFAULTS), ''
            elif saved['revision'] == revision(saved['policy']):
                return False
            else:
                before = self.active.read_text()
                policy, expected = deepcopy(saved['policy']), saved['revision']
            for name in INFRASTRUCTURE_RULES:
                if name in policy['scores']:
                    policy['scores'][name] = 0
        self.apply(policy, expected_revision=expected, expected_configuration=hashlib.sha256(before.encode()).hexdigest())
        return True

    @staticmethod
    def running():
        return subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT], timeout=5).returncode == 0

    def status(self):
        try:
            value = self.configured()
            running = self.running()
            local_mode = None
            if running:
                pid = subprocess.check_output(['/usr/bin/systemctl', 'show', '-p', 'MainPID', '--value', UNIT], timeout=5).decode().strip()
                if not pid.isdigit() or int(pid) < 2:
                    raise EngineError('SpamAssassin process unavailable')
                arguments = Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0')
                local_mode = any(arg in (b'-L', b'--local') for arg in arguments)
            verified = False
            if running and value:
                from .spamassassin_binding import process
                proof = self.read_proof()
                if proof:
                    verified = (proof['revision'] == value['revision'] and proof['identity']['pid'] == int(pid) and
                                process({key:proof['identity'][key] for key in ('pid','birth')}) == proof['identity'] and
                                proof['runtime'] == self.runtime_stamp())
            return dict(policy=value['policy'] if value else deepcopy(DEFAULTS),
                        revision=value['revision'] if value else None, configured=value is not None,
                        applied_at=value.get('applied_at') if value else None,
                        service_active=running, local_mode=local_mode, recovery_pending=self.journal.exists(),
                        daemon_verified=verified, optional_clients='disabled', scope='ClamShield isolated mail scanner')
        except (OSError, ValueError, KeyError, TypeError, ClamShieldError, subprocess.SubprocessError):
            return dict(error='SpamAssassin settings unavailable or changed; inspect recovery',
                        recovery_pending=self.journal.exists())

    def inspect(self, path):
        """Distro parser, default rules and plugins, then our supported include."""
        self._trusted(path)
        helper = Path(__file__).resolve().parents[2] / 'tools/spamassassin-config.pl'
        if not helper.is_file():
            raise EngineError('SpamAssassin validation helper is missing; update ClamShield and rerun the installer')
        self._trusted(helper)
        command = ['/usr/bin/setpriv', '--reuid=debian-spamd', '--regid=debian-spamd',
                   '--init-groups', '--no-new-privs', '/usr/bin/prlimit', '--cpu=30', '--as=805306368',
                   '--fsize=4194304', '--', '/usr/bin/perl', str(helper), str(path)]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, env={'PATH': '/usr/bin:/bin', 'HOME': '/var/lib/clamshield-spamd', 'LANG': 'C.UTF-8'}) as process:
            try:
                output, _diagnostic = process.communicate(timeout=40)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL); process.communicate()
                raise EngineError('SpamAssassin validation timed out') from exc
        if process.returncode or len(output) > 4 * 1024 * 1024:
            raise EngineError('SpamAssassin configuration validation failed')
        value = json.loads(output)
        if not isinstance(value.get('rules'), list) or len(value['rules']) > 12000:
            raise EngineError('Invalid installed SpamAssassin rule catalog')
        return value

    def catalog(self):
        with self.locked():
            path = self.base / 'catalog.cf'
            write(path, render(DEFAULTS), 0o644)
            try:
                return self.inspect(path)
            finally:
                path.unlink(); sync_directory(self.base)

    @staticmethod
    def _restart():
        subprocess.run(['/usr/bin/systemctl', 'restart', UNIT], check=True, timeout=45)

    @staticmethod
    def _stop():
        subprocess.run(['/usr/bin/systemctl', 'stop', UNIT], check=True, timeout=45)

    def probe(self, policy, *, deadline=None, legacy=False):
        token = revision(policy, legacy=legacy)
        # The daemon canary binds to the safety format as well as user policy.
        # Validate the installed rule scores before accepting process readiness.
        if not legacy:
            self.verify_infrastructure_scores(self.inspect(self.active))
        payload = ('From: control@invalid.test\r\nTo: control@invalid.test\r\n'
                   'Subject: ClamShield configuration check\r\nX-ClamShield-Config: ' + token +
                   '\r\n\r\nClamShield inert configuration probe.\r\n').encode()
        fd = os.memfd_create('clamshield-spamd-probe', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            os.write(fd, payload); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
            deadline = min(deadline if deadline is not None else float('inf'), time.monotonic() + 30)
            engine = SpamAssassin('/run/clamshield-mail-spamd/spamd.sock',
                                 expected_uid=pwd.getpwnam('debian-spamd').pw_uid, timeout=20, report=not legacy)
            while True:
                try:
                    report = engine.scan(fd, deadline=deadline)
                except EngineError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
                    continue
                if (abs(report['threshold'] - policy['required_score']) > 0.051 or
                        'CLAMSHIELD_CONFIG_' + token[:16] not in report['symbols']):
                    raise EngineError('SpamAssassin daemon has not loaded the expected configuration')
                from .spamassassin_binding import process
                identity = process(report.get('_peer'))
                current = self.configured(allow_legacy=legacy)
                if current is None or current['revision'] != token:
                    raise EngineError('SpamAssassin settings changed during process verification')
                stamp = self.runtime_stamp()
                if not legacy:
                    self.verify_contributions(report, stamp)
                write_json(self.proof, dict(revision=token, identity=identity, runtime=stamp))
                return report
        finally:
            os.close(fd)

    def _restore(self, saved):
        # A crash may have left a daemon reading candidate bytes. Stop first.
        self._stop()
        self.discard_proof()
        write(self.active, saved['config'], 0o644)
        if saved['metadata'] is None:
            self.metadata.unlink(missing_ok=True); sync_directory(self.settings.state)
        else:
            write_json(self.metadata, saved['metadata'])
        if saved['was_active']:
            self._restart()
            if saved['metadata']:
                policy = saved['metadata']['policy']
                if saved['metadata']['revision'] == revision(policy, legacy=True):
                    self.probe(policy, legacy=True)
                else:
                    self.probe(policy)
        self.journal.unlink(); sync_directory(self.settings.state)

    def recover(self):
        with self.locked(), engine_lock(self.settings, exclusive=True, blocking=True):
            if self.journal.exists():
                self._trusted(self.journal)
                self._restore(json.loads(self.journal.read_text()))
                return True
            return False

    def apply(self, policy, *, expected_revision=None, expected_configuration=None):
        policy = validate(policy)
        with self.locked(), engine_lock(self.settings, exclusive=True, blocking=True):
            if self.journal.exists():
                raise EngineError('SpamAssassin activation recovery is pending')
            old = self.configured(allow_legacy=True)
            if expected_revision is not None and (old['revision'] if old else '') != expected_revision:
                raise EngineError('SpamAssassin settings changed before safety activation')
            self._trusted(self.active)
            before = self.active.read_text()
            if expected_configuration is not None and hashlib.sha256(before.encode()).hexdigest() != expected_configuration:
                raise EngineError('SpamAssassin configuration changed before safety activation')
            if not before.startswith(MARKER):
                raise EngineError('Refusing unmanaged SpamAssassin configuration')
            candidate = self.base / 'candidate.cf'
            write(candidate, render(policy), 0o644)
            try:
                parsed = self.inspect(candidate)
                self.verify_infrastructure_scores(parsed)
                known = {rule['name'] for rule in parsed['rules']}
                if set(policy['scores']) - known:
                    raise ClamShieldError('A score override names an unavailable installed rule')
                if (abs(parsed['required_score'] - policy['required_score']) > 1e-8 or
                        parsed['skip_rbl_checks'] != int(not policy['rbl_enabled']) or
                        parsed['skip_uribl_checks'] != int(not policy['uribl_enabled']) or
                        any(parsed['dns_query_blocked'].get(zone) != 1 for zone in policy['blocked_zones'])):
                    raise EngineError('SpamAssassin parsed settings differ from the requested configuration')
                saved = dict(config=before, metadata=old, was_active=self.running())
                write_json(self.journal, saved)
                try:
                    self._stop()
                    self.discard_proof()
                    write(self.active, candidate.read_text(), 0o644)
                    result = dict(policy=policy, revision=revision(policy), applied_at=time.time())
                    write_json(self.metadata, result)
                    if saved['was_active']:
                        self._restart(); self.probe(policy)
                    self.journal.unlink(); sync_directory(self.settings.state)
                    return result | {'service_restarted': saved['was_active']}
                except Exception:
                    self._restore(saved)
                    raise
            finally:
                candidate.unlink(missing_ok=True); sync_directory(self.base)
