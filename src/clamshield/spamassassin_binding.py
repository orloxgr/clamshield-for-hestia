"""Kernel peer/process identity and fixed owned-daemon launch contract."""
import hashlib
import logging
from pathlib import Path

from .errors import EngineError
from .mail_bridge import process_start

UNIT = 'clamshield-mail-spamd.service'
ARGUMENTS = ['--socketpath=/run/clamshield-mail-spamd/spamd.sock', '--socketmode=600',
             '--nouser-config', '--max-children=2', '--min-children=1', '--min-spare=1',
             '--max-spare=2', '--helper-home-dir=/var/lib/clamshield-spamd',
             '--cf=bayes_auto_learn 0', '--cf=use_bayes 0',
             '--cf=include /etc/clamshield/spamassassin/active.cf',
             '--timeout-child=20', '--timeout-tcp=5']
EXTRA = {'--local', '-L', '--ipv4-only', '--ipv4', '-4', '--ipv6', '-6'}


def commandline(arguments):
    if arguments[:3] == ['/usr/bin/perl', '-T -w', '/usr/sbin/spamd']:
        values = arguments[3:]
    elif arguments[:4] == ['/usr/bin/perl', '-T', '-w', '/usr/sbin/spamd']:
        values = arguments[4:]
    elif arguments[:1] == ['/usr/sbin/spamd']:
        values = arguments[1:]
    else:
        raise EngineError('SpamAssassin is not using the owned launch contract')
    if values[:len(ARGUMENTS)] != ARGUMENTS or any(value not in EXTRA for value in values[len(ARGUMENTS):]):
        raise EngineError('SpamAssassin launch options can override validated settings')
    return '--local' in values or '-L' in values


def process(peer):
    if (not isinstance(peer, dict) or type(peer.get('pid')) is not int or peer['pid'] < 2 or
            type(peer.get('birth')) is not int or peer['birth'] < 0):
        raise EngineError('SpamAssassin has no trusted socket peer identity')
    pid = peer['pid']; root = Path('/proc')/str(pid)
    if process_start(pid) != peer['birth']:
        raise EngineError('SpamAssassin socket process was replaced')
    info = (root/'exe').stat(); native = Path('/usr/bin/perl').stat()
    if (info.st_dev, info.st_ino) != (native.st_dev, native.st_ino):
        raise EngineError('SpamAssassin process executable changed')
    if not any(line.split(':',2)[-1] == '/system.slice/'+UNIT for line in (root/'cgroup').read_text().splitlines()):
        raise EngineError('SpamAssassin peer is outside the owned service')
    raw = (root/'cmdline').read_bytes()
    local = commandline([value.decode('utf-8') for value in raw.split(b'\0') if value])
    if process_start(pid) != peer['birth'] or (root/'exe').stat().st_ino != info.st_ino:
        raise EngineError('SpamAssassin process changed during verification')
    return dict(pid=pid, birth=peer['birth'], executable_device=info.st_dev,
                executable_inode=info.st_ino, arguments_sha256=hashlib.sha256(raw).hexdigest(), local_mode=local)


class BoundSpamAssassin:
    def __init__(self, engine, controls, policy):
        self.engine, self.controls, self.policy = engine, controls, policy

    def scan(self, fd, *, deadline=None):
        report = self.engine.scan(fd, deadline=deadline)
        self.controls.verify_report(report, self.policy, deadline=deadline)
        from .dns_health import DnsHealth
        try:
            if report.get('dns_observations'):DnsHealth(self.controls.settings).observe(report)
        except (OSError,ValueError,EngineError) as exc:
            # Optional aggregate telemetry cannot change a verified score.
            # Per-message observations remain in the immutable decision.
            logging.getLogger(__name__).warning('DNS observations could not be saved (%s)',type(exc).__name__)
        return report
