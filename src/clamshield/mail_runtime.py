"""Small fail-closed state gate shared by the broker and control worker."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat

from .errors import EngineError

PHASES={'disabled','starting','active','draining','recovering'}


@contextmanager
def submission_guard(settings,*,exclusive=False):
    """Serialize durable gates against the check → submitting transition.

    The shared side ends before native Exim is spawned, so its broker callback
    never waits behind a controller waiting for the same native handoff.
    """
    settings.prepare();path=settings.state/'mail-runtime-submit.lock'
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if (path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
                info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
            raise EngineError('Untrusted mail submission gate lock')
        fcntl.flock(fd,fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:os.close(fd)


def read(path):
    if not path.exists() and not path.is_symlink():return None
    info=path.lstat()
    if (path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
            info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>32*1024*1024):
        raise EngineError('Mail integration state is not private or trusted')
    return json.loads(path.read_text())


def state(settings):
    value=read(settings.state/'mail-integration.json')
    owner=read(settings.state/'mail-integration-owner.json')
    if value is None:
        if owner is not None:raise EngineError('Mail integration state is missing')
        return None
    if (not isinstance(value,dict) or owner!={'owner':'clamshield','schema':1} or
            value.get('owner')!='clamshield' or value.get('schema')!=1 or value.get('phase') not in PHASES):
        raise EngineError('Mail integration state is invalid')
    return value


def fingerprint(path):
    info=Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:
        raise EngineError('Mail integration runtime file is untrusted')
    return {name:getattr(info,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_mode','st_nlink')}


def mode(settings):
    journal=read(settings.state/'mail-integration-journal.json')
    current=state(settings)
    if journal is not None:
        return 'draining' if journal.get('action')=='disable' and journal.get('phase') in ('prepared','draining') else 'starting'
    if current is None:return 'legacy'
    if current['phase']=='active':
        if set(current.get('runtime',{}))!={'/opt/clamshield-mail/local_scan.so','/etc/exim4/exim4.conf.localmacros','/usr/sbin/exim4'}:
            raise EngineError('Mail integration runtime identity is incomplete')
        for name,expected in current['runtime'].items():
            if fingerprint(name)!=expected:raise EngineError('Native mail runtime changed; integration verification is required')
    return current['phase']


def may_deliver(settings):
    return mode(settings) in ('legacy','active','draining')
