"""Persistent administrator intent for the owned website ClamAV service."""
import json
import os
import stat

from .errors import EngineError


def validate_policy(value):
    if (not isinstance(value,dict) or set(value)!={'owner','schema','enabled','changed_at'} or
            value['owner']!='clamshield' or type(value['schema']) is not int or value['schema']!=1 or
            type(value['enabled']) is not bool or type(value['changed_at']) not in (int,float) or
            not 0<=value['changed_at']<10**12):
        raise EngineError('Invalid website engine policy')
    return value


def website_policy(settings):
    path=settings.state/'website-engine.json'
    if not path.exists() and not path.is_symlink():return None
    info=path.lstat();parent=path.parent.lstat()
    if (path.resolve()!=path or info.st_uid!=os.geteuid() or info.st_mode&0o077 or
            not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>4096 or
            parent.st_uid!=os.geteuid() or parent.st_mode&0o077):
        raise EngineError('Website engine policy is not owned or protected')
    try:return validate_policy(json.loads(path.read_text()))
    except (ValueError,TypeError):raise EngineError('Invalid website engine policy') from None
