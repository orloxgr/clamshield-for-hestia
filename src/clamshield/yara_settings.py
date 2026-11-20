"""Administrator-owned website YARA selection and execution limits."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import stat

from .atomic import write_json
from .errors import ClamShieldError
from .store import encode

DEFAULTS = dict(enabled=True, timeout_seconds=45, max_file_mib=50)


class YaraSettings:
    def __init__(self, settings):
        self.settings = settings
        self.path = settings.state / 'yara-settings.json'

    @staticmethod
    def validate(value):
        if not isinstance(value, dict) or set(value) != set(DEFAULTS) or type(value['enabled']) is not bool:
            raise ClamShieldError('Choose a YARA scanning toggle, timeout and file-size limit')
        for key, maximum in (('timeout_seconds', 3600), ('max_file_mib', 4096)):
            if type(value[key]) is not int or not 1 <= value[key] <= maximum:
                raise ClamShieldError('Invalid YARA timeout or file-size limit')
        return dict(value)

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():
            return dict(DEFAULTS)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ClamShieldError('YARA scanning settings are not protected')
        return self.validate(json.loads(self.path.read_text()))

    def token(self):
        return hashlib.sha256(encode(self.read()).encode()).hexdigest()[:20]

    @contextmanager
    def locked(self):
        self.settings.prepare()
        fd = os.open(self.settings.state/'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def apply(self, value):
        policy = self.validate(value)
        with self.locked():
            write_json(self.path, policy)
        return policy
