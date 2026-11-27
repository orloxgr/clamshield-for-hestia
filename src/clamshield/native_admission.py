"""Bound engine occupancy by purpose, including work after a client disappears."""
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import stat
import time

from .errors import EngineError

SLOTS={'website':1,'mail':2,'native-mail':4}


class Reservation:
    def __init__(self,fd,maximum_seconds,grace):
        self.fd,self.maximum_seconds,self.grace=fd,maximum_seconds,grace

    def write(self,value):
        data=json.dumps(dict(busy_until=value),separators=(',',':')).encode()
        os.lseek(self.fd,0,os.SEEK_SET);os.ftruncate(self.fd,0)
        view=memoryview(data)
        while view:
            count=os.write(self.fd,view)
            if not count:raise EngineError('Native ClamAV capacity record could not be written')
            view=view[count:]
        os.fsync(self.fd)

    def started(self):
        # A disconnect does not prove that clamd stopped evaluating the file.
        # The active daemon must have this verified MaxScanTime bound.
        self.write(time.monotonic()+self.maximum_seconds+self.grace)

    def complete(self):self.write(0)


class NativeAdmission:
    def __init__(self,directory,*,native_threads,maximum_seconds=20,grace=2):
        if type(native_threads) is not int or native_threads<sum(SLOTS.values())+1:
            raise EngineError('Native ClamAV needs capacity reserved for mail')
        if (type(maximum_seconds) not in (int,float) or type(grace) not in (int,float) or
                not math.isfinite(maximum_seconds) or not math.isfinite(grace) or
                not 0<maximum_seconds<=120 or not 0<=grace<=5):
            raise EngineError('Invalid verified native scan time limit')
        self.directory=Path(directory);self.maximum_seconds=maximum_seconds;self.grace=grace

    def trusted(self):
        info=self.directory.lstat()
        if (self.directory.resolve()!=self.directory or not stat.S_ISDIR(info.st_mode) or
                info.st_uid!=0 or info.st_mode&0o077):
            raise EngineError('Native ClamAV capacity directory is not trusted')

    @contextmanager
    def reserve(self,purpose,deadline):
        if not isinstance(purpose,str) or purpose not in SLOTS:raise EngineError('Unknown native ClamAV scan purpose')
        self.trusted();held=None
        try:
            while held is None:
                if time.monotonic()>=deadline:raise EngineError('Native ClamAV capacity is busy; scan did not start')
                for index in range(SLOTS[purpose]):
                    path=self.directory/(purpose+'-'+str(index)+'.lock')
                    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
                    try:
                        info=os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or
                                info.st_mode&0o077 or info.st_size>256):
                            raise EngineError('Native ClamAV capacity record is not trusted')
                        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:continue
                        raw=os.read(fd,257)
                        record=json.loads(raw) if raw else dict(busy_until=0)
                        if not isinstance(record,dict) or set(record)!={'busy_until'}:
                            raise EngineError('Invalid native ClamAV capacity lease')
                        value=record.get('busy_until')
                        if type(value) not in (float,int) or not 0<=value<float('inf'):
                            raise EngineError('Invalid native ClamAV capacity lease')
                        now=time.monotonic()
                        if value>now+self.maximum_seconds+self.grace+1:
                            raise EngineError('Native ClamAV capacity lease exceeds the active scan bound')
                        if value>now:continue
                        held=fd;fd=None;break
                    finally:
                        if fd is not None:os.close(fd)
                if held is None:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise EngineError('Native ClamAV capacity is busy; scan did not start')
                    time.sleep(min(.02,remaining))
            yield Reservation(held,self.maximum_seconds,self.grace)
        except (OSError,ValueError,TypeError) as exc:
            raise EngineError('Native ClamAV capacity state is unavailable') from exc
        finally:
            if held is not None:os.close(held)
