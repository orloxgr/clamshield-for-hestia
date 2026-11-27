"""Bounded native Exim gateway with the existing daemon and verified catalog."""
from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import threading
import time

from .atomic import write_json,sync_directory
from .errors import EngineError,Conflict
from .native_configuration import NativeConfiguration
from .native_integration import NativeIntegration
from .native_gate import NativeGate
from .signature_catalog import SignatureCatalog,engine_lock
from .settings import Settings


def notify_ready():
    address=os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):address='\0'+address[1:]
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:
            channel.connect(address);channel.sendall(b'READY=1')


def serve(settings=None):
    from .signatures import Signatures
    settings=settings or Settings();manager=NativeIntegration(settings);value=manager.read()
    if value is None:raise EngineError('Native ClamAV integration is not configured')
    manager.prepare_runtime();path=Path(value['original_socket']);receipt=manager.runtime/'listener.json'
    identity=pwd.getpwnam('clamav');exim=pwd.getpwnam('Debian-exim')
    # Only our exact dead listener may be unlinked after a crash.
    if path.exists() or path.is_symlink():
        info=path.lstat();NativeConfiguration.trusted(receipt,4096)
        prior=json.loads(receipt.read_text())
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=identity.pw_uid or
                prior!=dict(path=str(path),device=info.st_dev,inode=info.st_ino)):
            raise Conflict('Native frontend address is already owned by another listener')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
            try:probe.connect(str(path))
            except OSError as error:
                if error.errno!=errno.ECONNREFUSED:raise
            else:raise Conflict('Native frontend listener is still active')
        path.unlink()
    deadline=time.monotonic()+75
    while True:
        try:manager.client('native-mail',timeout=25,maximum=80*1024**2,transition=True);break
        except EngineError:
            if time.monotonic()>=deadline:raise
            time.sleep(.3)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    stopping=threading.Event();capacity=threading.BoundedSemaphore(4)
    def stop(_number,_frame):stopping.set()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def handle(connection):
        try:
            with connection,engine_lock(settings):
                native=manager.client('native-mail',timeout=25,maximum=80*1024**2,transition=True)
                signatures=Signatures(settings);manifest=signatures.manifest()
                if manifest is None or manifest.get('engine_mode')!='native-shared':
                    raise EngineError('Native baseline signature generation is not pinned')
                with SignatureCatalog((signatures.base/'current').resolve(),manifest) as catalog:
                    gate=NativeGate(native,catalog.resolve,exim_uid=exim.pw_uid)
                    gate.handle(connection)
        except Exception:
            try:connection.sendall(b'Native antivirus unavailable ERROR\n')
            except OSError:pass
            connection.close()
        finally:capacity.release()
    owned=None
    try:
        listener.bind(str(path));info=path.lstat();owned=dict(path=str(path),device=info.st_dev,inode=info.st_ino)
        os.chown(path,identity.pw_uid,identity.pw_gid);path.chmod(0o666)
        write_json(receipt,owned);listener.listen(32);listener.settimeout(.5);notify_ready()
        with ThreadPoolExecutor(max_workers=4,thread_name_prefix='native-antivirus') as pool:
            while not stopping.is_set():
                try:connection,_=listener.accept()
                except socket.timeout:continue
                if capacity.acquire(blocking=False):pool.submit(handle,connection)
                else:
                    with connection:
                        connection.settimeout(1)
                        try:connection.sendall(b'Native antivirus capacity busy ERROR\n')
                        except OSError:pass
    finally:
        listener.close()
        if owned is not None and path.exists():
            current=path.lstat()
            if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):path.unlink()
        if owned is not None and receipt.exists() and json.loads(receipt.read_text())==owned:
            receipt.unlink();sync_directory(manager.runtime)
