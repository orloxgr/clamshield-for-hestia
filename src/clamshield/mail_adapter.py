"""Build and prove owned Exim API glue against exact installed Ubuntu headers.

No Exim/ClamAV/YARA engine is built or installed here. Preparing a candidate
does not change the native hook, active library, service or domain flags.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

from .atomic import write, write_json, sync_directory
from .errors import ClamShieldError, EngineError

OWNER = 'clamshield\n'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8'}
GENERATION = r'adapter-[a-f0-9]{32}'


def trusted(path, *, directory=False):
    info = path.lstat()
    if (path.resolve() != path or info.st_uid != os.geteuid() or info.st_mode & 0o022 or
            (directory and not stat.S_ISDIR(info.st_mode)) or
            (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise EngineError('Untrusted mail adapter storage')
    return info


def sha(path):
    trusted(path)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def bounded(arguments, *, timeout=45, cwd=None, check=True, data=None):
    command = ['/usr/bin/prlimit','--cpu=60','--as=1073741824','--fsize=67108864','--',*arguments]
    # File-backed output is also covered by RLIMIT_FSIZE. Reject by stat before
    # reading, rather than accumulating an unbounded pipe in the root worker.
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(command,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,
                              start_new_session=True,env=ENV,cwd=cwd) as process:
            try:
                process.communicate(data,timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid,signal.SIGKILL);process.communicate()
                raise EngineError('Mail adapter preparation timed out') from exc
        if os.fstat(stdout.fileno()).st_size>16*1024**2 or os.fstat(stderr.fileno()).st_size>1024**2 or (check and process.returncode):
            raise EngineError('Mail adapter preparation command failed: '+Path(arguments[0]).name)
        stdout.seek(0);stderr.seek(0)
        output,error=stdout.read(16*1024**2+1),stderr.read(1024**2+1)
        if len(output)>16*1024**2 or len(error)>1024**2:
            raise EngineError('Mail adapter preparation output exceeded its limit')
    return subprocess.CompletedProcess(arguments,process.returncode,output,error)


def native():
    path=Path('/usr/sbin/exim4');trusted(path)
    owner=bounded(['/usr/bin/dpkg-query','-S',str(path)]).stdout.decode().strip()
    match=re.fullmatch(r'(exim4-daemon-(?:heavy|light)): /usr/sbin/exim4',owner)
    if not match:raise EngineError('Exim is not owned by a supported Ubuntu package')
    package=match[1]
    fields=bounded(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}\t${Version}\t${Architecture}',package]).stdout.decode().split('\t')
    if (len(fields)!=3 or fields[0]!='installed' or not re.fullmatch(r'[0-9A-Za-z.+:~_-]{1,100}',fields[1]) or
            not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}',fields[2])):
        raise EngineError('Installed Exim package identity is unavailable')
    result=bounded([str(path),'-C','/dev/null','-bP','local_scan_path'],check=False)
    if result.returncode or b'local_scan_path' not in result.stdout:
        raise EngineError('Installed Exim has no dynamic local_scan API')
    return dict(package=package,version=fields[1],architecture=fields[2],binary_sha256=sha(path))


def extract_headers(data, destination):
    """Select only flat regular headers. Never extract archive paths or links."""
    count=total=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for member in archive:
            name=member.name.removeprefix('./')
            if not name.startswith('usr/include/exim4/'):
                continue
            filename=name.removeprefix('usr/include/exim4/')
            if member.isdir() and not filename:continue
            if not re.fullmatch(r'[A-Za-z0-9_.-]+\.h',filename) or not member.isfile():
                raise EngineError('Unexpected Exim header archive member')
            path=destination/filename
            if path.exists() or member.size>4*1024**2 or total+member.size>16*1024**2:
                raise EngineError('Exim header archive exceeds its limits or has duplicates')
            stream=archive.extractfile(member)
            content=stream.read(member.size+1)
            if len(content)!=member.size:raise EngineError('Incomplete Exim header archive')
            write(path,content,0o644);count+=1;total+=member.size
    if not (destination/'local_scan.h').is_file() or count>100:
        raise EngineError('Exim local_scan headers are missing')
    return {path.name:sha(path) for path in sorted(destination.iterdir())}


class MailAdapter:
    def __init__(self,settings):
        self.settings,self.base=settings,settings.mail_adapters
        self.source=Path(__file__).resolve().parents[2]/'native/local_scan.c'

    def prepare(self):
        self.settings.prepare()
        if not self.base.exists():
            self.base.mkdir(mode=0o755);self.base.chmod(0o755)
            write(self.base/'.clamshield-owner',OWNER,0o644)
        trusted(self.base,directory=True);trusted(self.base/'.clamshield-owner')
        if (self.base/'.clamshield-owner').read_text()!=OWNER:raise EngineError('Unmanaged mail adapter directory')

    @contextmanager
    def locked(self):
        self.prepare()
        path=self.settings.state/'mail-adapter.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            trusted(path);fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def candidate(self, *, expected=None):
        pointer=self.base/'candidate'
        if not pointer.exists() and not pointer.is_symlink():return None
        if not pointer.is_symlink():raise EngineError('Mail adapter candidate pointer is not owned')
        return self.generation(os.readlink(pointer),expected=expected)

    def generation(self,name,*,expected=None):
        """Read an exact frozen generation, independently of later preparation."""
        trusted(self.base,directory=True)
        trusted(self.base/'.clamshield-owner')
        if (self.base/'.clamshield-owner').read_text()!=OWNER:raise EngineError('Unmanaged mail adapter directory')
        if not isinstance(name,str) or not re.fullmatch(GENERATION,name):raise EngineError('Mail adapter generation path is invalid')
        stage=self.base/name;trusted(stage,directory=True);trusted(stage/'manifest.json')
        if (stage/'manifest.json').stat().st_size>1024**2:raise EngineError('Mail adapter manifest exceeds its limit')
        manifest=json.loads((stage/'manifest.json').read_text())
        if (manifest['generation']!=name or not manifest['abi_probed'] or
                manifest['source_sha256']!=sha(stage/'local_scan.c') or manifest['library_sha256']!=sha(stage/'local_scan.so')):
            raise EngineError('Mail adapter candidate bytes changed')
        if expected is not None and manifest['native']!=expected:
            raise EngineError('Mail adapter belongs to another Exim package or binary')
        return manifest

    def status(self):
        try:
            current=native();candidate=self.candidate()
            return dict(available=True,candidate=candidate,native=current,
                        compatible=bool(candidate and candidate['native']==current and candidate['source_sha256']==sha(self.source)))
        except ClamShieldError as exc:
            return dict(available=False,error=str(exc))
        except (OSError,ValueError,KeyError,TypeError):
            return dict(available=False,error='Adapter unavailable, stale or changed; prepare matching native data')

    def headers(self,stage,current):
        package=stage/'package';package.mkdir(mode=0o700)
        bounded(['/usr/bin/apt-get','-o','APT::Get::AllowUnauthenticated=false',
                 '-o','Acquire::AllowInsecureRepositories=false','download',
                 'exim4-dev:'+current['architecture']+'='+current['version']],cwd=package,timeout=120)
        files=list(package.iterdir())
        if len(files)!=1 or files[0].suffix!='.deb' or trusted(files[0]).st_size>32*1024**2:
            raise EngineError('Exact Exim development package is unavailable')
        fields=bounded(['/usr/bin/dpkg-deb','-f',str(files[0]),'Package','Version','Architecture']).stdout.decode()
        wanted={'Package':'exim4-dev','Version':current['version'],'Architecture':current['architecture']}
        actual=dict(line.split(': ',1) for line in fields.strip().splitlines())
        if actual!=wanted:raise EngineError('Exim development package does not match installed native version')
        tar=bounded(['/usr/bin/dpkg-deb','--fsys-tarfile',str(files[0])]).stdout
        headers=stage/'headers';headers.mkdir(mode=0o755)
        headers.chmod(0o755)
        hashes=extract_headers(tar,headers)
        proof=dict(package=wanted,package_sha256=sha(files[0]),headers=hashes)
        shutil.rmtree(package)
        return headers,proof

    def abi_probe(self,stage):
        """Actual installed Exim, private queue, no delivery or native config edit."""
        account=pwd.getpwnam('Debian-exim');probe=stage/'probe';probe.mkdir(mode=0o750)
        os.chown(probe,0,account.pw_gid);probe.chmod(0o750)
        for name in ('spool','log'):
            path=probe/name;path.mkdir(mode=0o750);os.chown(path,account.pw_uid,account.pw_gid)
        domain=stage.name+'.invalid'
        configuration=('primary_hostname = adapter.clamshield.invalid\nexim_user = Debian-exim\nexim_group = Debian-exim\n'
                       'qualify_domain = probe.invalid\nspool_directory = '+str(probe/'spool')+'\nlog_file_path = '+str(probe/'log/%slog')+
                       '\nlocal_scan_path = '+str(stage/'local_scan.so')+'\nlocal_scan_timeout = 35s\nqueue_only = true\nhost_lookup =\n'
                       'begin routers\nfixture:\n driver = accept\n domains = '+domain+'\n transport = fixture\n'
                       'begin transports\nfixture:\n driver = appendfile\n file = /dev/null\n user = Debian-exim\n'
                       'begin retry\n* * F,1h,5m\n')
        write(probe/'exim.conf',configuration,0o644)
        message=('From: adapter@'+domain+'\nTo: fixture@'+domain+'\nSubject: ClamShield inert adapter ABI probe\n\nNon-executable adapter control.\n').encode()
        result=bounded(['/usr/sbin/exim4','-C',str(probe/'exim.conf'),'-odq','-oi','-f','adapter@'+domain,'fixture@'+domain],data=message,check=False,timeout=40)
        logs=b''.join(path.read_bytes() for path in (probe/'log').iterdir() if path.is_file())
        observed=result.stdout+result.stderr+logs
        success=(b'ClamShield mail check unavailable; please retry' in observed or
                 (result.returncode==0 and b'ClamShield decision=0 event=' in observed))
        if not success:
            write_json(self.settings.state/'mail-adapter-probe-error.json',dict(exit_code=result.returncode,
                       stdout=result.stdout.decode(errors='replace')[:8192],stderr=result.stderr.decode(errors='replace')[:8192],
                       fixture_logs=logs.decode(errors='replace')[:16384]))
        shutil.rmtree(probe)
        if not success:raise EngineError('Native Exim could not execute the prepared adapter ABI')

    def build(self):
        import uuid
        with self.locked():
            current=native();trusted(self.source)
            candidate=self.candidate()
            if candidate and candidate['native']==current and candidate['source_sha256']==sha(self.source):
                return candidate|{'reused':True}
            if not all(Path(name).is_file() for name in ('/usr/bin/cc','/usr/bin/dpkg-deb','/usr/bin/apt-get','/usr/bin/prlimit')):
                raise EngineError('Install Ubuntu gcc/libc6-dev and package tools before preparing the mail adapter')
            name='adapter-'+uuid.uuid4().hex;stage=self.base/name;stage.mkdir(mode=0o755);stage.chmod(0o755)
            next_pointer=self.base/'.candidate-next';link_created=False
            try:
                source_hash=sha(self.source);headers,header_proof=self.headers(stage,current)
                write(stage/'local_scan.c',self.source.read_bytes(),0o644)
                bounded(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
                         '-Wl,-z,relro,-z,now','-Wl,-z,noexecstack','-I'+str(headers),
                         str(stage/'local_scan.c'),'-o',str(stage/'local_scan.so')])
                (stage/'local_scan.so').chmod(0o644)
                self.abi_probe(stage)
                if current!=native() or source_hash!=sha(self.source):
                    raise EngineError('Exim package or addon source changed during preparation')
                result=dict(generation=name,created=time.time(),native=current,source_sha256=source_hash,
                            library_sha256=sha(stage/'local_scan.so'),development=header_proof,abi_probed=True)
                write_json(stage/'manifest.json',result,0o644);sync_directory(stage)
                if next_pointer.exists() or next_pointer.is_symlink():raise EngineError('Unexpected adapter staging pointer')
                next_pointer.symlink_to(name);link_created=True
                os.replace(next_pointer,self.base/'candidate');sync_directory(self.base)
                return result|{'reused':False}
            except BaseException:
                # A final fsync failure must never delete a generation already
                # selected by the visible pointer. Preserve uncertain state.
                pointer=self.base/'candidate'
                if pointer.is_symlink() and os.readlink(pointer)==name:raise
                if link_created and next_pointer.is_symlink() and os.readlink(next_pointer)==name:
                    next_pointer.unlink();sync_directory(self.base)
                if stage.parent!=self.base or stage.resolve()!=stage:raise EngineError('Unsafe adapter cleanup path')
                shutil.rmtree(stage)
                raise

    def verify(self):
        """Re-execute frozen candidate bytes without downloading or compiling."""
        import uuid
        with self.locked():
            current=native();candidate=self.candidate(expected=current)
            if candidate is None or candidate['source_sha256']!=sha(self.source):
                raise EngineError('Prepare a matching native adapter before verification')
            stage=self.base/('verify-'+uuid.uuid4().hex);stage.mkdir(mode=0o755);stage.chmod(0o755)
            try:
                write(stage/'local_scan.so',(self.base/candidate['generation']/'local_scan.so').read_bytes(),0o644)
                if sha(stage/'local_scan.so')!=candidate['library_sha256']:
                    raise EngineError('Adapter changed while preparing verification')
                self.abi_probe(stage)
                if (current!=native() or candidate!=self.candidate(expected=current) or
                        candidate['source_sha256']!=sha(self.source)):
                    raise EngineError('Native Exim, adapter or addon source changed during verification')
                return dict(generation=candidate['generation'],verified=True,verified_at=time.time(),native=current,
                            library_sha256=candidate['library_sha256'])
            finally:
                if stage.parent!=self.base or stage.resolve()!=stage:raise EngineError('Unsafe adapter verification cleanup path')
                shutil.rmtree(stage)
