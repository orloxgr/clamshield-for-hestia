"""Import native freshclam data without a second official downloader."""
import hashlib
from datetime import datetime,timezone
import json
from pathlib import Path
import pwd
import re
import stat
import shutil
import subprocess
import time

from .atomic import write_json
from .errors import Conflict,EngineError
from .native_configuration import NativeConfiguration
from .native_integration import NativeIntegration

SUFFIXES=frozenset(('.cvd','.cld','.ndb','.ldb','.hdb','.hsb','.mdb','.msb','.cdb',
                    '.pdb','.wdb','.ign','.ign2','.fp','.sfp','.ftm','.yar','.yara','.cbc','.crb','.idb','.db'))


class NativeUpdates:
    def __init__(self,settings):
        self.settings=settings;self.manager=NativeIntegration(settings)
        self.path=settings.state/'native-database-import.json'

    def sources(self):
        value=self.manager.read()
        if value is None or value['phase']!='active':raise Conflict('Native ClamAV must be active before importing updates')
        folder=Path(value['original_directory']);info=folder.lstat()
        if (folder.resolve()!=folder or not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022 or
                info.st_uid not in (0,pwd.getpwnam('clamav').pw_uid)):
            raise EngineError('Native database directory is not trusted')
        result=[]
        for stem in ('main','daily','bytecode'):
            source=next((folder/(stem+ext) for ext in ('.cld','.cvd') if (folder/(stem+ext)).is_file()),None)
            if source is None:raise EngineError('Native official databases are incomplete')
            result.append(('official',source.name,source))
        for source in sorted(folder.iterdir()):
            if re.fullmatch(r'(main|daily|bytecode)\.c[vl]d',source.name):continue
            signed=re.fullmatch(r'(main|daily|bytecode)-\d+\.cvd\.sign',source.name)
            if not signed and source.suffix not in SUFFIXES:continue
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}',source.name):
                raise EngineError('Native database filename is unsupported')
            result.append(('official' if signed else 'native',source.name if signed else 'native--'+source.name,source))
        return result

    def fingerprint(self):
        rows=[]
        for provider,name,source in self.sources():
            info=source.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o022:
                raise EngineError('Native database source is not a protected regular file')
            rows.append((provider,name,info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():return None
        NativeConfiguration.trusted(self.path,16384);value=json.loads(self.path.read_text())
        if not isinstance(value,dict) or value.get('owner')!='clamshield' or value.get('schema')!=1:
            raise Conflict('Native database import state is invalid')
        return value

    def record(self,source,phase,**detail):
        write_json(self.path,dict(owner='clamshield',schema=1,source=source,phase=phase,observed=time.time(),**detail))

    def changed(self):
        source=self.fingerprint();previous=self.read()
        # One automatic attempt per observed input. A failure remains visible;
        # explicit maintenance can retry it without an automatic error loop.
        return previous is None or previous.get('source')!=source

    def ingest(self):
        from .signatures import Signatures
        manager=Signatures(self.settings)
        with manager.locked():
            source=self.fingerprint();self.record(source,'checking');stage=None
            try:
                stage,manifest=manager.stage_native_refresh()
                if self.fingerprint()!=source:raise Conflict('Native databases changed during validation; wait for the native update to finish')
                if stage is not None:manager.activate(stage,manifest)
                self.record(source,'active',generation=manifest['generation'])
                manager.providers.status('activation',state='active',last_success=time.time(),generation=manifest['generation'],error=None)
                return dict(changed=stage is not None,generation=manifest['generation'],native_import=True)
            except Exception:
                self.record(source,'error',error='Native database import failed; review maintenance history and retry explicitly')
                if (stage is not None and not self.manager.journal.exists() and
                        all((manager.base/name).resolve()!=stage for name in ('current','previous'))):shutil.rmtree(stage)
                raise

    def check(self):
        """Leave an active native updater in charge; otherwise run its config once."""
        value=self.manager.read();path=Path('/etc/clamav/freshclam.conf')
        if value is None or value.get('phase')!='active':raise Conflict('Native ClamAV integration is not active')
        NativeConfiguration.trusted(path,65536)
        before=path.stat()
        fingerprint=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        directories=re.findall(r'(?m)^\s*DatabaseDirectory\s+(\S+)\s*$',path.read_text())
        if len(directories)!=1 or directories[0]!=value['original_directory']:
            raise Conflict('Native freshclam and ClamAV database directories differ; review native updater configuration')
        active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','clamav-freshclam.service'],capture_output=True,timeout=5)
        if active.returncode==0:
            return dict(native_updater=True,state='native-updater-active',check_completed=False)
        # Native freshclam's log lock prevents a simultaneous native updater.
        # No custom official cache/configuration and no raw diagnostics escape.
        # Run the fixed native updater outside the maintenance filesystem
        # namespace. Its configured native data/log locations may be custom.
        # This transient unit disappears on completion and runs no clamd.
        result=subprocess.run(['/usr/bin/systemd-run','--unit=clamshield-native-freshclam','--collect','--wait','--pipe','--quiet',
            '--property=Type=exec','--property=MemoryMax=3G','--property=CPUQuota=100%',
            '--property=RuntimeMaxSec=540','--property=TimeoutStopSec=20','--setenv=TZ=UTC','--setenv=LANG=C.UTF-8',
            '--property=NoNewPrivileges=yes','/usr/bin/freshclam','--config-file='+str(path),'--stdout'],
            capture_output=True,timeout=600,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','TZ':'UTC'})
        if fingerprint(path.stat())!=fingerprint(before):raise Conflict('Native freshclam configuration changed during its check')
        output=(result.stdout or b'')+b'\n'+(result.stderr or b'');deadlines=[]
        for text in re.findall(rb'cool-down until after: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',output):
            try:deadlines.append(datetime.strptime(text.decode('ascii'),'%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
            except ValueError:pass
        if deadlines and max(deadlines)>time.time():
            from .providers import Providers
            Providers(self.settings).status('official',retry_after=max(deadlines))
            raise EngineError('Native freshclam postponed its check until the provider cooldown expires')
        if result.returncode:raise EngineError('Native freshclam check failed; inspect the native updater log and provider cooldown')
        return dict(native_updater=True,state='downloaded',check_completed=True)
