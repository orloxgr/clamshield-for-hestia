"""Unprivileged, network-free load probe; only root-prepared inert inputs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

plan=json.loads(Path(sys.argv[1]).read_text())
rows=[]
for repeat in range(3):
    for case in plan['cases']:
        with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
            started=time.monotonic()
            process=subprocess.Popen(['/usr/bin/clamscan','--allmatch','--no-summary',
                '--database='+case['directory'],plan['input']],stdin=subprocess.DEVNULL,
                stdout=output,stderr=errors,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','TMPDIR':'/tmp'})
            _,status,usage=os.wait4(process.pid,0)
            process.returncode=os.waitstatus_to_exitcode(status)
            if output.tell()>65536 or errors.tell()>65536:raise RuntimeError('Load probe output exceeds limit')
            output.seek(0)
            if process.returncode!=1 or (plan['canary']+' FOUND').encode() not in output.read():
                raise RuntimeError('Signature load canary failed; measurement is incomplete')
            rows.append(dict(case=case['id'],repeat=repeat,peak_rss_bytes=int(usage.ru_maxrss)*1024,
                             elapsed_seconds=time.monotonic()-started))
            print(json.dumps({'sample':len(rows),'total':len(plan['cases'])*3}),flush=True)
print(json.dumps({'complete':True,'rows':rows}),flush=True)
