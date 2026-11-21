"""Read-only explanations for the gates used by the single website worker."""
import fcntl
import os
import stat
import subprocess
import time


class ScanQueue:
    def __init__(self,settings,store):self.settings,self.store=settings,store

    def lock_busy(self):
        # A leftover filename is normal. Only an actual held OS lock is busy.
        try:fd=os.open(self.settings.state/'worker.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:return False
        except OSError:return None
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o022:return None
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return True
            return False
        finally:os.close(fd)

    @staticmethod
    def units():
        names=('clamshield-worker.service','clamshield-worker.timer')
        try:
            result=subprocess.run(['/usr/bin/systemctl','show','--no-pager',
                '--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus',*names],
                capture_output=True,text=True,timeout=2)
        except (OSError,subprocess.SubprocessError):return {}
        units={}
        for block in result.stdout.strip().split('\n\n'):
            fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
            if fields.get('Id') in names:units[fields['Id']]=fields
        return units

    def describe(self,jobs,*,admin=False):
        queued=[job for job in jobs if job['status']=='queued']
        if not queued:return
        # Capture global position independently of the visible account, filter
        # and page. Do not expose another customer's job or maintenance payload.
        with self.store.connection() as db:
            db.execute('BEGIN')
            ids=[job['id'] for job in queued]
            positions={row['id']:row['position'] for row in db.execute("SELECT id,position FROM (SELECT id,ROW_NUMBER() OVER(ORDER BY created,id) AS position FROM jobs WHERE status='queued') WHERE id IN ("+','.join('?' for _ in ids)+')',ids)}
            running=db.execute("SELECT owner,domain,source FROM jobs WHERE status='running' ORDER BY started,id LIMIT 1").fetchone()
            control=bool(db.execute("SELECT 1 FROM maintenance WHERE action IN ('website-engine-start','website-engine-stop') AND status IN ('queued','running') LIMIT 1").fetchone())
        busy=self.lock_busy();units=self.units()
        worker=units.get('clamshield-worker.service',{});timer=units.get('clamshield-worker.timer',{})
        code,message,action='waiting','Waiting for the scan worker’s next run (normally every 5 seconds).',None
        if worker.get('LoadState') in ('not-found','masked') or timer.get('LoadState') in ('not-found','masked'):
            code,message='unavailable','The scan worker or its timer is missing or masked. Administrator attention is required.'
        elif worker.get('ActiveState')=='failed':
            code,message='worker-failed','The last scan worker run failed. Administrator attention is required; review the worker service log.'
        elif timer.get('ActiveState') in ('inactive','failed') and worker.get('ActiveState') not in ('active','activating','reloading'):
            code,message='timer-stopped','The scan worker timer is stopped. Queued scans cannot start automatically.'
        else:
            journals=(('signature-activation.json','signature-activation','Waiting for signature activation or recovery.'),
                ('resources-activation.json','resource-activation','Waiting for scanner resource changes or recovery.'),
                ('website-engine-activation.json','engine-activation','Waiting for the website ClamAV service change or recovery.'))
            pending=next(((key,text) for name,key,text in journals if (self.settings.state/name).exists() or (self.settings.state/name).is_symlink()),None)
            if pending:code,message=pending;action='history'
            elif control:code,message,action='engine-control','Waiting for the queued website ClamAV service change.','history'
            elif busy is True:
                code,message=('scan-running','Waiting for another scan to finish.') if running else ('scanner-busy','The scanner lock is held by another operation; waiting for it to finish.')
                if running and admin:
                    names={'wordpress-integrity':'WordPress integrity check','manual':'manual scan','scheduled':'scheduled scan','watch':'changed-file scan','watch-initial':'initial monitoring scan'}
                    message='Waiting for '+names.get(running['source'],'another scan')+': '+running['owner']+' / '+running['domain']+'.'
            elif busy is None:code,message='unknown','The scanner lock could not be checked. Administrator attention is required.'
            elif running:code,message='recovery','A previous scan is still marked running, but its worker lock is free. Waiting for worker recovery.'
            elif worker.get('ActiveState') in ('active','activating','reloading'):code,message='starting','The scan worker is active but has not claimed this scan yet.'
            elif not worker or not timer:code,message='unknown','The scan worker service state could not be checked. Administrator attention is required if the wait continues.'
        now=time.time()
        for job in queued:
            wait=max(0,int(now-job['created']));position=positions.get(job['id'])
            current_code,current_message=code,message
            if code=='waiting' and wait>=30:
                current_code,current_message='delayed','The timer is active, but the scan worker has not claimed this scan. Administrator attention is required; review the worker service log.'
            job['queue']=dict(code=current_code,message=current_message,position=position,wait_seconds=wait,action=action if admin else None)
