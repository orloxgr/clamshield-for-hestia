"""Installed integrity evidence stays separate from optional version changes."""
from .errors import ClamShieldError
from .paths import walk
from .wordpress import WordPress


class Capture:
    def __init__(self,store):self.store,self.findings=store,[]
    def cancelled(self,job_id):return self.store.cancelled(job_id)
    def progress(self,*_args):pass
    def file_result(self,*_args):pass
    def add_finding(self,job,path,fingerprint,hit):
        self.findings.append(dict(path=path,fingerprint=fingerprint,hit=hit))


def target_findings(recovery,plan,job,refs,components,counters):
    changes=[];files=None
    for component in components:
        recovery.check_cancel(job)
        if not component.get('version'):
            component['recovery_version']=None;continue
        try:
            target_method=getattr(type(refs),'target',None)
            target=refs.target(component) if callable(target_method) else component
            component['recovery_version']=target['version']
            if target['version']==component.get('version'):continue
            if files is None:
                files=set()
                for path,state,_detail in walk(job['root'],job['target']):
                    recovery.check_cancel(job)
                    if state=='regular':files.add(path)
            capture=Capture(recovery.store);check={key:value for key,value in component.items() if key not in ('error','status','counts')}
            coverage=dict(scanned=0,bytes=0,modified=0,missing=0,additional=0,unverified=0,errors=0,detections=0)
            WordPress(recovery.settings,capture,recovery.hestia,refs).component(job,check,files,coverage)
            if check['status'] in ('unverified','partial'):
                raise ClamShieldError(check.get('error','Selected recovery version could not be fully checked'))
            for change in capture.findings:
                # Additional files are reviewed against the installed reference,
                # rather than treating old-version files as malware/extra code.
                if not change['fingerprint']['wordpress'].get('expected'):continue
                change['component']=component
                changes.append(change)
        except (OSError,ClamShieldError) as exc:
            component['recovery_version']=None;component['recovery_error']=recovery.message(exc)
            plan['report']['errors'].append('Recovery release unavailable: '+component['path']+': '+recovery.message(exc))
            counters['errors']+=1
    return changes
