"""Owner-scoped candidate/active comparisons without changing live policy."""
import json
import time

from .engines import Yara
from .errors import AccessDenied, ClamShieldError, Conflict
from .paths import relative_path, snapshot, walk
from .rule_manager import RuleManager
from .store import encode


class RuleTrials:
    def __init__(self, settings, store, hestia):
        self.settings,self.store,self.hestia=settings,store,hestia
        self.manager=RuleManager(settings)

    def queue(self, context, domain, target='', name=None):
        site=next((s for s in self.hestia.sites(context['owner']) if s['domain']==domain and not s['suspended']),None)
        if site is None:raise AccessDenied('Site unavailable')
        candidate=self.manager.candidate(); active=self.manager.rules.status()
        available=[m['generation'] for m in (candidate,active) if m and m.get('generation')]
        name=name or (candidate or active).get('generation')
        if name not in available and not context.get('admin'):
            raise AccessDenied('Choose the current candidate or active rules generation')
        self.manager.metadata(name)
        job_id=self.store.enqueue(context,site,relative_path(target),source='yara-trial',generation=name)
        baseline=active.get('generation') if active.get('configured') else None
        with self.store.connection() as db:
            db.execute('INSERT INTO rule_trials(job_id,owner,identity,generation,baseline) VALUES(?,?,?,?,?)',
                       (job_id,*self.store.scope(context),name,baseline))
        return job_id

    def run(self, job):
        counters=dict(seen=0,scanned=0,infected=0,detections=0,skipped=0,errors=0,bytes=0,
                      candidate_matches=0,baseline_matches=0,new_signatures=0,removed_signatures=0,
                      candidate_seconds=0.0,baseline_seconds=0.0)
        started=time.monotonic(); status='failed'; error=None
        context={k:job[k] for k in ('owner','identity','actor')}
        try:
            with self.store.connection() as db:
                row=db.execute('SELECT * FROM rule_trials WHERE job_id=? AND owner=? AND identity=?',
                               (job['id'],*self.store.scope(context))).fetchone()
            if row is None:raise AccessDenied('Trial unavailable')
            candidate_path,_=self.manager.rules.validate_generation(row['generation'])
            candidate=Yara(self.settings.yara_binary,candidate_path/'rules.yarac',self.settings.engine_timeout)
            baseline=None
            if row['baseline']:
                baseline_path,_=self.manager.rules.validate_generation(row['baseline'])
                baseline=Yara(self.settings.yara_binary,baseline_path/'rules.yarac',self.settings.engine_timeout)
            for relative,state,detail in walk(job['root'],job['target']):
                if self.store.cancelled(job['id']):status='cancelled';break
                counters['seen']+=1
                if state!='regular':
                    counters['skipped' if state=='skipped' else 'errors']+=1
                    self.store.file_result(job['id'],relative,state,{'message':detail})
                    self.store.progress(job['id'],counters);continue
                try:
                    with snapshot(job['root'],relative,self.settings.snapshots,self.settings.max_file_bytes) as (copy,fingerprint):
                        values={'candidate':[],'baseline':[]};failures=[]
                        for label,engine in [('candidate',candidate),('baseline',baseline)]:
                            if engine is None:continue
                            if self.store.cancelled(job['id']):break
                            before=time.monotonic()
                            try:values[label]=engine.scan(copy)
                            except ClamShieldError as exc:failures.append({'engine':label,'message':str(exc)})
                            counters[label+'_seconds']+=time.monotonic()-before
                            self.store.progress(job['id'],counters)
                        if self.store.cancelled(job['id']):status='cancelled';break
                        before={h['signature'] for h in values['baseline']};after={h['signature'] for h in values['candidate']}
                        new,removed=sorted(after-before),sorted(before-after)
                        counters['candidate_matches']+=len(after);counters['baseline_matches']+=len(before)
                        counters['new_signatures']+=len(new);counters['removed_signatures']+=len(removed)
                        counters['detections']+=len(after);counters['bytes']+=fingerprint['size']
                        counters['errors' if failures else 'scanned']+=1
                        self.store.file_result(job['id'],relative,'error' if failures else 'trial',
                            values|dict(new_signatures=new,removed_signatures=removed,failures=failures,sha256=fingerprint['sha256']))
                except Conflict as exc:
                    counters['skipped']+=1
                    self.store.file_result(job['id'],relative,'skipped',{'message':str(exc)})
                except (OSError,ClamShieldError):
                    counters['errors']+=1
                    self.store.file_result(job['id'],relative,'error',{'message':'Trial file could not be captured safely'})
                self.store.progress(job['id'],counters)
            else:status='partial' if counters['errors'] or counters['skipped'] else 'completed'
        except (OSError,ClamShieldError) as exc:
            counters['errors']+=1
            error=str(exc) if isinstance(exc,ClamShieldError) else 'Trial could not read its rules or document root'
        counters['wall_seconds']=round(time.monotonic()-started,6)
        counters['candidate_seconds']=round(counters['candidate_seconds'],6)
        counters['baseline_seconds']=round(counters['baseline_seconds'],6)
        with self.store.connection() as db:
            db.execute('UPDATE rule_trials SET result=? WHERE job_id=?',(encode(counters),job['id']))
        self.store.finish(job,status,counters,error)
        self.store.notify(job['owner'],job['identity'],'rules.trial_finished',job['domain'],
                          {'job_id':job['id'],'generation':job['generation'],'counters':counters},job['id'])

    def list(self, context):
        with self.store.connection() as db:
            rows=db.execute('''SELECT t.*,j.domain,j.target,j.created,j.status,j.error FROM rule_trials t JOIN jobs j ON j.id=t.job_id
              WHERE t.owner=? AND t.identity=? ORDER BY j.created DESC LIMIT 50''',self.store.scope(context)).fetchall()
        return [dict(r)|{'result':json.loads(r['result'])} for r in rows]

    def report(self, context, job_id, offset=0):
        job=self.store.job(context,job_id)
        if job['counters'].get('history_expired'):
            raise AccessDenied('Detailed scan history expired under this account retention policy')
        if job['source']!='yara-trial' or type(offset) is not int or not 0<=offset<=1000000:
            raise AccessDenied('Trial report unavailable')
        with self.store.connection() as db:
            db.execute('BEGIN')
            current=db.execute('SELECT counters FROM jobs WHERE id=? AND owner=? AND identity=?',(job_id,*self.store.scope(context))).fetchone()
            if not current or json.loads(current['counters']).get('history_expired'):
                raise AccessDenied('Detailed scan history expired under this account retention policy')
            cursor=db.execute('SELECT * FROM file_results WHERE job_id=? ORDER BY id LIMIT 101 OFFSET ?',(job_id,offset))
            rows=[];size=0;more=False
            for row in cursor:
                if rows and (len(rows)>=100 or size+len(row['detail'])>4*1024**2):
                    more=True;break
                rows.append(row);size+=len(row['detail'])
        return dict(job=job,files=[dict(r)|{'detail':json.loads(r['detail'])} for r in rows[:100]],
                    next_offset=offset+len(rows) if more else None)
