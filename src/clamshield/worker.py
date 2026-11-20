"""Queue worker; an incomplete engine or filesystem result is never clean."""
import fcntl
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import time
import uuid

from .engines import ClamAV, Yara
from .errors import ClamShieldError, Conflict, EngineError
from .paths import snapshot, walk
from .generations import current as current_generation
from .exceptions import Exceptions


class UnavailableEngine:
    def __init__(self, name, error):
        self.name, self.error = name, error

    def scan(self, _path):
        raise EngineError(self.error)


class Worker:
    def __init__(self, settings, store, hestia, engines=None):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.engines = engines if engines is not None else [
            ClamAV(settings.clamd_socket, settings.engine_timeout, settings.max_file_bytes),
            Yara(settings.yara_binary, settings.rules, settings.engine_timeout)]
        self.worker_id = f'{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}'

    def validate(self, job):
        context = self.hestia.authorize(job['owner'], job['owner'])
        if context['identity'] != job['identity']:
            raise Conflict('Account was replaced after this scan was queued')
        site = next((s for s in self.hestia.sites(job['owner']) if s['domain'] == job['domain']), None)
        if not site or site['root'] != job['root'] or site['suspended']:
            raise Conflict('Site configuration changed after this scan was queued')
        capability={'manual':'scan','wordpress-integrity':'scan','yara-trial':'rule_trials'}.get(job['source'])
        if job['source']=='repair-preview':
            from .repairs import Repairs
            plan=Repairs(self.settings,self.store,self.hestia).get(context,job['id'])
            capability='cleanup' if plan['metadata'].get('source',{}).get('kind')=='targeted-cleanup' else 'repair'
            # Automatic previews follow the policy's recorded authority. The
            # executor revalidates delegation before publication; administrators
            # can keep server protection active while restricting user actions.
            with self.store.connection() as db:
                automatic=db.execute("SELECT 1 FROM remediation_actions WHERE json_extract(detail,'$.plan_id')=?",(job['id'],)).fetchone()
            if automatic:capability=None
        if capability:
            from .website_permissions import WebsitePermissions
            WebsitePermissions(self.settings,self.store,self.hestia).require(dict(actor=job['actor'],owner=job['owner'],identity=job['identity']),capability)

    def once(self):
        # The OS releases this lock after a crash. A lock file alone is not a
        # running-worker signal. A replacement worker marks abandoned jobs failed.
        self.settings.prepare()
        with (self.settings.state / 'worker.lock').open('a+b') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            if any((self.settings.state/name).exists() for name in ('signature-activation.json','resources-activation.json','website-engine-activation.json')):
                # The updater may have been killed while changing databases.
                # Maintenance recovers its journal before new scans are claimed.
                return False
            with self.store.connection(True) as db:
                abandoned = [dict(row) for row in db.execute("SELECT * FROM jobs WHERE status='running'").fetchall()]
            for stale in abandoned:
                self.store.finish(stale, 'failed', json.loads(stale['counters']), 'Worker stopped before completion')
            job = self.store.claim(self.worker_id)
            if job is None:
                return False
            # Pin one concrete rules generation for the entire job. A data
            # update cannot silently change policy between two files in a scan.
            if job['source']!='yara-trial' and any(isinstance(engine, (ClamAV, Yara)) for engine in self.engines):
                job['generation'] = current_generation(self.settings)
                with self.store.connection() as db:
                    db.execute('UPDATE jobs SET generation=? WHERE id=?', (job['generation'], job['id']))
            yara_generation = job['generation'].split('|', 1)[0]
            if yara_generation.startswith('generation-'):
                expected = self.settings.state / 'rules' / yara_generation / 'rules.yarac'
                for engine in self.engines:
                    if isinstance(engine, Yara):
                        engine.rules = expected
            self.run(job)
            from .remediation import Remediation
            automatic=Remediation(self.settings,self.store,self.hestia)
            with automatic.locked():automatic.discover(job['id'])
            if job['source'] in ('repair-recheck', 'repair-preview'):
                from .repairs import Repairs
                Repairs(self.settings, self.store, self.hestia).reconcile()
            return True

    def run(self, job):
        try:
            self.validate(job)
            with ExitStack() as stack:
                engines = self.engines; errors = 0
                if job['source'] not in ('yara-trial', 'wordpress-integrity', 'repair-absence-recheck'):
                    from .website_generation import pinned
                    engines = []
                    for engine in self.engines:
                        if isinstance(engine, ClamAV):
                            try:
                                engine = stack.enter_context(pinned(self.settings, engine, job['generation']))
                            except (OSError, ClamShieldError) as exc:
                                message = str(exc) if isinstance(exc, ClamShieldError) else 'Website signature provenance unavailable'
                                engine = UnavailableEngine('clamav', message); errors += 1
                        engines.append(engine)
                self._run(job, engines, errors)
        except (OSError, ClamShieldError) as exc:
            counters = dict(seen=0, scanned=0, infected=0, detections=0, skipped=0, errors=1, bytes=0, suppressed=0)
            message=str(exc) if isinstance(exc,ClamShieldError) else 'Website signature provenance unavailable'
            self.store.finish(job,'failed',counters,message);self.fail_preview(job,message)

    def fail_preview(self,job,message):
        if job['source']!='repair-preview':return
        from .repairs import Repairs
        repairs=Repairs(self.settings,self.store,self.hestia)
        context={key:job[key] for key in ('actor','owner','identity')}
        try:plan=repairs.get(context,job['id'])
        except ClamShieldError:return
        if plan['status']=='queued':repairs.update(context,plan,'failed',message)

    def _run(self, job, engines, preflight_errors=0):
        counters = {'seen': 0, 'scanned': 0, 'infected': 0, 'detections': 0,
                    'skipped': 0, 'errors': preflight_errors, 'bytes': 0, 'suppressed': 0}
        try:
            self.validate(job)
            if job['source'] == 'repair-absence-recheck':
                from .missing_files import MissingFiles
                from .repairs import Repairs
                MissingFiles(Repairs(self.settings,self.store,self.hestia)).recheck(job)
                return
            if job['source']=='yara-trial':
                from .rule_trials import RuleTrials
                RuleTrials(self.settings,self.store,self.hestia).run(job)
                return
            if job['source'] == 'repair-preview':
                from .repairs import Repairs
                Repairs(self.settings, self.store, self.hestia).prepare(job, engines)
                return
            if job['source'] == 'wordpress-integrity':
                from .wordpress import WordPress
                WordPress(self.settings, self.store, self.hestia).run(job)
                return
            if not engines:
                raise ClamShieldError('No scanning engines are enabled')
            for relative, state, detail in walk(job['root'], job['target']):
                if self.store.cancelled(job['id']):
                    self.store.finish(job, 'cancelled', counters)
                    return
                counters['seen'] += 1
                if state != 'regular':
                    counters['skipped' if state == 'skipped' else 'errors'] += 1
                    self.store.file_result(job['id'], relative, state, {'message': detail})
                    self.store.progress(job['id'], counters)
                    continue
                try:
                    with snapshot(job['root'], relative, self.settings.snapshots,
                                  self.settings.max_file_bytes) as (path, fingerprint):
                        failures, detections = [], []
                        for engine in engines:
                            if self.store.cancelled(job['id']):
                                self.store.finish(job, 'cancelled', counters)
                                return
                            try:
                                detections.extend(engine.scan(path))
                            except ClamShieldError as exc:
                                failures.append({'engine': engine.name, 'message': str(exc)})
                            self.store.progress(job['id'], counters)
                        detections, suppressed = Exceptions(self.store).filter(job, relative, fingerprint, detections)
                        counters['suppressed'] += len(suppressed)
                        for detection in detections:
                            self.store.add_finding(job, relative, fingerprint, detection)
                        counters['detections'] += len(detections)
                        counters['infected'] += bool(detections)
                        counters['bytes'] += fingerprint['size']
                        if failures:
                            counters['errors'] += 1
                        else:
                            counters['scanned'] += 1
                            self.store.observed(job, relative, fingerprint)
                        self.store.file_result(job['id'], relative,
                            'error' if failures else 'infected' if detections else 'excepted' if suppressed else 'clean',
                            {'failures': failures, 'detections': detections, 'suppressed': suppressed,
                             'sha256': fingerprint['sha256'],'engines':sorted(engine.name for engine in engines)})
                except Conflict as exc:
                    counters['skipped'] += 1
                    self.store.file_result(job['id'], relative, 'skipped', {'message': str(exc)})
                except (OSError, ClamShieldError):
                    counters['errors'] += 1
                    self.store.file_result(job['id'], relative, 'error',
                                           {'message': 'File changed or could not be captured'})
                self.store.progress(job['id'], counters)
            status = 'partial' if counters['errors'] or counters['skipped'] else 'completed'
            self.store.finish(job, status, counters)
        except (OSError, ClamShieldError) as exc:
            counters['errors'] += 1
            message=str(exc) if isinstance(exc,ClamShieldError) else 'Website could not be read'
            self.store.finish(job,'failed',counters,message);self.fail_preview(job,message)
