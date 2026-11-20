"""Scoped WordPress discovery and integrity jobs using static reads only."""
import hashlib
import json
import re

from .errors import AccessDenied, ClamShieldError, Conflict
from .paths import absence, snapshot, walk
from .store import encode
from .wordpress_sources import References, ReferenceUnavailable, token


def joined(*parts):
    return '/'.join(p for p in parts if p)


def assignment(text, name, default=None):
    # Read literal release metadata, never evaluate PHP, wp-config or wp-cli.
    values = re.findall(r'^\s*\$' + re.escape(name) + r'\s*=\s*[\'"]([^\'"\r\n]+)[\'"]\s*;', text, re.M)
    if len(values) != 1:
        if not values and default is not None:
            return default
        raise ReferenceUnavailable('WordPress release metadata is missing or ambiguous')
    return values[0]


def header(text, name):
    values = re.findall(r'^[ \t/*#@]*' + re.escape(name) + r':[ \t]*([^\r\n]+)', text, re.M | re.I)
    if len(values) != 1:
        raise ReferenceUnavailable('Component ' + name + ' header is missing or ambiguous')
    return values[0].split('*/')[0].strip()


def release_marker(settings, root, component):
    kind=component['kind']
    path=component.get('release_path') or joined(component['path'],'wp-includes/version.php' if kind=='core' else 'style.css' if kind=='theme' else '')
    if kind=='plugin' and not component.get('release_path'):
        raise ReferenceUnavailable('Plugin release identity requires a fresh integrity scan')
    try:
        with snapshot(root,path,settings.snapshots,256*1024) as (copy,fingerprint):
            text=copy.read_text(encoding='utf-8',errors='replace')
        version=assignment(text,'wp_version') if kind=='core' else header(text[:8192],'Version')
        if (version!=component['version'] or fingerprint['links']!=1 or
                (kind=='core' and assignment(text,'wp_local_package','en_US')!=component.get('locale','en_US'))):
            raise ReferenceUnavailable('Component release changed; run a fresh integrity scan')
        return {'path':path,'fingerprint':fingerprint}
    except OSError as exc:
        raise ReferenceUnavailable('Component release identity is unavailable') from exc


class WordPress:
    def __init__(self, settings, store, hestia, references=None):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.references = references or References(settings)

    def text(self, root, path):
        with snapshot(root, path, self.settings.snapshots, 256 * 1024) as (copy, _):
            return copy.read_text(encoding='utf-8', errors='replace')

    def components(self, root, installation, files):
        base = installation['path']
        yield dict(kind='core', slug='wordpress', version=installation['version'],
                   locale=installation['locale'], path=base, release_path=joined(base,'wp-includes/version.php'))
        for kind, folder, marker in [('plugin', 'plugins', None), ('theme', 'themes', 'style.css')]:
            prefix = joined(base, 'wp-content', folder) + '/'
            slugs = sorted({p[len(prefix):].split('/')[0] for p in files if p.startswith(prefix) and '/' in p[len(prefix):]})
            for slug in slugs:
                component = dict(kind=kind, slug=slug, path=prefix + slug)
                try:
                    token(slug, 'slug')
                    if marker:
                        component['release_path']=joined(component['path'],marker)
                        text = self.text(root, joined(component['path'], marker))
                        header(text, 'Theme Name')
                    else:
                        candidates = [p for p in files if p.startswith(component['path'] + '/')
                                      and '/' not in p[len(component['path']) + 1:] and p.endswith('.php')]
                        texts = []
                        for path in sorted(candidates):
                            text = self.text(root, path)
                            try:
                                header(text[:8192], 'Plugin Name')
                                texts.append((text[:8192],path))
                            except ReferenceUnavailable:
                                continue
                        if len(texts) != 1:
                            raise ReferenceUnavailable('Plugin entry point is missing or ambiguous')
                        text,component['release_path'] = texts[0]
                    component['version'] = token(header(text[:8192], 'Version'), 'version')
                except (OSError, ClamShieldError) as exc:
                    component['error'] = str(exc) if isinstance(exc, ClamShieldError) else 'Component metadata could not be read'
                yield component
            if kind == 'plugin':
                # Standalone plugin files have no directory slug to authenticate.
                for path in sorted(files):
                    if path.startswith(prefix) and '/' not in path[len(prefix):] and path.endswith('.php') and not path.endswith('/index.php'):
                        yield dict(kind='plugin', path=path, slug=path[len(prefix):],
                                   error='Standalone plugin requires a trusted reference mapping')

    def run(self, job):
        counters = dict(seen=0, scanned=0, infected=0, detections=0, skipped=0, errors=0,
                        bytes=0, installations=0, modified=0, missing=0, additional=0, unverified=0)
        report = {'installations': [], 'components': [], 'discovery_complete': False}
        try:
            files, entries = set(), set()
            for path, state, detail in walk(job['root'], job['target']):
                self.check_cancel(job)
                counters['seen'] += 1
                entries.add(path)
                if counters['seen'] > 200000:
                    raise Conflict('WordPress discovery exceeds the configured inventory limit')
                if state == 'regular':
                    files.add(path)
                else:
                    counters['skipped' if state == 'skipped' else 'errors'] += 1
                    self.store.file_result(job['id'], path, state, {'message': detail})
                if counters['seen'] % 100 == 0:
                    self.store.progress(job['id'], counters)
            report['discovery_complete'] = True
            bases = {p[:-len('wp-includes/version.php')].rstrip('/') for p in entries
                     if p == 'wp-includes/version.php' or p.endswith('/wp-includes/version.php')}
            bases.update(p[:-len('wp-settings.php')].rstrip('/') for p in entries
                         if (p == 'wp-settings.php' or p.endswith('/wp-settings.php'))
                         and joined(p[:-len('wp-settings.php')].rstrip('/'), 'wp-load.php') in entries)
            for base in sorted(bases):
                self.check_cancel(job)
                version_file = joined(base, 'wp-includes/version.php')
                installation = {'path': base}
                counters['installations'] += 1
                try:
                    text = self.text(job['root'], version_file)
                    installation['version'] = token(assignment(text, 'wp_version'), 'version')
                    installation['locale'] = token(assignment(text, 'wp_local_package', 'en_US'), 'locale')
                    report['installations'].append(installation)
                    for component in self.components(job['root'], installation, files):
                        self.check_cancel(job)
                        self.component(job, component, files, counters)
                        report['components'].append(component)
                except (OSError, ClamShieldError) as exc:
                    if isinstance(exc, Cancelled):
                        raise
                    installation['error'] = str(exc) if isinstance(exc, ClamShieldError) else 'Release metadata could not be read'
                    if installation not in report['installations']:
                        report['installations'].append(installation)
                    counters['errors'] += 1
            self.save_report(job, report)
            status = 'partial' if any(counters[k] for k in ('errors', 'skipped', 'unverified')) else 'completed'
            self.store.finish(job, status, counters)
        except Cancelled:
            self.save_report(job, report)
            self.store.finish(job, 'cancelled', counters)
        except (OSError, ClamShieldError) as exc:
            counters['errors'] += 1
            report['error'] = str(exc) if isinstance(exc, ClamShieldError) else 'WordPress inventory could not be read'
            self.save_report(job, report)
            self.store.finish(job, 'failed', counters, report['error'])

    def check_cancel(self, job):
        if self.store.cancelled(job['id']):
            raise Cancelled('Integrity check cancelled')

    def component(self, job, component, files, counters):
        component['counts'] = dict(verified=0, modified=0, missing=0, additional=0, errors=0)
        try:
            if component.get('error'):
                raise ReferenceUnavailable(component['error'])
            manifest = self.references.manifest(component)
            marker = release_marker(self.settings,job['root'],component)
        except ReferenceUnavailable as exc:
            component.update(status='unverified', error=str(exc))
            counters['unverified'] += 1
            self.store.file_result(job['id'], component['path'], 'unverified', {'component': component, 'message': str(exc)})
            return
        component['source'] = manifest['source']
        for relative, expected in sorted(manifest['files'].items()):
            self.check_cancel(job)
            path = joined(component['path'], relative)
            detail = {'component': {k: v for k, v in component.items() if k not in ('counts', 'status')},
                      'file': relative, 'expected': expected, 'source': manifest['source'], 'release_marker': marker}
            try:
                with snapshot(job['root'], path, self.settings.snapshots, self.settings.max_file_bytes) as (copy, fingerprint):
                    digest = hashlib.new(expected['algorithm'], copy.read_bytes()).hexdigest()
                    status = 'verified' if digest == expected['digest'] else 'modified'
                    detail['sha256'] = fingerprint['sha256']
                    detail['actual_digest'] = digest
                    counters['scanned'] += 1
                    counters['bytes'] += fingerprint['size']
                    if status == 'modified':
                        counters['modified'] += 1
                        counters['detections'] += 1
                        self.store.add_finding(job, path, fingerprint | {'wordpress': detail},
                            dict(engine='integrity', signature='WordPress.' + component['kind'] + '.Modified',
                                 provider='wordpress.org', severity='review'))
            except FileNotFoundError:
                try:
                    fingerprint = absence(job['root'], path)
                    status = 'missing'
                    counters['missing'] += 1
                    counters['detections'] += 1
                    self.store.add_finding(job, path, fingerprint | {'wordpress': detail},
                        dict(engine='integrity', signature='WordPress.' + component['kind'] + '.Missing',
                             provider='wordpress.org', severity='review'))
                except (OSError, ClamShieldError):
                    status = 'errors'; counters['errors'] += 1
                    detail['message'] = 'Missing path changed during inspection; scan again'
            except (OSError, ClamShieldError):
                status = 'errors'
                counters['errors'] += 1
                detail['message'] = 'Reference file could not be captured safely'
            component['counts'][status] += 1
            self.store.file_result(job['id'], path, status, detail)
            self.store.progress(job['id'], counters)
        prefix = component['path'] + '/' if component['path'] else ''
        for path in sorted(files):
            self.check_cancel(job)
            if not path.startswith(prefix):
                continue
            relative = path[len(prefix):]
            if relative in manifest['files']:
                continue
            if component['kind'] == 'core':
                # Root code absent from the release merits review too. User
                # content and the site's own wp-config are independently owned.
                root_code = '/' not in relative and relative.lower().endswith(('.php', '.phtml', '.phar', '.js')) and relative != 'wp-config.php'
                if not relative.startswith(('wp-admin/', 'wp-includes/')) and not root_code:
                    continue
            counters['additional'] += 1
            component['counts']['additional'] += 1
            detail = {'component': {k: v for k, v in component.items() if k not in ('counts', 'status')},
                      'file': relative, 'message': 'File is absent from this official release; review required'}
            self.store.file_result(job['id'], path, 'additional', detail)
            try:
                with snapshot(job['root'], path, self.settings.snapshots, self.settings.max_file_bytes) as (_, fingerprint):
                    self.store.add_finding(job, path, fingerprint | {'wordpress': detail},
                        dict(engine='integrity', signature='WordPress.' + component['kind'] + '.Additional',
                             provider='wordpress.org', severity='review'))
                    counters['detections'] += 1
            except (OSError, ClamShieldError):
                counters['errors'] += 1
                component['counts']['errors'] += 1
        component['status'] = 'partial' if component['counts']['errors'] else 'review' if any(component['counts'][k] for k in ('modified', 'missing', 'additional')) else 'verified'

    def save_report(self, job, report):
        with self.store.connection() as db:
            db.execute('INSERT OR REPLACE INTO wordpress_reports VALUES(?,?,?,?,?)',
                       (job['id'], job['owner'], job['identity'], job['domain'], encode(report)))

    def list(self, context):
        with self.store.connection() as db:
            rows = db.execute('''SELECT w.*,j.created,j.status,j.counters FROM wordpress_reports w
              JOIN jobs j ON j.id=w.job_id WHERE w.owner=? AND w.identity=? ORDER BY j.created DESC LIMIT 20''',
              self.store.scope(context)).fetchall()
        return [dict(row) | {'report': json.loads(row['report']), 'counters': json.loads(row['counters'])} for row in rows]

    def report(self, context, job_id, offset=0):
        job = self.store.job(context, job_id)
        if job['counters'].get('history_expired'):raise AccessDenied('Detailed scan history expired under this account retention policy')
        if job['source'] != 'wordpress-integrity':
            raise AccessDenied('WordPress integrity job unavailable')
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 1000000:
            raise AccessDenied('Invalid report offset')
        with self.store.connection() as db:
            db.execute('BEGIN')
            current = db.execute('SELECT counters FROM jobs WHERE id=? AND owner=? AND identity=?', (job_id,*self.store.scope(context))).fetchone()
            if not current or json.loads(current['counters']).get('history_expired'):
                raise AccessDenied('Detailed scan history expired under this account retention policy')
            rows = db.execute("SELECT * FROM file_results WHERE job_id=? AND status<>'verified' ORDER BY id LIMIT 201 OFFSET ?", (job_id, offset)).fetchall()
        return {'job': job, 'files': [dict(row) | {'detail': json.loads(row['detail'])} for row in rows[:200]],
                'next_offset': offset + 200 if len(rows) > 200 else None}


class Cancelled(ClamShieldError):
    pass
