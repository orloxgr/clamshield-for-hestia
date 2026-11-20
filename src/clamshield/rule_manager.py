"""Versioned rule sources, dependency-aware candidates and explicit activation."""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit
import uuid

from .atomic import write, write_json, sync_directory
from .engines import engine_identity, sealed_file, Yara
from .errors import ClamShieldError, Conflict, EngineError
from .rules import Rules, download
from .store import encode


def sha(content):
    return hashlib.sha256(content).hexdigest()


def revision(config):
    return sha(encode(config).encode())


class RuleManager:
    def __init__(self, settings):
        self.settings = settings
        self.rules = Rules(settings)
        self.folder = settings.state / 'rule-sources'
        self.config_path = settings.state / 'rules-config.json'

    @contextmanager
    def locked(self):
        self.settings.prepare()
        if self.folder.is_symlink():
            raise ClamShieldError('Unexpected rule sources directory')
        self.folder.mkdir(mode=0o700, exist_ok=True)
        with (self.settings.state / 'rule-manager.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def read(self):
        if self.config_path.is_symlink():
            raise ClamShieldError('Unexpected rule configuration path')
        if self.config_path.is_file():
            return json.loads(self.config_path.read_text())
        result = {'sources': {}, 'disabled': []}
        active = self.rules.status()
        if active.get('configured'):
            content = (self.rules.base / 'current/rules.yar').read_bytes()
            # Migrate the existing active Forge data without changing activation.
            if active.get('provider') == 'yara-forge':
                with self.locked():
                    if self.config_path.is_file():
                        return json.loads(self.config_path.read_text())
                    filename = 'forge-' + sha(content) + '.yar'
                    write(self.folder / filename, content)
                    result['sources']['forge'] = dict(id='forge', name='YARA Forge', kind='forge', enabled=True,
                        namespace='default', file=filename, sha256=sha(content), version=active.get('version'),
                        profile=active.get('profile'), source_url=active.get('source_url', ''),
                        license='Upstream per-repository notices retained in the original source', fetched=time.time())
                    write_json(self.config_path, result)
        return result

    @staticmethod
    def source_id(value):
        if not isinstance(value, str) or not re.fullmatch('[a-z][a-z0-9_]{0,31}', value) or value in ('default', 'forge'):
            raise ClamShieldError('Choose a source ID using lowercase letters, digits and underscores; forge/default are reserved')
        return value

    @staticmethod
    def remote_url(value):
        try:
            url = urlsplit(value)
            valid = (isinstance(value,str) and len(value)<=2000 and url.scheme == 'https' and url.hostname == 'raw.githubusercontent.com'
                     and url.port in (None, 443) and not url.username and not url.password
                     and not url.query and not url.fragment and len(url.path.split('/')) >= 5
                     and url.path.endswith(('.yar', '.yara')))
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ClamShieldError('Remote sources require an HTTPS raw.githubusercontent.com rule-file URL; other sources can be uploaded locally')
        return value

    def save_source(self, value):
        if not isinstance(value, dict) or set(value) - {'id', 'name', 'kind', 'url', 'license', 'version', 'content'}:
            raise ClamShieldError('Invalid rule source')
        source_id = self.source_id(value.get('id'))
        kind = value.get('kind', 'local')
        if kind not in ('local', 'remote'):
            raise ClamShieldError('Invalid rule source kind')
        for field, maximum in (('name', 120), ('license', 16384), ('version', 100)):
            if not isinstance(value.get(field), str) or not value[field].strip() or len(value[field]) > maximum:
                raise ClamShieldError('Provide a bounded source name, version and license/notice')
        if kind == 'remote':
            self.remote_url(value.get('url'))
        else:
            content = value.get('content')
            if not isinstance(content, str) or not content.strip() or len(content.encode()) > 4 * 1024**2 or '\0' in content:
                raise ClamShieldError('Local rules must be nonempty UTF-8 text up to 4 MiB')
        config = self.read()
        with self.locked():
            config = self.read()
            if config['sources'].get(source_id,{}).get('kind') in ('php-hosting','web-hosting'):
                raise Conflict('Use the managed hosting update action for this source')
            if source_id not in config['sources'] and len(config['sources']) >= 16:
                raise Conflict('Rule source count limit reached')
            source = dict(id=source_id, namespace=source_id, kind=kind, enabled=config['sources'].get(source_id,{}).get('enabled',True),
                          name=value['name'].strip(), license=value['license'], version=value['version'],
                          source_url=value.get('url') or 'local-upload')
            if kind == 'local':
                data = content.encode(); filename = source_id + '-' + sha(data) + '.yar'
                write(self.folder / filename, data)
                source.update(file=filename, sha256=sha(data), fetched=time.time())
            config['sources'][source_id] = source
            write_json(self.config_path, config)
        return {'revision': revision(config), 'source_id': source_id, 'fetch_required': kind == 'remote'}

    def toggle_source(self, source_id, enabled):
        if type(enabled) is not bool:
            raise ClamShieldError('Invalid source state')
        self.read()
        with self.locked():
            config = self.read()
            if source_id not in config['sources']:
                raise ClamShieldError('Unknown source')
            config['sources'][source_id]['enabled'] = enabled
            write_json(self.config_path, config)
        return {'revision': revision(config)}

    def toggle_rule(self, rule_id, enabled, cascade=False):
        if not isinstance(rule_id, str) or len(rule_id) > 250 or type(enabled) is not bool or type(cascade) is not bool:
            raise ClamShieldError('Invalid rule state')
        self.read()
        with self.locked():
            config = self.read()
            known = False; nodes={}
            for pointer in ('candidate', 'current'):
                path = self.rules.base / pointer
                if path.is_symlink():
                    catalog = self.catalog_data(path.resolve().name)
                    for node in catalog:nodes.setdefault(node['id'],node)
                    if any(r['id'] == rule_id for r in catalog):
                        known = True
            if not known and not (enabled and rule_id in config['disabled']):
                raise ClamShieldError('Rule is not in an available catalog')
            disabled = set(config['disabled'])
            affected={rule_id}
            if cascade and not enabled:
                reverse={}
                for node in nodes.values():
                    for dependency in node['dependencies']:reverse.setdefault(dependency,set()).add(node['id'])
                pending=[rule_id]
                while pending:
                    dependency=pending.pop()
                    for dependent in reverse.get(dependency,()):
                        if dependent not in affected:affected.add(dependent);pending.append(dependent)
            disabled.discard(rule_id) if enabled else disabled.update(affected)
            config['disabled'] = sorted(disabled)
            write_json(self.config_path, config)
        return {'revision': revision(config),'affected_rules':len(affected)}

    def fetch(self, source_id):
        config = self.read()
        source = config['sources'].get(source_id)
        if source and source.get('kind')=='php-hosting':return self.php_hosting()
        if source and source.get('kind')=='web-hosting':return self.web_hosting()
        if not source or source['kind'] != 'remote':
            raise ClamShieldError('Unknown remote rule source')
        url = self.remote_url(source['source_url'])
        # Raw GitHub file URLs do not need arbitrary redirect destinations.
        from urllib.request import HTTPRedirectHandler, build_opener, Request
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args):
                raise ClamShieldError('Rule source redirect was rejected')
        try:
            with build_opener(NoRedirect()).open(Request(url, headers={'User-Agent':'ClamShield rule updater'}), timeout=45) as response:
                data = response.read(4 * 1024**2 + 1)
            if len(data) > 4 * 1024**2 or not data.strip():
                raise ClamShieldError('Remote rule source exceeds its size allowance')
            data.decode('utf-8')
        except (OSError, UnicodeError) as exc:
            raise ClamShieldError('Remote rule source could not be retrieved as UTF-8') from exc
        with self.locked():
            current = self.read()
            if current['sources'].get(source_id) != source:
                raise Conflict('Source configuration changed during download')
            filename = source_id + '-' + sha(data) + '.yar'
            write(self.folder / filename, data)
            source.update(file=filename, sha256=sha(data), fetched=time.time())
            current['sources'][source_id] = source
            write_json(self.config_path, current)
        return self.build(revision(current))

    def php_hosting(self):
        from .php_hosting_rules import fetch,SOURCE_ID
        return self.managed_hosting(fetch,SOURCE_ID,'php-hosting','PHP Malware Finder — hosting heuristics','PHP')

    def web_hosting(self):
        from .web_hosting_rules import fetch,SOURCE_ID
        return self.managed_hosting(fetch,SOURCE_ID,'web-hosting','Community web hosting — JS/phishing heuristics','Web')

    def managed_hosting(self,fetch,source_id,kind,name,label):
        config=self.read();wanted=revision(config);old=config['sources'].get(source_id)
        if old and old.get('kind')!=kind:raise Conflict(label+' hosting source ID is already used by another source')
        if not old and len(config['sources'])>=16:raise Conflict('Rule source count limit reached')
        content,metadata=fetch()
        with self.locked():
            config=self.read()
            if revision(config)!=wanted:raise Conflict('Rule settings changed during '+label+' hosting download; stage again')
            filename=source_id+'-'+sha(content)+'.yar';write(self.folder/filename,content)
            config['sources'][source_id]=dict(metadata,id=source_id,namespace=source_id,
                name=name,kind=kind,
                enabled=old.get('enabled',True) if old else True,file=filename,sha256=sha(content),fetched=time.time())
            config['sources'][source_id]['review_only']=old.get('review_only',True) if old else True
            write_json(self.config_path,config)
        return self.build(revision(config))

    def review_mode(self, source_id, review_only):
        if type(review_only) is not bool:raise ClamShieldError('Choose a boolean heuristic review mode')
        with self.locked():
            config=self.read();source=config['sources'].get(source_id)
            if not source or source.get('kind') not in ('php-hosting','web-hosting'):raise ClamShieldError('Choose a managed hosting source')
            source['review_only']=review_only;write_json(self.config_path,config)
        return {'revision':revision(config)}

    def forge(self, profile, release=None):
        content, upstream = self.rules.fetch_forge(profile, release)
        self.read()
        with self.locked():
            config = self.read()
            filename = 'forge-' + sha(content) + '.yar'
            write(self.folder / filename, content)
            config['sources']['forge'] = dict(id='forge', namespace='default', name='YARA Forge', kind='forge', enabled=True,
                file=filename, sha256=sha(content), version=upstream['version'], profile=profile,
                source_url=upstream['source_url'], archive_sha256=upstream['archive_sha256'],
                license=upstream['licenses'], fetched=time.time())
            write_json(self.config_path, config)
        return self.build(revision(config))

    def parse(self, request):
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
            resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            with sealed_file(Path(__file__).with_name('rule_catalog.py')) as helper_fd:
                result = subprocess.run(['/usr/bin/python3', '-I', '/proc/self/fd/'+str(helper_fd)],
                                        input=json.dumps(request,ensure_ascii=False).encode(), capture_output=True, timeout=185,
                                        pass_fds=(helper_fd,),preexec_fn=limits, **engine_identity(), cwd='/tmp',
                                        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise EngineError('Rule catalog parser failed or timed out') from exc
        if len(result.stdout) > 128 * 1024**2:
            raise EngineError('Rule catalog exceeds its output allowance')
        try:
            value = json.loads(result.stdout)
        except ValueError as exc:
            raise EngineError('Ubuntu plyara did not produce a valid rule catalog') from exc
        if result.returncode or value.get('error'):
            raise EngineError('Rule catalog validation failed: ' + str(value.get('error', 'parser unavailable'))[:300])
        return value

    def build(self, expected_revision=None):
        config = self.read(); wanted = revision(config)
        if expected_revision and expected_revision != wanted:
            raise Conflict('Rule configuration changed before this build; use the latest queued revision')
        sources = []
        for source_id, source in sorted(config['sources'].items()):
            if not source['enabled']:
                continue
            if 'file' not in source:
                raise Conflict('Fetch the configured remote rule source first')
            path = self.folder / source['file']
            if path.is_symlink() or path.parent.resolve() != self.folder or not path.is_file():
                raise ClamShieldError('Unexpected rule source file')
            content = path.read_bytes()
            if sha(content) != source['sha256']:
                raise EngineError('Original rule source verification failed')
            sources.append(dict(id=source_id, namespace=source['namespace'], content=content.decode('utf-8-sig')))
        if not sources:
            raise Conflict('Select at least one rule source')
        parsed = self.parse({'sources':sources, 'disabled':config['disabled']})
        if not any(n['enabled'] for n in parsed['catalog']):
            raise Conflict('At least one rule must remain enabled')
        with self.rules.locked():
            release = self.rules.base / ('generation-' + uuid.uuid4().hex)
            release.mkdir(mode=0o700)
        try:
            inputs, combined = {}, []
            for source in sources:
                source_id = source['id']
                write(release / ('original-' + source_id + '.yar'), source['content'])
                selected = parsed['selected'][source_id]
                selected_path = release / ('source-' + source_id + '.yar')
                write(selected_path, selected)
                inputs[source['namespace']] = selected_path
                combined.append('// Namespace: ' + source['namespace'] + '\n' + selected)
            write(release / 'rules.yar', '\n\n'.join(combined))
            write_json(release / 'catalog.json', parsed['catalog'])
            started = time.monotonic()
            self.rules.compile_many(inputs, release / 'rules.yarac')
            compile_seconds = time.monotonic() - started
            smoke = release / 'smoke'
            write(smoke, b'ClamShield candidate compatibility fixture')
            Yara(self.settings.yara_binary, release / 'rules.yarac', timeout=20).scan(smoke)
            smoke.unlink()
            files = {p.name:sha(p.read_bytes()) for p in release.iterdir() if p.is_file()}
            forge = config['sources'].get('forge', {})
            metadata = dict(provider='managed', generation=release.name, created=time.time(),
                profile=forge.get('profile'), version=forge.get('version'), sha256=files['rules.yar'],
                files=files, config_sha256=wanted, config=config, sources=parsed['sources'],
                rules=len(parsed['catalog']), enabled=sum(n['enabled'] for n in parsed['catalog']),
                stale_overrides=[r for r in parsed['stale_overrides'] if config['sources'].get(r.split(':',1)[0],{}).get('enabled',True)],
                compile_seconds=round(compile_seconds,4),
                licenses='Original sources and complete upstream notices retained per source')
            write_json(release / 'metadata.json', metadata)
            sync_directory(release)
            with self.locked():
                if revision(self.read()) != wanted:
                    raise Conflict('Rule configuration changed while building; the newer revision must be staged')
                self.rules.pointer(self.rules.base / 'candidate', release)
            return self.summary(metadata)
        except BaseException:
            # A partial private candidate never becomes the active pointer.
            import shutil
            if not (self.rules.base/'candidate').is_symlink() or (self.rules.base/'candidate').resolve() != release:
                shutil.rmtree(release)
            raise

    @staticmethod
    def summary(metadata):
        return {k:v for k,v in metadata.items() if k not in ('config','files')}

    def metadata(self, name):
        if not isinstance(name, str) or not re.fullmatch('generation-[a-zA-Z0-9_-]{1,80}', name):
            raise ClamShieldError('Invalid rules generation')
        path = self.rules.base / name
        if path.is_symlink() or path.resolve().parent != self.rules.base or not path.is_dir():
            raise ClamShieldError('Rules generation unavailable')
        return path, json.loads((path/'metadata.json').read_text())

    def catalog_data(self, name):
        path, metadata = self.metadata(name)
        catalog = path/'catalog.json'
        if not catalog.is_file():
            return []
        if catalog.is_symlink() or sha(catalog.read_bytes()) != metadata.get('files',{}).get('catalog.json'):
            raise EngineError('Rule catalog verification failed')
        return json.loads(catalog.read_text())

    def catalog(self, name=None, search='', offset=0):
        if not isinstance(search,str) or len(search)>200 or type(offset) is not int or not 0<=offset<=50000:
            raise ClamShieldError('Invalid catalog query')
        if name is None:
            pointer=self.rules.base/('candidate' if (self.rules.base/'candidate').is_symlink() else 'current')
            if not pointer.is_symlink():
                return {'rules':[], 'total':0, 'next_offset':None, 'generation':None}
            name=pointer.resolve().name
        values=self.catalog_data(name)
        _,metadata=self.metadata(name)
        source_info=metadata.get('config',{}).get('sources',{})
        desired=self.read()
        if search.lower().startswith('source:'):
            values=[n for n in values if n['source_id']==search[7:].strip().lower()]
        elif search:
            values=[n for n in values if search.lower() in json.dumps(n,ensure_ascii=False).lower()]
        return dict(rules=[n|{'source':source_info.get(n['source_id'],{}),
                             'selected':n['id'] not in desired['disabled'],
                             'source_selected':desired['sources'].get(n['source_id'],{}).get('enabled',False)}
                          for n in values[offset:offset+100]],total=len(values),generation=name,
                    next_offset=offset+100 if len(values)>offset+100 else None)

    def candidate(self):
        pointer=self.rules.base/'candidate'
        if not pointer.is_symlink():return None
        _,metadata=self.metadata(pointer.resolve().name)
        return self.summary(metadata)

    def activate(self, name):
        self.read()
        with self.locked():
            _, metadata=self.metadata(name)
            if metadata.get('config_sha256') != revision(self.read()):
                raise Conflict('Candidate uses older source settings; build the current revision first')
            if metadata.get('stale_overrides'):
                raise Conflict('Clear obsolete rule overrides before activation')
            self.rules.activate(name)
        return self.summary(metadata)

    def rollback(self):
        self.read()
        with self.locked():
            metadata=self.rules.rollback()
            if 'config' in metadata:
                write_json(self.config_path,metadata['config'])
            else:
                # Legacy Forge generations retain their original bytes too.
                current=self.rules.base/'current/rules.yar'
                config=self.read();source=config['sources'].get('forge')
                if source and metadata.get('provider')=='yara-forge':
                    content=current.read_bytes();filename='forge-'+sha(content)+'.yar';write(self.folder/filename,content)
                    config['sources']={'forge':source|dict(file=filename,sha256=sha(content),version=metadata.get('version'),profile=metadata.get('profile'))}
                    config['disabled']=[];write_json(self.config_path,config)
        return self.summary(metadata)

    def status(self):
        config=self.read()
        return dict(sources=list(config['sources'].values()),disabled=config['disabled'],revision=revision(config),
                    candidate=self.candidate(),parser_available=importlib.util.find_spec('plyara') is not None)
