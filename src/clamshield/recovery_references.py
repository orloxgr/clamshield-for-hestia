"""Pinned recovery releases from WordPress.org or account-supplied archives."""
import hashlib
import json
import pwd
import re
from urllib.parse import urlencode

from .errors import Conflict
from .paths import snapshot
from .wordpress import header
from .wordpress_sources import References, ReferenceUnavailable, archive_files, token, checksum_matches


class RecoveryReferences(References):
    def __init__(self, settings, root, options, *, owner=None, fetch=None, comparison=False):
        super().__init__(settings)
        if fetch is not None:self.fetch=fetch
        self.root,self.options,self.packages,self.receipts=root,options,{},{}
        self.manifests,self.archives,self.targets={},{},{}
        self.owner,self.comparison=owner,comparison

    def installed(self):
        return type(self)(self.settings,self.root,self.options|dict(release_policy='installed',versions={}),
                          owner=self.owner,fetch=self.fetch,comparison=True)

    def budget(self):
        if sum(len(value) for archive in [*self.packages.values(),*self.archives.values()] for value in archive.values())>256*1024**2:
            raise Conflict('Recovery packages exceed the memory limit; select fewer components')

    def target(self, component):
        path=component['path']
        if path not in self.targets:
            if self.comparison:version=component['version']
            elif path in self.options['packages']:
                self.package(component);version=self.receipts[path]['version']
            elif path in self.options['versions']:version=self.options['versions'][path]
            elif self.options.get('release_policy','installed')=='installed':version=component['version']
            else:version=self.latest(component)
            self.targets[path]=component|dict(version=token(version,'version'))
        component['recovery_version']=self.targets[path]['version']
        return self.targets[path]

    def latest(self,component):
        kind=component['kind']
        if kind=='core':
            locale=token(component.get('locale','en_US'),'locale')
            url='https://api.wordpress.org/core/version-check/1.7/?'+urlencode({'locale':locale})
        elif kind in ('plugin','theme'):
            slug=token(component['slug'],'slug')
            url='https://api.wordpress.org/'+('plugins' if kind=='plugin' else 'themes')+'/info/1.2/?'+urlencode({'action':kind+'_information','request[slug]':slug,'request[fields][sections]':'0','request[fields][versions]':'0'})
        else:raise ReferenceUnavailable('Unsupported recovery component')
        # Mutable release metadata is read afresh for each analysis; exact
        # resolved releases and downloaded candidates stay pinned to that plan.
        try:
            value=json.loads(self.fetch(url,1024*1024))
            if not isinstance(value,dict):raise ValueError()
            if kind=='core':
                offers=value['offers']
                if not isinstance(offers,list):raise ValueError()
                versions=[offer['current'] for offer in offers if isinstance(offer,dict) and offer.get('response') in ('upgrade','latest') and offer.get('locale')==locale and isinstance(offer.get('current'),str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*',offer['current'])]
                if not versions:raise ValueError()
                version=max(versions,key=lambda value:tuple(map(int,value.split('.'))))
            else:
                if value.get('slug')!=slug:raise ValueError()
                version=value['version']
            if not isinstance(version,str) or len(version)>64 or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*',version):raise ValueError()
            return version
        except (ValueError,TypeError,KeyError) as exc:
            raise ReferenceUnavailable('Latest stable '+kind+' release is unavailable; select a version or trusted vendor ZIP') from exc

    def package(self, component):
        path=component['path'];archive=self.options['packages'].get(path)
        if not archive:return None
        if component['kind']=='core':raise Conflict('Core replacements require an official WordPress release')
        if path not in self.packages:
            source_root,source_path=self.root,archive
            if archive.startswith('~/'):
                if not self.owner:raise Conflict('Private vendor ZIP requires an authorized hosting account')
                try:source_root,source_path=pwd.getpwnam(self.owner).pw_dir,archive[2:]
                except KeyError as exc:raise Conflict('Native hosting home is unavailable') from exc
            with snapshot(source_root,source_path,self.settings.snapshots,80*1024**2) as (copy,fingerprint):
                if fingerprint['links']!=1:raise Conflict('Trusted ZIP must not be hard linked')
                data=copy.read_bytes()
            files=archive_files(data,token(component['slug'],'slug'))
            marker=component['release_path'][len(path)+1:]
            if marker not in files:raise Conflict('Trusted ZIP is missing its component release header')
            version=header(files[marker][:8192].decode('utf-8',errors='replace'),'Version')
            token(version,'version')
            if self.comparison and version!=component['version']:
                raise ReferenceUnavailable('The vendor ZIP is a different version; it cannot verify the installed version')
            expected=self.options['versions'].get(path)
            if expected and version!=expected:raise Conflict('Trusted ZIP version differs from the selected version')
            self.packages[path]=files
            self.budget()
            self.receipts[path]=dict(source=archive,sha256=hashlib.sha256(data).hexdigest(),version=version,
                                     authenticity='user-supplied',warning='Package authenticity and compatibility depend on the selected vendor ZIP.')
        return self.packages[path]

    def manifest(self, component):
        target=self.target(component)
        files=self.package(component)
        if files is None:
            key=(target['kind'],target['path'],target['version'])
            if key not in self.manifests:self.manifests[key]=super().manifest(target)
            return self.manifests[key]
        return dict(source='Selected vendor ZIP: '+self.receipts[component['path']]['source'],
                    files={name:dict(algorithm='sha256',digest=hashlib.sha256(content).hexdigest()) for name,content in files.items()})

    def replacement(self, component, path, expected):
        files=self.package(component)
        if files is None:
            target=self.target(component);manifest=self.manifest(component)
            if manifest['files'].get(path)!=expected:raise ReferenceUnavailable('Release reference changed')
            kind=target['kind'];version=token(target['version'],'version');slug=token(target.get('slug','wordpress'),'slug')
            language='' if target.get('locale','en_US')=='en_US' else token(target['locale'],'locale')+'/'
            url=f'https://downloads.wordpress.org/release/{language}wordpress-{version}.zip' if kind=='core' else f'https://downloads.wordpress.org/{kind}/{slug}.{version}.zip'
            if url not in self.archives:
                self.archives[url]=archive_files(self.get(url,80*1024**2),'wordpress' if kind=='core' else slug)
                self.budget()
            content=self.archives[url].get(path)
            if content is None or not checksum_matches(expected,hashlib.new(expected['algorithm'],content).hexdigest()):raise ReferenceUnavailable('Replacement differs from the official release checksum')
            return content,dict(source=url,reference=manifest['source'],expected=expected,sha256=hashlib.sha256(content).hexdigest(),size=len(content))
        content=files.get(path)
        if content is None or hashlib.sha256(content).hexdigest()!=expected['digest']:raise Conflict('Vendor ZIP content no longer matches the analyzed package')
        return content,self.receipts[component['path']]|dict(size=len(content),sha256=hashlib.sha256(content).hexdigest())
