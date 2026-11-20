"""Explicit version selections and account-supplied premium archives."""
import hashlib
import pwd

from .errors import Conflict
from .paths import snapshot
from .wordpress import header
from .wordpress_sources import References, ReferenceUnavailable, archive_files, token


class RecoveryReferences(References):
    def __init__(self, settings, root, options, *, owner=None):
        super().__init__(settings)
        self.root,self.options,self.packages,self.receipts=root,options,{},{}
        self.manifests,self.archives={},{}
        self.owner=owner

    def budget(self):
        if sum(len(value) for archive in [*self.packages.values(),*self.archives.values()] for value in archive.values())>256*1024**2:
            raise Conflict('Recovery packages exceed the memory limit; select fewer components')

    def target(self, component):
        return component | {'version':self.options['versions'].get(component['path'],component['version'])}

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
            if version!=self.target(component)['version']:raise Conflict('Trusted ZIP version differs from the selected version')
            self.packages[path]=files
            self.budget()
            self.receipts[path]=dict(source=archive,sha256=hashlib.sha256(data).hexdigest(),version=version,
                                     authenticity='user-supplied',warning='Package authenticity and compatibility depend on the selected vendor ZIP.')
        return self.packages[path]

    def manifest(self, component):
        files=self.package(component)
        if files is None:
            target=self.target(component);key=(target['kind'],target['path'],target['version'])
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
            if content is None or hashlib.new(expected['algorithm'],content).hexdigest()!=expected['digest']:raise ReferenceUnavailable('Replacement differs from the official release checksum')
            return content,dict(source=url,reference=manifest['source'],expected=expected,sha256=hashlib.sha256(content).hexdigest(),size=len(content))
        content=files.get(path)
        if content is None or hashlib.sha256(content).hexdigest()!=expected['digest']:raise Conflict('Vendor ZIP content no longer matches the analyzed package')
        return content,self.receipts[component['path']]|dict(size=len(content),sha256=hashlib.sha256(content).hexdigest())
