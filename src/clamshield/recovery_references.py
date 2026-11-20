"""Explicit version selections and account-supplied premium archives."""
import hashlib

from .errors import Conflict
from .paths import snapshot
from .wordpress import header, joined
from .wordpress_sources import References, archive_files, token


class RecoveryReferences(References):
    def __init__(self, settings, root, options):
        super().__init__(settings)
        self.root,self.options,self.packages,self.receipts=root,options,{},{}

    def target(self, component):
        return component | {'version':self.options['versions'].get(component['path'],component['version'])}

    def package(self, component):
        path=component['path'];archive=self.options['packages'].get(path)
        if not archive:return None
        if component['kind']=='core':raise Conflict('Core replacements require an official WordPress release')
        if path not in self.packages:
            with snapshot(self.root,archive,self.settings.snapshots,80*1024**2) as (copy,fingerprint):
                if fingerprint['links']!=1:raise Conflict('Trusted ZIP must not be hard linked')
                data=copy.read_bytes()
            files=archive_files(data,token(component['slug'],'slug'))
            marker=component['release_path'][len(path)+1:]
            if marker not in files:raise Conflict('Trusted ZIP is missing its component release header')
            version=header(files[marker][:8192].decode('utf-8',errors='replace'),'Version')
            if version!=self.target(component)['version']:raise Conflict('Trusted ZIP version differs from the selected version')
            self.packages[path]=files
            self.receipts[path]=dict(source=archive,sha256=hashlib.sha256(data).hexdigest(),version=version,
                                     authenticity='user-supplied',warning='Package authenticity and compatibility depend on the selected vendor ZIP.')
        return self.packages[path]

    def manifest(self, component):
        files=self.package(component)
        if files is None:return super().manifest(self.target(component))
        return dict(source='Selected vendor ZIP: '+self.receipts[component['path']]['source'],
                    files={name:dict(algorithm='sha256',digest=hashlib.sha256(content).hexdigest()) for name,content in files.items()})

    def replacement(self, component, path, expected):
        files=self.package(component)
        if files is None:return super().replacement(self.target(component),path,expected)
        content=files.get(path)
        if content is None or hashlib.sha256(content).hexdigest()!=expected['digest']:raise Conflict('Vendor ZIP content no longer matches the analyzed package')
        return content,self.receipts[component['path']]|dict(size=len(content),sha256=hashlib.sha256(content).hexdigest())
