"""Build and verify a reproducible application source archive, without lab data."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    version=re.search(r'__version__ = "([0-9.]+)"',(ROOT/'src/clamshield/__init__.py').read_text(encoding='utf-8'))[1]
    prefix='clamshield-hestia-'+version
    names=['README.md','LICENSE','pyproject.toml','entry.py','tools/install.py','tools/uninstall.py','tools/package.py',
           'tools/spamassassin-config.pl']
    for directory in ('src','panel','config','systemd','native','docs','tests'):
        for path in (ROOT/directory).rglob('*'):
            if {'__pycache__','node_modules'}.intersection(path.parts) or path.suffix=='.pyc':continue
            if path.is_symlink():raise RuntimeError('Source package cannot include symlinks')
            if path.is_file():names.append(path.relative_to(ROOT).as_posix())
    if (ROOT/'CHANGELOG.md').is_file():names.append('CHANGELOG.md')
    names=sorted(names)
    assert len(names)==len(set(names))
    manifest={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}
    output=ROOT/'dist';output.mkdir(exist_ok=True)
    archive=output/(prefix+'.tar.gz')
    with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,filename='',mode='wb',mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as tar:
        for name in names:
            data=(ROOT/name).read_bytes();info=tarfile.TarInfo(prefix+'/'+name)
            info.size=len(data);info.mode=0o644;info.mtime=0
            tar.addfile(info,io.BytesIO(data))
    # Verify every archived byte and path without extracting anything.
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers()
        assert [v.name for v in members]==[prefix+'/'+name for name in names]
        assert all(v.isfile() and hashlib.sha256(tar.extractfile(v).read()).hexdigest()==manifest[v.name[len(prefix)+1:]] for v in members)
        assert all(not any(part in {'lab','private','node_modules','.git'} for part in Path(v.name).parts) for v in members)
        assert all(Path(v.name).suffix not in {'.so','.exe','.dll','.sqlite3','.db','.key'} for v in members)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (output/(prefix+'.manifest.json')).write_text(json.dumps(dict(version=version,archive=archive.name,sha256=digest,files=manifest),indent=2)+'\n',encoding='utf-8')
    (output/(prefix+'.sha256')).write_text(digest+'  '+archive.name+'\n',encoding='ascii')
    print(json.dumps(dict(version=version,archive=str(archive),sha256=digest,source_files=len(names),size=archive.stat().st_size,verified=True)))


if __name__=='__main__':main()
