"""Bounded upstream PHP rule data; no third-party code is imported or executed."""
import hashlib
import json
import posixpath
import re
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import ClamShieldError

REPOSITORY = 'jvoisin/php-malware-finder'
SOURCE_ID = 'php_hosting'
MAXIMUM = 4 * 1024 * 1024


def download(url, maximum):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise ClamShieldError('PHP rule source redirect was rejected')
    try:
        request = Request(url, headers={'User-Agent':'ClamShield hosting rules', 'Accept':'application/vnd.github+json'})
        with build_opener(NoRedirect()).open(request, timeout=45) as response:
            value = response.read(maximum + 1)
    except OSError as exc:
        raise ClamShieldError('PHP hosting rule data could not be retrieved') from exc
    if len(value) > maximum:
        raise ClamShieldError('PHP hosting rule data exceeds its size limit')
    return value


def fetch(fetcher=download):
    """Resolve one immutable commit, verify its complete include graph and notice."""
    def read(url, maximum):
        data=fetcher(url, maximum)
        if not isinstance(data,bytes) or len(data)>maximum:
            raise ClamShieldError('PHP hosting response exceeds its size limit')
        return data
    def document(url):
        try:return json.loads(read(url,MAXIMUM))
        except (ValueError,UnicodeError) as exc:raise ClamShieldError('Invalid PHP hosting repository metadata') from exc
    try:
        commit=document('https://api.github.com/repos/'+REPOSITORY+'/commits/master')['sha']
        if not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit):
            raise ClamShieldError('Invalid PHP hosting commit identity')
        tree=document('https://api.github.com/repos/'+REPOSITORY+'/git/trees/'+commit+'?recursive=1')
        if tree.get('truncated') or not isinstance(tree.get('tree'),list) or len(tree['tree'])>10000:
            raise ClamShieldError('Incomplete PHP hosting repository tree')
        nodes={}
        for node in tree['tree']:
            path=node.get('path')
            if node.get('type')!='blob' or not isinstance(path,str):continue
            if path in nodes:raise ClamShieldError('Duplicate PHP hosting source path')
            nodes[path]=node
        receipts={};cache={};total=0
        def blob(path, maximum):
            nonlocal total
            if path in cache:return cache[path]
            node=nodes.get(path)
            if not node or type(node.get('size')) is not int or not 0<node['size']<=maximum or not re.fullmatch('[0-9a-f]{40}',str(node.get('sha',''))):
                raise ClamShieldError('Invalid PHP hosting dependency identity')
            if len(cache)>=24:raise ClamShieldError('Too many PHP hosting dependencies')
            data=read('https://raw.githubusercontent.com/'+REPOSITORY+'/'+commit+'/'+path,maximum)
            if len(data)!=node['size'] or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=node['sha']:
                raise ClamShieldError('PHP hosting dependency content does not match its commit')
            total+=len(data)
            if total>MAXIMUM:raise ClamShieldError('PHP hosting bundle exceeds its size limit')
            try:data.decode('utf-8')
            except UnicodeError as exc:raise ClamShieldError('PHP hosting data must be UTF-8') from exc
            cache[path]=data;receipts[path]=dict(path=path,git_blob=node['sha'],sha256=hashlib.sha256(data).hexdigest())
            return data
        def expand(path, stack=()):
            if path in stack or len(stack)>=8:raise ClamShieldError('Cyclic or excessive PHP rule includes')
            output=[]
            for line in blob(path,1024*1024).decode('utf-8').splitlines(keepends=True):
                if re.match(r'^\s*include\b',line):
                    match=re.fullmatch(r'\s*include\s+"([^"\r\n]+)"\s*',line)
                    if not match:raise ClamShieldError('Unsupported PHP rule include directive')
                    value=match[1]
                    target=posixpath.normpath(posixpath.join(posixpath.dirname(path),value))
                    if (value.startswith('/') or '\\' in value or not target.startswith('data/') or
                            not target.endswith(('.yar','.yara')) or '..' in target.split('/') or '\0' in value):
                        raise ClamShieldError('PHP rule includes must remain in the upstream data tree')
                    output.append(expand(target,(*stack,path)))
                else:output.append(line)
            value=''.join(output)
            if len(value.encode())>MAXIMUM:raise ClamShieldError('Expanded PHP rules exceed their size limit')
            return value
        content=expand('data/php.yar')
        notice=blob('LICENSE',65536)
        if 'GNU LESSER GENERAL PUBLIC LICENSE' not in notice.decode():
            raise ClamShieldError('PHP hosting license changed; administrator review is required')
        metadata=dict(commit=commit,version=commit,repository='https://github.com/'+REPOSITORY,
            source_url='https://github.com/'+REPOSITORY+'/blob/'+commit+'/data/php.yar',
            license=notice.decode(),license_url='https://github.com/'+REPOSITORY+'/blob/'+commit+'/LICENSE',
            license_sha256=hashlib.sha256(notice).hexdigest(),dependencies=list(receipts.values()),
            review_only=True,scope='website')
        return content.encode(),metadata
    except (KeyError,TypeError,AttributeError) as exc:
        raise ClamShieldError('Invalid PHP hosting rule metadata') from exc
