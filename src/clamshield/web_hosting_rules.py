"""Bounded original community web rule data; Ubuntu remains the YARA engine."""
import hashlib
import json
import posixpath
import re
from urllib.request import HTTPRedirectHandler,Request,build_opener

from .errors import ClamShieldError

REPOSITORY='Yara-Rules/rules'
SOURCE_ID='web_hosting'
MAXIMUM=4*1024*1024
INDEX='exploit_kits_index.yar'
EXTRA=('email/Email_generic_phishing.yar','packers/Javascript_exploit_and_obfuscation.yar')


def download(url,maximum):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args):raise ClamShieldError('Web hosting source redirect was rejected')
    try:
        with build_opener(NoRedirect()).open(Request(url,headers={'User-Agent':'ClamShield web hosting rules','Accept':'application/vnd.github+json'}),timeout=45) as response:data=response.read(maximum+1)
    except OSError as exc:raise ClamShieldError('Web hosting rule data could not be retrieved') from exc
    if len(data)>maximum:raise ClamShieldError('Web hosting rule data exceeds its size limit')
    return data


def fetch(fetcher=download):
    """Pin one tree; retain the original index, selected bodies and full notice."""
    def read(url,maximum):
        value=fetcher(url,maximum)
        if not isinstance(value,bytes) or len(value)>maximum:raise ClamShieldError('Web hosting response exceeds its size limit')
        return value
    def document(url):
        try:return json.loads(read(url,MAXIMUM))
        except (ValueError,UnicodeError) as exc:raise ClamShieldError('Invalid web hosting repository metadata') from exc
    try:
        commit=document('https://api.github.com/repos/'+REPOSITORY+'/commits/master')['sha']
        if not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit):raise ClamShieldError('Invalid web hosting commit identity')
        tree=document('https://api.github.com/repos/'+REPOSITORY+'/git/trees/'+commit+'?recursive=1')
        if tree.get('truncated') or not isinstance(tree.get('tree'),list) or len(tree['tree'])>10000:raise ClamShieldError('Incomplete web hosting repository tree')
        nodes={}
        for node in tree['tree']:
            path=node.get('path')
            if node.get('type')!='blob' or not isinstance(path,str):continue
            if path in nodes:raise ClamShieldError('Duplicate web hosting source path')
            nodes[path]=node
        receipts={};cache={};total=0
        def blob(path,maximum):
            nonlocal total
            if path in cache:return cache[path]
            node=nodes.get(path)
            if (not re.fullmatch('[A-Za-z0-9_./-]+',path) or '..' in path.split('/') or path.startswith('/') or
                not node or node.get('mode') not in ('100644','100755') or type(node.get('size')) is not int or not 0<node['size']<=maximum or
                not re.fullmatch('[0-9a-f]{40}',str(node.get('sha','')))):
                raise ClamShieldError('Invalid web hosting dependency identity')
            if len(cache)>=48:raise ClamShieldError('Too many web hosting dependencies')
            data=read('https://raw.githubusercontent.com/'+REPOSITORY+'/'+commit+'/'+path,maximum)
            if len(data)!=node['size'] or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=node['sha']:raise ClamShieldError('Web hosting dependency content does not match its commit')
            total+=len(data)
            if total>MAXIMUM:raise ClamShieldError('Web hosting bundle exceeds its size limit')
            try:data.decode('utf8')
            except UnicodeError as exc:raise ClamShieldError('Web hosting data must be UTF-8') from exc
            cache[path]=data;receipts[path]=dict(path=path,git_blob=node['sha'],sha256=hashlib.sha256(data).hexdigest())
            return data
        index=blob(INDEX,65536).decode('utf8');index=re.sub(r'/\*.*?\*/','',index,flags=re.S);paths=[]
        for line in index.splitlines():
            if not line.strip() or line.lstrip().startswith('//'):continue
            match=re.fullmatch(r'\s*include\s+"([^"\r\n]+)"\s*(?://[^\r\n]*)?',line)
            if not match:raise ClamShieldError('Unsupported web hosting index directive')
            value=match[1];path=posixpath.normpath(value)
            if ('..' in value.split('/') or '\\' in value or not path.startswith('exploit_kits/') or not path.endswith('.yar') or path in paths):
                raise ClamShieldError('Web hosting index must name unique files in the exploit-kit tree')
            paths.append(path)
        if not 1<=len(paths)<=32:raise ClamShieldError('Web hosting index size changed; review the upstream selection')
        selected=sorted(paths)+list(EXTRA);parts=[]
        for path in selected:
            data=blob(path,1024**2)
            if b'\0' in data or re.search(rb'\bglobal\s+rule\b',data) or re.search(rb'^\s*include\b',data,re.M):
                raise ClamShieldError('Web hosting source context changed; review NUL bytes, global rules or filesystem includes')
            parts.append('// Original upstream file: '+path+'\n'+data.decode('utf8'))
        content='\n\n'.join(parts).encode()
        if len(content)>MAXIMUM:raise ClamShieldError('Expanded web hosting rules exceed their size limit')
        notice=blob('LICENSE',65536)
        if b'GNU GENERAL PUBLIC LICENSE' not in notice or b'Version 2' not in notice:raise ClamShieldError('Web hosting license changed; administrator review is required')
        metadata=dict(commit=commit,version=commit,repository='https://github.com/'+REPOSITORY,
            source_url='https://github.com/'+REPOSITORY+'/tree/'+commit,license=notice.decode('utf8'),
            license_url='https://github.com/'+REPOSITORY+'/blob/'+commit+'/LICENSE',license_sha256=hashlib.sha256(notice).hexdigest(),
            dependencies=list(receipts.values()),selection='Complete original exploit-kit index plus original generic phishing and JavaScript exploit/obfuscation files; rule conditions unchanged',
            review_only=True,scope='website')
        return content,metadata
    except (KeyError,TypeError,AttributeError) as exc:raise ClamShieldError('Invalid web hosting rule metadata') from exc
