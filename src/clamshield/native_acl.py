"""Render an owned native-config copy; never write vendor templates.

The native extension and IP-list matches become authenticated observations.
Recipient verification, relay/auth checks and every other native ACL stay as-is.
Installation/lifecycle must publish this only with the matching policy adapter.
"""
import re

# Managed by clamshield. The installer also publishes this exact stdlib-only
# module outside the application release, for native startup without its CLI.
if __package__:
    from .errors import Conflict,EngineError
else:
    class EngineError(Exception):pass
    class Conflict(EngineError):pass

MARKER='# Managed by clamshield: native recipient policy observations\n'
DNS_MESSAGE='Rejected because $sender_host_address'
MIME_MESSAGE='Blacklisted file extension detected'
LOCAL_MESSAGE='${if and{{>{$recipients_count}{0}}{forall{$recipients_list}{match_domain{${domain:$item}}{+local_domains}}}}{yes}{no}}'
ERROR_ZONE=r'^(?:(?:zen|sbl|xbl|pbl)\.spamhaus\.org|[a-z0-9-]+\.(?:zen|sbl|xbl|pbl)\.dq\.spamhaus\.net)(?:!=|$)'
# Equality matching is required: bit masks can also match non-loopback replies.
ERROR_CODES=tuple('127.255.255.'+str(n) for n in range(256))
ERROR_LISTS='${map{${filter{${readfile {/etc/exim4/dnsbl.conf}{:}}}{match{$item}{\\N'+ERROR_ZONE+'\\N}}}}{${sg{$item}{\\N!=.*\\N}{}}='+','.join(ERROR_CODES)+'}}'


def _section(text,name):
    matches=list(re.finditer(r'^'+re.escape(name)+r':[ \t]*\n',text,re.M))
    if len(matches)!=1:raise EngineError('Native ACL layout is unsupported: '+name)
    start=matches[0].end()
    after=re.search(r'^(?:[A-Za-z][A-Za-z0-9_]*:|begin[ \t]+[a-z]+)[ \t]*$',text[start:],re.M)
    return start,start+after.start() if after else len(text)


def _block(text,section,message):
    start,end=_section(text,section);body=text[start:end]
    pattern=r'^[ \t]+deny[ \t]+message[ \t]*=[ \t]*'+re.escape(message)+r'[^\n]*\n(?:[ \t]+[^\n]+\n)*'
    matches=list(re.finditer(pattern,body,re.M))
    if len(matches)!=1:raise EngineError('Native policy block is unsupported: '+section)
    value=matches[0];lines=value.group().splitlines()
    return start+value.start(),start+value.end(),lines


def render(source):
    if not isinstance(source,str) or len(source.encode())>8*1024**2 or '\0' in source or '\r' in source:
        raise EngineError('Native configuration text is invalid')
    if 'acl_m_clamshield_' in source or MARKER in source:raise Conflict('Native ACL observations are already present')
    for option,name in (('acl_smtp_mail','acl_check_mail'),('acl_smtp_rcpt','acl_check_rcpt'),('acl_smtp_mime','acl_check_mime')):
        values=re.findall(r'^'+option+r'[ \t]*=[ \t]*([^\n]+)',source,re.M)
        if len(values)!=1 or values[0].strip()!=name:raise EngineError('Native ACL binding is unsupported: '+option)
    ds,de,dns=_block(source,'acl_check_rcpt',DNS_MESSAGE)
    ms,me,mime=_block(source,'acl_check_mime',MIME_MESSAGE)
    if (len(dns)!=3 or not re.fullmatch(r'\s*hosts\s*=\s*!\+whitelist\s*',dns[1]) or
            not re.fullmatch(r'\s*dnslists\s*=\s*\$\{readfile\s*\{/etc/exim4/dnsbl\.conf\}\s*\{:\}\}\s*',dns[2])):
        raise EngineError('Native IP-list policy differs from the supported layout')
    if len(mime)!=2 or not re.fullmatch(r'\s*condition\s*=\s*\$\{if match .*',mime[1]):
        raise EngineError('Native extension policy differs from the supported layout')
    dns_text=('  warn    domains = +local_domains\n'
              '          log_message = ClamShield native IP-list policy observed\n'+dns[1]+'\n'+dns[2]+'\n'
              '          set acl_m_clamshield_dnsbl_zone = $dnslist_domain\n'
              '          set acl_m_clamshield_dnsbl_value = $dnslist_value\n\n'+dns[0]+'\n'
              '          domains = !+local_domains\n'+dns[1]+'\n'+dns[2]+'\n\n'
              # The ordinary native list condition treats temporary lookup
              # failure as a negative. Observe it only when no listing matched;
              # do not change any native IP filters or recipient decisions.
              '  warn    domains = +local_domains\n'+dns[1]+'\n'
              '          condition = ${if eq{$acl_m_clamshield_dnsbl_zone}{}{yes}{no}}\n'
              '          dnslists = +include_unknown : ${readfile {/etc/exim4/dnsbl.conf}{:}}\n'
              '          condition = ${if eq{$dnslist_value}{}{yes}{no}}\n'
              '          set acl_m_clamshield_dnsbl_zone = $dnslist_domain\n'
              '          set acl_m_clamshield_dnsbl_value = lookup-failed\n'
              '          log_message = ClamShield native IP-list lookup unavailable\n\n'
              # Native exclusions correctly prevent rejection, but hide these
              # positive operational replies from the ordinary match above.
              # Observe the same configured zones with an error-only condition;
              # never replace a genuine native listing already captured.
              '  warn    domains = +local_domains\n'+dns[1]+'\n'
              '          condition = ${if eq{$acl_m_clamshield_dnsbl_zone}{}{yes}{no}}\n'
              '          dnslists = '+ERROR_LISTS+'\n'
              '          set acl_m_clamshield_dnsbl_zone = $dnslist_domain\n'
              '          set acl_m_clamshield_dnsbl_value = $dnslist_value\n'
              '          log_message = ClamShield native IP-list provider access unavailable\n')
    mime_text=('  warn    condition = '+LOCAL_MESSAGE+'\n'+mime[1]+'\n          set acl_m_clamshield_mime_blocked = 1\n\n'+mime[0]+'\n'
               '          condition = '+LOCAL_MESSAGE.removesuffix('{yes}{no}}')+'{no}{yes}}\n'+mime[1]+'\n')
    result=source
    for start,end,replacement in sorted(((ds,de,dns_text),(ms,me,mime_text)),reverse=True):result=result[:start]+replacement+result[end:]
    at,_=_section(result,'acl_check_mail')
    reset=('  warn    set acl_m_clamshield_dnsbl_zone =\n'
           '          set acl_m_clamshield_dnsbl_value =\n'
           '          set acl_m_clamshield_mime_blocked = 0\n\n')
    return MARKER+result[:at]+reset+result[at:]


def fallback(source):
    """No policy adapter: preserve local delivery, explicitly incomplete.

    Keep native relay/recipient checks and remote policy unchanged. Do not load
    an unverified local_scan library or depend on the application/database.
    """
    include='.include_if_exists /run/clamshield-exim/hook.conf\n'
    if source.count(include)!=1 or source.splitlines().count('CLAMSHIELD_NATIVE_CONFIG_INCLUDED=1')!=1:
        raise EngineError('Native fallback has no unique owned integration marker')
    if re.search(r'^local_scan_path\s*=',source,re.M):
        raise Conflict('Native fallback cannot adopt a different local_scan binding')
    result=render(source.replace(include,''))
    bindings=re.findall(r'^acl_smtp_data\s*=\s*([^\n]+)',result,re.M)
    if bindings!=['acl_check_data']:raise EngineError('Native data ACL binding is unsupported')
    at,_=_section(result,'acl_check_data')
    return (result[:at]+'  warn    condition = '+LOCAL_MESSAGE+'\n'
            '          log_message = ClamShield native delivery fallback; check incomplete\n\n'+result[at:])


def standalone():
    """Fixed-path root bootstrap; never edit the native generated source."""
    import hashlib
    import os
    from pathlib import Path
    import stat
    import subprocess
    import tempfile
    if os.geteuid()!=0:raise EngineError('Native startup requires root')
    runtime=Path('/run/clamshield-exim');base=runtime/'native.conf';original=runtime/'native-source.conf'
    def trusted(path,directory=False):
        info=path.lstat()
        if (path.resolve()!=path or info.st_uid!=0 or info.st_mode&0o022 or
                (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)):
            raise EngineError('Untrusted native fallback path')
        return info
    trusted(runtime,True);initial=trusted(base)
    if initial.st_size>8*1024**2:raise EngineError('Native fallback source exceeds its limit')
    if original.exists() or original.is_symlink():
        raise Conflict('Native source receipt already exists; regenerate before preparing fallback')
    source=base.read_bytes()
    if len(source)>8*1024**2:raise EngineError('Native fallback source exceeds its limit')
    before=hashlib.sha256(source).digest();content=fallback(source.decode())
    with tempfile.TemporaryDirectory(prefix='.fallback-check-',dir=runtime) as folder:
        candidate=Path(folder)/'candidate.conf'
        fd=os.open(candidate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:output.write(content.encode());output.flush();os.fsync(output.fileno())
        subprocess.run(['/usr/sbin/exim4','-C',str(candidate),'-bV'],check=True,timeout=5,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        current=trusted(base)
        if ((initial.st_dev,initial.st_ino,initial.st_size,initial.st_mtime_ns)!=
                (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns) or
                hashlib.sha256(base.read_bytes()).digest()!=before):raise Conflict('Native fallback source changed')
        # Preserve the freshly generated native input for the full policy
        # renderer. Both publications stay inside the owned runtime directory.
        raw=Path(folder)/'native-source.conf'
        fd=os.open(raw,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'wb') as output:output.write(source);output.flush();os.fsync(output.fileno())
        os.link(raw,original,follow_symlinks=False);raw.unlink()
        candidate.chmod(0o644);os.replace(candidate,base)
        fd=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)


if __name__=='__main__':
    standalone()
