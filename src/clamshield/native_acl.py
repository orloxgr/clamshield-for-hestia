"""Render an owned native-config copy; never write vendor templates.

The native extension and IP-list matches become authenticated observations.
Recipient verification, relay/auth checks and every other native ACL stay as-is.
Installation/lifecycle must publish this only with the matching policy adapter.
"""
import re

from .errors import Conflict,EngineError

MARKER='# Managed by clamshield: native recipient policy observations\n'
DNS_MESSAGE='Rejected because $sender_host_address'
MIME_MESSAGE='Blacklisted file extension detected'
LOCAL_MESSAGE='${if and{{>{$recipients_count}{0}}{forall{$recipients_list}{match_domain{${domain:$item}}{+local_domains}}}}{yes}{no}}'


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
              '          domains = !+local_domains\n'+dns[1]+'\n'+dns[2]+'\n')
    mime_text=('  warn    condition = '+LOCAL_MESSAGE+'\n'+mime[1]+'\n          set acl_m_clamshield_mime_blocked = 1\n\n'+mime[0]+'\n'
               '          condition = '+LOCAL_MESSAGE.removesuffix('{yes}{no}}')+'{no}{yes}}\n'+mime[1]+'\n')
    result=source
    for start,end,replacement in sorted(((ds,de,dns_text),(ms,me,mime_text)),reverse=True):result=result[:start]+replacement+result[end:]
    at,_=_section(result,'acl_check_mail')
    reset=('  warn    set acl_m_clamshield_dnsbl_zone =\n'
           '          set acl_m_clamshield_dnsbl_value =\n'
           '          set acl_m_clamshield_mime_blocked = 0\n\n')
    return MARKER+result[:at]+reset+result[at:]
