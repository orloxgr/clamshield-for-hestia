"""Interpret authenticated Exim DNSBL variables without retaining query keys.

This is a separate native reputation observation, never SpamAssassin points.
Unknown providers/return codes are diagnostic uncertainty, not inferred spam.
"""
import ipaddress
import re

IP_CODES={
    'zen':{2,3,4,9,10,11,30},'sbl':{2,3,9,30},'xbl':{4},
    'pbl':{10,11},'sbl-xbl':{2,3,4,9,30},'authbl':{20},
}
PUBLIC={name+'.spamhaus.org':{'127.0.0.'+str(code) for code in codes} for name,codes in IP_CODES.items()}
PUBLIC['bl.spamcop.net']={'127.0.0.2'}
DOMAIN_ZONES={'dbl','zrd','hbl'}


def observe(zone,value):
    if zone==value=='':return None
    result=dict(source='native-exim-acl',zone='other-native-dnsbl',access='unknown',state='invalid',
                return_codes=[],listing_codes=[],error_codes=[],unrecognized_codes=[],score_contribution=0)
    if not isinstance(zone,str) or not isinstance(value,str) or len(zone)>256 or len(value)>2048:return result
    zone=zone.lower().removesuffix('.')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',zone):return result
    if any(not part or len(part)>63 for part in zone.split('.')):return result
    if zone in PUBLIC or zone in {name+'.spamhaus.org' for name in DOMAIN_ZONES}:
        result.update(zone=zone,access='public')
    else:
        match=re.fullmatch(r'[a-z0-9-]+\.(zen|sbl|xbl|pbl|sbl-xbl|authbl|dbl|zrd|hbl)\.dq\.spamhaus\.net',zone)
        if match:result.update(zone=match[1]+'.spamhaus.org',access='dqs')
    parts=[part.strip() for part in value.split(',')]
    if not 1<=len(parts)<=128:return result
    try:
        codes=sorted({str(ipaddress.IPv4Address(part)) for part in parts})
        if any(not ipaddress.IPv4Address(code).is_loopback for code in codes):return result
    except ipaddress.AddressValueError:return result
    result['return_codes']=codes
    spamhaus=result['zone'].endswith('.spamhaus.org')
    errors=[code for code in codes if spamhaus and (code.startswith('127.255.255.') or code in {'127.0.1.255','127.0.2.255','127.0.3.255'})]
    listings=[code for code in codes if code in PUBLIC.get(result['zone'],set())]
    unknown=[code for code in codes if code not in errors and code not in listings]
    result.update(listing_codes=listings,error_codes=errors,unrecognized_codes=unknown,
                  state='listed' if listings else 'unsupported' if unknown else 'blocked')
    return result


def verified_listing(value):
    """Recheck a persisted canonical observation before partial-scan custody."""
    if (not isinstance(value,dict) or value.get('access') not in ('public','dqs') or
            not isinstance(value.get('return_codes'),list) or not 1<=len(value['return_codes'])<=128 or
            any(not isinstance(code,str) or len(code)>15 for code in value['return_codes'])):return False
    expected=observe(value.get('zone'),','.join(value['return_codes']))
    if not expected or not expected['listing_codes']:return False
    expected['access']=value['access']
    return value==expected


def verified_policy_match(value):
    """An authenticated native ACL match, without guessing a spam verdict.

    Unmanaged recipients retain a configured native list's positive condition,
    including custom lists. Known operational replies alone never authorize it.
    """
    if (not isinstance(value,dict) or value.get('access') not in ('public','dqs','unknown') or
            value.get('state') not in ('listed','unsupported') or not value.get('return_codes') or
            value.get('error_codes') and not value.get('listing_codes')):return False
    codes=value['return_codes']
    if not isinstance(codes,list) or len(codes)>128 or any(not isinstance(c,str) or len(c)>15 for c in codes):return False
    expected=observe(value.get('zone'),','.join(codes))
    if expected is None:return False
    if value['access']!=expected['access'] and not (value['access']=='dqs' and expected['access']=='public'):return False
    expected['access']=value['access']
    return expected==value
