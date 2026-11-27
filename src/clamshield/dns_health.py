"""Bounded provider observations from verified reports; no query labels or PII."""
import fcntl
import json
import math
import os
import re
import time

from .atomic import write_json
from .errors import EngineError

APACHE='https://cwiki.apache.org/confluence/display/SPAMASSASSIN/DnsBlocklists'
PROVIDERS={
    'sa-trusted.bondedsender.org':('Validity Certified','rbl','https://knowledge.validity.com/hc/en-us/articles/20961730681243'),
    'sa-accredit.habeas.com':('Validity Safe','rbl','https://knowledge.validity.com/hc/en-us/articles/20961730681243'),
    'bl.score.senderscore.com':('Validity RPBL','rbl','https://knowledge.validity.com/hc/en-us/articles/20961730681243'),
    'list.dnswl.org':('DNSWL','rbl',APACHE),
    'lookup.dkimwl.org':('DKIMWL','other',APACHE),
    'fresh.fmb.la':('FMBLA','other',APACHE),
    'multi.uribl.com':('URIBL','uribl',APACHE),
    'multi.surbl.org':('SURBL','uribl',APACHE),
    'zen.spamhaus.org':('Spamhaus ZEN','both','https://www.spamhaus.org/returnc/pub/'),
    'dbl.spamhaus.org':('Spamhaus DBL','uribl','https://www.spamhaus.org/returnc/pub/'),
}
STATES={'blocked','failed','response-observed'}


def validate(observations):
    if not isinstance(observations,list) or len(observations)>len(PROVIDERS):raise ValueError('Invalid DNS observations')
    seen=set()
    for row in observations:
        if (not isinstance(row,dict) or set(row)!={'zone','state'} or not isinstance(row['zone'],str) or
                row['zone'] not in PROVIDERS or row['zone'] in seen or not isinstance(row['state'],str) or row['state'] not in STATES):
            raise ValueError('Invalid DNS observation')
        seen.add(row['zone'])
    return observations


class DnsHealth:
    def __init__(self,settings):self.settings=settings;self.path=settings.state/'dns-observations.json'

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():return {}
        from .spamassassin import SpamAssassinControls
        SpamAssassinControls._trusted(self.path)
        if self.path.stat().st_size>32768:raise EngineError('DNS observation storage exceeds its limit')
        value=json.loads(self.path.read_text())
        if not isinstance(value,dict) or set(value)-set(PROVIDERS):raise EngineError('Invalid DNS observation storage')
        for zone,row in value.items():
            if (not isinstance(row,dict) or set(row)!={'state','observed','revision'} or not isinstance(row['state'],str) or row['state'] not in STATES or
                    type(row['observed']) not in (int,float) or not math.isfinite(row['observed']) or row['observed']<0 or
                    not isinstance(row['revision'],str) or len(row['revision'])!=64 or any(c not in '0123456789abcdef' for c in row['revision'])):
                raise EngineError('Invalid DNS observation record')
        return value

    def observe(self,report):
        observations=validate(report.get('dns_observations',[]))
        if not observations:return
        if not isinstance(report.get('revision'),str) or not re.fullmatch(r'[0-9a-f]{64}',report['revision']):
            raise ValueError('Invalid DNS observation revision')
        self.settings.prepare();path=self.settings.state/'dns-observations.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            from .spamassassin import SpamAssassinControls
            SpamAssassinControls._trusted(path);fcntl.flock(fd,fcntl.LOCK_EX)
            values=self.read();now=time.time()
            for row in observations:values[row['zone']]=dict(state=row['state'],observed=now,revision=report['revision'])
            write_json(self.path,values)
        finally:os.close(fd)

    def status(self,policy,local_mode):
        values=self.read();rows=[]
        for zone,(label,kind,url) in PROVIDERS.items():
            latest=values.get(zone)
            blocked=any(zone==value or zone.endswith('.'+value) for value in policy['blocked_zones'])
            enabled=kind=='other' or any(policy[key+'_enabled'] for key in (('rbl','uribl') if kind=='both' else (kind,)))
            disabled=local_mode is True or blocked or not enabled
            rows.append(dict(zone=zone,label=label,state='disabled' if disabled else latest['state'] if latest else 'unknown',
                             observation=latest,help_url=url,action='Review provider access, subscription and resolver settings; disable only this zone if it cannot be used.'))
        return rows
