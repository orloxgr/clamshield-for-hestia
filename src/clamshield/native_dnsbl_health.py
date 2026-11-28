"""Passive native IP-list observations, separate from SpamAssassin DNS checks."""
import fcntl
import math
import os
import re
import time
import uuid

from .atomic import write_json
from .errors import EngineError
from .native_dnsbl_context import observe

ZONES={name+'.spamhaus.org':'Spamhaus '+name.upper() for name in ('zen','sbl','xbl','pbl')}
STATES={'blocked','failed','response-observed'}
GUIDANCE='https://www.spamhaus.org/returnc/pub/'


class NativeDnsblHealth:
    def __init__(self,settings,store=None):
        self.settings,self.store=settings,store
        self.path=settings.state/'native-dnsbl-observations.json'

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():return {}
        from .spamassassin import SpamAssassinControls
        SpamAssassinControls._trusted(self.path)
        if self.path.stat().st_size>32768:raise EngineError('Native DNSBL observation storage exceeds its limit')
        import json
        values=json.loads(self.path.read_text())
        if not isinstance(values,dict) or set(values)-set(ZONES):raise EngineError('Invalid native DNSBL observation storage')
        for row in values.values():
            if (not isinstance(row,dict) or set(row)!={'state','observed','episode'} or not isinstance(row['state'],str) or row['state'] not in STATES or
                    type(row['observed']) not in (int,float) or not math.isfinite(row['observed']) or row['observed']<0 or
                    not isinstance(row['episode'],str) or not re.fullmatch(r'[0-9a-f]{32}',row['episode'])):
                raise EngineError('Invalid native DNSBL observation')
        return values

    def observe(self,zone,value):
        native=observe(zone,value)
        if native is None or native['zone'] not in ZONES:return
        state='blocked' if native['error_codes'] else 'response-observed' if native['state']=='listed' else 'failed'
        self.settings.prepare();lock=self.settings.state/'native-dnsbl-observations.lock'
        fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            from .spamassassin import SpamAssassinControls
            SpamAssassinControls._trusted(lock)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return
            values=self.read();zone=native['zone'];prior=values.get(zone)
            episode=prior['episode'] if prior and prior['state']==state else uuid.uuid4().hex
            values[zone]=dict(state=state,observed=time.time(),episode=episode);write_json(self.path,values)
        finally:os.close(fd)

    def publish(self):
        # Notification SQL runs in maintenance, outside the SMTP request budget.
        if self.store is None:return
        for zone,row in self.read().items():
            if row['state'] in ('blocked','failed'):
                self.store.notify('@admin','','mail.dnsbl_unavailable',zone,
                    dict(message='Native IP-list access needs review. This operational failure contributes no spam points.',
                         zone=zone,state=row['state'],action='Review provider access, subscription and resolver settings.',help_url=GUIDANCE),
                    'native-dnsbl:'+row['episode'])

    def status(self):
        values=self.read()
        return [dict(zone=zone,label=label,state=values[zone]['state'] if zone in values else 'unknown',
                     observed=values[zone]['observed'] if zone in values else None,help_url=GUIDANCE)
                for zone,label in ZONES.items()]
