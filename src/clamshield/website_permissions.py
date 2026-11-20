"""Native-generation website delegation, serialized with new user mutations."""
from contextlib import contextmanager
import fcntl
import json
import os
import stat
import time
import uuid

from .errors import AccessDenied,ClamShieldError
from .store import encode

DEFAULTS=dict(scan=True,schedule=True,quarantine=True,restore=True,repair=True,
              cleanup=True,exceptions=True,automatic=True)
LABELS=dict(scan='Run website and integrity scans',schedule='Change scan schedules and monitoring',
    quarantine='Quarantine detected website files',restore='Restore quarantined files and undo repairs',
    repair='Prepare and apply trusted or backup replacements',cleanup='Prepare and apply recognized infection cleaning',
    exceptions='Manage website detection exceptions',automatic='Change automatic website actions')
ACTIONS={'automatic-rechecks-resume':'schedule','scan':'scan','wordpress-scan':'scan','policy-save':'schedule','policy-reset':'schedule','policy-defaults-save':'schedule','policy-defaults-reset':'schedule','quarantine':'quarantine',
    'restore':'restore','repair-preview':'repair','repair-backup-preview':'repair','repair-hestia-preview':'repair',
    'cleanup-preview':'cleanup','repair-undo':'restore','exception-add':'exceptions','exception-remove':'exceptions',
    'remediation-policy-save':'automatic','repair-apply':None}
ACTIONS['wordpress-recovery-analyze']='scan'
MODE_REQUIREMENTS={'report':(), 'quarantine':('automatic','quarantine'),
    'cleanup':('automatic','cleanup'),'cleanup-or-quarantine':('automatic','cleanup','quarantine')}


class WebsitePermissions:
    def __init__(self,settings,store,hestia):self.settings,self.store,self.hestia=settings,store,hestia

    @contextmanager
    def locked(self,exclusive=False):
        self.settings.prepare()
        fd=os.open(self.settings.state/'website-permissions.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a+b') as lock:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise AccessDenied('Unsafe website permissions lock')
            fcntl.flock(lock,fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH);yield

    def native(self,context):
        live=self.hestia.authorize(context['actor'],context['owner'])
        if live['identity']!=context['identity']:raise AccessDenied('Website permission account was replaced')
        return live

    def snapshot(self,context,server=False):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM website_permissions WHERE owner=? AND identity=?',('@server','') if server else self.store.scope(context)).fetchone()
            if row is None and not server:row=db.execute("SELECT * FROM website_permissions WHERE owner='@server' AND identity=''").fetchone()
        if not row:return dict(permissions=dict(DEFAULTS),revision='default',updated=0)
        values=json.loads(row['settings'])
        if 'rule_trials' in values:
            if type(values['rule_trials']) is not bool:raise AccessDenied('Website permission data requires administrator review')
            values.pop('rule_trials')  # Read legacy permissions without the retired capability.
        if set(values)!=set(DEFAULTS) or any(type(v) is not bool for v in values.values()):raise AccessDenied('Website permission data requires administrator review')
        return dict(permissions=values,revision=row['revision'],updated=row['updated'])

    def get(self,context,server=False):
        live=self.native(context)
        if server and not live['admin']:raise AccessDenied('Administrator access required')
        result=self.snapshot(context,server)
        return result|dict(effective=dict(DEFAULTS) if live['admin'] else result['permissions'],labels=LABELS)

    def require(self,context,capability):
        live=self.native(context)
        if capability not in DEFAULTS:raise AccessDenied('Unknown website capability')
        if not live['admin'] and not self.snapshot(context)['permissions'][capability]:
            raise AccessDenied(LABELS[capability]+' is disabled by the administrator')
        return live

    def save(self,context,value,server=False,reset=False):
        if not reset and (not isinstance(value,dict) or set(value)!=set(DEFAULTS) or any(type(v) is not bool for v in value.values())):
            raise ClamShieldError('Choose a boolean value for every website permission')
        with self.locked(True):
            live=self.native(context)
            if not live['admin']:raise AccessDenied('Administrator access required')
            revision=uuid.uuid4().hex;updated=time.time();scope=('@server','') if server else self.store.scope(context)
            with self.store.connection(True) as db:
                if reset:db.execute('DELETE FROM website_permissions WHERE owner=? AND identity=?',scope)
                else:db.execute('INSERT INTO website_permissions VALUES(?,?,?,?,?) ON CONFLICT(owner,identity) DO UPDATE SET settings=excluded.settings,updated=excluded.updated,revision=excluded.revision',
                    (*scope,encode(value),updated,revision))
                self.store.audit(dict(live,owner='@admin',identity='') if server else live,'website.permissions_saved','server' if server else live['owner'],dict(permissions=value,revision=revision),db)
        return self.get(context,server)

    @contextmanager
    def guard(self,context,action,request):
        if action not in ACTIONS:yield;return
        with self.locked():
            capability=ACTIONS[action]
            if action=='repair-apply':
                from .repairs import Repairs
                plan=Repairs(self.settings,self.store,self.hestia).get(context,request.get('plan_id'))
                capability='cleanup' if plan['metadata'].get('source',{}).get('kind')=='targeted-cleanup' else 'repair'
            yield self.require(context,capability)
