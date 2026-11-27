"""Native owner-scoped inherited mail policies and deterministic decisions.

SMTP transport activation and durable message custody are separate from policy
selection. Never expose evaluate/record as a browser-supplied verdict endpoint.
"""
from copy import deepcopy
import hashlib
import json
import math
import re
import time
import uuid

from .errors import AccessDenied, ClamShieldError, Conflict
from . import mail_inventory
from .store import encode

DEFAULTS = {'enabled': False, 'malware_action': 'reject', 'phishing_action': 'quarantine',
            'spam_action': 'junk', 'spam_high_action': 'reject', 'block_action': 'quarantine',
            'spam_threshold': 5.0, 'spam_high_threshold': 15.0, 'signature_spam_score': 5.0,
            'allow_senders': [], 'block_senders': [], 'exceptions': []}
PERMISSIONS = {'manage_policy': False, 'manage_exceptions': False, 'release': False, 'delete': False}
ACTIONS = {'deliver': 0, 'tag': 1, 'junk': 2, 'quarantine': 3, 'reject': 4, 'defer': 5}


def exception_id(entry):
    return hashlib.sha256(encode(entry).encode()).hexdigest()


def policy_revision(parent, overrides):
    return hashlib.sha256(encode([parent, overrides]).encode()).hexdigest()


def check_revision(expected, parent, overrides):
    if expected is not None and expected != policy_revision(parent, overrides):
        raise Conflict('Email policy changed. Reload it before saving your changes.')


def finite(value, low, high):
    if type(value) not in (float, int) or not low <= value <= high or not math.isfinite(value):
        raise ClamShieldError('Invalid mail score or expiry')
    return float(value)


def sender_pattern(value):
    if not isinstance(value, str) or len(value) > 320 or value.count('@') != 1:
        raise ClamShieldError('Use an envelope sender address or *@domain')
    local, domain = value.rsplit('@', 1)
    if not local or any(ord(c) < 33 or ord(c) == 127 for c in local) or any(c in local for c in '<>\\'):
        raise ClamShieldError('Invalid envelope sender pattern')
    return local.lower() + '@' + mail_inventory.domain_name(domain)


def validate(value):
    """Validate only explicit overrides, preserving mailbox inheritance."""
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ClamShieldError('Invalid mail policy')
    result = deepcopy(value)
    if 'enabled' in result and type(result['enabled']) is not bool:
        raise ClamShieldError('Invalid mail policy toggle')
    for key in ('malware_action', 'phishing_action', 'spam_action', 'spam_high_action', 'block_action'):
        if key not in result:
            continue
        allowed = {'reject', 'quarantine', 'tag'} if key == 'malware_action' else {'reject', 'quarantine', 'junk', 'tag'}
        if not isinstance(result[key], str) or result[key] not in allowed:
            raise ClamShieldError('Invalid mail handling action')
    for key in ('spam_threshold', 'spam_high_threshold', 'signature_spam_score'):
        if key in result:
            result[key] = finite(result[key], 0, 100)
    for key in ('allow_senders', 'block_senders'):
        if key in result:
            if not isinstance(result[key], list) or len(result[key]) > 500:
                raise ClamShieldError('Mail sender list exceeds 500 entries')
            result[key] = sorted({sender_pattern(item) for item in result[key]})
    if 'exceptions' in result:
        if not isinstance(result['exceptions'], list) or len(result['exceptions']) > 100:
            raise ClamShieldError('Mail exceptions exceed 100 entries')
        normalized = []
        for entry in result['exceptions']:
            if not isinstance(entry, dict) or set(entry) != {'engine', 'signature', 'sha256', 'expires', 'reason'}:
                raise ClamShieldError('Mail exception requires an engine, signature, SHA-256, expiry and reason')
            item = dict(entry)
            if item['engine'] not in ('clamav', 'yara') or not isinstance(item['signature'], str) or not 1 <= len(item['signature']) <= 512:
                raise ClamShieldError('Invalid mail exception signature')
            if any(ord(c) < 32 or ord(c) == 127 for c in item['signature']):
                raise ClamShieldError('Invalid mail exception signature')
            if not isinstance(item['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
                raise ClamShieldError('Mail exceptions require an exact content SHA-256')
            if not isinstance(item['reason'], str) or not item['reason'].strip() or len(item['reason']) > 1000:
                raise ClamShieldError('Mail exceptions require a reason')
            item['expires'] = finite(item['expires'], 1, 32503680000)
            normalized.append(item)
        result['exceptions'] = normalized
    return result


def effective(domain, mailbox=None):
    result = deepcopy(DEFAULTS) | domain | (mailbox or {})
    if result['spam_high_threshold'] < result['spam_threshold']:
        raise ClamShieldError('High spam threshold must be at least the spam threshold')
    return result


def matches_sender(patterns, sender):
    if not isinstance(sender, str) or sender.count('@') != 1:
        return False
    local, domain = sender.rsplit('@', 1)
    try:
        address = local.lower() + '@' + mail_inventory.domain_name(domain)
    except AccessDenied:
        return False
    return address in patterns or '*@' + address.rsplit('@', 1)[1] in patterns


def evaluate(policy, scan, *, sender, sha256, now=None):
    """Evaluate trusted scanner output; allow-sender entries affect spam only."""
    now = time.time() if now is None else now
    revision = hashlib.sha256(encode(policy).encode()).hexdigest()
    base = {'policy_revision': revision, 'scan_complete': False, 'detections': [], 'suppressed': []}
    def incomplete():
        return base | {'action': 'deliver', 'classification': 'incomplete', 'spam_score': None}
    if not policy['enabled']:
        return base | {'action': 'deliver', 'classification': 'unmanaged', 'spam_score': None}
    if not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise ClamShieldError('Mail decision requires an exact content hash')
    if (not isinstance(scan, dict) or not isinstance(scan.get('detections'), list) or len(scan['detections']) > 2000):
        return incomplete()
    complete = scan.get('complete') is True and not scan.get('errors')
    if not complete:
        base['scan_errors'] = [error for error in scan.get('errors', [])
                               if isinstance(error, str) and re.fullmatch(r'[A-Za-z]{1,64}', error)] if isinstance(scan.get('errors', []), list) else []
    for key, pattern in (('signature_generation', r'generation-[A-Za-z0-9_-]{1,100}'),
                         ('signature_content_sha256', r'[0-9a-f]{64}')):
        if key in scan:
            if not isinstance(scan[key], str) or not re.fullmatch(pattern, scan[key]):
                return incomplete()
            base[key] = scan[key]
    try:
        score_available = scan.get('spam_score') is not None
        spam_score = finite(scan.get('spam_score'), -1000, 1000000) if score_available else 0
        if not score_available and complete: return incomplete()
        if 'spam_threshold' in scan and score_available:
            threshold = finite(scan['spam_threshold'], -1000000, 1000000)
            symbols = scan.get('spam_symbols', [])
            if (not isinstance(symbols, list) or len(symbols) > 1000 or
                    any(not isinstance(s, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,128}', s) for s in symbols)):
                raise ClamShieldError('Invalid SpamAssassin symbols')
            base['spamassassin'] = dict(score=spam_score, required_score=threshold, symbols=symbols)
            if 'spamassassin_revision' in scan:
                if not isinstance(scan['spamassassin_revision'], str) or not re.fullmatch(r'[0-9a-f]{64}', scan['spamassassin_revision']):
                    raise ClamShieldError('Invalid SpamAssassin revision')
                base['spamassassin']['revision'] = scan['spamassassin_revision']
            if 'spam_report' in scan:
                from .spam_report import validate as validate_report
                try:
                    detail = validate_report(dict(scan['spam_report'], version=1, complete=1))
                    if detail['score'] != spam_score or detail['threshold'] != threshold or sorted(
                            rule['name'] for rule in detail['rules']) != sorted(symbols):
                        raise ValueError('Inconsistent SpamAssassin contribution report')
                except (ValueError, TypeError) as exc:
                    raise ClamShieldError('Invalid SpamAssassin contribution report') from exc
                base['spamassassin'].update({key: detail[key] for key in ('rules', 'engine_version', 'rules_version', 'reporter_sha256')})
                base['spamassassin']['dns_observations']=detail.get('dns_observations',[])
    except ClamShieldError:
        return incomplete()
    hits, suppressed, detail_bytes = [], [], 0
    for hit in scan['detections']:
        if (not isinstance(hit, dict) or hit.get('category') not in ('malware', 'phishing', 'spam') or
                hit.get('engine') not in ('clamav', 'yara') or not isinstance(hit.get('signature'), str) or
                not 1 <= len(hit['signature']) <= 512):
            return incomplete()
        snapshot = {key: hit[key] for key in ('engine', 'signature', 'category', 'provider', 'source_id', 'source_version', 'classification_basis', 'attribution', 'origins') if key in hit}
        from .signature_catalog import validate_origin
        try:
            validate_origin({key: value for key, value in snapshot.items() if key not in ('engine', 'signature')})
        except ClamShieldError:
            return incomplete()
        detail_bytes += len(encode(snapshot).encode())
        if detail_bytes > 1024 * 1024:
            return incomplete()
        if any(e['engine'] == hit['engine'] and e['signature'] == hit['signature'] and
               e['sha256'] == sha256 and e['expires'] > now for e in policy['exceptions']):
            suppressed.append(snapshot)
        else:
            hits.append(snapshot)
    choices = []
    if matches_sender(policy['block_senders'], sender):
        choices.append((policy['block_action'], 'blocked-sender'))
    for category in ('malware', 'phishing'):
        if any(h['category'] == category for h in hits):
            choices.append((policy[category + '_action'], category))
    spam_score += policy['signature_spam_score'] * sum(h['category'] == 'spam' for h in hits)
    spam_allowed = matches_sender(policy['allow_senders'], sender)
    if not spam_allowed:
        if spam_score >= policy['spam_high_threshold']:
            choices.append((policy['spam_high_action'], 'spam'))
        elif spam_score >= policy['spam_threshold']:
            choices.append((policy['spam_action'], 'spam'))
    default_class = ('excepted' if suppressed else 'allowlisted' if spam_allowed and spam_score >= policy['spam_threshold']
                     else 'below-threshold' if hits else 'clean')
    action, classification = max(choices, key=lambda item: ACTIONS[item[0]]) if choices else ('deliver', default_class)
    if not complete and not choices: classification = 'incomplete'
    return base | {'action': action, 'classification': classification, 'scan_complete': complete,
                   'detections': hits, 'suppressed': suppressed, 'spam_score': spam_score if score_available else None,
                   'spam_allowlisted': spam_allowed}


def transaction_plan(decisions):
    """One SMTP DATA reply, with no per-recipient custody on rejection/defer."""
    if not isinstance(decisions, list) or not 1 <= len(decisions) <= 1000:
        raise ClamShieldError('Invalid mail transaction decisions')
    if any(not isinstance(d, dict) or not isinstance(d.get('action'), str) or d['action'] not in ACTIONS for d in decisions):
        raise ClamShieldError('Invalid mail transaction action')
    actions = [d['action'] for d in decisions]
    if 'defer' in actions:
        return {'smtp': 'defer', 'custody': [], 'native': []}
    if 'reject' in actions:
        return {'smtp': 'reject', 'custody': [], 'native': []}
    custody = [i for i, action in enumerate(actions) if action in ('quarantine', 'junk', 'tag') or action=='deliver' and decisions[i].get('capture') is True]
    native = [i for i, action in enumerate(actions) if action == 'deliver' and i not in custody]
    return {'smtp': 'accept', 'custody': custody, 'native': native}


class MailPolicies:
    def __init__(self, store, hestia):
        self.store, self.hestia = store, hestia

    def targets(self, context, domain=None):
        rows = mail_inventory.domains(self.hestia, context['owner'], selected=domain)
        if any((row['owner'], row['identity']) != self.store.scope(context) for row in rows):
            raise AccessDenied('Mail inventory belongs to another account generation')
        if self.hestia.identity(context['owner']) != context['identity']:
            raise AccessDenied('Native mail account generation changed')
        return rows

    def target(self, context, domain, mailbox=''):
        domain = mail_inventory.domain_name(domain)
        if not isinstance(mailbox, str):
            raise AccessDenied('Invalid mailbox name')
        mailbox = mail_inventory.local_name(mailbox) if mailbox else ''
        row = next((r for r in self.targets(context, domain) if r['domain'] == domain), None)
        if row is None or row['suspended']:
            raise AccessDenied('Mail domain unavailable')
        if mailbox and not any(m['name'] == mailbox and not m['suspended'] for m in row['mailboxes']):
            raise AccessDenied('Mailbox unavailable')
        return row, mailbox

    def permissions(self, context, db=None):
        if db is None:
            with self.store.connection() as connection:return self.permissions(context,connection)
        global_row=db.execute("SELECT settings FROM mail_permissions WHERE owner='@server' AND identity=''").fetchone()
        row=db.execute('SELECT settings FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context)).fetchone()
        return dict(PERMISSIONS) | (json.loads(global_row['settings']) if global_row else {}) | (json.loads(row['settings']) if row else {})

    def server(self, context, db=None):
        if not context['admin']:raise AccessDenied('Administrator access required')
        if db is None:
            with self.store.connection() as connection:return self.server(context,connection)
        defaults=self.server_defaults(db)
        row=db.execute("SELECT settings FROM mail_permissions WHERE owner='@server' AND identity=''").fetchone()
        permissions=dict(PERMISSIONS) | (json.loads(row['settings']) if row else {})
        return dict(defaults=effective(defaults),permissions=permissions,
                    revision=policy_revision(defaults,permissions))

    def save_server(self, context, value, revision):
        live=self.hestia.authorize(context['actor'],context['actor'])
        if not live['admin'] or live['identity']!=context['identity']:raise AccessDenied('Administrator account changed')
        if not isinstance(value,dict) or set(value)!={'defaults','permissions'}:
            raise ClamShieldError('Choose server mail defaults and hosting-user permissions')
        defaults=validate(value['defaults']);permissions=value['permissions']
        if set(defaults)&{'enabled','exceptions'}:raise ClamShieldError('Server activation is managed by Enable mail protection')
        if not isinstance(permissions,dict) or set(permissions)!=set(PERMISSIONS) or any(type(v) is not bool for v in permissions.values()):
            raise ClamShieldError('Invalid mail permissions')
        with self.store.connection(True) as db:
            current=self.server(context,db)
            if revision!=current['revision']:raise Conflict('Server mail settings changed. Refresh before saving.')
            saved=self.server_defaults(db)|defaults;effective(saved)
            # Validate the complete hierarchy together. Old account generations
            # are excluded; they cannot block or inherit a new account's policy.
            rows=db.execute("SELECT * FROM mail_policies WHERE owner<>'@server'").fetchall()
            identities={}
            for row in rows:
                if row['owner'] not in identities:
                    try:identities[row['owner']]=self.hestia.identity(row['owner'])
                    except (AccessDenied,FileNotFoundError,KeyError):identities[row['owner']]=None
            domains={(r['owner'],r['identity'],r['domain']):validate(json.loads(r['settings'])) for r in rows if not r['mailbox']}
            for row in rows:
                if identities.get(row['owner'])!=row['identity']:continue
                parent=saved|domains.get((row['owner'],row['identity'],''),{})|domains.get((row['owner'],row['identity'],row['domain']),{})
                effective(parent,validate(json.loads(row['settings'])) if row['mailbox'] else {})
            db.execute("INSERT INTO mail_policies VALUES('@server','','','',?,?) ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET settings=excluded.settings,updated=excluded.updated",(encode(saved),time.time()))
            db.execute("INSERT INTO mail_permissions VALUES('@server','',?) ON CONFLICT(owner,identity) DO UPDATE SET settings=excluded.settings",(encode(permissions),))
            self.store.audit(dict(actor=live['actor'],owner='@admin',identity=''),'mail.server_settings_saved','server',value,db)
        return self.server(context)

    def account_defaults(self,context,db):
        return self.server_defaults(db)|self._saved(context,'','',db)

    def account_revision(self,context,db):
        grant=db.execute('SELECT settings FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context)).fetchone()
        return policy_revision([self.server_defaults(db),self._saved(context,'','',db)],
                               [self.permissions(context,db),json.loads(grant['settings']) if grant else None])

    def account(self,context):
        if not context['admin']:raise AccessDenied('Administrator access required')
        self.targets(context)
        with self.store.connection() as db:
            db.execute('BEGIN')
            defaults=self.account_defaults(context,db);permissions=self.permissions(context,db)
            grant=db.execute('SELECT 1 FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context)).fetchone()
            return dict(defaults=effective(defaults),permissions=permissions,
                        overrides=self._saved(context,'','',db),permissions_inherited=not bool(grant),
                        revision=self.account_revision(context,db))

    def save_account(self,context,value,revision,reset=False):
        if not context['admin']:raise AccessDenied('Administrator access required')
        self.targets(context)
        if not reset and (not isinstance(value,dict) or set(value)!={'defaults','permissions'}):
            raise ClamShieldError('Choose account mail defaults and permissions')
        defaults={} if reset else validate(value['defaults'])
        if set(defaults)&{'enabled','exceptions'}:raise ClamShieldError('Mail activation is managed by the server administrator')
        permissions=self.permissions(context) if reset else value['permissions']
        if permissions is not None and (not isinstance(permissions,dict) or set(permissions)!=set(PERMISSIONS) or any(type(v) is not bool for v in permissions.values())):
            raise ClamShieldError('Invalid mail permissions')
        with self.store.connection(True) as db:
            if revision!=self.account_revision(context,db):raise Conflict('Account mail defaults changed. Refresh before saving.')
            parent=self.server_defaults(db)|defaults;effective(parent)
            rows=db.execute('SELECT * FROM mail_policies WHERE owner=? AND identity=? AND domain<>\'\'',self.store.scope(context)).fetchall()
            domains={row['domain']:validate(json.loads(row['settings'])) for row in rows if not row['mailbox']}
            for row in rows:effective(parent|domains.get(row['domain'],{}),validate(json.loads(row['settings'])) if row['mailbox'] else {})
            if reset:
                db.execute("DELETE FROM mail_policies WHERE owner=? AND identity=? AND domain='' AND mailbox=''",self.store.scope(context))
                db.execute('DELETE FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context))
            else:
                db.execute('INSERT INTO mail_policies VALUES(?,?,?,?,?,?) ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET settings=excluded.settings,updated=excluded.updated',(*self.store.scope(context),'','',encode(defaults),time.time()))
                if permissions is None:db.execute('DELETE FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context))
                else:db.execute('INSERT INTO mail_permissions VALUES(?,?,?) ON CONFLICT(owner,identity) DO UPDATE SET settings=excluded.settings',(*self.store.scope(context),encode(permissions)))
            self.store.audit(context,'mail.account_defaults_reset' if reset else 'mail.account_defaults_saved',context['owner'],value,db)
        return self.account(context)

    def save_permissions(self, context, value, reset=False):
        if not context['admin']:
            raise AccessDenied('Administrator access required')
        if not reset and (not isinstance(value, dict) or set(value) != set(PERMISSIONS) or any(type(v) is not bool for v in value.values())):
            raise ClamShieldError('Invalid mail permissions')
        self.targets(context)
        with self.store.connection(True) as db:
            if reset:db.execute('DELETE FROM mail_permissions WHERE owner=? AND identity=?',self.store.scope(context))
            else:db.execute('INSERT INTO mail_permissions VALUES(?,?,?) ON CONFLICT(owner,identity) DO UPDATE SET settings=excluded.settings',
                            (*self.store.scope(context), encode(value)))
            self.store.audit(context, 'mail.permissions_saved', context['owner'], value, db)
        return self.permissions(context)

    def _saved(self, context, domain, mailbox, db):
        row = db.execute('SELECT settings FROM mail_policies WHERE owner=? AND identity=? AND domain=? AND mailbox=?',
                         (*self.store.scope(context), domain, mailbox)).fetchone()
        return validate(json.loads(row['settings'])) if row else {}

    def server_defaults(self, db=None):
        # Reserved scope cannot be a native account; tenant overrides retain
        # their own native generations and never inherit another tenant's data.
        if db is None:
            with self.store.connection() as connection:return self.server_defaults(connection)
        row=db.execute("SELECT settings FROM mail_policies WHERE owner='@server' AND identity='' AND domain='' AND mailbox=''").fetchone()
        return validate(json.loads(row['settings'])) if row else {}

    def enable_server_defaults(self, context):
        live=self.hestia.authorize(context['actor'],context['actor'])
        if not live['admin'] or live['identity']!=context['identity']:
            raise AccessDenied('Administrator account changed before enabling mail protection')
        with self.store.connection(True) as db:
            value=self.server_defaults(db)|{'enabled':True}
            db.execute("INSERT INTO mail_policies VALUES('@server','','','',?,?) ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET settings=excluded.settings,updated=excluded.updated",(encode(value),time.time()))
            self.store.audit(dict(actor=live['actor'],owner='@admin',identity=''),'mail.defaults_enabled','server',{},db)

    def get(self, context, domain, mailbox=''):
        target, mailbox = self.target(context, domain, mailbox)
        with self.store.connection() as db:
            db.execute('BEGIN')
            saved = self._saved(context, target['domain'], '', db)
            defaults = self.account_defaults(context,db)
            parent = defaults | saved
            overrides = self._saved(context, target['domain'], mailbox, db) if mailbox else saved
        resolved = effective(parent, overrides if mailbox else {})
        if 'enabled' in defaults:resolved['enabled']=defaults['enabled']
        return {'domain': target['domain'], 'mailbox': mailbox, 'overrides': overrides,
                'effective': resolved,
                'revision': policy_revision(parent, overrides),
                'exception_entries': [dict(id=exception_id(entry), **entry)
                                      for entry in resolved['exceptions']],
                'permissions': self.permissions(context),
                'native_antivirus': target['native_antivirus'], 'native_antispam': target['native_antispam'],
                'native_reject_spam': target['native_reject_spam']}

    def list(self, context):
        rows = self.targets(context)
        from .mail_service import transport_active
        with self.store.connection() as db:
            blocked=db.execute('''SELECT count(*) FROM mail_body_cleanup c WHERE c.status='blocked' AND
              ((c.kind='source' AND EXISTS(SELECT 1 FROM mail_recipients r WHERE r.transaction_id=c.subject AND r.owner=? AND r.identity=?))
              OR (c.kind='delivery' AND EXISTS(SELECT 1 FROM mail_delivery_attempts a JOIN mail_recipients r ON r.id=a.recipient_id WHERE a.id=c.subject AND r.owner=? AND r.identity=?)))''',
              (*self.store.scope(context),*self.store.scope(context))).fetchone()[0]
        return {'domains': rows, 'permissions': self.permissions(context),
                'transport_active': transport_active(), 'cleanup_blocked': blocked}

    def save(self, context, domain, mailbox, value, reset=False, revision=None):
        target, mailbox = self.target(context, domain, mailbox)
        value = {} if reset else validate(value)
        with self.store.connection(True) as db:
            permissions=self.permissions(context,db)
            if not context['admin'] and not permissions['manage_policy']:
                raise AccessDenied('Mail policy changes are disabled for this account')
            defaults = self.account_defaults(context,db)
            if not context['admin'] and 'enabled' in value:
                raise AccessDenied('Mail protection activation is managed by the server administrator')
            parent = defaults | self._saved(context, target['domain'], '', db)
            old = self._saved(context, target['domain'], mailbox, db)
            check_revision(revision, parent, old)
            # Legacy per-domain activation remains an administrator decision
            # until the server master switch is configured. Omitting the field
            # or resetting handling settings must not let a customer change it.
            legacy_activation=not context['admin'] and 'enabled' not in defaults and 'enabled' in old
            if legacy_activation:value['enabled']=old['enabled']
            proposed = effective(parent, value) if mailbox else effective(defaults | value)
            if not context['admin'] and not permissions['manage_exceptions'] and old.get('exceptions') != value.get('exceptions'):
                raise AccessDenied('Mail exception changes are disabled for this account')
            # A domain edit must not silently invalidate inherited mailbox limits.
            if not mailbox:
                for row in db.execute('SELECT settings FROM mail_policies WHERE owner=? AND identity=? AND domain=? AND mailbox<>\'\'',
                                      (*self.store.scope(context), target['domain'])):
                    effective(defaults | value, validate(json.loads(row['settings'])))
            if reset and not legacy_activation:
                db.execute('DELETE FROM mail_policies WHERE owner=? AND identity=? AND domain=? AND mailbox=?',
                           (*self.store.scope(context), target['domain'], mailbox))
            else:
                db.execute('INSERT INTO mail_policies VALUES(?,?,?,?,?,?) ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET settings=excluded.settings,updated=excluded.updated',
                           (*self.store.scope(context), target['domain'], mailbox, encode(value), time.time()))
            self.store.audit(context, 'mail.policy_reset' if reset else 'mail.policy_saved', target['domain'] + ('/' + mailbox if mailbox else ''),
                             {'overrides': value, 'effective_revision': hashlib.sha256(encode(proposed).encode()).hexdigest()}, db)
        return self.get(context, target['domain'], mailbox)

    def change_exception(self, context, domain, mailbox, operation, value=None, *, entry_id=None,
                         revision=None, source=None):
        """Merge one scoped exception atomically without granting policy editing."""
        target, mailbox = self.target(context, domain, mailbox)
        if operation not in ('add', 'remove', 'inherit'):
            raise ClamShieldError('Invalid mail exception operation')
        if operation == 'add':
            value = validate({'exceptions': [value]})['exceptions'][0]
            if value['expires'] <= time.time():
                raise ClamShieldError('Choose a future expiry for this exception')
        if operation == 'inherit' and not mailbox:
            raise ClamShieldError('Only a mailbox can inherit domain exceptions')
        with self.store.connection(True) as db:
            permissions = self.permissions(context,db)
            if not context['admin'] and not permissions['manage_exceptions']:
                raise AccessDenied('Mail exception changes are disabled for this account')
            parent = self.account_defaults(context,db) | self._saved(context, target['domain'], '', db)
            old = self._saved(context, target['domain'], mailbox, db)
            check_revision(revision, parent, old)
            proposed = deepcopy(old)
            entries = effective(parent, old if mailbox else {})['exceptions']
            if operation == 'inherit':
                proposed.pop('exceptions', None)
            elif operation == 'remove':
                if not isinstance(entry_id, str) or not any(exception_id(e) == entry_id for e in entries):
                    raise Conflict('This exception changed or is no longer present. Reload the policy.')
                proposed['exceptions'] = [e for e in entries if exception_id(e) != entry_id]
            else:
                key = lambda e: (e['engine'], e['signature'], e['sha256'])
                proposed['exceptions'] = [e for e in entries if key(e) != key(value)] + [value]
            proposed = validate(proposed)
            db.execute('''INSERT INTO mail_policies VALUES(?,?,?,?,?,?)
                ON CONFLICT(owner,identity,domain,mailbox) DO UPDATE SET settings=excluded.settings,updated=excluded.updated''',
                (*self.store.scope(context), target['domain'], mailbox, encode(proposed), time.time()))
            self.store.audit(context, 'mail.exception_'+operation,
                target['domain'] + ('/'+mailbox if mailbox else ''),
                dict(entry=value if operation == 'add' else entry_id,
                     source_delivery=source, inherited_snapshot=bool(mailbox and 'exceptions' not in old and operation != 'inherit')),
                db)
        return self.get(context, target['domain'], mailbox)

    def decisions(self, context, search='', offset=0):
        self.targets(context)
        if not isinstance(search, str) or len(search) > 300 or type(offset) is not int or not 0 <= offset <= 10000000:
            raise ClamShieldError('Invalid mail history search')
        from .review import visible
        query = ' FROM mail_decisions r WHERE owner=? AND identity=? AND (instr(sender,?)>0 OR instr(recipient,?)>0 OR instr(exim_id,?)>0) AND '+visible('email-decisions')
        args = (*self.store.scope(context), search, search, search)
        with self.store.connection() as db:
            total = db.execute('SELECT count(*)' + query, args).fetchone()[0]
            rows = db.execute('SELECT *' + query + ' ORDER BY created DESC,id LIMIT 100 OFFSET ?', (*args, offset)).fetchall()
        result, size = [], 0
        for row in rows:
            item = dict(row) | {'detail': json.loads(row['detail'])}
            amount = len(encode(item).encode())
            if size + amount > 3 * 1024 * 1024:
                if not result:
                    raise ClamShieldError('Mail decision exceeds the report size limit')
                break
            result.append(item); size += amount
        return {'total': total, 'decisions': result,
                'next_offset': offset + len(result) if offset + len(result) < total else None}

    def record(self, context, target, request, sha256, decision):
        """Internal service call, one scoped row per recipient; no shared headers."""
        if (target['owner'], target['identity']) != self.store.scope(context):
            raise AccessDenied('Mail decision belongs to another account generation')
        self.target(context, target['domain'], target['mailbox'])
        resolved = mail_inventory.resolve(self.targets(context), target['recipient'])
        if (not resolved or any(resolved[key] != target[key] for key in ('owner', 'identity', 'domain', 'mailbox')) or
                target['recipient'] not in request.recipients):
            raise AccessDenied('Mail decision does not match the native envelope recipient')
        if (not isinstance(decision.get('action'), str) or decision['action'] not in ACTIONS or
                not re.fullmatch(r'[0-9a-f]{64}', sha256) or len(encode(decision).encode()) > 2 * 1024 * 1024):
            raise ClamShieldError('Invalid internal mail decision')
        event = uuid.uuid4().hex
        with self.store.connection(True) as db:
            db.execute('INSERT INTO mail_decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (event, *self.store.scope(context), target['domain'], target['mailbox'], target['recipient'],
                        request.message_id, request.sender, time.time(), sha256, decision['action'], decision['classification'], encode(decision)))
            self.store.audit(context, 'mail.decision', event, {'action': decision['action'], 'classification': decision['classification'], 'exim_id': request.message_id}, db)
        return event

    def outcome(self,exim_id,outcome):
        """Internal native result, never a browser-supplied history mutation."""
        if outcome not in ('accepted','reject','defer'):raise ClamShieldError('Invalid native mail outcome')
        with self.store.connection(True) as db:
            for row in db.execute('SELECT * FROM mail_decisions WHERE exim_id=?',(exim_id,)).fetchall():
                detail=json.loads(row['detail']);planned=detail.get('policy_action',detail['action'])
                classification=detail.get('policy_classification',detail['classification'])
                detail.update(policy_action=planned,policy_classification=classification,smtp_outcome=outcome)
                action=planned if outcome=='accepted' else outcome
                if outcome!='accepted' and planned!=outcome:classification='transaction-rejected' if outcome=='reject' else 'transaction-deferred'
                db.execute('UPDATE mail_decisions SET action=?,classification=?,detail=? WHERE id=?',(action,classification,encode(detail),row['id']))
