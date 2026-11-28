"""Personal notification selection and opt-in native Hestia Bell delivery."""
import fcntl
import html
import json
import os
import re
import stat
import time
import uuid
from urllib.parse import urlencode

from .errors import AccessDenied, ClamShieldError, Conflict

CATEGORIES = {
    'detections': 'Website malware detections',
    'integrity': 'WordPress integrity differences',
    'scan_problems': 'Failed, incomplete or interrupted scans',
    'health': 'Engine and scanning-data health',
    'maintenance': 'Updates and maintenance',
    'mail': 'Email protection alerts',
    'actions': 'Quarantine, cleaning and repairs',
    'other': 'Other notifications',
}


def category(event):
    if event in ('scan.malware_found', 'scan.repeated_detection'): return 'detections'
    if event == 'wordpress.integrity_issues': return 'integrity'
    if event.startswith('scan.'): return 'scan_problems'
    if event.startswith('health.'): return 'health'
    if event.startswith(('maintenance.', 'installation.')): return 'maintenance'
    if event.startswith('mail.'): return 'mail'
    if event.startswith(('automatic.', 'repair.', 'cleanup.', 'quarantine.')): return 'actions'
    return 'other'


class NotificationPreferences:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia

    def personal(self, context):
        # Viewing an account as administrator must not edit that customer's choices.
        return self.hestia.authorize(context['actor'], context['actor'])

    def get(self, context):
        live = self.personal(context)
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM notification_preferences WHERE actor=? AND identity=?',
                             (live['actor'], live['identity'])).fetchone()
        settings = dict(bell=False, categories=list(CATEGORIES), bell_categories=list(CATEGORIES), revision='default', last_sent=None, error=None)
        if row:
            settings.update(bell=bool(row['bell']), categories=[key for key in json.loads(row['categories']) if key in CATEGORIES],
                            bell_categories=[key for key in self.bell_categories(dict(row)) if key in CATEGORIES],
                            revision=row['revision'], last_sent=row['last_sent'])
        settings['error'] = self.delivery_error(live)
        from .notification_clear import BellClear
        cleanup_error=BellClear(self.settings,self.store,self.hestia).error(live)
        if cleanup_error:settings['error']=cleanup_error
        return dict(settings=settings, categories=CATEGORIES, account=live['actor'], server=live['admin'])

    def delivery_error(self, context):
        with self.store.connection() as db:
            row = db.execute("""SELECT d.error FROM notification_bell_deliveries d
              JOIN notifications n ON n.id=d.notification_id
              WHERE d.actor=? AND d.identity=? AND d.status='error'
              AND NOT EXISTS(SELECT 1 FROM review_deleted r WHERE r.kind='notices'
                AND r.record_id=n.id AND r.owner=n.owner AND r.identity=n.identity)
              ORDER BY d.attempted DESC LIMIT 1""",
              (context['actor'], context['identity'])).fetchone()
        if not row: return None
        error = row['error'] or 'HestiaCP notification delivery failed. No automatic retry.'
        if error.startswith('Bell delivery could not be confirmed.'):
            return 'HestiaCP notification delivery failed; the previous attempt did not record its cause. No automatic retry.'
        return error

    def save(self, context, policy, revision):
        if (not isinstance(policy, dict) or set(policy) not in ({'bell', 'categories'},{'bell','categories','bell_categories'}) or
            type(policy['bell']) is not bool or not isinstance(policy['categories'], list) or
            any(not isinstance(v, str) or v not in CATEGORIES for v in policy['categories']) or
            len(set(policy['categories'])) != len(policy['categories'])):
            raise ClamShieldError('Choose valid notification types and a Bell preference')
        bell_categories=policy.get('bell_categories',policy['categories'])
        if (not isinstance(bell_categories,list) or any(not isinstance(v,str) or v not in CATEGORIES for v in bell_categories)
                or len(set(bell_categories))!=len(bell_categories)):
            raise ClamShieldError('Choose valid HestiaCP notification types')
        live = self.personal(context)
        selected = [key for key in CATEGORIES if key in policy['categories']]
        bell_selected = [key for key in CATEGORIES if key in bell_categories]
        with self.store.connection(True) as db:
            row = db.execute('SELECT * FROM notification_preferences WHERE actor=? AND identity=?',
                             (live['actor'], live['identity'])).fetchone()
            if revision != (row['revision'] if row else 'default'):
                raise Conflict('Notification preferences changed. Refresh preferences and try again.')
            confirmed = self.personal(context)
            if confirmed['identity'] != live['identity']: raise AccessDenied('Hosting account changed')
            changed = not row or bool(row['bell']) != policy['bell'] or self.bell_categories(dict(row)) != bell_selected
            start = time.time() if changed else row['starts_after']
            db.execute('''INSERT INTO notification_preferences(actor,identity,bell,categories,starts_after,revision,updated,bell_categories)
              VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(actor,identity) DO UPDATE SET bell=excluded.bell,
              categories=excluded.categories,starts_after=excluded.starts_after,revision=excluded.revision,
              updated=excluded.updated,bell_categories=excluded.bell_categories,error=NULL''',
              (live['actor'], live['identity'], int(policy['bell']), json.dumps(selected), start, uuid.uuid4().hex, time.time(),json.dumps(bell_selected)))
        return self.get(context)

    @staticmethod
    def bell_categories(pref):
        return json.loads(pref.get('bell_categories') or pref['categories'])

    def authorized(self, pref, notification):
        live = self.hestia.authorize(pref['actor'], pref['actor'])
        if live['identity'] != pref['identity']: raise AccessDenied('Notification subscriber changed')
        if notification['owner'] == '@admin':
            return live['admin'] and notification['identity'] == ''
        if not live['admin'] and notification['owner'] != live['owner']: return False
        source = self.hestia.authorize(live['actor'], notification['owner'])
        return source['identity'] == notification['identity']

    @staticmethod
    def content(notification):
        title = 'ClamShield: ' + CATEGORIES[category(notification['event'])]
        # Older Hestia versions render notice HTML directly. Generate our own
        # markup and entity-encode every nontrivial untrusted character.
        def safe(value):
            return ''.join(c if re.fullmatch(r'[A-Za-z0-9 ._/@:,+-]', c) else '&#'+str(ord(c))+';' for c in str(value))
        owner = notification['owner']
        body = 'Account: ' + safe('Server' if owner == '@admin' else owner) + '<br>'
        body += safe(notification['subject'])[:1500] + '<br>'
        body += safe(notification['event'].replace('.', ': ').replace('_', ' ')) + '<br>'
        detail = json.loads(notification['detail'])
        for key in ('path', 'signature'):
            if isinstance(detail.get(key), str): body += safe(key.capitalize()+': '+detail[key])[:1000] + '<br>'
        counters = detail.get('counters', {})
        for key, label in (('infected', 'Files with detections'), ('detections', 'Detections')):
            if isinstance(counters.get(key), (int, float)): body += label+': '+str(counters[key])+'<br>'
        query = {'notice': notification['id']}
        if owner != '@admin': query['owner'] = owner
        link = '/plugins/clamshield/?'+urlencode(query)+'#review/notices'
        body += '<a href="'+html.escape(link, quote=True)+'">Open ClamShield</a>'
        return title, body

    def receipt(self, pref, notice, status, *, native_id=None, error=None):
        with self.store.connection(True) as db:
            db.execute('''INSERT INTO notification_bell_deliveries VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(actor,identity,notification_id) DO UPDATE SET status=excluded.status,
              attempted=excluded.attempted,native_id=excluded.native_id,error=excluded.error''',
              (pref['actor'], pref['identity'], notice['id'], status, time.time(), native_id, error))
            if status == 'sent':
                db.execute('UPDATE notification_preferences SET last_sent=?,error=NULL WHERE actor=? AND identity=? AND revision=?',
                           (time.time(), pref['actor'], pref['identity'], pref['revision']))
            elif error:
                db.execute('UPDATE notification_preferences SET error=? WHERE actor=? AND identity=? AND revision=?',
                           (error, pref['actor'], pref['identity'], pref['revision']))

    def once(self):
        self.settings.prepare()
        fd = os.open(self.settings.state/'notification-bell.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise AccessDenied('Notification delivery lock is not private')
            try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: return {'bell_busy': True}
            result=self.deliver()
            from .notification_clear import BellClear
            return result | BellClear(self.settings,self.store,self.hestia).once()
        finally: os.close(fd)

    def deliver(self):
        result = dict(bell_sent=0, bell_skipped=0, bell_failed=0)
        with self.store.connection(True) as db:
            # The caller holds the delivery lock. A prior interrupted attempt
            # is terminal; do not inspect or resend it on the next timer tick.
            db.execute("UPDATE notification_bell_deliveries SET status='error',error=? WHERE status='sending'",
                       ('HestiaCP notification delivery was interrupted; check the native notification state. No automatic retry.',))
            prefs = [dict(row) for row in db.execute('SELECT * FROM notification_preferences WHERE bell=1 ORDER BY last_checked LIMIT 100')]
        budget = 25
        for pref in prefs:
            if budget <= 0: break
            with self.store.connection() as db:
                db.execute('UPDATE notification_preferences SET last_checked=? WHERE actor=? AND identity=?',
                           (time.time(),pref['actor'],pref['identity']))
            try:
                live = self.hestia.authorize(pref['actor'], pref['actor'])
                if live['identity'] != pref['identity']: continue
            except ClamShieldError: continue
            with self.store.connection() as db:
                scope = '' if live['admin'] else ' AND n.owner=? AND n.identity=?'
                args = (pref['actor'], pref['identity'], pref['starts_after'])
                if not live['admin']: args += (live['owner'], live['identity'])
                rows = [dict(row) for row in db.execute('''SELECT n.* FROM notifications n
                  LEFT JOIN notification_bell_deliveries d ON d.notification_id=n.id AND d.actor=? AND d.identity=?
                  WHERE n.created>? AND d.status IS NULL'''
                  +scope+' ORDER BY n.created,n.id LIMIT ?', (*args, budget))]
            for notice in rows:
                budget -= 1
                with self.store.connection() as db:
                    current = db.execute('SELECT * FROM notification_preferences WHERE actor=? AND identity=?',
                                         (pref['actor'], pref['identity'])).fetchone()
                    fresh = db.execute('SELECT read_at FROM notifications WHERE id=?', (notice['id'],)).fetchone()
                if not current or not current['bell'] or current['revision'] != pref['revision']: break
                if not fresh or fresh['read_at'] is not None or category(notice['event']) not in self.bell_categories(pref):
                    self.receipt(pref, notice, 'skipped'); result['bell_skipped'] += 1; continue
                try:
                    if not self.authorized(pref, notice):
                        self.receipt(pref, notice, 'skipped'); result['bell_skipped'] += 1; continue
                    # Persist the one allowed attempt before any native call.
                    self.receipt(pref, notice, 'sending')
                    # Recognize an already existing owned copy without adding a duplicate.
                    native = self.hestia.call('v-list-user-notifications', pref['actor'], 'json')
                    if any(not isinstance(value,dict) or not isinstance(value.get('TOPIC'),str) or
                           not isinstance(value.get('NOTICE'),str) for value in native.values()):
                        raise ClamShieldError('Native Bell list could not be verified')
                    marker = 'notice='+notice['id']
                    found = next((str(key) for key, value in native.items()
                                  if value.get('TOPIC', '').startswith('ClamShield: ') and marker in value.get('NOTICE', '')), None)
                    if found is None:
                        if not self.authorized(pref, notice): raise AccessDenied('Notification source changed')
                        with self.store.connection() as db:
                            final = db.execute('SELECT bell,revision FROM notification_preferences WHERE actor=? AND identity=?',
                                               (pref['actor'],pref['identity'])).fetchone()
                        if not final or not final['bell'] or final['revision'] != pref['revision']:
                            self.receipt(pref, notice, 'skipped'); break
                        topic, body = self.content(notice)
                        self.hestia.add_notification(pref['actor'], topic, body)
                        found = 'submitted'
                    self.receipt(pref, notice, 'sent', native_id=found); result['bell_sent'] += 1
                except (ClamShieldError, OSError, ValueError, TypeError, KeyError) as exc:
                    reason = str(exc) if isinstance(exc, ClamShieldError) else type(exc).__name__
                    message = 'HestiaCP notification delivery failed: '+reason+'. No automatic retry.'
                    self.receipt(pref, notice, 'error', error=message); result['bell_failed'] += 1
        return result
