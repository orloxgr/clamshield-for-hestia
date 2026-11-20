"""Durable personal Bell cleanup after confirmed Review clearing."""
import time

from .errors import ClamShieldError
from .hestia import same_notification
from .notification_preferences import NotificationPreferences


class BellClear:
    def __init__(self,settings,store,hestia):
        self.settings,self.store,self.hestia=settings,store,hestia

    @staticmethod
    def enqueue(db,context,notices):
        count=0
        for row in notices:
            notice=dict(row);topic,body=NotificationPreferences.content(notice)
            count+=db.execute('''INSERT OR IGNORE INTO notification_bell_clears
              (actor,identity,notification_id,topic,notice,created) VALUES(?,?,?,?,?,?)''',
              (context['actor'],context['identity'],notice['id'],topic,body,time.time())).rowcount
        return count

    def error(self,context):
        with self.store.connection() as db:
            row=db.execute("""SELECT error FROM notification_bell_clears
              WHERE actor=? AND identity=? AND status='error' ORDER BY attempted DESC LIMIT 1""",
              (context['actor'],context['identity'])).fetchone()
        return row['error'] if row else None

    def once(self):
        # Caller holds the native delivery lock. Interrupted attempts are final.
        with self.store.connection(True) as db:
            db.execute("""UPDATE notification_bell_clears SET status='error',error=?
              WHERE status='processing'""",('HestiaCP notification deletion was interrupted; check the native notification state. No automatic retry.',))
            rows=[dict(r) for r in db.execute("""SELECT * FROM notification_bell_clears
              WHERE status='pending' ORDER BY created LIMIT 25""")]
        result=dict(bell_cleared=0,bell_clear_failed=0);native={}
        for row in rows:
            with self.store.connection(True) as db:
                claimed=db.execute("""UPDATE notification_bell_clears SET status='processing',attempted=?
                  WHERE actor=? AND identity=? AND notification_id=? AND status='pending'""",
                  (time.time(),row['actor'],row['identity'],row['notification_id'])).rowcount
            if not claimed:continue
            status,error='cleared',None
            try:
                live=self.hestia.authorize(row['actor'],row['actor'])
                if live['identity']!=row['identity']:
                    status='skipped'
                else:
                    key=(row['actor'],row['identity'])
                    if key not in native:
                        native[key]=self.hestia.call('v-list-user-notifications',row['actor'],'json')
                        if any(not isinstance(value,dict) or not isinstance(value.get('TOPIC'),str) or
                               not isinstance(value.get('NOTICE'),str) for value in native[key].values()):
                            native.pop(key,None)
                            raise ClamShieldError('Native Bell list could not be verified')
                    matches=[str(nid) for nid,value in native[key].items() if same_notification(value,row['topic'],row['notice'])]
                    for nid in matches:
                        current=self.hestia.authorize(row['actor'],row['actor'])
                        if current['identity']!=row['identity']:raise ClamShieldError('Bell recipient account changed')
                        self.hestia.delete_notification(row['actor'],nid,row['topic'],row['notice'])
                        native[key].pop(nid,None)
                    result['bell_cleared']+=1
            except (ClamShieldError,OSError,ValueError,TypeError,KeyError) as exc:
                status='error';error='HestiaCP notification deletion failed: '+str(exc)+'. No automatic retry.'
                result['bell_clear_failed']+=1
            with self.store.connection(True) as db:
                db.execute('''UPDATE notification_bell_clears SET status=?,attempted=?,error=?
                  WHERE actor=? AND identity=? AND notification_id=?''',
                  (status,time.time(),error,row['actor'],row['identity'],row['notification_id']))
        return result
