import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError, Conflict
from clamshield.hestia import Hestia
from clamshield.notification_preferences import CATEGORIES, NotificationPreferences, category
from clamshield.settings import Settings
from clamshield.store import Store


class PersonalBell(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.settings=Settings(state=Path(self.temp.name)/'state');self.settings.prepare()
        self.store=Store(self.settings.database)
        self.accounts={name:dict(actor=name,owner=name,identity=name+'-generation',admin=name=='admin') for name in ('alice','bob','admin')}
        self.hestia=Mock();self.hestia.authorize.side_effect=self.authorize
        self.native={name:{} for name in self.accounts};self.sent=[]
        self.hestia.call.side_effect=lambda command,owner,format:dict(self.native[owner])
        self.hestia.add_notification.side_effect=self.append
        self.preferences=NotificationPreferences(self.settings,self.store,self.hestia)

    def authorize(self,actor,owner=None):
        owner=owner or actor
        if actor not in self.accounts or owner not in self.accounts or (actor!=owner and actor!='admin'):raise AccessDenied('Unavailable')
        return dict(self.accounts[owner],actor=actor,admin=self.accounts[actor]['admin'])

    def append(self,owner,topic,notice):
        self.sent.append((owner,topic,notice));self.native[owner][str(len(self.sent))]={'TOPIC':topic,'NOTICE':notice}

    def save(self,actor='alice',bell=True,categories=None):
        context=self.accounts[actor];current=self.preferences.get(context)
        return self.preferences.save(context,dict(bell=bell,categories=list(CATEGORIES) if categories is None else categories),current['settings']['revision'])

    def notify(self,owner='alice',event='scan.malware_found',identity=None):
        identity=identity if identity is not None else ('' if owner=='@admin' else self.accounts[owner]['identity'])
        self.store.notify(owner,identity,event,owner+'.test',{'counters':{'infected':1,'detections':2}})

    def retry_now(self):
        with self.store.connection() as db:db.execute('UPDATE notification_bell_deliveries SET attempted=0')

    def test_default_off_and_personal_preferences_do_not_follow_selected_customer(self):
        selected=self.authorize('admin','bob')
        before=self.preferences.get(selected)
        self.assertEqual('admin',before['account']);self.assertFalse(before['settings']['bell'])
        self.preferences.save(selected,{'bell':True,'categories':['detections']},'default')
        self.assertTrue(self.preferences.get(self.accounts['admin'])['settings']['bell'])
        self.assertFalse(self.preferences.get(self.accounts['bob'])['settings']['bell'])
        self.hestia.authorize.assert_any_call('admin','admin')

    def test_validation_revisions_and_account_recreation(self):
        for policy in ({'bell':'yes','categories':[]},{'bell':True,'categories':['unknown']},{'bell':True,'categories':['mail','mail']},{'bell':True,'categories':[],'owner':'bob'}):
            with self.subTest(policy=policy),self.assertRaises(ClamShieldError):self.preferences.save(self.accounts['alice'],policy,'default')
        self.save(categories=[])
        with self.assertRaises(Conflict):self.preferences.save(self.accounts['alice'],{'bell':False,'categories':[]},'default')
        self.accounts['alice']['identity']='replacement'
        current=self.preferences.get(self.accounts['alice'])
        self.assertFalse(current['settings']['bell']);self.assertEqual('default',current['settings']['revision'])
        self.notify();self.preferences.once();self.assertEqual([],self.sent)

    def test_only_new_selected_unread_events_are_delivered_once(self):
        self.notify();self.save(categories=['detections'])
        self.notify(event='scan.partial');self.notify(owner='bob');self.notify();self.notify(event='scan.repeated_detection')
        result=self.preferences.once()
        self.assertEqual(2,result['bell_sent']);self.assertEqual(1,result['bell_skipped'])
        self.assertEqual(['alice','alice'],[r[0] for r in self.sent])
        self.preferences.once();self.assertEqual(2,len(self.sent))
        self.notify();notice=self.store.notifications(self.accounts['alice'])[0]
        self.store.read_notification(self.accounts['alice'],notice['id']);self.preferences.once()
        self.assertEqual(2,len(self.sent));self.assertIsNotNone(self.preferences.get(self.accounts['alice'])['settings']['last_sent'])

    def test_administrator_receives_current_accounts_and_server_alerts_but_not_old_generations(self):
        self.save('admin');self.notify();self.notify('bob');self.notify('@admin','health.problem');self.notify('bob',identity='old-generation')
        result=self.preferences.once();self.assertEqual(3,result['bell_sent']);self.assertEqual(1,result['bell_skipped'])
        self.assertTrue(all(row[0]=='admin' for row in self.sent))
        self.assertFalse(self.preferences.get(self.accounts['alice'])['settings']['bell'])

    def test_replayed_delivery_recovers_native_append_after_process_stop(self):
        self.save();self.notify()
        def stopped(*args):self.append(*args);raise KeyboardInterrupt()
        self.hestia.add_notification.side_effect=stopped
        with self.assertRaises(KeyboardInterrupt):self.preferences.once()
        self.assertEqual(1,len(self.sent));self.retry_now()
        self.hestia.add_notification.side_effect=self.append
        self.assertEqual(1,self.preferences.once()['bell_sent']);self.assertEqual(1,len(self.sent))
        with self.store.connection() as db:self.assertEqual('1',db.execute('SELECT native_id FROM notification_bell_deliveries').fetchone()[0])

    def test_native_failures_back_off_and_remain_visible_without_claiming_delivery(self):
        self.save();self.notify();self.hestia.add_notification.side_effect=ClamShieldError('Unavailable')
        self.assertEqual(1,self.preferences.once()['bell_failed'])
        self.assertIsNone(self.preferences.get(self.accounts['alice'])['settings']['last_sent'])
        self.assertIn('could not be confirmed',self.preferences.get(self.accounts['alice'])['settings']['error'])
        self.preferences.once();self.assertEqual(1,self.hestia.add_notification.call_count)
        self.retry_now();self.hestia.add_notification.side_effect=self.append
        self.assertEqual(1,self.preferences.once()['bell_sent']);self.assertIsNone(self.preferences.get(self.accounts['alice'])['settings']['error'])

    def test_unverifiable_native_list_never_triggers_a_blind_resend(self):
        self.save();self.notify();self.hestia.call.side_effect=lambda *args:{'1':None}
        self.assertEqual(1,self.preferences.once()['bell_failed'])
        self.assertEqual([],self.sent);self.hestia.add_notification.assert_not_called()

    def test_disable_or_revoked_administrator_authority_stops_pending_delivery(self):
        self.save('admin');self.notify('bob')
        def disable(command,owner,format):self.save('admin',bell=False);return {}
        self.hestia.call.side_effect=disable
        self.preferences.once();self.assertEqual([],self.sent)
        self.hestia.call.side_effect=lambda *args:{}
        self.save('admin');self.notify('bob');self.accounts['admin']['admin']=False
        self.preferences.once();self.assertEqual([],self.sent)

    def test_personal_settings_api_does_not_accept_customer_or_service_authority(self):
        app=Application(self.settings,self.store,self.hestia)
        response=app.dispatch(dict(actor='admin',owner='bob',action='notification-settings-get'))
        self.assertEqual('admin',response['account'])
        app.dispatch(dict(actor='alice',action='notification-settings-save',policy={'bell':True,'categories':['detections']},revision='default'))
        self.assertTrue(self.preferences.get(self.accounts['alice'])['settings']['bell'])
        with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',owner='bob',action='notification-settings-get'))

    def test_bell_receipts_follow_retained_notification_lifetime(self):
        self.save();self.notify();self.preferences.once()
        with self.store.connection() as db:
            db.execute('DELETE FROM notifications')
            self.assertEqual(0,db.execute('SELECT COUNT(*) FROM notification_bell_deliveries').fetchone()[0])
        self.notify();self.assertEqual(1,self.preferences.once()['bell_sent'])

    def test_budget_rotates_between_subscribers_instead_of_starving_other_accounts(self):
        self.save('alice',categories=[]);self.save('bob',categories=['detections'])
        for _ in range(30):self.notify()
        self.notify('bob')
        self.preferences.once();self.assertEqual([],self.sent)
        self.preferences.once();self.assertEqual('bob',self.sent[0][0])

    def test_message_uses_owned_safe_markup_and_stable_correlation_link(self):
        notice={'id':'a'*32,'owner':'alice','event':'scan.malware_found','subject':'<script>$(touch /tmp/x)`id`\\',
                'detail':json.dumps({'path':'evil\"\'\n<script>.php','signature':'Inert.<img>'})}
        topic,body=self.preferences.content(notice)
        self.assertTrue(topic.startswith('ClamShield: '));self.assertIn('notice='+'a'*32,body)
        for forbidden in ('<script>','<img>','$(','`','\n','\\'):self.assertNotIn(forbidden,body)
        self.assertIn('&#60;',body);self.assertIn('owner=alice',body)


class NativeBellCommand(unittest.TestCase):
    def test_only_fixed_native_command_and_safe_argument_vector_are_used(self):
        hestia=Hestia(Path('/fixture/hestia'))
        with patch('clamshield.hestia.subprocess.run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            hestia.add_notification('alice','ClamShield: Website malware detections','Owned notice')
            self.assertEqual(['/fixture/hestia/bin/v-add-user-notification','alice','ClamShield: Website malware detections','Owned notice','info'],run.call_args.args[0])
            self.assertNotIn('shell',run.call_args.kwargs)
        with self.assertRaises(AccessDenied):hestia.add_notification('../bob','ClamShield: Event','text')
        with self.assertRaises(AccessDenied):hestia.add_notification('alice','Other product','text')
        with self.assertRaises(AccessDenied):hestia.add_notification('alice','ClamShield: Event','line\nbreak')
        with self.assertRaises(AccessDenied):hestia.call('v-add-user-notification','alice','arbitrary','text')

    def test_category_selection_covers_existing_events_without_treating_integrity_as_malware(self):
        for event,expected in [('scan.malware_found','detections'),('scan.repeated_detection','detections'),('wordpress.integrity_issues','integrity'),
            ('scan.update_interrupted','scan_problems'),('health.recovered','health'),('maintenance.completed','maintenance'),
            ('mail.refreshed','mail'),('automatic.failed','actions'),('cleanup.verified','actions'),('rules.trial_finished','other'),('new.event','other')]:
            self.assertEqual(expected,category(event))
