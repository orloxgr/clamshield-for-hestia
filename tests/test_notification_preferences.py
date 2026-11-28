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
from clamshield.review import Review


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
        self.hestia.sites.return_value=[]
        self.hestia.inventory.side_effect=lambda:[dict(value,sites=[]) for value in self.accounts.values()]
        self.removed=[]
        def remove(owner,nid,topic,body):
            self.assertEqual(topic,self.native[owner][nid]['TOPIC']);self.assertEqual(body,self.native[owner][nid]['NOTICE'])
            self.removed.append((owner,nid));del self.native[owner][nid]
        self.hestia.delete_notification.side_effect=remove
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

    def clear(self,actor='alice',scope='account',selected=None):
        review=Review(self.settings,self.store,self.hestia);context=self.accounts[actor]
        proof=review.bulk(context,'notices',scope,'preview',selected=selected)
        return review.bulk(context,'notices',scope,'clear',proof['token'])

    def test_channels_choose_different_categories_and_clamshield_changes_do_not_reset_bell_window(self):
        self.preferences.save(self.accounts['alice'],dict(bell=True,categories=['integrity'],bell_categories=['detections']),'default')
        with self.store.connection() as db:before=db.execute('SELECT starts_after FROM notification_preferences').fetchone()[0]
        self.notify();self.notify(event='wordpress.integrity_issues');current=self.preferences.get(self.accounts['alice'])
        self.preferences.save(self.accounts['alice'],dict(bell=True,categories=[],bell_categories=['detections']),current['settings']['revision'])
        with self.store.connection() as db:self.assertEqual(before,db.execute('SELECT starts_after FROM notification_preferences').fetchone()[0])
        self.assertEqual(1,self.preferences.once()['bell_sent'])
        self.assertIn('Website malware detections',self.sent[0][1])
        value=self.preferences.get(self.accounts['alice'])['settings']
        self.assertEqual([],value['categories']);self.assertEqual(['detections'],value['bell_categories'])

    def test_legacy_channel_selection_is_preserved_and_new_bell_categories_are_validated(self):
        self.save(categories=['mail'])
        with self.store.connection() as db:db.execute('UPDATE notification_preferences SET bell_categories=NULL')
        self.assertEqual(['mail'],self.preferences.get(self.accounts['alice'])['settings']['bell_categories'])
        for bad in ('mail',['unknown'],['mail','mail'],[True]):
            with self.subTest(value=bad),self.assertRaises(ClamShieldError):
                self.preferences.save(self.accounts['alice'],dict(bell=True,categories=[],bell_categories=bad),'default')

    def test_clear_selected_removes_only_own_matching_native_notice_and_preserves_other_notifications(self):
        self.save();self.save('admin');self.notify();self.preferences.once()
        first=self.store.notifications(self.accounts['alice'])[0]['id']
        self.native['alice']['900']={'TOPIC':'Backups','NOTICE':'Unrelated Hestia notice'}
        self.notify(event='health.problem');self.preferences.once()
        before_admin=dict(self.native['admin']);before=len(self.native['alice'])
        result=self.clear(selected=[first]);self.assertEqual(1,result['bell_pending'])
        self.preferences.once();self.assertEqual(before-1,len(self.native['alice']))
        self.assertEqual(before_admin,self.native['admin']);self.assertIn('900',self.native['alice'])
        self.assertEqual(['alice'],[owner for owner,_id in self.removed])
        self.preferences.once();self.assertEqual(1,len(self.removed))

    def test_clear_global_reconciles_current_admin_copy_without_removing_customer_copy(self):
        self.save('admin');self.save();self.notify();self.notify('bob');self.notify('@admin','health.problem')
        self.preferences.once();customer=dict(self.native['alice'])
        self.assertEqual(3,self.clear('admin','server')['changed'])
        self.preferences.once();self.assertEqual({},self.native['admin']);self.assertEqual(customer,self.native['alice'])
        self.assertTrue(all(owner=='admin' for owner,_id in self.removed))

    def test_clear_failure_is_attempted_once_and_visible_even_when_bell_is_disabled(self):
        self.save();self.notify();self.preferences.once();self.clear();self.save(bell=False)
        self.hestia.delete_notification.side_effect=ClamShieldError('Native validation failed')
        self.assertEqual(1,self.preferences.once()['bell_clear_failed']);self.assertTrue(self.native['alice'])
        self.assertEqual(0,self.preferences.once()['bell_clear_failed'])
        with self.store.connection() as db:db.execute('UPDATE notification_bell_clears SET attempted=0')
        self.assertEqual(0,self.preferences.once()['bell_cleared'])
        self.assertEqual(1,self.hestia.delete_notification.call_count)
        error=self.preferences.get(self.accounts['alice'])['settings']['error']
        self.assertIn('Native validation failed',error);self.assertIn('No automatic retry',error)
        review=Review(self.settings,self.store,self.hestia)
        self.assertEqual(error,review.query(self.accounts['alice'],'notices',filters={})['bell_cleanup_error'])
        self.assertIsNone(self.preferences.get(self.accounts['bob'])['settings']['error'])

    def test_interrupted_native_deletion_is_not_repeated(self):
        self.save();self.notify();self.preferences.once();self.clear()
        self.hestia.delete_notification.side_effect=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.preferences.once()
        self.assertEqual(0,self.preferences.once()['bell_cleared'])
        self.assertEqual(1,self.hestia.delete_notification.call_count)
        error=self.preferences.get(self.accounts['alice'])['settings']['error']
        self.assertIn('interrupted',error);self.assertIn('No automatic retry',error)

    def test_clear_during_native_append_is_reconciled_after_delivery_finishes(self):
        self.save();self.notify()
        def concurrent_clear(*args):self.append(*args);self.clear()
        self.hestia.add_notification.side_effect=concurrent_clear
        result=self.preferences.once()
        self.assertEqual(1,result['bell_sent']);self.assertEqual(1,result['bell_cleared']);self.assertEqual({},self.native['alice'])
        self.preferences.once();self.assertEqual(1,len(self.sent))

    def test_recreated_recipient_and_forged_prefix_match_are_not_deleted(self):
        self.save();self.notify();self.preferences.once();self.clear()
        self.native['alice']['1']['NOTICE']+=' unrelated suffix'
        self.preferences.once();self.assertTrue(self.native['alice']);self.assertEqual([],self.removed)
        self.notify();self.preferences.once();self.clear();self.accounts['alice']['identity']='recreated'
        self.preferences.once();self.assertEqual([],self.removed)

    def test_cleanup_survives_source_retention_and_does_not_remove_read_only_records(self):
        self.save();self.notify();self.preferences.once();notice=self.store.notifications(self.accounts['alice'])[0]
        self.store.read_notification(self.accounts['alice'],notice['id']);self.preferences.once()
        self.assertTrue(self.native['alice']);self.assertEqual([],self.removed)
        self.clear()
        with self.store.connection() as db:db.execute('DELETE FROM notifications')
        self.preferences.once();self.assertEqual({},self.native['alice'])

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

    def test_interrupted_append_is_terminal_without_native_checks_or_resend(self):
        self.save();self.notify()
        def stopped(*args):self.append(*args);raise KeyboardInterrupt()
        self.hestia.add_notification.side_effect=stopped
        with self.assertRaises(KeyboardInterrupt):self.preferences.once()
        self.assertEqual(1,len(self.sent));self.retry_now()
        self.hestia.call.reset_mock();self.hestia.add_notification.reset_mock()
        self.assertEqual(0,self.preferences.once()['bell_sent'])
        self.hestia.call.assert_not_called();self.hestia.add_notification.assert_not_called()
        error=self.preferences.get(self.accounts['alice'])['settings']['error']
        self.assertIn('interrupted',error);self.assertIn('No automatic retry',error)

    def test_native_failure_is_terminal_and_reports_cause_in_preferences_and_review(self):
        self.save();self.notify();self.hestia.add_notification.side_effect=ClamShieldError('v-add-user-notification exited with code 7')
        self.assertEqual(1,self.preferences.once()['bell_failed'])
        self.assertIsNone(self.preferences.get(self.accounts['alice'])['settings']['last_sent'])
        error=self.preferences.get(self.accounts['alice'])['settings']['error']
        self.assertIn('exited with code 7',error);self.assertIn('No automatic retry',error)
        self.retry_now();self.hestia.call.reset_mock();self.hestia.add_notification.reset_mock()
        self.assertEqual(0,self.preferences.once()['bell_sent'])
        self.hestia.call.assert_not_called();self.hestia.add_notification.assert_not_called()
        review=Review(self.settings,self.store,self.hestia)
        self.assertEqual(error,review.query(self.accounts['alice'],'notices',filters={})['bell_delivery_error'])
        self.assertIsNone(self.preferences.get(self.accounts['bob'])['settings']['error'])

    def test_new_success_does_not_hide_an_unresolved_failure_and_clear_all_dismisses_it(self):
        self.save();self.notify();self.hestia.add_notification.side_effect=ClamShieldError('Native validation failed')
        self.preferences.once();self.notify();self.hestia.add_notification.side_effect=self.append
        self.assertEqual(1,self.preferences.once()['bell_sent'])
        self.assertIn('Native validation failed',self.preferences.get(self.accounts['alice'])['settings']['error'])
        self.clear();self.assertIsNone(self.preferences.get(self.accounts['alice'])['settings']['error'])

    def test_old_error_receipts_are_terminal_and_do_not_promise_a_retry(self):
        self.save();self.notify();notice=self.store.notifications(self.accounts['alice'])[0]
        pref=dict(actor='alice',identity=self.accounts['alice']['identity'],revision=self.preferences.get(self.accounts['alice'])['settings']['revision'])
        self.preferences.receipt(pref,notice,'error',error='Bell delivery could not be confirmed. ClamShield will check the native notification before retrying.')
        self.retry_now();self.preferences.once()
        self.hestia.call.assert_not_called();self.hestia.add_notification.assert_not_called()
        error=self.preferences.get(self.accounts['alice'])['settings']['error']
        self.assertIn('previous attempt did not record its cause',error);self.assertIn('No automatic retry',error)

    def test_unverifiable_native_list_never_triggers_a_blind_resend(self):
        self.save();self.notify();self.hestia.call.side_effect=lambda *args:{'1':None}
        self.assertEqual(1,self.preferences.once()['bell_failed'])
        self.assertEqual([],self.sent);self.hestia.add_notification.assert_not_called()
        self.retry_now();self.hestia.call.reset_mock();self.preferences.once();self.hestia.call.assert_not_called()

    def test_disable_or_revoked_administrator_authority_stops_pending_delivery(self):
        self.save('admin');self.notify('bob')
        def disable(command,owner,format):self.save('admin',bell=False);return {}
        self.hestia.call.side_effect=disable
        self.preferences.once();self.assertEqual([],self.sent)
        self.preferences.once();self.assertIsNone(self.preferences.get(self.accounts['admin'])['settings']['error'])
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
    def test_native_deletion_rechecks_exact_content_and_never_accepts_all_or_foreign_ids(self):
        hestia=Hestia(Path('/fixture/hestia'));topic='ClamShield: Event';body='<a href="/plugins/clamshield/?notice=abc">Open</a>'
        hestia.call=Mock(side_effect=[{'1':dict(TOPIC=topic,NOTICE=body.replace('"',"'"))},{}])
        with patch('clamshield.hestia.subprocess.run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            hestia.delete_notification('alice','1',topic,body)
            self.assertEqual(['/fixture/hestia/bin/v-delete-user-notification','alice','1'],run.call_args.args[0])
            self.assertNotIn('shell',run.call_args.kwargs)
        for nid in ('all','1;id','-1','../1','0'):
            with self.assertRaises(AccessDenied):hestia.delete_notification('alice',nid,topic,body)
        hestia.call=Mock(return_value={'1':dict(TOPIC='Other product',NOTICE=body)})
        with patch('clamshield.hestia.subprocess.run') as run:
            with self.assertRaises(Conflict):hestia.delete_notification('alice','1',topic,body)
            run.assert_not_called()

    def test_native_delivery_diagnostics_identify_command_and_failure_without_raw_output(self):
        hestia=Hestia(Path('/fixture/hestia'))
        for command,operation in (
            ('v-add-user-notification',lambda:hestia.add_notification('alice','ClamShield: Event','Owned notice')),
            ('v-list-user-notifications',lambda:hestia.call('v-list-user-notifications','alice','json'))):
            with self.subTest(command=command):
                with patch('clamshield.hestia.subprocess.run',return_value=subprocess.CompletedProcess([],7,'private output','private error')):
                    with self.assertRaisesRegex(ClamShieldError,command+' exited with code 7') as caught:operation()
                    self.assertNotIn('private',str(caught.exception))
                with patch('clamshield.hestia.subprocess.run',side_effect=subprocess.TimeoutExpired(command,10)):
                    with self.assertRaisesRegex(ClamShieldError,command+' timed out'):operation()

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
