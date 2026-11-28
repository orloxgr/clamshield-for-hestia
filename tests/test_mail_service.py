import array
from dataclasses import replace
import json
import os
import socket
import subprocess
import sys
from threading import Thread
import unittest
from unittest.mock import Mock, patch

import test_mail_custody as fixtures
import test_mail_bridge as bridge
from clamshield.mail_service import MailBroker,hook_status,service_error
from clamshield.mail_scanners import digest_snapshot
from clamshield.errors import EngineError


class MailServiceHealthTests(unittest.TestCase):
    def test_hook_timeout_does_not_crash_or_cache_a_false_healthy_result(self):
        timeout=subprocess.TimeoutExpired(['/usr/sbin/exim4','-bP','local_scan_path'],3,output='private message')
        success=subprocess.CompletedProcess([],0,'local_scan_path = /opt/clamshield-mail/local_scan.so\n','')
        with patch('clamshield.mail_service.subprocess.run',side_effect=[timeout,success]) as run:
            failed=hook_status();recovered=hook_status()
        self.assertFalse(failed['connected']);self.assertEqual('TimeoutExpired',failed['hook_error']['type'])
        self.assertEqual(3,failed['hook_error']['timeout_seconds']);self.assertNotIn('private message',str(failed))
        self.assertEqual({'connected':True},recovered);self.assertEqual(2,run.call_count)

    def test_hook_errors_are_false_and_do_not_expose_native_stderr(self):
        for outcome in (PermissionError(13,'private path'),subprocess.CompletedProcess([],1,'','private message'),
                        subprocess.CompletedProcess([],0,'local_scan_path = /foreign/library','')):
            with self.subTest(outcome=type(outcome).__name__),patch('clamshield.mail_service.subprocess.run') as run:
                if isinstance(outcome,Exception):run.side_effect=outcome
                else:run.return_value=outcome
                result=hook_status()
                self.assertFalse(result['connected']);self.assertIn('hook_error',result)
                self.assertNotIn('private',str(result));self.assertNotIn('/foreign',str(result))

    def test_maintenance_diagnostic_keeps_phase_and_type_without_message_content(self):
        try:raise OSError(28,'sensitive message recipient and file')
        except OSError as exc:result=service_error(exc,'delivery-maintenance')
        self.assertEqual({'phase':'delivery-maintenance','type':'OSError','errno':28},result)


class MailBrokerTests(unittest.TestCase):
    request_for=fixtures.MailCustodyTests.request_for
    items=fixtures.MailCustodyTests.items
    capture=fixtures.MailCustodyTests.capture
    delivery=fixtures.MailCustodyTests.delivery
    blob=fixtures.MailCustodyTests.blob

    def setUp(self):
        fixtures.MailCustodyTests.setUp(self)
        native_call=self.native.call.side_effect
        self.native.call.side_effect=lambda command,*args: {name:{} for name in self.ids} if command=='v-list-users' else native_call(command,*args)
        self.report=dict(complete=True,spam_score=0,detections=[],errors=[])
        self.scans=0
        parent=self
        class Scanner:
            timeout=25
            def scan(self,fd):
                parent.scans+=1
                return dict(parent.report,sha256=digest_snapshot(fd))
        self.factory=Scanner
        self.transport=Mock();self.transport.checkpoint.return_value={'device':1,'inode':2,'offset':0}

    def broker(self):return MailBroker(self.settings,self.store,self.native,self.factory,native=self.transport)

    def enable(self):
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='quarantine'))
        self.policies.save(self.native.authorize('admin','bob'),'bob.test','',dict(enabled=True,malware_action='reject'))

    def exchange(self,broker=None,protocol='esmtp',native_score=None,native_dnsbl=None,native_mime=None,tags_supported=False):
        broker=broker or self.broker();client,server=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        native_fields={} if native_score is None else dict(native_spam_score=native_score)
        if native_dnsbl is not None:native_fields.update(native_dnsbl_zone=native_dnsbl[0],native_dnsbl_value=native_dnsbl[1])
        if native_mime is not None:native_fields['native_mime_blocked']=native_mime
        if tags_supported:native_fields['fallback_tags_supported']=True
        packet=bridge.envelope(message_id=self.request.message_id,sender=self.request.sender,
                               recipients=list(self.request.recipients),protocol=protocol,flags=self.request.flags,
                               remote_ip=self.request.remote_ip,authenticated_id=self.request.authenticated_id,**native_fields)
        result=[]
        def handle():
            with server:result.append(broker.handle(server,expected_uid=os.getuid(),expected_binary=sys.executable))
        thread=Thread(target=handle);thread.start()
        try:
            client.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.request.fd]))])
            response=client.recv(4096)
        finally:client.close();thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(b'CSMRSP01',response[:8])
        self.last_response=response
        return int.from_bytes(response[8:12],'big'),result[0]

    def test_unmanaged_messages_remain_native_without_engine_or_custody_work(self):
        self.assertEqual((0,'unmanaged'),self.exchange());self.assertEqual(0,self.scans)
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])

    def test_clean_local_bounce_is_scanned_but_not_blackholed_or_reinjected(self):
        self.enable();self.request=replace(self.request,flags=0,sender='',remote_ip='')
        self.assertEqual((0,'unmanaged'),self.exchange(protocol='local'))
        self.assertEqual(1,self.scans)
        for context in (self.alice,self.bob):
            rows=self.policies.decisions(context)['decisions']
            self.assertEqual(('clean','deliver'),(rows[0]['classification'],rows[0]['action']))
            self.assertTrue(rows[0]['detail']['scan_complete'])
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])

    def test_local_message_still_uses_selected_quarantine_or_tag(self):
        self.enable();self.request=replace(self.request,flags=0,sender='',remote_ip='')
        self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.assertEqual((3,'custody'),self.exchange(protocol='local'))
        self.assertEqual('tag',self.custody.list(self.alice)['messages'][0]['action'])
        self.assertEqual('quarantine',self.custody.list(self.bob)['messages'][0]['action'])

    def test_incomplete_local_check_remains_fallback_and_never_clean(self):
        self.enable();self.request=replace(self.request,flags=0,sender='',remote_ip='')
        self.report.update(complete=False,errors=['scanner unavailable'])
        self.assertEqual((5,'native-fallback'),self.exchange(protocol='local'))
        for context in (self.alice,self.bob):
            rows=self.policies.decisions(context)['decisions']
            self.assertEqual('incomplete',rows[0]['classification'])

    def test_smtp_and_batched_smtp_keep_durable_clean_custody(self):
        self.enable()
        for flags in (1,3):
            self.request=replace(self.request_for(),flags=flags)
            self.assertEqual((3,'custody'),self.exchange())

    def test_native_mime_policy_rejects_unmanaged_but_does_not_invent_malware_for_managed(self):
        self.assertEqual((1,'reject'),self.exchange(native_mime='1'));self.assertEqual(0,self.scans)
        for context in (self.alice,self.bob):
            detail=self.policies.decisions(context)['decisions'][0]['detail']
            self.assertEqual('native-mime',detail['classification']);self.assertEqual(0,detail['native_mime']['score_contribution'])
        self.request=replace(self.request,message_id='mime-managed')
        self.enable();self.assertEqual((3,'custody'),self.exchange(native_mime='1'))
        for context in (self.alice,self.bob):
            detail=self.policies.decisions(context)['decisions'][0]['detail']
            self.assertEqual(('clean','deliver'),(detail['classification'],detail['action']))
            self.assertEqual('blocked-extension',detail['native_mime']['policy'])

    def test_native_mime_and_dnsbl_mixed_recipients_keep_selected_delivery_and_native_reject_copy(self):
        for fields,classification in ((dict(native_mime='1'),'native-mime'),
                                      (dict(native_dnsbl=('zen.spamhaus.org','127.0.0.2')),'native-dnsbl')):
            # Independent source identity, never repeat custody of one request.
            self.request=replace(self.request,message_id='mixed-'+classification)
            self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,spam_action='tag'))
            self.assertEqual((3,'custody'),self.exchange(**fields))
            row=self.custody.list(self.bob)['messages'][0]
            with self.store.connection() as db:
                detail=json.loads(db.execute('SELECT detail FROM mail_recipients WHERE id=? AND owner=? AND identity=?',
                                             (row['id'],*self.store.scope(self.bob))).fetchone()[0])
            self.assertEqual(('quarantine',classification),(row['action'],detail['classification']))

    def test_native_dnsbl_operational_error_never_rejects_an_unmanaged_message(self):
        self.assertEqual((5,'native-fallback'),self.exchange(native_dnsbl=('zen.spamhaus.org','127.255.255.251')))
        self.assertEqual(0,self.scans)

    def test_native_spam_pass_cannot_erase_an_independent_dns_failure(self):
        delegated={(owner,self.ids[owner],owner+'.test') for owner in ('alice','bob')}
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value=delegated), \
                patch('clamshield.native_spam.rejection_threshold',return_value=dict(required_score=10,source='fixture')):
            plan=self.broker().plan(replace(self.request,native_dnsbl_zone='zen.spamhaus.org',native_dnsbl_value='127.255.255.251',native_spam_score=0.0))
            self.assertTrue(all((r['decision']['classification'],r['decision']['scan_complete'])==('incomplete',False) for r in plan['items']))
            self.assertEqual((5,'native-fallback'),self.exchange(native_dnsbl=('zen.spamhaus.org','127.255.255.251'),native_score='0'))

    def test_optional_native_dns_telemetry_failure_does_not_change_selected_delivery(self):
        self.enable()
        with patch('clamshield.native_dnsbl_health.NativeDnsblHealth.observe',side_effect=OSError('Telemetry disk unavailable')):
            self.assertEqual((5,'native-fallback'),self.exchange(native_dnsbl=('zen.spamhaus.org','127.255.255.251')))

    def test_custom_native_list_keeps_its_unmanaged_policy_without_inventing_spam_points(self):
        self.assertEqual((1,'reject'),self.exchange(native_dnsbl=('custom.example.test','127.0.0.2')))
        self.assertEqual(0,self.scans)

    def test_native_spam_result_cannot_clear_another_verified_native_policy_match(self):
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True))
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value={('bob',self.ids['bob'],'bob.test')}), \
                patch('clamshield.native_spam.rejection_threshold',return_value=dict(required_score=10,source='fixture')):
            self.assertEqual((3,'custody'),self.exchange(native_mime='1',native_score='0'))
        self.assertEqual('quarantine',self.custody.list(self.bob)['messages'][0]['action'])

    def test_clean_managed_recipients_get_bound_custody_and_await_native_proof(self):
        self.enable();self.assertEqual((3,'custody'),self.exchange());self.assertEqual(1,self.scans)
        for context in (self.alice,self.bob):
            row=self.custody.list(context)['messages'][0]
            self.assertEqual('deliver',row['action']);self.assertEqual('prepared',row['status'])
            self.assertEqual('response_sent',row['source_status'])
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_delivery_attempts').fetchone()[0])

    def test_native_dnsbl_context_is_retained_in_each_owners_selected_policy_record(self):
        self.enable();self.assertEqual((3,'custody'),self.exchange(native_dnsbl=('private-key.zen.dq.spamhaus.net','127.0.0.2')))
        for context in (self.alice,self.bob):
            detail=self.policies.decisions(context)['decisions'][0]['detail']
            self.assertEqual(('spam','junk',0),(detail['classification'],detail['action'],detail['spam_score']))
            self.assertEqual('listed',detail['native_dnsbl']['state']);self.assertNotIn('private-key',str(detail))

    def test_verified_native_listing_still_gets_selected_custody_during_other_dns_errors(self):
        self.enable();self.assertEqual((3,'custody'),self.exchange(native_dnsbl=('zen.spamhaus.org','127.255.255.251, 127.0.0.2')))
        for context in (self.alice,self.bob):
            detail=self.policies.decisions(context)['decisions'][0]['detail']
            self.assertEqual(('spam','junk',False),(detail['classification'],detail['action'],detail['scan_complete']))
            self.assertEqual(['127.0.0.2'],detail['native_dnsbl']['listing_codes'])

    def test_mixed_unmanaged_recipient_stays_native_and_others_are_captured(self):
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True))
        self.assertEqual((4,'custody'),self.exchange())
        self.assertEqual(1,len(self.custody.list(self.alice)['messages']))
        self.assertEqual([],self.custody.list(self.bob)['messages'])

    def test_mixed_reject_retains_only_that_copy_without_rejecting_sibling(self):
        self.enable();self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.assertEqual((3,'custody'),self.exchange())
        for context in (self.alice,self.bob):
            self.assertEqual('quarantine',self.custody.list(context)['messages'][0]['action'])
            row=self.policies.decisions(context)['decisions'][0]
            self.assertEqual('quarantine',row['action']);self.assertEqual('pending',row['detail']['smtp_outcome'])
        self.assertEqual('quarantine',self.policies.decisions(self.alice)['decisions'][0]['detail']['policy_action'])
        denied=self.policies.decisions(self.bob)['decisions'][0]['detail']
        self.assertEqual('reject',denied['policy_action']);self.assertIn('SMTP cannot reject one recipient',denied['transport_note'])
        self.assertNotIn('inbox@bob.test',str(self.policies.decisions(self.alice)))
        self.policies.outcome(self.request.message_id,'accepted')
        row=self.policies.decisions(self.bob)['decisions'][0]
        self.assertEqual('quarantine',row['action']);self.assertEqual('reject',row['detail']['policy_action'])

    def test_selected_malware_delivery_survives_other_recipient_rejection(self):
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.assertEqual((3,'custody'),self.exchange())
        self.assertEqual('tag',self.custody.list(self.alice)['messages'][0]['action'])
        self.assertEqual('quarantine',self.custody.list(self.bob)['messages'][0]['action'])
        for context in (self.alice,self.bob):
            self.assertNotIn('reject', [row['action'] for row in self.policies.decisions(context)['decisions']])

    def test_unanimous_rejection_still_uses_smtp_without_creating_copies(self):
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='reject'))
        self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.assertEqual((1,'reject'),self.exchange())
        for context in (self.alice,self.bob):self.assertEqual([],self.custody.list(context)['messages'])

    def test_unmanaged_native_antivirus_rejection_cannot_cancel_managed_delivery(self):
        original=self.native.call.side_effect
        self.native.call.side_effect=lambda command,*args: ({key:dict(value,ANTIVIRUS='yes') for key,value in original(command,*args).items()}
            if command=='v-list-mail-domains' else original(command,*args))
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.report.update(complete=False,errors=['later engine failed'],
            detections=[dict(engine='clamav',signature='Eicar-Test-Signature',category='malware',provider='clamav')])
        self.assertEqual((3,'custody'),self.exchange())
        self.assertEqual('tag',self.custody.list(self.alice)['messages'][0]['action'])
        row=self.custody.list(self.bob)['messages'][0]
        self.assertEqual('quarantine',row['action'])
        native_record=self.policies.decisions(self.bob)['decisions'][0]
        self.assertEqual(('quarantine','native-malware'),(native_record['action'],native_record['classification']))
        self.assertEqual('reject',native_record['detail']['policy_action'])

    def test_mixed_rejected_copy_storage_failure_falls_back_without_bouncing_siblings(self):
        self.enable();self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        broker=self.broker()
        with patch.object(broker.custody,'stage',side_effect=OSError('No space available')):
            self.assertEqual((5,'error'),self.exchange(broker))
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])
        for context in (self.alice,self.bob):
            row=self.policies.decisions(context)['decisions'][0]
            self.assertEqual('deliver',row['action']);self.assertEqual('incomplete',row['classification'])
            self.assertFalse(row['detail']['scan_complete']);self.assertIn('native delivery',row['detail']['transport_note'])

    def test_verified_native_spam_rejection_is_retained_beside_managed_delivery(self):
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True))
        delegated={('bob',self.ids['bob'],'bob.test')}
        self.report.update(complete=False,errors=['later engine failed'],
            detections=[dict(engine='clamav',signature='Inert.Test',category='malware')])
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value=delegated), \
                patch('clamshield.native_spam.rejection_threshold',return_value=dict(required_score=10,source='fixture')):
            self.assertEqual((3,'custody'),self.exchange(native_score='101'))
        self.assertEqual('tag',self.custody.list(self.alice)['messages'][0]['action'])
        self.assertEqual('quarantine',self.custody.list(self.bob)['messages'][0]['action'])

    def test_incomplete_engine_report_stays_in_native_exim_without_capture(self):
        self.enable();self.report.update(complete=False,errors=['EngineError'])
        self.assertEqual((5,'native-fallback'),self.exchange())
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])
        row=self.policies.decisions(self.alice)['decisions'][0]
        self.assertEqual('incomplete',row['detail']['policy_classification'])
        self.assertFalse(row['detail']['scan_complete'])
        self.assertEqual('accepted',row['detail']['smtp_outcome'])

    def test_prior_native_score_is_stored_separately_from_the_selected_policy_score(self):
        self.enable();self.assertEqual((3,'custody'),self.exchange(native_score='10000'))
        row=self.policies.decisions(self.alice)['decisions'][0]
        self.assertEqual(dict(score=1000,source='native-exim-acl'),row['detail']['native_spamassassin'])
        self.assertEqual(0,row['detail']['spam_score']);self.assertEqual('deliver',row['action'])

    def test_native_antivirus_is_preserved_for_unmanaged_recipients(self):
        original=self.native.call.side_effect
        def call(command,*args):
            result=original(command,*args)
            if command=='v-list-mail-domains':
                return {key:dict(value,ANTIVIRUS='yes') for key,value in result.items()}
            return result
        self.native.call.side_effect=call
        self.report['detections']=[dict(engine='clamav',signature='Eicar-Test-Signature',category='malware',provider='clamav')]
        self.assertEqual((1,'reject'),self.exchange())
        for owner in ('alice','bob'):
            self.policies.save(self.native.authorize('admin',owner),owner+'.test','',dict(enabled=True,malware_action='tag'))
        self.assertEqual((3,'custody'),self.exchange())

    def test_delegated_native_spam_cannot_override_a_managed_delivery_policy(self):
        self.enable()
        delegated={('alice',self.ids['alice'],'alice.test'),('bob',self.ids['bob'],'bob.test')}
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value=delegated), \
                patch('clamshield.native_spam.rejection_threshold') as threshold:
            self.assertEqual((3,'custody'),self.exchange(native_score='10000'))
        threshold.assert_not_called()

    def test_delegated_unmanaged_native_rejection_uses_original_strict_threshold(self):
        delegated={('alice',self.ids['alice'],'alice.test'),('bob',self.ids['bob'],'bob.test')}
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value=delegated), \
                patch('clamshield.native_spam.rejection_threshold',return_value=dict(required_score=10,revision='fixture',source='native-exim-macro')):
            self.assertEqual((0,'unmanaged'),self.exchange(native_score='100'))
            self.assertEqual((1,'reject'),self.exchange(native_score='101'))
        self.assertEqual(0,self.scans)

    def test_unchecked_native_score_is_scanned_by_verified_native_service_and_failure_delivers_incomplete(self):
        delegated={('alice',self.ids['alice'],'alice.test'),('bob',self.ids['bob'],'bob.test')}
        with patch('clamshield.native_rejection.NativeRejection.delegated',return_value=delegated), \
                patch('clamshield.native_spam.rejection_threshold',return_value=dict(required_score=10,source='fixture')), \
                patch('clamshield.native_spam_client.NativeSpamAssassin.scan',return_value=dict(score=1000,source='native-spamd-report')) as scan:
            self.assertEqual((1,'reject'),self.exchange());scan.assert_called_once()
            scan.side_effect=EngineError('Unavailable')
            self.assertEqual((5,'native-fallback'),self.exchange())
        self.assertEqual(0,self.scans)

    def test_engine_start_failure_uses_native_but_reserved_reference_spoof_is_denied(self):
        self.enable()
        self.factory=Mock(side_effect=EngineError('Unavailable'))
        self.assertEqual((5,'error'),self.exchange())
        self.assertEqual((2,'error'),self.exchange(protocol='clamshield-delivery-'+'a'*32))

    def test_partial_known_malware_follows_policy_even_when_spam_engine_fails(self):
        self.enable();self.report.update(complete=False,errors=['EngineError'],spam_score=None,
            detections=[dict(engine='clamav',signature='Inert.Test',category='malware')])
        self.assertEqual((3,'custody'),self.exchange())
        self.request=self.request_for()
        self.policies.save(self.native.authorize('admin','bob'),'bob.test','',dict(enabled=True,malware_action='tag'))
        self.assertEqual((3,'custody'),self.exchange())
        with self.store.connection() as db:
            import json
            detail=json.loads(db.execute('SELECT r.detail FROM mail_recipients r JOIN mail_transactions t ON t.id=r.transaction_id WHERE r.owner=? AND t.exim_id=?',('bob',self.request.message_id)).fetchone()[0])
        self.assertFalse(detail['scan_complete'])
        self.assertEqual('tag',detail['action'])

    def test_owner_recreation_during_scan_cannot_commit_old_policy(self):
        self.enable();old=self.factory;parent=self
        class Changed(old):
            def scan(self,fd):
                result=super().scan(fd);parent.ids['alice']='new-generation';return result
        self.factory=Changed
        self.assertEqual((5,'error'),self.exchange())
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])

    def test_history_storage_and_custody_failures_do_not_reject_original_native_message(self):
        self.enable()
        for phase,attribute in [('record','policies.record'),('stage','custody.stage'),('arm','acceptance.arm')]:
            with self.subTest(phase=phase):
                broker=self.broker();target,name=attribute.split('.')
                with patch.object(getattr(broker,target),name,side_effect=OSError('No space available')):
                    self.assertEqual((5,'error'),self.exchange(broker))
                self.assertEqual('OSError:'+phase,broker.last_error)
        with self.store.connection() as db:
            self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions WHERE status=\'committed\'').fetchone()[0])

    def test_native_fallback_keeps_verified_subject_marks_scoped_to_each_selected_policy(self):
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.report.update(complete=False,detections=[dict(engine='clamav',signature='Known.Malware',category='malware')])
        for phase,attribute in [('record','policies.record'),('stage','custody.stage'),('arm','acceptance.arm')]:
            with self.subTest(phase=phase):
                self.request=replace(self.request_for(),message_id='tag-fallback-'+phase)
                broker=self.broker();target,name=attribute.split('.')
                with patch.object(getattr(broker,target),name,side_effect=OSError('Storage unavailable')):
                    self.assertEqual((6,'error'),self.exchange(broker,tags_supported=True))
                self.assertEqual((2).to_bytes(4,'big')+bytes([1,0]),self.last_response[44:])
                for context in (self.alice,self.bob):
                    rows=self.policies.decisions(context)['decisions']
                    own=[r for r in rows if r['exim_id']==self.request.message_id]
                    if phase=='record':self.assertEqual([],own);continue
                    self.assertEqual(1,len(own));detail=own[0]['detail']
                    self.assertFalse(detail['scan_complete']);self.assertEqual('deliver',detail['action'])
                    self.assertEqual('malware' if context==self.alice else None,detail.get('native_fallback_tag_requested'))

    def test_known_tag_reply_precedes_any_second_failed_outcome_write(self):
        import sqlite3
        from clamshield.mail_service import respond as real_respond
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.report['detections']=[dict(engine='clamav',signature='Known.Malware',category='malware')]
        broker=self.broker();events=[]
        def reply(*args,**kwargs):events.append('reply');return real_respond(*args,**kwargs)
        def outcome(*args,**kwargs):events.append('outcome');raise sqlite3.OperationalError('database is locked')
        with patch.object(broker.policies,'record',side_effect=sqlite3.OperationalError('database is locked')),patch.object(broker.policies,'outcome',side_effect=outcome),patch('clamshield.mail_service.respond',side_effect=reply):
            self.assertEqual((6,'error'),self.exchange(broker,tags_supported=True))
        self.assertEqual(['reply','outcome'],events)
        self.assertEqual((2).to_bytes(4,'big')+bytes([1,0]),self.last_response[44:])

    def test_fallback_does_not_guess_marks_for_older_adapter_or_unknown_verdict(self):
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        for capability,hits in ((False,[dict(engine='clamav',signature='Known.Malware',category='malware')]),(True,[])):
            self.request=self.request_for();self.report['detections']=hits;broker=self.broker()
            with patch.object(broker.custody,'stage',side_effect=OSError('Storage unavailable')):
                self.assertEqual((5,'error'),self.exchange(broker,tags_supported=capability))
            self.assertEqual(44,len(self.last_response))

    def test_fallback_does_not_reuse_a_recreated_owners_subject_mark(self):
        self.enable();self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True,malware_action='tag'))
        self.report['detections']=[dict(engine='clamav',signature='Known.Malware',category='malware')]
        broker=self.broker()
        def failed_capture(*_args):
            self.ids['alice']='replacement-owner';raise OSError('Storage unavailable')
        with patch.object(broker.custody,'stage',side_effect=failed_capture):
            self.assertEqual((5,'error'),self.exchange(broker,tags_supported=True))
        self.assertEqual(44,len(self.last_response))
