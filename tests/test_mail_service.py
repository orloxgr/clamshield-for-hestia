import array
import os
import socket
import sys
from threading import Thread
import unittest
from unittest.mock import Mock

import test_mail_custody as fixtures
import test_mail_bridge as bridge
from clamshield.mail_service import MailBroker
from clamshield.mail_scanners import digest_snapshot
from clamshield.errors import EngineError


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

    def exchange(self,broker=None,protocol='esmtp'):
        broker=broker or self.broker();client,server=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        packet=bridge.envelope(message_id=self.request.message_id,sender=self.request.sender,
                               recipients=list(self.request.recipients),protocol=protocol)
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
        return int.from_bytes(response[8:12],'big'),result[0]

    def test_unmanaged_messages_remain_native_without_engine_or_custody_work(self):
        self.assertEqual((0,'unmanaged'),self.exchange());self.assertEqual(0,self.scans)
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])

    def test_clean_managed_recipients_get_bound_custody_and_await_native_proof(self):
        self.enable();self.assertEqual((3,'custody'),self.exchange());self.assertEqual(1,self.scans)
        for context in (self.alice,self.bob):
            row=self.custody.list(context)['messages'][0]
            self.assertEqual('deliver',row['action']);self.assertEqual('prepared',row['status'])
            self.assertEqual('response_sent',row['source_status'])
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_delivery_attempts').fetchone()[0])

    def test_mixed_unmanaged_recipient_stays_native_and_others_are_captured(self):
        self.policies.save(self.native.authorize('admin','alice'),'alice.test','',dict(enabled=True))
        self.assertEqual((4,'custody'),self.exchange())
        self.assertEqual(1,len(self.custody.list(self.alice)['messages']))
        self.assertEqual([],self.custody.list(self.bob)['messages'])

    def test_mixed_reject_records_actual_whole_smtp_result_without_quarantine(self):
        self.enable();self.report['detections']=[dict(engine='clamav',signature='Inert.Test',category='malware')]
        self.assertEqual((1,'reject'),self.exchange())
        for context in (self.alice,self.bob):
            self.assertEqual([],self.custody.list(context)['messages'])
            row=self.policies.decisions(context)['decisions'][0]
            self.assertEqual('reject',row['action']);self.assertEqual('reject',row['detail']['smtp_outcome'])
        self.assertEqual('quarantine',self.policies.decisions(self.alice)['decisions'][0]['detail']['policy_action'])
        self.assertNotIn('inbox@bob.test',str(self.policies.decisions(self.alice)))

    def test_incomplete_engine_report_stays_in_native_exim_without_capture(self):
        self.enable();self.report.update(complete=False,errors=['EngineError'])
        self.assertEqual((5,'native-fallback'),self.exchange())
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])
        row=self.policies.decisions(self.alice)['decisions'][0]
        self.assertEqual('incomplete',row['detail']['policy_classification'])
        self.assertFalse(row['detail']['scan_complete'])
        self.assertEqual('accepted',row['detail']['smtp_outcome'])

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

    def test_engine_start_failure_uses_native_but_reserved_reference_spoof_is_denied(self):
        self.enable()
        self.factory=Mock(side_effect=EngineError('Unavailable'))
        self.assertEqual((5,'error'),self.exchange())
        self.assertEqual((2,'error'),self.exchange(protocol='clamshield-delivery-'+'a'*32))

    def test_partial_known_malware_follows_policy_even_when_spam_engine_fails(self):
        self.enable();self.report.update(complete=False,errors=['EngineError'],spam_score=None,
            detections=[dict(engine='clamav',signature='Inert.Test',category='malware')])
        self.assertEqual((1,'reject'),self.exchange())
        self.policies.save(self.native.authorize('admin','bob'),'bob.test','',dict(enabled=True,malware_action='tag'))
        self.assertEqual((3,'custody'),self.exchange())
        with self.store.connection() as db:
            import json
            detail=json.loads(db.execute('SELECT detail FROM mail_recipients WHERE owner=?',('bob',)).fetchone()[0])
        self.assertFalse(detail['scan_complete'])

    def test_owner_recreation_during_scan_cannot_commit_old_policy(self):
        self.enable();old=self.factory;parent=self
        class Changed(old):
            def scan(self,fd):
                result=super().scan(fd);parent.ids['alice']='new-generation';return result
        self.factory=Changed
        self.assertEqual((2,'error'),self.exchange())
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM mail_transactions').fetchone()[0])
