from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import test_mail_custody as fixtures
from clamshield.errors import AccessDenied,Conflict
from clamshield.mail_acceptance import MailAcceptance
from clamshield.mail_bridge import Decision,process_start
from clamshield.mail_delivery import MailDelivery,NativeExim


class NativeSourceEvidenceTests(unittest.TestCase):
    def test_exact_hook_decision_and_native_receipt_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'mainlog';path.write_bytes(b'');native=NativeExim(log=path);checkpoint=native.checkpoint()
            event='a'*32;prefix='2026-11-19 07:00:00 source-id '
            path.write_text(prefix+'ClamShield decision=3 event='+event+'\n')
            self.assertEqual('unknown',native.observe_acceptance('source-id',event,3,checkpoint)['state'])
            with path.open('a') as stream:stream.write(prefix+'<= sender@test H=host [192.0.2.1] P=esmtp S=100\n')
            self.assertEqual('accepted',native.observe_acceptance('source-id',event,3,checkpoint)['state'])
            with self.assertRaises(Conflict):native.observe_acceptance('source-id',event,4,checkpoint)
            with self.assertRaises(Conflict):native.observe_acceptance('source-id','b'*32,3,checkpoint)
            self.assertEqual('unknown',native.observe_acceptance('unrelated-id',event,3,checkpoint)['state'])

    def test_explicit_rejection_can_resolve_but_silence_and_contradiction_cannot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'mainlog';path.write_bytes(b'');native=NativeExim(log=path);checkpoint=native.checkpoint()
            event='a'*32;prefix='2026-11-19 07:00:00 source-id '
            self.assertEqual('unknown',native.observe_acceptance('source-id',event,3,checkpoint)['state'])
            path.write_text(prefix+'F=sender@test U=root P=local-esmtp temporarily rejected by local_scan(): ClamShield mail check unavailable; please retry\n')
            self.assertEqual('rejected',native.observe_acceptance('source-id',event,3,checkpoint)['state'])
            with path.open('a') as stream:stream.write(prefix+'<= sender@test U=root P=local S=100\n')
            with self.assertRaises(Conflict):native.observe_acceptance('source-id',event,3,checkpoint)


class MailAcceptanceTests(unittest.TestCase):
    setUp=fixtures.MailCustodyTests.setUp
    request_for=fixtures.MailCustodyTests.request_for
    items=fixtures.MailCustodyTests.items
    capture=fixtures.MailCustodyTests.capture
    delivery=fixtures.MailCustodyTests.delivery
    blob=fixtures.MailCustodyTests.blob

    def armed(self,actions=('quarantine','quarantine')):
        native=Mock();native.checkpoint.return_value={'device':1,'inode':2,'offset':0}
        native.observe_acceptance.return_value={'state':'unknown'}
        request=replace(self.request,peer_pid=os.getpid(),peer_start=process_start(os.getpid()))
        staged=self.custody.stage(request,self.items(request,actions))
        acceptance=MailAcceptance(self.settings,self.store,self.native,native)
        response=acceptance.arm(staged,request)
        return acceptance,native,staged,request,response

    def test_sent_response_and_unknown_log_do_not_commit_preview_release_abort_or_deliver(self):
        acceptance,native,staged,request,response=self.armed(actions=('tag','deliver'))
        self.assertEqual(Decision.SELECTED,response['decision']);self.assertEqual([True,False],response['selected'])
        acceptance.response_sent(staged['transaction_id'])
        self.assertEqual('uncertain',acceptance.reconcile(staged['transaction_id']))
        with self.assertRaises(Conflict):self.custody.commit(staged['transaction_id'])
        with self.assertRaises(Conflict):self.custody.abort(staged['transaction_id'])
        with self.assertRaises(Conflict):self.custody.preview(self.alice,self.delivery(self.alice))
        worker=MailDelivery(self.settings,self.store,self.native,Mock())
        self.assertIsNone(worker.once()['attempt'])
        row=self.custody.list(self.alice)['messages'][0]
        self.assertEqual('uncertain',row['source_status']);self.assertNotIn('peer_pid',row);self.assertNotIn('metadata',row)

    def test_proven_native_acceptance_commits_only_then_and_is_idempotent(self):
        acceptance,native,staged,request,response=self.armed()
        self.assertEqual(Decision.HANDLED,response['decision']);self.assertIsNone(response['selected'])
        native.observe_acceptance.return_value={'state':'accepted','native_id':request.message_id,'event':staged['transaction_id'],'decision':3,'hook_seen':True}
        self.assertEqual('accepted',acceptance.reconcile(staged['transaction_id']))
        self.assertEqual('quarantined',self.custody.list(self.alice)['messages'][0]['status'])
        self.assertEqual('accepted',acceptance.reconcile(staged['transaction_id']))
        with self.assertRaises(Conflict):self.custody.abort(staged['transaction_id'])

    def test_proven_rejection_aborts_exact_unaccepted_bytes(self):
        acceptance,native,staged,request,response=self.armed()
        native.observe_acceptance.return_value={'state':'rejected','native_id':request.message_id}
        self.assertEqual('rejected',acceptance.reconcile(staged['transaction_id']))
        self.assertFalse(self.blob(staged['transaction_id']).exists())
        self.assertEqual([],self.custody.list(self.alice)['messages'])

    def test_kernel_process_changed_snapshot_and_repeat_arming_are_denied(self):
        acceptance,native,staged,request,response=self.armed()
        with self.assertRaises(Conflict):acceptance.arm(staged,request)
        changed=self.request_for();staged2=self.custody.stage(changed,self.items(changed))
        with self.assertRaises(AccessDenied):acceptance.arm(staged2,changed)
        with self.assertRaises(AccessDenied):acceptance.arm(staged2,replace(changed,peer_pid=os.getpid(),peer_start=request.peer_start+1))
        other=self.request_for(content=b'From: changed@test\n\nChanged contents')
        with self.assertRaises(Conflict):acceptance.arm(staged2,replace(other,message_id=changed.message_id,peer_pid=os.getpid(),peer_start=request.peer_start))

    def test_interruption_after_proof_uses_durable_evidence_without_rereading_lost_log(self):
        acceptance,native,staged,request,response=self.armed()
        native.observe_acceptance.return_value={'state':'accepted','native_id':request.message_id}
        with patch.object(acceptance.custody,'commit',side_effect=fixtures.Interrupted):
            with self.assertRaises(fixtures.Interrupted):acceptance.reconcile(staged['transaction_id'])
        native.observe_acceptance.side_effect=FileNotFoundError
        acceptance.recover()
        self.assertEqual('quarantined',self.custody.list(self.alice)['messages'][0]['status'])

    def test_recreated_account_retains_proven_mail_without_inheriting_or_aborting(self):
        acceptance,native,staged,request,response=self.armed()
        native.observe_acceptance.return_value={'state':'accepted','native_id':request.message_id}
        self.ids['alice']='recreated-generation'
        self.assertEqual('proven',acceptance.reconcile(staged['transaction_id']))
        self.assertTrue(self.blob(staged['transaction_id']).exists())
        with self.assertRaises(Conflict):self.custody.abort(staged['transaction_id'])
        self.assertEqual([],self.custody.list(self.native.authorize('alice'))['messages'])
