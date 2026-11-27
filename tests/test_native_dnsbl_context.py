import json
import unittest

from clamshield.native_dnsbl_context import observe,verified_listing
from clamshield.mail_policy import effective,evaluate


class NativeDnsblContextTests(unittest.TestCase):
    def decision(self,zone,value,**policy):
        return evaluate(effective(dict(enabled=True,spam_action='tag')|policy),
                        dict(complete=True,errors=[],spam_score=1.25,detections=[]),
                        sender='sender@example.test',sha256='a'*64,native_dnsbl=(zone,value))

    def test_actual_listing_uses_selected_spam_action_without_inventing_score_points(self):
        result=self.decision('zen.spamhaus.org','127.0.0.2')
        self.assertEqual(('tag','spam',1.25,True),(result['action'],result['classification'],result['spam_score'],result['scan_complete']))
        self.assertEqual(0,result['native_dnsbl']['score_contribution'])
        self.assertEqual(['127.0.0.2'],result['native_dnsbl']['listing_codes'])
        result=self.decision('bl.spamcop.net','127.0.0.2',spam_action='reject')
        self.assertEqual(('reject','spam'),(result['action'],result['classification']))

    def test_all_spamhaus_administrative_replies_are_zero_point_incomplete_delivery(self):
        for number in range(256):
            with self.subTest(number=number):
                result=self.decision('zen.spamhaus.org','127.255.255.'+str(number))
                self.assertEqual(('deliver','incomplete',1.25,False),(result['action'],result['classification'],result['spam_score'],result['scan_complete']))
                self.assertEqual('blocked',result['native_dnsbl']['state'])
                self.assertEqual(['NativeDnsblUnavailable'],result['scan_errors'])

    def test_ignored_administrative_reply_does_not_hide_later_genuine_listing(self):
        result=self.decision('zen.spamhaus.org','127.255.255.251, 127.0.0.2, 127.0.0.2')
        self.assertEqual(('tag','spam',False),(result['action'],result['classification'],result['scan_complete']))
        self.assertEqual(['127.0.0.2'],result['native_dnsbl']['listing_codes'])
        self.assertEqual(['127.255.255.251'],result['native_dnsbl']['error_codes'])

    def test_dqs_key_and_unknown_zone_names_never_enter_stored_explanations(self):
        for zone in ('private-key.zen.dq.spamhaus.net','recipient-and-key.other.example.test'):
            result=self.decision(zone,'127.0.0.2')
            self.assertNotIn('private-key',json.dumps(result));self.assertNotIn('recipient-and-key',json.dumps(result))
        self.assertEqual('dqs',self.decision('private-key.zen.dq.spamhaus.net','127.0.0.2')['native_dnsbl']['access'])
        self.assertEqual('unsupported',self.decision('private-key.other.example.test','127.0.0.2')['native_dnsbl']['state'])

    def test_unknown_malformed_and_wrong_query_type_responses_are_not_guessed_as_spam(self):
        for zone,value in [('zen.spamhaus.org','127.0.0.99'),('other.example.test','127.0.0.2'),
                           ('dbl.spamhaus.org','127.0.1.255'),('zrd.spamhaus.org','127.0.2.255'),
                           ('hbl.spamhaus.org','127.0.3.255'),('list.dnswl.org','127.0.0.2'),
                           ('zen.spamhaus.org','192.0.2.45'),('zen.spamhaus.org','not-an-address'),
                           ('','127.0.0.2'),('zen..spamhaus.org','127.0.0.2'),('zen.spamhaus.org','')]:
            with self.subTest(zone=zone,value=value):
                result=self.decision(zone,value)
                self.assertEqual(('deliver','incomplete',False),(result['action'],result['classification'],result['scan_complete']))
                self.assertEqual(1.25,result['spam_score']);self.assertNotIn('192.0.2.45',json.dumps(result))

    def test_explicit_sender_spam_allowlist_does_not_make_a_malware_exception(self):
        result=self.decision('zen.spamhaus.org','127.0.0.2',allow_senders=['sender@example.test'])
        self.assertEqual(('deliver','allowlisted'),(result['action'],result['classification']))
        result=evaluate(effective(dict(enabled=True,malware_action='tag',allow_senders=['sender@example.test'])),
                        dict(complete=True,errors=[],spam_score=0,detections=[dict(engine='clamav',signature='Eicar-Test-Signature',category='malware')]),
                        sender='sender@example.test',sha256='a'*64,native_dnsbl=('zen.spamhaus.org','127.255.255.251'))
        self.assertEqual(('tag','malware',False),(result['action'],result['classification'],result['scan_complete']))

    def test_absent_context_is_absent_not_an_invented_successful_native_query(self):
        self.assertIsNone(observe('',''))
        result=self.decision('','');self.assertNotIn('native_dnsbl',result);self.assertTrue(result['scan_complete'])
        self.assertEqual('clean',result['classification'])

    def test_partial_scan_custody_requires_consistent_recognized_native_evidence(self):
        original=observe('private-key.zen.dq.spamhaus.net','127.255.255.251,127.0.0.2')
        self.assertTrue(verified_listing(original))
        for change in (dict(source='header'),dict(listing_codes=['127.0.0.99']),dict(state='clean'),dict(score_contribution=3)):
            self.assertFalse(verified_listing(original|change))
        for value in (None,{},observe('zen.spamhaus.org','127.255.255.251'),observe('other.test','127.0.0.2')):
            self.assertFalse(verified_listing(value))
