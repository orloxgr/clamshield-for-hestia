from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock

from clamshield.application import Application
from clamshield.errors import AccessDenied, ClamShieldError
from clamshield.hestia import Hestia
from clamshield import mail_inventory
from clamshield.mail_policy import DEFAULTS, PERMISSIONS, MailPolicies, effective, evaluate, transaction_plan, validate
from clamshield.settings import Settings
from clamshield.store import Store


def scan(category=None, score=0):
    return {'complete': True, 'errors': [], 'spam_score': score, 'detections':
            [{'engine': 'clamav', 'signature': 'Fixture.Signature', 'category': category}] if category else []}


class MailPolicyTests(unittest.TestCase):
    def test_selected_domain_avoids_reading_unrelated_mailboxes(self):
        self.domain_rows['alice']['unrelated.test']={}
        self.native.call.reset_mock()
        row,box=self.mail.target(self.context,'alice.test','first')
        self.assertEqual('alice.test',row['domain']);self.assertEqual('first',box)
        reads=[call.args for call in self.native.call.call_args_list if call.args[0]=='v-list-mail-accounts']
        self.assertEqual([('v-list-mail-accounts','alice','alice.test','json')],reads)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name)); self.store = Store(self.settings.database)
        self.ids = {'alice': 'alice-generation', 'bob': 'bob-generation', 'admin': 'admin-generation'}
        self.native = Hestia(); self.native.identity = lambda owner: self.ids[owner]
        self.native.call = Mock(side_effect=self.call)
        self.mail = MailPolicies(self.store, self.native)
        self.context = self.native.authorize('alice')
        self.domain_rows = {'alice': {'alice.test': {'ANTIVIRUS': 'yes', 'ANTISPAM': 'yes', 'REJECT': 'no'}},
                            'bob': {'bob.test': {}}, 'admin': {}}
        self.account_rows = {'alice.test': {'first': {'ALIAS': 'alias', 'FWD_ONLY': 'no'}, 'second': {}},
                             'bob.test': {'other': {}}}

    def call(self, command, *args):
        if command == 'v-list-user':
            return {args[0]: {'ROLE': 'admin' if args[0] == 'admin' else 'user', 'SUSPENDED': 'no'}}
        if command == 'v-list-users':
            return {name: {'SUSPENDED': 'no'} for name in self.ids}
        if command == 'v-list-mail-domains':
            return deepcopy(self.domain_rows[args[0]])
        if command == 'v-list-mail-accounts':
            return deepcopy(self.account_rows[args[1]])
        raise AssertionError(command)

    def policy(self, **kwargs):
        return effective(validate({'enabled': True, **kwargs}))

    def verdict(self, result=None, **policy):
        return evaluate(self.policy(**policy), result or scan(), sender='sender@remote.test', sha256='a' * 64, now=100)

    def test_native_inventory_sanitizes_and_resolves_alias_without_plus_guess(self):
        self.account_rows['alice.test']['first']['PASSWORD'] = 'must-not-escape'
        rows = mail_inventory.inventory(self.native)
        self.assertNotIn('must-not-escape', str(rows))
        target = mail_inventory.resolve(rows, 'alias@ALICE.TEST')
        self.assertEqual(('alice', 'first'), (target['owner'], target['mailbox']))
        self.assertEqual('', mail_inventory.resolve(rows, 'first+suffix@alice.test')['mailbox'])
        self.assertIsNone(mail_inventory.resolve(rows, 'remote@remote.test'))
        self.account_rows['alice.test']['second']['ALIAS'] = 'alias'
        with self.assertRaises(ClamShieldError):
            mail_inventory.resolve(mail_inventory.inventory(self.native), 'alias@alice.test')

    def test_native_identity_change_or_partial_inventory_fails(self):
        self.native.identity = Mock(side_effect=['old', 'new'])
        with self.assertRaises(AccessDenied):
            mail_inventory.domains(self.native, 'alice')
        self.native.identity = lambda owner: self.ids[owner]
        self.native.call = Mock(side_effect=ClamShieldError('Native inventory failed'))
        with self.assertRaises(ClamShieldError):
            self.mail.list(self.context)

    def test_domain_and_mailbox_overrides_retain_inheritance(self):
        self.mail.save(self.context, 'alice.test', '', {'enabled': True, 'spam_threshold': 6})
        self.mail.save(self.context, 'alice.test', 'first', {'spam_action': 'tag'})
        self.mail.save(self.context, 'alice.test', '', {'enabled': True, 'spam_threshold': 8})
        value = self.mail.get(self.context, 'alice.test', 'first')
        self.assertEqual({'spam_action': 'tag'}, value['overrides'])
        self.assertEqual(8, value['effective']['spam_threshold'])
        self.assertTrue(value['effective']['enabled'])
        self.assertEqual('junk', self.mail.get(self.context, 'alice.test', 'second')['effective']['spam_action'])
        self.mail.save(self.context, 'alice.test', 'first', None, reset=True)
        self.assertEqual('junk', self.mail.get(self.context, 'alice.test', 'first')['effective']['spam_action'])

    def test_domain_change_cannot_invalidate_mailbox_thresholds(self):
        self.mail.save(self.context, 'alice.test', 'first', {'spam_high_threshold': 8})
        with self.assertRaises(ClamShieldError):
            self.mail.save(self.context, 'alice.test', '', {'spam_threshold': 9})
        self.assertEqual(5, self.mail.get(self.context, 'alice.test')['effective']['spam_threshold'])

    def test_admin_controls_tenant_policy_and_exception_permissions(self):
        admin = self.native.authorize('admin', 'alice')
        self.mail.save_permissions(admin, PERMISSIONS | {'manage_policy': False})
        with self.assertRaises(AccessDenied):
            self.mail.save(self.context, 'alice.test', '', {'enabled': True})
        with self.assertRaises(AccessDenied):
            self.mail.save_permissions(self.context, PERMISSIONS)
        self.mail.save_permissions(admin, PERMISSIONS | {'manage_exceptions': False})
        self.mail.save(self.context, 'alice.test', '', {'enabled': True})
        with self.assertRaises(AccessDenied):
            self.mail.save(self.context, 'alice.test', '', {'exceptions': [self.exception()]})
        self.mail.save(admin, 'alice.test', '', {'exceptions': [self.exception()]})

    def exception(self):
        return {'engine': 'clamav', 'signature': 'Fixture.Signature', 'sha256': 'a' * 64, 'expires': 200, 'reason': 'Verified fixture false positive'}

    def test_spam_allowlist_never_suppresses_malware_or_phishing(self):
        for category, expected in (('malware', 'reject'), ('phishing', 'quarantine')):
            verdict = self.verdict(scan(category, score=1000), allow_senders=['*@remote.test'])
            self.assertEqual(expected, verdict['action'])
        self.assertEqual('allowlisted', self.verdict(scan(score=1000), allow_senders=['*@remote.test'])['classification'])
        self.assertEqual('quarantine', self.verdict(scan(), allow_senders=['*@remote.test'], block_senders=['sender@remote.test'])['action'])

    def test_signature_scoring_thresholds_and_action_precedence(self):
        self.assertEqual('junk', self.verdict(scan('spam'))['action'])
        self.assertEqual('reject', self.verdict(scan(score=16))['action'])
        self.assertEqual('tag', self.verdict(scan('spam'), spam_action='tag')['action'])
        result = scan('phishing', score=50)
        self.assertEqual('reject', self.verdict(result)['action'])

    def test_incomplete_or_malformed_scans_never_deliver_even_if_allowlisted(self):
        for value in (scan() | {'complete': False}, scan() | {'errors': ['timeout']},
                      scan() | {'spam_score': float('nan')}, scan() | {'spam_score': None},
                      scan() | {'detections': [{}]}, scan() | {'detections': [{'engine': 'clamav', 'signature': 'x', 'category': 'unknown'}]}):
            verdict = self.verdict(value, allow_senders=['*@remote.test'])
            self.assertEqual('defer', verdict['action']); self.assertFalse(verdict['scan_complete'])

    def test_false_positive_exception_requires_same_hash_engine_rule_and_unexpired_time(self):
        policy = self.policy(exceptions=[self.exception()])
        result = evaluate(policy, scan('malware'), sender='', sha256='a' * 64, now=100)
        self.assertEqual('excepted', result['classification']); self.assertEqual(1, len(result['suppressed']))
        for digest, now in (('b' * 64, 100), ('a' * 64, 201)):
            self.assertEqual('reject', evaluate(policy, scan('malware'), sender='', sha256=digest, now=now)['action'])
        changed = scan('malware'); changed['detections'][0]['signature'] = 'Other.Signature'
        self.assertEqual('reject', evaluate(policy, changed, sender='', sha256='a' * 64, now=100)['action'])

    def test_policy_and_decisions_scope_survives_account_recreation(self):
        self.mail.save(self.context, 'alice.test', '', {'enabled': True})
        target = mail_inventory.resolve(self.mail.targets(self.context), 'first@alice.test')
        request = SimpleNamespace(message_id='native-exim-id', sender='sender@remote.test', recipients=('first@alice.test', 'other@bob.test'))
        self.mail.record(self.context, target, request, 'a' * 64, self.verdict(scan('malware')))
        history = self.mail.decisions(self.context)
        self.assertEqual(1, history['total']); self.assertNotIn('other@bob.test', str(history))
        self.assertEqual(0, self.mail.decisions(self.native.authorize('bob'))['total'])
        self.assertEqual(0, self.mail.decisions(self.context, search='%')['total'])
        self.ids['alice'] = 'new-generation'
        with self.assertRaises(AccessDenied):
            self.mail.decisions(self.context)
        recreated = self.native.authorize('alice')
        self.assertEqual(0, self.mail.decisions(recreated)['total'])
        self.assertFalse(self.mail.get(recreated, 'alice.test')['effective']['enabled'])

    def test_root_api_rejects_forged_owner_domain_mailbox_and_internal_verdict_endpoint(self):
        app = Application(self.settings, self.store, self.native)
        for value in ({'action': 'mail-dashboard', 'owner': 'bob'},
                      {'action': 'mail-policy-get', 'domain': 'bob.test'},
                      {'action': 'mail-policy-save', 'domain': 'alice.test', 'mailbox': 'not-a-mailbox', 'policy': {}},
                      {'action': 'mail-verdict', 'scan': scan()}):
            with self.assertRaises(AccessDenied):
                app.dispatch({'actor': 'alice', **value})
        result = app.dispatch({'actor': 'alice', 'action': 'mail-policy-save', 'domain': 'alice.test', 'policy': {'enabled': True}})
        self.assertTrue(result['effective']['enabled'])
        self.assertFalse(app.dispatch({'actor': 'alice', 'action': 'mail-dashboard'})['transport_active'])

    def test_invalid_policy_values_are_rejected(self):
        for value in ({'enabled': 'true'}, {'spam_threshold': float('inf')}, {'spam_threshold': True},
                      {'spam_threshold': 10 ** 1000}, {'malware_action': []}, {'allow_senders': ['*@remote.test\nBcc:x']},
                      {'exceptions': [self.exception() | {'sha256': '*'}]}, {'unknown': True}):
            with self.assertRaises(ClamShieldError):
                validate(value)

    def test_native_permitted_local_names_and_single_label_domains_are_not_guessed_away(self):
        self.domain_rows['alice']['mailhost'] = {}
        self.account_rows['mailhost'] = {'.native-name': {}}
        rows = self.mail.targets(self.context)
        self.assertEqual('.native-name', mail_inventory.resolve(rows, '.native-name@mailhost')['mailbox'])
        self.domain_rows['alice']['mailhost']['SUSPENDED'] = 'yes'
        with self.assertRaises(AccessDenied):
            self.mail.get(self.context, 'mailhost')

    def test_history_pages_are_byte_bounded_and_do_not_omit_following_records(self):
        target = mail_inventory.resolve(self.mail.targets(self.context), 'first@alice.test')
        request = SimpleNamespace(message_id='native-exim-id', sender='sender@remote.test', recipients=('first@alice.test',))
        decision = self.verdict() | {'evidence': 'x' * 200000}
        for _ in range(20):
            self.mail.record(self.context, target, request, 'a' * 64, decision)
        first = self.mail.decisions(self.context)
        self.assertLess(len(first['decisions']), 20); self.assertGreater(len(first['decisions']), 0)
        second = self.mail.decisions(self.context, offset=first['next_offset'])
        self.assertEqual(20, len(first['decisions']) + len(second['decisions']))
        self.assertIsNone(second['next_offset'])
        with self.assertRaises(AccessDenied):
            self.mail.record(self.context, target | {'recipient': 'other@bob.test'}, request, 'a' * 64, decision)

    def test_mixed_recipient_transaction_never_captures_while_rejecting_or_deferring(self):
        decisions = [{'action': 'junk'}, {'action': 'deliver'}, {'action': 'quarantine'}]
        self.assertEqual({'smtp': 'accept', 'custody': [0, 2], 'native': [1]}, transaction_plan(decisions))
        self.assertEqual({'smtp': 'reject', 'custody': [], 'native': []}, transaction_plan(decisions + [{'action': 'reject'}]))
        self.assertEqual({'smtp': 'defer', 'custody': [], 'native': []}, transaction_plan(decisions + [{'action': 'reject'}, {'action': 'defer'}]))
