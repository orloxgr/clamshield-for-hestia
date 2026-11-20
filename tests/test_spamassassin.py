from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import fcntl
import unittest
from unittest.mock import patch, Mock

from clamshield.atomic import write, write_json
from clamshield.errors import AccessDenied, ClamShieldError, EngineError
from clamshield.settings import Settings
from clamshield.spamassassin import DEFAULTS, SpamAssassinControls, render, revision, validate
from clamshield.mail_policy import DEFAULTS as MAIL_DEFAULTS, evaluate
from clamshield.application import Application
from clamshield.spamassassin_binding import ARGUMENTS, commandline
from clamshield.mail_bridge import process_start


class Controls(SpamAssassinControls):
    active_service = False
    fail_probe = False

    def inspect(self, path):
        content = path.read_text()
        import re
        return dict(rules=[dict(name='GTUBE')],
                    required_score=float(re.search(r'^required_score (.+)$', content, re.M)[1]),
                    skip_rbl_checks=int(re.search(r'^skip_rbl_checks (\d)$', content, re.M)[1]),
                    skip_uribl_checks=int(re.search(r'^skip_uribl_checks (\d)$', content, re.M)[1]),
                    dns_query_blocked={zone:1 for zone in re.findall(r'^dns_query_restriction deny (.+)$', content, re.M)})

    def running(self):
        return self.active_service

    def _stop(self):
        self.active_service = False

    def _restart(self):
        self.active_service = True

    def probe(self, policy):
        if self.fail_probe and policy['required_score'] != 5:
            raise EngineError('Wrong loaded configuration')


class SpamAssassinControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(state=root/'state')
        self.controls = Controls(self.settings, base=root/'owned-config')
        self.controls.prepare()
        write(self.controls.active, render(DEFAULTS), 0o644)

    def test_structured_fields_reject_injection_nonfinite_unknown_and_credentials(self):
        for key, value in [('required_score', True), ('required_score', float('nan')),
                           ('required_score', 7.25), ('rbl_enabled', 1), ('scores', {'GTUBE\nloadplugin Evil': 1}),
                           ('scores', {'GTUBE': float('inf')}), ('scores', {'__INDIRECT': 0}),
                           ('scores', {'GTUBE': 0.00000001}),
                           ('scores', {'CLAMSHIELD_CONFIG_FORGED': 0}),
                           ('blocked_zones', ['foo.test\nuse_pyzor 1']), ('blocked_zones', ['*.example.test']),
                           ('blocked_zones', ['key@dns.example.test']), ('blocked_zones', ['-bad.test'])]:
            with self.subTest(key=key, value=value), self.assertRaises(ClamShieldError):
                validate(deepcopy(DEFAULTS) | {key: value})
        with self.assertRaises(ClamShieldError):
            validate(DEFAULTS | {'raw_config': 'loadplugin Evil'})

    def test_dns_controls_disable_lookups_not_just_visible_scores(self):
        content = render(DEFAULTS | dict(rbl_enabled=False, uribl_enabled=False,
                         blocked_zones=['zen.spamhaus.org'], scores={'GTUBE': 2.5}))
        for line in ('skip_rbl_checks 1', 'skip_uribl_checks 1',
                     'dns_query_restriction deny zen.spamhaus.org', 'score GTUBE 2.500000',
                     'use_pyzor 0', 'use_razor2 0', 'use_dcc 0'):
            self.assertIn(line, content.splitlines())

    def test_unavailable_rule_is_rejected_before_mutation_or_service_change(self):
        before = self.controls.active.read_bytes()
        with self.assertRaisesRegex(ClamShieldError, 'unavailable'):
            self.controls.apply(DEFAULTS | {'scores': {'DOES_NOT_EXIST': 2}})
        self.assertEqual(before, self.controls.active.read_bytes())
        self.assertFalse(self.controls.metadata.exists()); self.assertFalse(self.controls.journal.exists())

    def test_stopped_service_stays_stopped_and_failed_live_probe_restores_exact_state(self):
        first = self.controls.apply(DEFAULTS)
        self.assertFalse(first['service_restarted']); self.assertFalse(self.controls.running())
        before = self.controls.active.read_bytes(); metadata = self.controls.metadata.read_bytes()
        self.controls.active_service = True; self.controls.fail_probe = True
        with self.assertRaises(EngineError):
            self.controls.apply(DEFAULTS | {'required_score': 7})
        self.assertEqual(before, self.controls.active.read_bytes())
        self.assertEqual(metadata, self.controls.metadata.read_bytes())
        self.assertTrue(self.controls.running()); self.assertFalse(self.controls.journal.exists())

    def test_interrupted_apply_restores_journal_before_accepting_another_change(self):
        old = self.controls.apply(DEFAULTS)
        saved = dict(config=self.controls.active.read_text(), metadata=self.controls.configured(), was_active=True)
        write_json(self.controls.journal, saved)
        write(self.controls.active, render(DEFAULTS | {'required_score': 8}), 0o644)
        with self.assertRaisesRegex(EngineError, 'recovery'):
            self.controls.apply(DEFAULTS)
        self.assertTrue(self.controls.recover())
        self.assertEqual(old['revision'], self.controls.configured()['revision'])
        self.assertTrue(self.controls.running()); self.assertFalse(self.controls.recover())

    def test_symlink_or_changed_live_configuration_never_becomes_managed(self):
        self.controls.apply(DEFAULTS)
        target = self.controls.base/'unrelated'; target.write_text('unrelated')
        self.controls.active.unlink(); self.controls.active.symlink_to(target)
        with self.assertRaises(EngineError): self.controls.apply(DEFAULTS)
        self.assertEqual('unrelated', target.read_text())
        self.controls.active.unlink(); write(self.controls.active, render(DEFAULTS | {'required_score': 8}), 0o644)
        with self.assertRaises(EngineError): self.controls.configured()

    def test_spamassassin_and_domain_scores_are_retained_separately(self):
        hit = dict(engine='clamav', signature='Spam.Test', category='spam', provider='local',
                   source_id='test.hdb', source_version='1')
        report = dict(complete=True, detections=[hit], spam_score=2.5, spam_threshold=8,
                      spam_symbols=['GTUBE'], spamassassin_revision='a'*64)
        result = evaluate(MAIL_DEFAULTS | {'enabled': True}, report, sender='test@example.test', sha256='b'*64)
        self.assertEqual(7.5, result['spam_score']); self.assertEqual('junk', result['action'])
        self.assertEqual(dict(score=2.5, required_score=8, symbols=['GTUBE'], revision='a'*64), result['spamassassin'])
        for forged in ({'spam_threshold': float('nan')}, {'spam_symbols': ['A\nFORGED']},
                       {'spamassassin_revision': 'not-a-hash'}):
            self.assertEqual('defer', evaluate(MAIL_DEFAULTS | {'enabled': True}, report | forged,
                                             sender='test@example.test', sha256='b'*64)['action'])

    def test_tenant_cannot_query_catalog_status_or_queue_server_controls(self):
        class Hestia:
            def authorize(self, *_args): return dict(admin=False, actor='tenant', owner='tenant')
        app = Application(self.settings, None, Hestia())
        for action in ('spamassassin-save', 'spamassassin-status', 'spamassassin-catalog'):
            with self.subTest(action=action), self.assertRaises(AccessDenied):
                app.dispatch(dict(actor='tenant', action=action, policy=DEFAULTS, admin=True))

    def test_runtime_contract_rejects_score_include_user_and_socket_overrides(self):
        args = ['/usr/bin/perl', '-T -w', '/usr/sbin/spamd', *ARGUMENTS]
        self.assertFalse(commandline(args)); self.assertTrue(commandline(args+['--local']))
        for extra in (['--cf=score GTUBE 99'], ['--cf=include /tmp/other.cf'],
                      ['--user-config'], ['--socketpath=/tmp/forged'], ['--allow-tell']):
            with self.subTest(extra=extra), self.assertRaises(EngineError): commandline(args+extra)
        with self.assertRaises(EngineError): commandline(args[:-1])

    def binding_fixture(self):
        self.controls.apply(DEFAULTS)
        self.controls.runtime_stamp = Mock(return_value={'runtime':'one'})
        identity = dict(pid=99,birth=123,arguments_sha256='a'*64,local_mode=True)
        wanted = dict(revision=revision(DEFAULTS),identity=identity,runtime={'runtime':'one'})
        report = dict(score=1,threshold=5,symbols=[],_peer=dict(pid=99,birth=123))
        return identity,wanted,report

    def test_only_process_readiness_is_cached_and_new_process_needs_a_fresh_probe(self):
        identity,wanted,report = self.binding_fixture()
        self.controls.probe = Mock(side_effect=lambda *_args,**_kw:write_json(self.controls.proof,wanted))
        with patch('clamshield.spamassassin_binding.process', return_value=identity):
            self.controls.verify_report(report,DEFAULTS,deadline=1234)
            self.controls.probe.assert_called_once_with(DEFAULTS,deadline=1234)
            self.controls.verify_report(report|{'score':8},DEFAULTS)
            self.assertEqual(1,self.controls.probe.call_count)
            wanted['identity']=identity|{'birth':124}
        with patch('clamshield.spamassassin_binding.process',return_value=wanted['identity']):
            self.controls.verify_report(report|{'_peer':dict(pid=99,birth=124)},DEFAULTS)
            self.assertEqual(2,self.controls.probe.call_count)

    def test_busy_probe_or_process_change_cannot_authorize_a_score(self):
        identity,wanted,report = self.binding_fixture()
        self.controls.probe=Mock(side_effect=lambda *_args,**_kw:write_json(self.controls.proof,wanted))
        with patch('clamshield.spamassassin_binding.process', side_effect=[identity,identity|{'birth':999}]), self.assertRaises(EngineError):
            self.controls.verify_report(report,DEFAULTS)
        self.controls.proof.unlink()
        with (self.settings.state/'spamassassin-proof.lock').open('a+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with patch('clamshield.spamassassin_binding.process',return_value=identity),self.assertRaisesRegex(EngineError,'already running'):
                self.controls.verify_report(report,DEFAULTS)

    def test_runtime_file_changes_and_threshold_mismatch_invalidate_proof(self):
        identity,wanted,report = self.binding_fixture();write_json(self.controls.proof,wanted)
        self.controls.runtime_stamp.return_value={'runtime':'two'}
        self.controls.probe=Mock(side_effect=EngineError('New daemon could not be verified'))
        with patch('clamshield.spamassassin_binding.process',return_value=identity):
            with self.assertRaises(EngineError):self.controls.verify_report(report,DEFAULTS)
            self.controls.probe.assert_called_once()
            self.controls.probe.reset_mock()
            with self.assertRaises(EngineError):self.controls.verify_report(report|{'threshold':8},DEFAULTS)
            self.controls.probe.assert_not_called()

    def test_same_uid_process_outside_owned_daemon_cannot_supply_a_verdict(self):
        from clamshield.spamassassin_binding import process
        for peer in (None,dict(pid=os.getpid(),birth=process_start(os.getpid())),dict(pid=True,birth=1)):
            with self.subTest(peer=peer),self.assertRaises(EngineError):process(peer)
