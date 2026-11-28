from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
import fcntl
import unittest
from unittest.mock import patch, Mock

from clamshield.atomic import write, write_json
from clamshield.errors import AccessDenied, ClamShieldError, EngineError
from clamshield.settings import Settings
from clamshield.spamassassin import DEFAULTS, INFRASTRUCTURE_RULES, SpamAssassinControls, render, revision, validate
from clamshield.mail_policy import DEFAULTS as MAIL_DEFAULTS, evaluate
from clamshield.application import Application
from clamshield.spamassassin_binding import ARGUMENTS, commandline
from clamshield.mail_bridge import process_start, SEALS


class Controls(SpamAssassinControls):
    active_service = False
    fail_probe = False

    def inspect(self, path):
        content = path.read_text()
        import re
        return dict(rules=[dict(name='GTUBE')] + [dict(name=name, score=0, scores=[0]*4)
                                                for name in INFRASTRUCTURE_RULES],
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

    def probe(self, policy, **_kwargs):
        if self.fail_probe and policy['required_score'] != 5:
            raise EngineError('Wrong loaded configuration')


class SpamAssassinControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(state=root/'state')
        reporter = Path(__file__).resolve().parents[1] / 'tools/spamassassin-report.pm'
        replacement = patch('clamshield.spamassassin.REPORTER', reporter)
        replacement.start(); self.addCleanup(replacement.stop)
        self.controls = Controls(self.settings, base=root/'owned-config')
        self.reporter = reporter
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

    def test_administrative_dns_responses_cannot_receive_positive_or_negative_points(self):
        for name in INFRASTRUCTURE_RULES:
            self.assertIn('score ' + name + ' 0', render(DEFAULTS).splitlines())
            for amount in (1, .001, -1):
                with self.subTest(name=name, amount=amount), self.assertRaisesRegex(ClamShieldError, 'zero'):
                    validate(DEFAULTS | {'scores': {name: amount}})
        self.assertNotEqual(revision(DEFAULTS), revision(DEFAULTS, legacy=True))
        with self.assertRaisesRegex(ClamShieldError, 'zero'):
            validate(DEFAULTS | {'scores': {'RCVD_IN_VALIDITY_FUTURE_BLOCKED': 1}})

    def test_nonzero_inactive_score_set_is_rejected_before_configuration_or_service_change(self):
        original = self.controls.inspect
        def inspect(path):
            value = original(path)
            value['rules'][1]['scores'] = [0, 0, 1, 0]
            return value
        self.controls.inspect = inspect
        before = self.controls.active.read_bytes()
        with self.assertRaisesRegex(EngineError, 'still contributes'):
            self.controls.apply(DEFAULTS)
        self.assertEqual(before, self.controls.active.read_bytes())
        self.assertFalse(self.controls.metadata.exists())
        self.assertFalse(self.controls.journal.exists())

    def test_exact_owned_legacy_policy_upgrades_once_preserving_admin_choices(self):
        policy = validate(deepcopy(DEFAULTS) | {'required_score': 7, 'uribl_enabled': False,
                                             'scores': {'GTUBE': 4, INFRASTRUCTURE_RULES[0]: 1}}, legacy=True)
        write(self.controls.active, render(policy, legacy=True), 0o644)
        write_json(self.controls.metadata, dict(policy=policy, revision=revision(policy, legacy=True)))
        with self.assertRaises(ClamShieldError):
            self.controls.configured()
        self.assertTrue(self.controls.upgrade_safety())
        upgraded = self.controls.configured()['policy']
        self.assertEqual(7, upgraded['required_score'])
        self.assertFalse(upgraded['uribl_enabled'])
        self.assertEqual({'GTUBE': 4, INFRASTRUCTURE_RULES[0]: 0}, upgraded['scores'])
        self.assertFalse(self.controls.upgrade_safety())
        before = self.controls.active.read_bytes()
        with self.assertRaisesRegex(EngineError, 'changed before safety'):
            self.controls.apply(DEFAULTS, expected_revision=revision(DEFAULTS, legacy=True))
        self.assertEqual(before, self.controls.active.read_bytes())

    def test_upgrade_refuses_unrecognized_bytes_and_preserves_them(self):
        policy = deepcopy(DEFAULTS)
        write(self.controls.active, render(policy, legacy=True) + '# admin change\n', 0o644)
        write_json(self.controls.metadata, dict(policy=policy, revision=revision(policy, legacy=True)))
        before = self.controls.active.read_bytes()
        with self.assertRaises(EngineError):
            self.controls.upgrade_safety()
        self.assertEqual(before, self.controls.active.read_bytes())

    def test_previous_safety_version_is_upgraded_once_without_resetting_admin_policy(self):
        policy=deepcopy(DEFAULTS)|dict(required_score=7.1,uribl_enabled=False,scores={'GTUBE':9,'SURBL_BLOCKED':1})
        write(self.controls.active,render(policy,safety_version=1),0o644)
        write_json(self.controls.metadata,dict(policy=policy,revision=revision(policy,safety_version=1)))
        with self.assertRaises(ClamShieldError):self.controls.configured()
        self.assertTrue(self.controls.upgrade_safety());self.assertFalse(self.controls.upgrade_safety())
        configured=self.controls.configured()
        self.assertEqual(7.1,configured['policy']['required_score']);self.assertFalse(configured['policy']['uribl_enabled'])
        self.assertEqual({'GTUBE':9,'SURBL_BLOCKED':0},configured['policy']['scores'])
        for name in ('DKIMWL_BLOCKED','FROM_FMBLA_NDBLOCKED','SURBL_BLOCKED'):
            self.assertIn('score '+name+' 0\n',self.controls.active.read_text())

    def test_failed_safety_upgrade_restores_the_exact_previous_version_and_uses_its_probe(self):
        text=render(DEFAULTS,safety_version=1);write(self.controls.active,text,0o644)
        write_json(self.controls.metadata,dict(policy=DEFAULTS,revision=revision(DEFAULTS,safety_version=1)))
        self.controls.active_service=True;self.controls.probe=Mock(side_effect=[EngineError('New daemon failed'),{}])
        with self.assertRaises(EngineError):self.controls.upgrade_safety()
        self.assertEqual(text,self.controls.active.read_text());self.assertFalse(self.controls.journal.exists())
        self.assertEqual({'safety_version':1},self.controls.probe.call_args.kwargs)
        self.assertEqual(revision(DEFAULTS,safety_version=1),self.controls.configured(allow_legacy=True)['revision'])

    def test_dns_reporter_upgrade_preserves_version_two_policy_and_recovers_its_exact_revision(self):
        policy=deepcopy(DEFAULTS)|dict(required_score=7.1,uribl_enabled=False,scores={'GTUBE':9})
        text=render(policy,safety_version=2);write(self.controls.active,text,0o644)
        write_json(self.controls.metadata,dict(policy=policy,revision=revision(policy,safety_version=2)))
        self.controls.active_service=True;self.controls.probe=Mock(side_effect=[EngineError('New daemon failed'),{}])
        with self.assertRaises(EngineError):self.controls.upgrade_safety()
        self.assertEqual(text,self.controls.active.read_text());self.assertFalse(self.controls.journal.exists())
        self.assertEqual({'safety_version':2},self.controls.probe.call_args.kwargs)
        self.controls.probe=Mock()
        self.assertTrue(self.controls.upgrade_safety());self.assertFalse(self.controls.upgrade_safety())
        self.assertEqual(policy,self.controls.configured()['policy'])
        self.assertNotEqual(revision(policy,safety_version=2),self.controls.configured()['revision'])

    def test_future_administrator_notices_cannot_use_default_scores_or_cached_process_proof(self):
        rule=dict(name='FUTURE_ACCESS_NOTICE',description='ADMINISTRATOR NOTICE: The query to example.test was blocked.',score=1,scores=[1]*4)
        with self.assertRaises(EngineError):self.controls.verify_infrastructure_scores(dict(rules=[rule]))
        self.controls.verify_infrastructure_scores(dict(rules=[dict(rule,score=0,scores=[0]*4)]))
        identity,wanted,report=self.binding_fixture();write_json(self.controls.proof,wanted)
        with patch('clamshield.spamassassin_binding.process',return_value=identity),self.assertRaises(EngineError):
            self.controls.verify_report(report|{'rules':[rule]},DEFAULTS)

    def test_upgrade_recognizes_original_initial_settings_without_ui_metadata(self):
        initial = ('# Managed by clamshield\n'
                   '# Initial isolated daemon defaults. Structured UI activation adds a verified revision.\n' +
                   '\n'.join(render(DEFAULTS, legacy=True).splitlines()[1:-2]) + '\n')
        write(self.controls.active, initial, 0o644)
        self.assertFalse(self.controls.metadata.exists())
        self.assertTrue(self.controls.upgrade_safety())
        self.assertEqual(revision(DEFAULTS), self.controls.configured()['revision'])
        before = self.controls.active.read_bytes()
        with self.assertRaisesRegex(EngineError, 'configuration changed before safety'):
            self.controls.apply(DEFAULTS, expected_configuration='0'*64)
        self.assertEqual(before, self.controls.active.read_bytes())

    def test_missing_validation_helper_reports_reinstall_before_starting_parser(self):
        missing_source = Path(self.temp.name) / 'incomplete/src/clamshield/spamassassin.py'
        with patch('clamshield.spamassassin.__file__', str(missing_source)), \
                patch('clamshield.spamassassin.subprocess.Popen') as parser:
            with self.assertRaisesRegex(EngineError, 'validation helper is missing'):
                SpamAssassinControls.inspect(self.controls, self.controls.active)
        parser.assert_not_called()

    def test_real_ubuntu_parser_checks_configuration_as_isolated_account(self):
        if os.geteuid() != 0 or not shutil.which('perl') or not shutil.which('setpriv'):
            self.skipTest('Requires root and Ubuntu SpamAssassin validation dependencies')
        try:
            pwd.getpwnam('debian-spamd')
        except KeyError:
            self.skipTest('Requires Ubuntu spamd account')
        # Allow the isolated parser to traverse only this test's configuration tree.
        Path(self.temp.name).chmod(0o755)
        before = self.controls.active.read_bytes()
        parsed = SpamAssassinControls.inspect(self.controls, self.controls.active)
        self.assertEqual(5.0, parsed['required_score'])
        self.assertEqual(0, parsed['skip_rbl_checks'])
        self.assertEqual(0, parsed['skip_uribl_checks'])
        self.assertIn('GTUBE', {rule['name'] for rule in parsed['rules']})
        self.controls.verify_infrastructure_scores(parsed)
        guarded = [rule for rule in parsed['rules'] if rule['name'] in INFRASTRUCTURE_RULES]
        self.assertTrue(guarded)
        self.assertTrue(all(rule['scores'] == [0]*4 for rule in guarded))
        self.assertIn('CLAMSHIELD_CONFIG_' + revision(DEFAULTS)[:16],
                      {rule['name'] for rule in parsed['rules']})
        self.assertEqual(before, self.controls.active.read_bytes())
        self.assertFalse(self.controls.metadata.exists())
        self.assertFalse(self.controls.journal.exists())
        invalid = self.controls.base / 'invalid.cf'
        write(invalid, render(DEFAULTS) + 'clamshield_invalid_directive 1\n', 0o644)
        with self.assertRaisesRegex(EngineError, 'configuration validation failed'):
            SpamAssassinControls.inspect(self.controls, invalid)

    def test_real_spamassassin_missing_admin_scores_do_not_turn_transactional_fixture_into_spam(self):
        if not Path('/usr/bin/spamassassin').exists():
            self.skipTest('Requires Ubuntu SpamAssassin')
        fixture = self.controls.base / 'fixture.cf'
        lines = ['loadplugin Mail::SpamAssassin::Plugin::Check',
                 'loadplugin Mail::SpamAssassin::Plugin::URIDNSBL',
                 'util_rb_tld com net org test invalid']
        for name in INFRASTRUCTURE_RULES[:3]:
            # Deliberately no score: reproduce the engine's implicit +1 default.
            lines += [f'header {name} X-Lab-Validity =~ /blocked/', f'describe {name} Lab access failure']
        lines += ['header LAB_TRANSACTIONAL X-Lab-Validity =~ /blocked/',
                  'describe LAB_TRANSACTIONAL Lab transactional pattern', 'score LAB_TRANSACTIONAL 2.503',
                  'header LAB_CREDITS X-Lab-Validity =~ /blocked/',
                  'describe LAB_CREDITS Lab legitimate signals', 'score LAB_CREDITS -0.108']
        fixture.write_text('\n'.join(lines) + '\n')
        empty = self.controls.base / 'empty'; empty.mkdir()
        legacy = self.controls.base / 'legacy.cf'; legacy.write_text(render(DEFAULTS, legacy=True))
        script = r'''
use strict; use warnings; use Mail::SpamAssassin; use JSON::PP;
my ($rules, $site, $config) = @ARGV;
my $sa = Mail::SpamAssassin->new({rules_filename=>$rules, site_rules_filename=>$site,
  userprefs_filename=>'/dev/null', dont_copy_prefs=>1, local_tests_only=>1,
  post_config_text=>"include $config\n"});
die "Invalid fixture configuration" if $sa->lint_rules();
my $mail = $sa->parse("From: sender\@example.test\nTo: recipient\@example.test\n" .
  "Subject: Transactional notification\nX-Lab-Validity: blocked\n\nHarmless content.\n");
my $status = $sa->check($mail);
print JSON::PP->new->canonical->encode({score=>0+$status->get_score(),
  required=>0+$status->get_required_score(), spam=>0+$status->is_spam(),
  symbols=>$status->get_names_of_tests_hit_with_scores(), report=>$status->get_report()});
$status->finish(); $mail->finish(); $sa->finish();
'''
        def scan(config):
            result = subprocess.run(['/usr/bin/perl', '-e', script, str(fixture), str(empty), str(config)],
                                    capture_output=True, timeout=25)
            self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
            return json.loads(result.stdout)
        before, after = scan(legacy), scan(self.controls.active)
        self.assertAlmostEqual(5.395, before['score'], places=6)
        self.assertTrue(before['spam'])
        self.assertAlmostEqual(2.395, after['score'], places=6)
        self.assertFalse(after['spam'])
        self.assertEqual(5, after['required'])
        self.assertIn('LAB_TRANSACTIONAL=2.503', after['symbols'])
        from clamshield.spam_report import parse
        detail = parse(after['report'].encode('ascii'))
        self.assertEqual(revision(DEFAULTS), detail['revision'])
        self.assertEqual(hashlib.sha256(self.reporter.read_bytes()).hexdigest(), detail['reporter_sha256'])
        self.assertAlmostEqual(2.395, detail['score'], places=6)
        self.assertEqual({'LAB_TRANSACTIONAL': 2.503, 'LAB_CREDITS': -.108},
                         {rule['name']: rule['score'] for rule in detail['rules']})
        for name in INFRASTRUCTURE_RULES[:3]:
            self.assertNotIn(name + '=1', after['symbols'])

    def test_real_report_fills_missing_descriptions_without_changing_contributions(self):
        if not Path('/usr/bin/spamassassin').exists():
            self.skipTest('Requires Ubuntu SpamAssassin')
        fixture = self.controls.base / 'descriptions.cf'
        fixture.write_text('loadplugin Mail::SpamAssassin::Plugin::Check\n'
                           'loadplugin Mail::SpamAssassin::Plugin::URIDNSBL\n'
                           'util_rb_tld com net org test invalid\n'
                           'header TVD_SPACE_RATIO X-Lab-Description =~ /fixture/\n'
                           'score TVD_SPACE_RATIO 0.25\n'
                           'header LAB_UNDESCRIBED X-Lab-Description =~ /fixture/\n'
                           'score LAB_UNDESCRIBED 0.75\n'
                           'header LAB_DESCRIBED X-Lab-Description =~ /fixture/\n'
                           'score LAB_DESCRIBED -0.125\n'
                           'describe LAB_DESCRIBED Upstream description retained\n')
        empty = self.controls.base / 'description-empty'; empty.mkdir()
        script = r'''
use strict; use warnings; use Mail::SpamAssassin;
my ($rules, $site, $config) = @ARGV;
my $sa = Mail::SpamAssassin->new({rules_filename=>$rules, site_rules_filename=>$site,
  userprefs_filename=>'/dev/null', dont_copy_prefs=>1, local_tests_only=>1,
  post_config_text=>"include $config\n"});
die "Invalid fixture configuration" if $sa->lint_rules();
my $mail = $sa->parse("From: sender\@example.test\nTo: inbox\@example.test\n" .
  "Subject: Description fixture\nX-Lab-Description: fixture\n\nHarmless content.\n");
my $status = $sa->check($mail); print $status->get_report();
$status->finish(); $mail->finish(); $sa->finish();
'''
        result = subprocess.run(['/usr/bin/perl', '-e', script, str(fixture), str(empty), str(self.controls.active)],
                                capture_output=True, timeout=25)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
        from clamshield.spam_report import parse
        report = parse(result.stdout)
        self.assertEqual(.875, report['score'])
        rules = {r['name']: r for r in report['rules']}
        self.assertEqual({'TVD_SPACE_RATIO': .25, 'LAB_UNDESCRIBED': .75, 'LAB_DESCRIBED': -.125},
                         {name: rule['score'] for name, rule in rules.items()})
        self.assertIn('ClamShield explanation:', rules['TVD_SPACE_RATIO']['description'])
        self.assertIn('very few spaces', rules['TVD_SPACE_RATIO']['description'])
        self.assertEqual('SpamAssassin did not provide a description for this rule', rules['LAB_UNDESCRIBED']['description'])
        self.assertEqual('Upstream description retained', rules['LAB_DESCRIBED']['description'])

    def test_real_spamd_report_carries_actual_scores_and_configuration_canary(self):
        if os.geteuid() != 0 or not Path('/usr/sbin/spamd').exists():
            self.skipTest('Requires Ubuntu spamd and isolated account')
        try:
            account = pwd.getpwnam('debian-spamd')
        except KeyError:
            self.skipTest('Requires Ubuntu spamd account')
        Path(self.temp.name).chmod(0o755)
        runtime = self.controls.base / 'runtime'; runtime.mkdir()
        os.chown(runtime, account.pw_uid, account.pw_gid); runtime.chmod(0o700)
        endpoint = runtime / 'spamd.sock'
        arguments = ['/usr/bin/setpriv', '--reuid=debian-spamd', '--regid=debian-spamd',
                     '--init-groups', '--no-new-privs', '/usr/sbin/spamd', '--local', '--nouser-config',
                     '--max-children=1', '--min-children=1', '--min-spare=1', '--max-spare=1',
                     '--socketpath=' + str(endpoint), '--socketmode=600',
                     '--pidfile=' + str(runtime/'spamd.pid'), '--cf=include ' + str(self.controls.active)]
        fd = os.memfd_create('clamshield-test-spamd', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        payload = ('From: sender@example.test\r\nTo: recipient@example.test\r\n'
                   'Subject: Inert GTUBE test\r\nX-ClamShield-Config: ' + revision(DEFAULTS) +
                   '\r\n\r\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n')
        os.write(fd, payload.encode()); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        try:
            with tempfile.TemporaryFile() as log:
                child = subprocess.Popen(arguments, stdout=log, stderr=log, start_new_session=True)
                try:
                    deadline = time.monotonic() + 12
                    while not endpoint.exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(.05)
                    if not endpoint.exists():
                        log.seek(0); self.fail(log.read().decode(errors='replace'))
                    from clamshield.mail_scanners import SpamAssassin
                    report = SpamAssassin(endpoint, expected_uid=account.pw_uid, timeout=10).scan(fd)
                    self.assertEqual(revision(DEFAULTS), report['revision'])
                    self.assertGreaterEqual(report['score'], 1000)
                    hits = {rule['name']: rule for rule in report['rules']}
                    self.assertEqual(1000, hits['GTUBE']['score'])
                    self.assertEqual(.001, hits['CLAMSHIELD_CONFIG_' + revision(DEFAULTS)[:16]]['score'])
                finally:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
        finally:
            os.close(fd)

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
            self.assertEqual('deliver', evaluate(MAIL_DEFAULTS | {'enabled': True}, report | forged,
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
        digest = hashlib.sha256(self.reporter.read_bytes()).hexdigest()
        stamp = {'runtime': 'one', str(self.reporter): digest}
        self.controls.runtime_stamp = Mock(return_value=stamp)
        identity = dict(pid=99,birth=123,arguments_sha256='a'*64,local_mode=True)
        wanted = dict(revision=revision(DEFAULTS),identity=identity,runtime=stamp)
        report = dict(score=1,threshold=5,symbols=[],revision=revision(DEFAULTS),reporter_sha256=digest,_peer=dict(pid=99,birth=123))
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

    def test_old_report_plugin_or_nonzero_admin_contribution_cannot_use_cached_proof(self):
        identity,wanted,report = self.binding_fixture()
        write_json(self.controls.proof, wanted)
        for changes in ({'reporter_sha256': '0'*64}, {'revision': '0'*64},
                        {'rules': [dict(name=INFRASTRUCTURE_RULES[0], score=1)]},
                        {'rules': [dict(name='RCVD_IN_VALIDITY_FUTURE_BLOCKED', score=1)]}):
            with self.subTest(changes=changes), patch('clamshield.spamassassin_binding.process', return_value=identity), \
                    self.assertRaises(EngineError):
                self.controls.verify_report(report | changes, DEFAULTS)

    def test_historical_contributions_survive_policy_changes_and_invalid_details_stay_incomplete(self):
        from clamshield.mail_scanners import SpamAssassin
        from test_mail_scanners import contribution_response
        spam = SpamAssassin.parse(contribution_response(2.395), require_details=True)
        report = dict(complete=True, detections=[], spam_score=spam['score'], spam_threshold=spam['threshold'],
                      spam_symbols=spam['symbols'], spamassassin_revision=spam['revision'],
                      spam_report={key: spam[key] for key in
                                   ('score', 'threshold', 'rules', 'engine_version', 'rules_version', 'reporter_sha256')})
        outcome = evaluate(MAIL_DEFAULTS | {'enabled': True}, report, sender='sender@example.test', sha256='b'*64)
        self.assertEqual('deliver', outcome['action'])
        self.assertEqual(2.395, outcome['spamassassin']['rules'][0]['score'])
        self.assertEqual('123456', outcome['spamassassin']['rules_version'])
        damaged = deepcopy(report); damaged['spam_report']['rules'][0]['score'] = 10
        self.assertEqual('deliver', evaluate(MAIL_DEFAULTS | {'enabled': True}, damaged,
                                         sender='sender@example.test', sha256='b'*64)['action'])
        self.controls.apply(DEFAULTS | {'scores': {'GTUBE': 99}})
        self.assertEqual(2.395, outcome['spamassassin']['rules'][0]['score'])

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
        self.controls.runtime_stamp.return_value=wanted['runtime'] | {'runtime':'two'}
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
