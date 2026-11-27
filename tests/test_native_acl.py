import unittest

from clamshield.errors import Conflict,EngineError
from clamshield.native_acl import render,fallback
from clamshield.native_mime_context import observe,verified

BASE='''acl_smtp_mail = acl_check_mail
acl_smtp_rcpt = acl_check_rcpt
acl_smtp_mime = acl_check_mime
begin acl
acl_check_mail:
  deny senders = forbidden@example.test
  accept

acl_check_rcpt:
  deny    message = Rejected because $sender_host_address is in a black list at $dnslist_domain
          hosts = !+whitelist
          dnslists = ${readfile {/etc/exim4/dnsbl.conf}{:}}

  require message = relay not permitted
          domains = +local_domains : +relay_to_domains
  require verify = recipient
  accept

acl_check_mime:
  deny   message = Blacklisted file extension detected
         condition = ${if match {${lc:$mime_filename}}{\\N(\\.exe|\\.js)$\\N}{1}{0}}

  accept
begin routers
unchanged_router:
  driver = accept
'''


class NativeAclTests(unittest.TestCase):
    def fallback_source(self):
        return ('CLAMSHIELD_NATIVE_CONFIG_INCLUDED=1\n'
                '.include_if_exists /run/clamshield-exim/hook.conf\n'
                'acl_smtp_data = acl_check_data\n'+BASE.replace('begin routers',
                'acl_check_data:\n  accept\nbegin routers'))

    def test_missing_application_fallback_keeps_native_auth_and_explicit_incomplete_status(self):
        source=self.fallback_source();result=fallback(source)
        self.assertNotIn('local_scan_path',result)
        self.assertNotIn('.include_if_exists /run/clamshield-exim/hook.conf',result)
        self.assertIn('ClamShield native delivery fallback; check incomplete',result)
        self.assertIn('domains = !+local_domains',result)
        self.assertIn('  require verify = recipient\n',result)
        self.assertIn('  deny senders = forbidden@example.test\n',result)
        self.assertIn('  require message = relay not permitted\n',result)

    def test_fallback_cannot_silently_adopt_a_foreign_binding_or_missing_marker(self):
        source=self.fallback_source()
        for value in (source.replace('CLAMSHIELD_NATIVE_CONFIG_INCLUDED=1',''),
                      source.replace('acl_smtp_data = acl_check_data','acl_smtp_data = foreign_acl'),
                      source+'\nlocal_scan_path = /foreign/plugin.so\n'):
            with self.subTest(value=value),self.assertRaises((Conflict,EngineError)):fallback(value)

    def test_bootstrap_module_runs_without_importing_the_application_package(self):
        import json
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        import clamshield.native_acl as module
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'native_fallback.py';path.write_text(Path(module.__file__).read_text())
            script='import json,runpy,sys; m=runpy.run_path(sys.argv[1]); print(json.dumps(m["fallback"](sys.stdin.read())))'
            result=subprocess.run([sys.executable,'-I','-B','-c',script,str(path)],input=self.fallback_source(),
                                  capture_output=True,text=True,check=True)
            self.assertEqual(fallback(self.fallback_source()),json.loads(result.stdout))

    def test_native_extension_observation_is_not_a_malware_finding_or_score(self):
        value=observe(True);self.assertTrue(verified(value));self.assertEqual(0,value['score_contribution'])
        self.assertIsNone(observe(False));self.assertIsNone(observe(1))
        for change in (dict(source='header'),dict(policy='malware'),dict(matched=1),dict(score_contribution=5)):
            self.assertFalse(verified(value|change))
    def test_only_two_native_policy_blocks_change_and_context_resets_per_message(self):
        result=render(BASE)
        self.assertIn('deny    message = Rejected because',result)
        self.assertIn('deny   message = Blacklisted',result)
        self.assertIn('domains = !+local_domains',result)
        self.assertIn('forall{$recipients_list}',result)
        self.assertIn('dnslists = ${readfile {/etc/exim4/dnsbl.conf}{:}}',result)
        self.assertIn('condition = ${if match {${lc:$mime_filename}}{\\N(\\.exe|\\.js)$\\N}{1}{0}}',result)
        self.assertIn('set acl_m_clamshield_dnsbl_value = $dnslist_value',result)
        self.assertIn('set acl_m_clamshield_mime_blocked = 1',result)
        self.assertLess(result.index('set acl_m_clamshield_mime_blocked = 0'),result.index('deny senders'))
        for tail in ('  require message = relay not permitted\n          domains = +local_domains : +relay_to_domains\n  require verify = recipient\n  accept',
                     'begin routers\nunchanged_router:\n  driver = accept\n'):
            self.assertIn(tail,result)
        with self.assertRaises(Conflict):render(result)

    def test_ambiguous_changed_or_missing_native_blocks_are_rejected_without_guessing(self):
        for source in (BASE.replace('acl_check_rcpt:','different_rcpt:'),BASE+'\nacl_check_rcpt:\n',
                       BASE.replace('acl_smtp_mime = acl_check_mime','acl_smtp_mime = another_acl'),
                       BASE.replace('!+whitelist','+other_list'),BASE.replace('/etc/exim4/dnsbl.conf','/custom/list'),
                       BASE.replace('  deny   message = Blacklisted','  warn   message = Blacklisted'),
                       BASE.replace('          hosts = !+whitelist','          hosts = !+whitelist\n          condition = extra')):
            with self.subTest(source=source),self.assertRaises(EngineError):render(source)
        for source in (BASE+'\0',BASE.replace('\n','\r\n')):
            with self.assertRaises(EngineError):render(source)
