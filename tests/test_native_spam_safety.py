import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write,write_json
from clamshield.errors import Conflict,EngineError
from clamshield.native_spam_safety import NativeSpamSafety,SOURCE,render
from clamshield.settings import Settings


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root owned native file lifecycle')
class NativeSpamSafetyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir='/root',prefix='cs-native-safety-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.source=self.root/'source.pm';write(self.source,SOURCE.read_bytes(),0o644)
        self.manager=NativeSpamSafety(self.settings,config=self.root/'native.cf',plugin=self.root/'native.pm',source=self.source)
        self.active=dict(active=True,unit='spamd.service',pid=100,birth=200)
        self.manager.service=Mock(side_effect=lambda:dict(self.active))
        self.catalog=dict(rules=[dict(name='RCVD_IN_VALIDITY_FUTURE_BLOCKED',description='Access failure',scores=[0]*4),dict(name='LEGITIMATE',description='Content signal',scores=[2.395]*4)])
        self.manager.inspect=Mock(side_effect=lambda text='':self.catalog)
        self.manager.configuration_stamp=Mock(return_value='same-configuration')
        self.manager.probe=Mock();self.manager.restart=Mock(side_effect=self.restart)

    def restart(self,service):
        value=self.manager.receipt();self.assertEqual('restart-intent',value['phase'])
        self.assertIn(value['state'],('applying','removing'));self.assertEqual(self.active,service)
        self.active['pid']+=1;self.active['birth']+=1

    def test_apply_once_live_proof_restore_and_no_other_files_changed(self):
        other=self.root/'administrator.cf';other.write_text('score LEGITIMATE 2.395\n')
        result=self.manager.ensure();self.assertTrue(result['verified']);self.assertEqual(1,self.manager.restart.call_count)
        self.assertIn('score RCVD_IN_VALIDITY_FUTURE_BLOCKED 0\n',self.manager.config.read_text())
        self.assertTrue(self.manager.status()['verified']);self.assertTrue(self.manager.ensure()['unchanged'])
        self.assertEqual(1,self.manager.restart.call_count);self.assertEqual(1,self.manager.probe.call_count)
        self.assertTrue(self.manager.restore()['restored']);self.assertFalse(self.manager.config.exists());self.assertFalse(self.manager.plugin.exists())
        self.assertEqual('score LEGITIMATE 2.395\n',other.read_text());self.assertFalse(self.manager.restore()['restored'])
        self.assertEqual(2,self.manager.restart.call_count)

    def test_inactive_native_daemon_stays_inactive_and_is_not_claimed_verified(self):
        self.active=dict(active=False);self.assertFalse(self.manager.ensure()['verified'])
        self.manager.restart.assert_not_called();self.manager.probe.assert_not_called();self.assertFalse(self.manager.status()['verified'])
        self.manager.restore();self.manager.restart.assert_not_called()

    def test_later_stop_is_preserved_on_removal(self):
        self.manager.ensure();self.active=dict(active=False);self.manager.restore();self.assertEqual(1,self.manager.restart.call_count)

    def test_new_process_is_probed_without_unnecessary_restart(self):
        self.manager.ensure();self.active['pid']+=1;self.active['birth']+=1
        self.assertFalse(self.manager.status()['verified']);self.manager.ensure()
        self.assertEqual(1,self.manager.restart.call_count);self.assertEqual(2,self.manager.probe.call_count)

    def test_later_administrator_edits_and_replaced_leaf_are_not_overwritten(self):
        self.manager.ensure();self.manager.config.write_text('administrator replacement\n')
        with self.assertRaises(Conflict):self.manager.ensure()
        with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual('administrator replacement\n',self.manager.config.read_text());self.assertEqual(1,self.manager.restart.call_count)

    def test_administrator_removed_owned_file_is_not_recreated_but_remaining_owned_file_can_be_removed(self):
        self.manager.ensure();self.manager.config.unlink()
        with self.assertRaises(Conflict):self.manager.ensure()
        self.manager.restore();self.assertFalse(self.manager.plugin.exists())

    def test_occupied_target_or_unsafe_parent_never_becomes_owned(self):
        self.manager.config.write_text('foreign\n')
        with self.assertRaises(Conflict):self.manager.ensure()
        self.assertFalse(self.manager.path.exists());self.manager.config.unlink();self.root.chmod(0o777)
        with self.assertRaises(EngineError):self.manager.ensure()
        self.root.chmod(0o700);self.assertFalse(self.manager.plugin.exists());self.manager.restart.assert_not_called()

    def test_failed_native_restart_is_not_retried_and_explicit_removal_is_separate_recovery(self):
        self.manager.restart.side_effect=EngineError('Native failure')
        with self.assertRaises(EngineError):self.manager.ensure()
        self.assertEqual('review',self.manager.receipt()['state'])
        for _ in range(2):
            with self.assertRaises(Conflict):self.manager.ensure()
        self.assertEqual(1,self.manager.restart.call_count)
        self.manager.restart.side_effect=self.restart;self.manager.restore();self.assertEqual(2,self.manager.restart.call_count)

    def test_uncertain_removal_restart_never_repeats_until_external_terminal_change(self):
        self.manager.ensure();self.manager.restart.side_effect=EngineError('Uncertain restoration')
        with self.assertRaises(EngineError):self.manager.restore()
        for _ in range(2):
            with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(2,self.manager.restart.call_count)
        self.active['pid']+=1;self.active['birth']+=1
        self.assertTrue(self.manager.restore()['restored']);self.assertEqual(2,self.manager.restart.call_count)

    def test_probe_failure_is_not_green_or_restarted_again(self):
        self.manager.probe.side_effect=EngineError('Missing live canary')
        with self.assertRaises(EngineError):self.manager.ensure()
        self.assertFalse(self.manager.status()['verified'])
        with self.assertRaises(Conflict):self.manager.ensure()
        self.assertEqual(1,self.manager.restart.call_count)

    def test_process_change_during_live_probe_is_not_recorded_as_verified(self):
        def changed(revision):self.active['pid']+=1;self.active['birth']+=1
        self.manager.probe.side_effect=changed
        with self.assertRaises(Conflict):self.manager.ensure()
        self.assertFalse(self.manager.status()['verified'])
        self.assertEqual(1,self.manager.restart.call_count)

    def test_preflight_nonzero_or_missing_score_sets_fail_before_owned_file_change(self):
        for scores in ([0,0,1,0],[None]*4,[0]):
            self.catalog['rules'][0]['scores']=scores
            with self.assertRaises(EngineError):self.manager.ensure()
            self.assertFalse(self.manager.config.exists());self.assertFalse(self.manager.plugin.exists())

    def test_pending_write_intent_can_be_cleaned_by_explicit_disable_without_replaying_apply(self):
        from clamshield import native_spam_safety as module
        original=module.write
        def interrupted(path,*args,**kwargs):
            original(path,*args,**kwargs)
            if Path(path)==self.manager.plugin:raise KeyboardInterrupt()
        with patch.object(module,'write',side_effect=interrupted),self.assertRaises(KeyboardInterrupt):self.manager.ensure()
        self.assertEqual('applying',self.manager.receipt()['state']);self.assertTrue(self.manager.plugin.exists())
        self.manager.restore();self.assertFalse(self.manager.plugin.exists());self.assertFalse(self.manager.config.exists())

    def test_systemctl_transition_is_not_misreported_as_stopped(self):
        manager=NativeSpamSafety(self.settings)
        response=subprocess.CompletedProcess([],0,'ActiveState=active\nMainPID=100\nControlGroup=/system.slice/spamd.service\nLoadState=loaded\nJob=123\n','')
        with patch('clamshield.native_spam_safety.subprocess.run',return_value=response):
            with self.assertRaises(EngineError):manager.service()


@unittest.skipUnless(Path('/usr/bin/spamassassin').is_file(),'Actual Ubuntu SpamAssassin')
class NativeSpamSafetyPerlTests(unittest.TestCase):
    def test_actual_parser_proof_detects_missing_defaults_and_per_user_score_override(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);empty=root/'empty';empty.mkdir();prefs=root/'prefs';prefs.write_text('score RCVD_IN_VALIDITY_SAFE_BLOCKED 2\n')
            names=['RCVD_IN_VALIDITY_'+kind+'_BLOCKED' for kind in ('CERTIFIED','SAFE','RPBL')]
            base='loadplugin Mail::SpamAssassin::Plugin::Check\n'+''.join('header '+name+' Subject =~ /transactional/\n' for name in names)+'header LEGITIMATE Subject =~ /transactional/\nscore LEGITIMATE 2.395\n'
            revision='a'*64
            script=r'''use Mail::SpamAssassin;use JSON::PP;my($empty,$file,$prefs,$revision)=@ARGV;open my $f,'<',$file or die;local $/;my $text=<$f>;my $sa=Mail::SpamAssassin->new({site_rules_filename=>$empty,rules_filename=>$empty,userprefs_filename=>'/dev/null',dont_copy_prefs=>1,local_tests_only=>1,post_config_text=>$text});die if $sa->lint_rules();$sa->read_scoreonly_config($prefs) if length($prefs);my $mail=$sa->parse("From: probe\@localhost\nTo: probe\@localhost\nSubject: transactional\nX-ClamShield-Native-Safety: $revision\n\nHarmless\n");my $s=$sa->check($mail);print JSON::PP->new->encode({score=>$s->get_score(),hits=>$s->get_names_of_tests_hit()});$s->finish();$mail->finish();$sa->finish();'''
            values=[]
            for safety,override in ((False,False),(True,False),(True,True)):
                config=root/'rules.cf';config.write_text(base+(render(names,SOURCE,revision) if safety else ''))
                result=subprocess.run(['/usr/bin/perl','-e',script,str(empty),str(config),str(prefs) if override else '',revision],capture_output=True,timeout=15)
                self.assertEqual(0,result.returncode,result.stderr.decode());values.append(json.loads(result.stdout))
            self.assertAlmostEqual(5.395,float(values[0]['score']),places=3)
            self.assertAlmostEqual(2.396,float(values[1]['score']),places=3)
            self.assertIn('CLAMSHIELD_NATIVE_SAFE_'+revision[:16],values[1]['hits'])
            self.assertNotIn('CLAMSHIELD_NATIVE_SAFE_'+revision[:16],values[2]['hits'])
