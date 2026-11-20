"""Root installer console/JSON contracts, without host installation or service changes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from clamshield import installer_output as output

SPEC = importlib.util.spec_from_file_location('console_installer', Path(__file__).resolve().parents[1]/'tools/install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerOutput(unittest.TestCase):
    def invoke(self, callback, machine=False):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = output.execute(callback, version='1.2.3', json_output=machine)
        return code, out.getvalue(), err.getvalue()

    def test_pretty_summary_has_actual_results_and_setup_steps_without_raw_json(self):
        def install():
            output.stage('[2/10] Validating 11 PHP templates')
            return dict(installed=True, route='/plugins/clamshield/', code_generation='release-test',
                        mode='New installation', php_templates_checked=11, timers_enabled=4,
                        dependencies_installed=['yara'], vendor_files_modified=False,
                        website_engine='Configure scanning data and start from the panel',
                        next_steps=['Open Hestia > Plugins > ClamShield.'])
        code, out, err = self.invoke(install)
        self.assertEqual(0, code)
        for text in ('1.2.3 - Installation completed', 'PHP templates validated: 11',
                     'Background timers enabled: 4', 'vendor files modified: No',
                     'yara installed', 'Next: Open Hestia', 'Elapsed:'):
            self.assertIn(text, out)
        self.assertNotIn('{', out);self.assertNotIn('\033', out)
        self.assertRegex(err, r'\[\d{2}:\d{2}:\d{2}\] \[2/10\]')

    def test_json_contains_one_complete_document_and_keeps_legacy_result_keys(self):
        def install():
            output.stage('Applying owned services')
            print('Incidental Python diagnostic')
            return dict(installed=True, route='/plugins/clamshield/', vendor_files_modified=False)
        code, out, err = self.invoke(install, machine=True)
        self.assertEqual(0, code)
        self.assertEqual(dict(installed=True,route='/plugins/clamshield/',vendor_files_modified=False,version='1.2.3'),json.loads(out))
        self.assertIn('Incidental Python diagnostic',err);self.assertIn('Applying owned services',err)
        self.assertNotIn('Elapsed:',out)

    def test_native_failure_retains_both_diagnostics_and_failing_command(self):
        def install():
            with output.command(['php','-l','index.php']):
                raise subprocess.CalledProcessError(255,['php','-l'],output=b'Invalid template',stderr=b'PHP parse error')
        for machine in (False,True):
            with self.subTest(machine=machine):
                code,out,err=self.invoke(install,machine)
                self.assertEqual(1,code)
                for text in ('Invalid template','PHP parse error','Traceback'):self.assertIn(text,err)
                if machine:
                    value=json.loads(out);self.assertIs(value['installed'],False)
                    self.assertEqual('Running: php -l index.php',value['stage'])
                else:
                    self.assertIn('Installation failed',out);self.assertNotIn('Installation completed',out)

    def test_only_explicit_completion_can_report_success(self):
        for result in (None,{},dict(installed=False),dict(installed=1)):
            with self.subTest(result=result):
                code,out,_=self.invoke(lambda:result,True)
                self.assertEqual(1,code);self.assertIs(json.loads(out)['installed'],False)

    def test_interruption_keeps_nonzero_status_and_restores_silent_reporting(self):
        def interrupted():
            output.stage('Waiting for installation lock')
            raise KeyboardInterrupt()
        code,out,_=self.invoke(interrupted,True)
        self.assertEqual(130,code);self.assertIs(json.loads(out)['installed'],False)
        err=io.StringIO()
        with contextlib.redirect_stderr(err):output.stage('Ordinary API operation')
        self.assertEqual('',err.getvalue())

    def test_closed_console_does_not_change_completed_work(self):
        out,err=io.StringIO(),io.StringIO();out.close();err.close();completed=[]
        def install():
            output.stage('Publishing owned files');completed.append(True)
            return dict(installed=True)
        for machine in (False,True):
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(0,output.execute(install,version='1',json_output=machine))
        self.assertEqual([True,True],completed)

    def test_color_is_terminal_only_and_respects_no_color(self):
        class Terminal(io.StringIO):
            def isatty(self):return True
        for environment,colored in (({},True),({'NO_COLOR':''},False),({'TERM':'dumb'},False)):
            stream=Terminal()
            with patch.dict(os.environ,environment,clear=True):
                output.summary(dict(installed=True,version='1'),.1,stream)
            self.assertEqual(colored,'\033[32m' in stream.getvalue())

    def test_real_cli_dispatch_supports_default_json_and_legacy_dependency_flag(self):
        for args in ([],['--json'],['--install-packages'],['--install-packages','--json']):
            for failing in (False,True):
                with self.subTest(args=args,failing=failing):
                    perform=Mock(return_value=dict(installed=True,route='/plugins/clamshield/'))
                    if failing:perform.side_effect=PermissionError('Use an administrator root shell')
                    out,err=io.StringIO(),io.StringIO()
                    with patch.object(installer,'perform',perform),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                        code=installer.main(args)
                    self.assertEqual(int(failing),code);perform.assert_called_once()
                    if '--json' in args:self.assertEqual(not failing,json.loads(out.getvalue())['installed'])
                    else:self.assertIn('Installation failed' if failing else 'Installation completed',out.getvalue())

    def test_native_command_is_quiet_on_success_and_has_no_reporting_timeout(self):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err),output.reporting(err,interval=.02):
            result=installer.run(sys.executable,'-c','print("Native completion")')
        self.assertEqual(b'Native completion',result.stdout.strip());self.assertEqual('',out.getvalue())
        self.assertIn('Running:',err.getvalue())
        with patch.object(installer.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as child:
            installer.run('fixed-command')
        self.assertNotIn('timeout',child.call_args.kwargs)

    @unittest.skipUnless(hasattr(signal,'setitimer'),'Linux installer heartbeat')
    def test_slow_forked_command_reports_without_a_heartbeat_thread_or_deadline(self):
        stream=io.StringIO()
        original=signal.getsignal(signal.SIGALRM)
        with patch.object(output.threading,'Thread',side_effect=AssertionError('Do not add threads before migration forks')):
            with output.reporting(stream,interval=.02):
                output.stage('Verifying scanning data')
                child=subprocess.run([sys.executable,'-c','import time;time.sleep(.13);print("done")'],
                                     capture_output=True,preexec_fn=lambda:None)
        self.assertEqual(0,child.returncode);self.assertEqual(b'done',child.stdout.strip())
        self.assertIn('Still working',stream.getvalue());self.assertIn('Verifying scanning data',stream.getvalue())
        self.assertEqual(original,signal.getsignal(signal.SIGALRM));self.assertEqual((0.0,0.0),signal.getitimer(signal.ITIMER_REAL))
        previous=stream.getvalue();time.sleep(.03);self.assertEqual(previous,stream.getvalue())

    @unittest.skipUnless(hasattr(signal,'setitimer'),'Linux caller-owned alarm')
    def test_existing_alarm_is_never_replaced_or_extended_by_reporting(self):
        with patch.object(output.signal,'getitimer',return_value=(5.0,0.0)),patch.object(output.signal,'setitimer') as timer,patch.object(output.signal,'signal') as handler:
            with output.reporting(io.StringIO()):output.stage('Respect caller deadline')
        timer.assert_not_called();handler.assert_not_called()
