"""Opt-in root installer reporting; ordinary application/worker output stays silent."""
from contextlib import contextmanager, redirect_stdout
from contextvars import ContextVar
from datetime import datetime
import json
import os
import shlex
import signal
import sys
import threading
import time
import traceback

_reporter = ContextVar('clamshield_installer_reporter', default=None)


def write(stream, text):
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError, UnicodeError, RuntimeError):
        # Console errors, including a reentrant signal-time write, must not
        # change a completed filesystem/service transaction.
        pass


class Reporter:
    def __init__(self, stream):
        self.stream = stream
        self.message = 'Starting installer'
        self.since = time.monotonic()
        self.writing = False

    def emit(self, message):
        if self.writing:
            return
        self.writing = True
        try:
            write(self.stream, '[' + datetime.now().astimezone().strftime('%H:%M:%S') + '] ' + message + '\n')
        finally:
            self.writing = False

    def stage(self, message):
        self.message, self.since = str(message), time.monotonic()
        self.emit(self.message)

    def heartbeat(self, *_):
        self.emit('Still working (' + str(int(time.monotonic() - self.since)) + 's): ' + self.message)


@contextmanager
def reporting(stream=None, interval=10):
    reporter = Reporter(sys.stderr if stream is None else stream)
    token = _reporter.set(reporter)
    previous = None
    # No heartbeat thread is started: scanner migrations fork children with
    # preexec_fn. An independent thread would make those forks unsafe.
    # Preserve any caller-owned alarm/deadline instead of replacing its timer.
    if (hasattr(signal, 'setitimer') and threading.current_thread() is threading.main_thread()
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)):
        previous = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, reporter.heartbeat)
        signal.setitimer(signal.ITIMER_REAL, interval, interval)
    try:
        yield reporter
    finally:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        _reporter.reset(token)


def stage(message):
    reporter = _reporter.get()
    if reporter is not None:
        reporter.stage(message)


@contextmanager
def command(arguments):
    reporter = _reporter.get()
    previous = reporter.message if reporter is not None else None
    stage('Running: ' + shlex.join(str(v) for v in arguments))
    try:
        yield
    except BaseException:
        # Keep the failing command as the final diagnostic stage.
        raise
    else:
        if reporter is not None:
            reporter.message, reporter.since = previous, time.monotonic()


def summary(result, elapsed, stream=None):
    stream = sys.stdout if stream is None else stream
    heading = 'ClamShield for HestiaCP ' + result['version'] + ' - Installation ' + ('completed' if result['installed'] else 'failed')
    try:
        color = stream.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'
    except (AttributeError, OSError, ValueError):
        color = False
    if color:
        heading = ('\033[32m' if result['installed'] else '\033[31m') + heading + '\033[0m'
    lines = ['\n' + heading]
    labels = {'mode': 'Operation', 'route': 'Hestia panel', 'code_generation': 'Application release',
              'php_templates_checked': 'PHP templates validated', 'timers_enabled': 'Background timers enabled',
              'website_engine': 'Website scanner', 'vendor_files_modified': 'Hestia vendor files modified',
              'error': 'Error', 'stage': 'Last stage'}
    for key, label in labels.items():
        if key in result:
            value = result[key]
            if isinstance(value, bool):value = 'Yes' if value else 'No'
            lines.append('  ' + label + ': ' + str(value))
    if result['installed']:
        packages = result.get('dependencies_installed', [])
        lines.append('  Ubuntu dependencies: ' + (', '.join(packages) + ' installed' if packages else 'Already installed'))
    for item in result.get('next_steps', []):
        lines.append('  Next: ' + item)
    lines.append('  Elapsed: ' + format(elapsed, '.1f') + 's\n')
    write(stream, '\n'.join(lines) + '\n')


def execute(operation, *, version, json_output=False):
    started = time.monotonic()
    code = 0
    with reporting() as reporter:
        stage('ClamShield for HestiaCP ' + version + ' - Installation / update')
        try:
            with redirect_stdout(sys.stderr):
                value = operation()
            if not isinstance(value, dict) or value.get('installed') is not True:
                raise RuntimeError('Installer did not confirm successful completion')
            result = {**value, 'version': version}
        except (Exception, KeyboardInterrupt) as error:
            code = 130 if isinstance(error, KeyboardInterrupt) else 1
            result = dict(installed=False, version=version, error_type=type(error).__name__,
                          error=str(error) or 'Interrupted; rerun the installer to resume pending work',
                          stage=reporter.message)
            for name in ('stdout', 'stderr'):
                diagnostic = getattr(error, name, None)
                if diagnostic:
                    if isinstance(diagnostic, bytes):diagnostic = diagnostic.decode(errors='replace')
                    write(sys.stderr, name + ':\n' + str(diagnostic).rstrip() + '\n')
            write(sys.stderr, traceback.format_exc())
    if json_output:
        write(sys.stdout, json.dumps(result) + '\n')
    else:
        summary(result, time.monotonic() - started)
    return code
