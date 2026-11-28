import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch, Mock
from zoneinfo import ZoneInfo

from clamshield.errors import EngineError
from clamshield.native_mail_health import NativeMailHealth, LIMIT, FALLBACK
from clamshield.settings import Settings
from clamshield.store import Store


class NativeMailHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = Settings(state=self.root/'state'); self.settings.prepare()
        self.log = self.root/'mainlog'; self.log.write_bytes(b''); self.log.chmod(0o640)
        self.store = Store(self.settings.database)
        self.health = NativeMailHealth(self.settings, self.store)
        self.addCleanup(patch.stopall)
        patch('clamshield.native_mail_health.pwd.getpwnam', return_value=Mock(pw_uid=os.geteuid())).start()
        patch.object(NativeMailHealth, 'source', return_value=(self.log, ZoneInfo('UTC'))).start()

    def line(self, n=0, kind='fallback', warning=False):
        prefix = f'2026-01-01 00:00:{n:02d} 1xX62m-000000005eO-{n:04d} '
        if kind == 'fallback':
            return (prefix + ('H=dns.google (controlled.test) [8.8.8.8] U=root Warning: ' if warning else '') + FALLBACK + '\n').encode()
        return (prefix + 'ClamShield decision=' + kind + ' event=' + 'a'*32 + '\n').encode()

    def append(self, raw):
        with self.log.open('ab') as output: output.write(raw)

    def counts(self):
        with self.store.connection() as db:
            return tuple(db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('native_mail_alerts', 'notifications', 'audit'))

    def test_passive_collection_groups_fallbacks_and_only_an_actual_reply_ends_incident(self):
        self.append(self.line() + self.line(1, warning=True))
        status = self.health.collect()
        self.assertEqual(2, status['fallbacks']); self.assertIsNone(status['last_response'])
        self.assertEqual((1, 1, 1), self.counts())
        self.health.collect(); self.assertEqual((1, 1, 1), self.counts())
        self.append(self.line(2)); self.health.collect()
        self.assertEqual((1, 1, 1), self.counts())
        self.append(self.line(3, '3')); self.health.collect()
        self.assertIsNotNone(self.health.status()['last_response'])
        self.append(self.line(4)); self.health.collect()
        self.assertEqual((2, 2, 2), self.counts())
        raw = self.health.path.read_text()
        self.assertNotIn('dns.google', raw); self.assertNotIn('8.8.8.8', raw); self.assertNotIn('1xX62m', raw)
        self.assertNotIn('controlled.test', raw)
        self.assertNotIn('healthy', raw); self.assertNotIn('scan_complete', raw)
        self.assertEqual(0o600, self.health.path.stat().st_mode & 0o777)

    def test_no_observation_and_quiet_log_do_not_assert_scanner_health(self):
        self.assertEqual('not-observed', self.health.status()['collection'])
        self.assertFalse(self.health.path.exists())
        status = self.health.collect()
        self.assertEqual('observed', status['collection']); self.assertEqual(0, status['fallbacks'])
        self.assertIsNone(status['last_fallback']); self.assertEqual((0, 0, 0), self.counts())
        self.assertNotIn('healthy', status)

    def test_subjects_forged_prefixes_and_non_successful_decisions_are_not_markers(self):
        for raw in (b'Subject: ' + self.line(), self.line().rstrip() + b' extra\n',
                    self.line().replace(b'ClamShield native', b'<= attacker@test Subject: ClamShield native'),
                    self.line(1, '5'), self.line(2, '9'), self.line().replace(b'00:00:00', b'99:99:99')):
            self.append(raw)
        self.health.collect(); self.assertEqual((0, 0, 0), self.counts())

    def test_partial_and_oversized_lines_have_bounded_work_and_no_partial_marker(self):
        raw = self.line(); self.append(raw[:-1]); self.health.collect()
        self.assertEqual(0, self.health.read()['cursor']['offset'])
        self.assertTrue(self.health.status()['backlog']); self.assertEqual((0, 0, 0), self.counts())
        self.append(b'\n'); self.health.collect(); self.assertEqual((1, 1, 1), self.counts())
        self.append(b'x'*(LIMIT + 30))
        old = self.health.read()['cursor']['offset']; self.health.collect()
        self.assertLessEqual(self.health.read()['cursor']['offset'] - old, LIMIT)
        self.append(b'\n' + self.line(1)); self.health.collect()
        self.assertEqual(2, self.health.status()['fallbacks'])
        self.assertTrue(self.health.status()['history_limited'])

    def test_initial_tail_rotation_truncation_and_disappearance_preserve_known_fault(self):
        self.log.write_bytes(b'x\n' * LIMIT + self.line()); self.health.collect()
        self.assertTrue(self.health.status()['history_limited']); self.assertEqual(1, self.health.status()['fallbacks'])
        self.log.rename(self.root/'mainlog.1'); self.log.write_bytes(self.line(1)); self.log.chmod(0o640)
        self.health.collect(); self.assertEqual(2, self.health.status()['fallbacks'])
        known = self.health.status()['last_fallback']
        self.log.write_bytes(b''); self.health.collect()
        self.assertEqual(known, self.health.status()['last_fallback']); self.assertIsNone(self.health.status()['last_response'])
        self.log.unlink(); status = self.health.collect()
        self.assertEqual('unavailable', status['collection']); self.assertEqual(known, status['last_fallback'])
        self.assertEqual((1, 1, 1), self.counts())

    def test_replayed_or_older_log_markers_do_not_duplicate_alerts_or_fake_recovery(self):
        self.append(self.line(5)); self.health.collect()
        self.log.rename(self.root/'mainlog.1'); self.log.write_bytes(self.line(1, '0') + self.line(5)); self.log.chmod(0o640)
        self.health.collect()
        self.assertIsNone(self.health.status()['last_response']); self.assertEqual(1, self.health.status()['fallbacks'])
        self.assertEqual((1, 1, 1), self.counts())

    def test_symlink_hardlink_fifo_writable_log_and_replaced_parent_are_rejected(self):
        content = self.line(); self.log.write_bytes(content)
        self.log.chmod(0o666); self.assertEqual('unavailable', self.health.collect()['collection'])
        self.log.chmod(0o640); os.link(self.log, self.root/'alias')
        self.assertEqual('unavailable', self.health.collect()['collection'])
        (self.root/'alias').unlink(); self.log.rename(self.root/'real')
        self.log.symlink_to(self.root/'real'); self.assertEqual('unavailable', self.health.collect()['collection'])
        self.log.unlink(); os.mkfifo(self.log)
        self.assertEqual('unavailable', self.health.collect()['collection'])
        self.assertEqual((0, 0, 0), self.counts())

    def test_concurrent_replacement_discards_partial_results(self):
        self.append(self.line()); actual = os.pread; changed = False
        def replace(fd, length, offset):
            nonlocal changed
            result = actual(fd, length, offset)
            if not changed:
                changed = True; self.log.rename(self.root/'previous'); self.log.write_bytes(self.line(1)); self.log.chmod(0o640)
            return result
        with patch('clamshield.native_mail_health.os.pread', side_effect=replace):
            self.assertEqual('unavailable', self.health.collect()['collection'])
        self.assertEqual((0, 0, 0), self.counts()); self.assertIsNone(self.health.read()['cursor'])

    def test_replaced_log_directory_cannot_publish_results_from_a_detached_tree(self):
        folder = self.root/'logs'; folder.mkdir(mode=0o700)
        log = folder/'mainlog'; log.write_bytes(self.line()); log.chmod(0o640)
        actual = os.pread; changed = False
        def replace(fd, length, offset):
            nonlocal changed
            result = actual(fd, length, offset)
            if not changed:
                changed = True; folder.rename(self.root/'logs-old'); folder.mkdir(mode=0o700)
                (folder/'mainlog').write_bytes(self.line(1))
            return result
        with patch.object(NativeMailHealth, 'source', return_value=(log, ZoneInfo('UTC'))), patch('clamshield.native_mail_health.os.pread', side_effect=replace):
            self.assertEqual('unavailable', self.health.collect()['collection'])
        self.assertEqual((0, 0, 0), self.counts()); self.assertIsNone(self.health.read()['cursor'])

    def test_many_incidents_keep_bounded_pending_state_without_losing_unpublished_alerts(self):
        for n in range(40): self.append(self.line(n) + self.line(n, '0'))
        first = self.health.collect()
        self.assertTrue(first['backlog']); self.assertEqual((32, 32, 32), self.counts())
        self.health.collect(); self.assertEqual((40, 40, 40), self.counts())
        self.assertFalse(self.health.status()['backlog']); self.assertEqual(32, len(self.health.read()['incidents']))
        self.assertLess(self.health.path.stat().st_size, 65536)

    def test_busy_lock_does_not_block_or_launch_any_repair(self):
        fd = os.open(self.settings.state/'native-mail-observations.lock', os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        results = []; thread = Thread(target=lambda: results.append(self.health.collect()), daemon=True)
        try:
            thread.start(); thread.join(1); self.assertFalse(thread.is_alive()); self.assertEqual([{'busy': True}], results)
            self.assertFalse(self.health.path.exists())
        finally: os.close(fd); thread.join(2)

    def test_sql_failure_retains_pending_event_and_commit_before_state_save_deduplicates(self):
        self.append(self.line())
        with patch.object(self.store, 'connection', side_effect=sqlite3.OperationalError('database unavailable')):
            with self.assertRaises(sqlite3.OperationalError): self.health.collect()
        value = self.health.read(); self.assertFalse(value['incidents'][0]['published'])
        real_save = self.health.save
        def fail_after_commit(v):
            if v['incidents'][0]['published']: raise OSError('state storage full')
            return real_save(v)
        with patch.object(self.health, 'save', side_effect=fail_after_commit):
            with self.assertRaises(OSError): self.health.collect()
        self.assertEqual((1, 1, 1), self.counts())
        self.assertFalse(self.health.read()['incidents'][0]['published'])
        self.health.collect(); self.assertEqual((1, 1, 1), self.counts())
        self.assertTrue(self.health.read()['incidents'][0]['published'])

    def test_native_alerts_and_history_do_not_leak_to_hosting_accounts(self):
        self.append(self.line()); self.health.collect()
        self.assertEqual([], self.store.notifications(dict(owner='alice', identity='new-account', admin=False)))
        rows = self.store.notifications(dict(owner='paneladmin', identity='admin', admin=True))
        self.assertEqual(1, len(rows)); self.assertEqual('mail.native_fallback', rows[0]['event'])
        self.assertNotIn('1xX62m', json.dumps(rows)); self.assertNotIn('controlled.test', json.dumps(rows))

    def test_unsafe_or_corrupt_observation_storage_is_not_silently_reset(self):
        self.health.collect(); original = self.health.path.read_bytes()
        self.health.path.chmod(0o644)
        with self.assertRaises(EngineError): self.health.status()
        self.health.path.chmod(0o600); self.health.path.write_text('{"version":[]}' )
        with self.assertRaises(EngineError): self.health.collect()
        self.assertEqual('{"version":[]}', self.health.path.read_text())
        self.health.path.write_bytes(original)
        self.health.path.rename(self.root/'saved'); self.health.path.symlink_to(self.root/'saved')
        with self.assertRaises(OSError): self.health.status()

    def test_corrupt_incident_order_or_duplicate_identity_is_rejected(self):
        self.append(self.line()); self.health.collect(); value = self.health.read()
        value['incidents'][0]['response'] = value['incidents'][0]['last'] - 1
        with self.assertRaises(EngineError): self.health.save(value)
        value['incidents'][0]['response'] = None
        value['incidents'].append(dict(value['incidents'][0]))
        with self.assertRaises(EngineError): self.health.save(value)

    def test_source_discovers_native_path_without_shell_and_rejects_unsupported_destinations(self):
        patch.stopall()
        with patch('clamshield.native_mail_health.subprocess.run', return_value=subprocess.CompletedProcess([], 0,
                b'log_file_path = /var/log/exim4/%slog\ntimezone = Europe/Athens\n')) as run:
            path, zone = NativeMailHealth.source()
            self.assertEqual(Path('/var/log/exim4/mainlog'), path); self.assertEqual('Europe/Athens', str(zone))
            self.assertEqual(['/usr/sbin/exim4', '-bP', 'log_file_path', 'timezone'], run.call_args.args[0])
            self.assertEqual(5, run.call_args.kwargs['timeout'])
        for destination in ('syslog', '/var/log/%slog:syslog', '/var/log/%D/%slog'):
            with patch('clamshield.native_mail_health.subprocess.run', return_value=subprocess.CompletedProcess([], 0,
                    f'log_file_path = {destination}\ntimezone = \n'.encode())):
                with self.assertRaises(EngineError): NativeMailHealth.source()

    def test_explicit_native_timezone_produces_same_utc_observation(self):
        first = self.health.parse(self.line().rstrip(), ZoneInfo('UTC'))
        second = self.health.parse(self.line().replace(b'00:00:00', b'02:00:00').rstrip(), ZoneInfo('Europe/Athens'))
        third = self.health.parse(self.line().replace(b'00:00:00 ', b'02:00:00 +0200 ').rstrip(), None)
        self.assertEqual(first, second); self.assertEqual(first, third)
