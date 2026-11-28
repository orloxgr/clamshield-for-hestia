import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from threading import Thread

from clamshield.errors import EngineError
from clamshield.native_dnsbl_health import NativeDnsblHealth
from clamshield.settings import Settings


class NativeDnsblHealthTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.settings=Settings(state=Path(temp.name)/'state');self.settings.prepare()
        self.store=Mock();self.health=NativeDnsblHealth(self.settings,self.store)

    def test_unknown_is_not_available_and_native_observations_do_not_invent_sa_checks(self):
        self.assertTrue(all(r['state']=='unknown' and r['observed'] is None for r in self.health.status()))
        self.health.observe('zen.spamhaus.org','lookup-failed')
        row=self.health.read()['zen.spamhaus.org'];self.assertEqual('failed',row['state'])
        self.health.observe('','');self.assertEqual(row,self.health.read()['zen.spamhaus.org'])
        self.assertFalse((self.settings.state/'dns-observations.json').exists())

    def test_dqs_keys_are_redacted_and_repeated_errors_share_one_alert_episode(self):
        self.health.observe('secret-key.zen.dq.spamhaus.net','127.255.255.251')
        self.store.notify.assert_not_called();self.health.publish()
        self.assertNotIn('secret-key',self.health.path.read_text()+str(self.store.notify.call_args))
        episode=self.store.notify.call_args.args[-1]
        self.health.observe('secret-key.zen.dq.spamhaus.net','127.255.255.250')
        self.health.publish()
        self.assertEqual(episode,self.store.notify.call_args.args[-1])
        self.health.observe('zen.spamhaus.org','127.0.0.2')
        self.assertEqual('response-observed',self.health.read()['zen.spamhaus.org']['state'])
        self.health.observe('zen.spamhaus.org','127.255.255.251')
        self.health.publish()
        self.assertNotEqual(episode,self.store.notify.call_args.args[-1])

    def test_unknown_zones_do_not_create_aggregate_data_and_corruption_is_explicit(self):
        self.health.observe('private.other.test','127.255.255.251');self.assertFalse(self.health.path.exists())
        self.health.path.write_text(json.dumps({'zen.spamhaus.org':{'state':[],'observed':1,'episode':'a'*32}}));self.health.path.chmod(0o600)
        with self.assertRaises(EngineError):self.health.status()

    def test_busy_optional_telemetry_lock_does_not_wait_in_the_smtp_path(self):
        lock=self.settings.state/'native-dnsbl-observations.lock'
        fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
        thread=Thread(target=lambda:self.health.observe('zen.spamhaus.org','lookup-failed'),daemon=True)
        try:
            thread.start();thread.join(1);self.assertFalse(thread.is_alive())
            self.assertFalse(self.health.path.exists());self.store.notify.assert_not_called()
        finally:os.close(fd);thread.join(2)
