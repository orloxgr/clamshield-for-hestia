from pathlib import Path
import tempfile
import unittest

from clamshield.errors import AccessDenied
from clamshield.health import Health
from clamshield.settings import Settings
from clamshield.store import Store


class NotificationIsolation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.settings=Settings(state=Path(self.temp.name)/'state');self.settings.prepare()
        self.store=Store(self.settings.database)
        self.alice=dict(actor='alice',owner='alice',identity='alice-generation',admin=False)
        self.bob=dict(actor='bob',owner='bob',identity='bob-generation',admin=False)

    def test_tenant_cannot_read_admin_or_other_tenant_alerts(self):
        self.store.notify('alice','alice-generation','scan.malware_found','alice.test',{})
        self.store.notify('@admin','','health.problem','engine',{})
        self.assertEqual(1,len(self.store.notifications(self.alice)))
        self.assertEqual([],self.store.notifications(self.bob))
        admin=self.alice|{'admin':True}
        self.assertEqual(2,len(self.store.notifications(admin)))
        alien=self.store.notifications(admin)[0]['id']
        with self.assertRaises(AccessDenied):self.store.read_notification(self.bob,alien)

    def test_deduplication_preserves_distinct_events(self):
        for _ in range(3):self.store.notify('alice','alice-generation','scan.partial','site',{},'same-job')
        self.assertEqual(1,len(self.store.notifications(self.alice)))
        self.store.notify('alice','alice-generation','scan.malware_found','site',{},'same-job')
        self.assertEqual(2,len(self.store.notifications(self.alice)))

    def test_unchanged_health_is_quiet_and_recovery_is_reported_once(self):
        health=Health(self.settings,self.store)
        admin=self.alice|{'admin':True}
        health.observe({'clamav':{'state':'healthy'}})
        self.assertEqual([],self.store.notifications(admin))
        for _ in range(3):health.observe({'clamav':{'state':'unavailable'}})
        self.assertEqual(['health.problem'],[r['event'] for r in self.store.notifications(admin)])
        for _ in range(3):health.observe({'clamav':{'state':'healthy'}})
        events=[r['event'] for r in self.store.notifications(admin)]
        self.assertEqual(1,events.count('health.recovered'))
