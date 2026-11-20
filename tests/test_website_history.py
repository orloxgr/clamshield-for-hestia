import unittest
from unittest.mock import patch

from clamshield.application import Application
from clamshield.errors import Conflict
from clamshield.repairs import Repairs
import test_quarantine as fixtures


class RetainedWebsiteHistory(unittest.TestCase):
    setUp = fixtures.ReversibleCapture.setUp

    def dashboard(self):
        app = Application(self.settings, self.store, self.hestia)
        with patch.object(app, 'engine_status', return_value={}):
            return app.dispatch(dict(actor='alice', action='dashboard'))

    def test_dashboard_removed_site_preserves_finding_and_rejects_direct_capture(self):
        before = self.store.finding(self.context, self.finding_id)
        # Keep more than a dashboard's worth of newer jobs; old root remains available.
        for _ in range(205): self.store.enqueue(self.context, self.site)
        self.hestia.sites.return_value = []
        data = self.dashboard()
        self.assertEqual('removed', data['findings'][0]['site_availability']['state'])
        self.assertEqual(self.site['root'], data['findings'][0]['root'])
        self.assertEqual('open', data['findings'][0]['status'])
        with self.assertRaises(Conflict): self.quarantine.capture(self.context, self.finding_id)
        self.assertEqual(before, self.store.finding(self.context, self.finding_id))
        self.assertEqual('original malicious fixture', self.file.read_text())

    def test_removed_site_keeps_quarantine_bytes_and_original_scoped_domain(self):
        operation = self.quarantine.capture(self.context, self.finding_id)
        original = (self.settings.quarantine/operation).read_bytes()
        self.hestia.sites.return_value = []
        data = self.dashboard(); row = data['quarantine'][0]
        self.assertEqual(self.site['domain'], row['domain'])
        self.assertEqual('removed', row['site_availability']['state'])
        self.assertEqual('quarantined', row['status'])
        with self.assertRaises(Conflict): self.quarantine.restore(self.context, operation)
        self.assertEqual(original, (self.settings.quarantine/operation).read_bytes())
        self.assertFalse(self.file.exists())
        self.assertEqual([], self.quarantine.list(self.context | dict(identity='recreated')))

    def test_moved_site_marks_queued_backup_plan_and_backend_refuses_new_preview(self):
        (self.root/'backup.php').write_text('clean backup')
        plan = Repairs(self.settings,self.store,self.hestia).queue(self.context,self.finding_id,backup_path='backup.php')
        self.hestia.sites.return_value = [self.site | dict(root=str(self.base/'new-root'))]
        data = self.dashboard(); row = next(r for r in data['repairs'] if r['id']==plan)
        self.assertEqual('root_changed', row['site_availability']['state'])
        with self.assertRaises(Conflict):
            Repairs(self.settings,self.store,self.hestia).queue(self.context,self.finding_id,backup_path='backup.php')
        self.assertTrue(self.file.exists())
