import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from clamshield.website_availability import WebsiteAvailability


class WebsiteAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.context = dict(actor='alice', owner='alice', identity='one', admin=False)
        self.site = dict(owner='alice', identity='one', domain='site.test', root='/home/alice/site', suspended=False)
        self.record = self.site | dict(id='finding-one', status='open', path='bad.php',
            engine='yara', provider='local', signature='Inert.Fixture', fingerprint={}, detail={})

    def describe(self, sites=None, record=None):
        return WebsiteAvailability(self.context, [self.site] if sites is None else sites).describe(record or self.record)

    def test_only_current_matching_scope_is_available(self):
        self.assertTrue(self.describe()['available'])
        for changes in ({'owner': 'bob'}, {'identity': 'new'}):
            with self.subTest(changes=changes):
                self.assertEqual('account_changed', self.describe(record=self.record | changes)['state'])
                self.assertEqual('account_changed', self.describe(sites=[self.site | changes])['state'])

    def test_removed_moved_suspended_and_unknown_are_distinct(self):
        self.assertEqual('removed', self.describe(sites=[])['state'])
        self.assertEqual('root_changed', self.describe(sites=[self.site | dict(root='/new/root')])['state'])
        self.assertEqual('suspended', self.describe(sites=[self.site | dict(suspended=True)])['state'])
        self.assertEqual('unknown', self.describe(record=self.record | dict(root=None))['state'])

    def test_annotations_do_not_rewrite_results_or_depend_on_recent_job_limit(self):
        # Historical findings use their persisted job root, not the 200-row job view.
        data = dict(jobs=[], findings=[self.record.copy()], repairs=[], quarantine=[], remediation_history=[])
        before = copy.deepcopy(data)
        WebsiteAvailability(self.context, []).annotate(data)
        self.assertEqual('removed', data['findings'][0].pop('site_availability')['state'])
        self.assertEqual(before, data)

    def test_quarantine_uses_original_storage_metadata_root(self):
        record = self.record | dict(root=self.site['root'], metadata=dict(root='/old/root'))
        data = dict(jobs=[], findings=[], repairs=[], quarantine=[record], remediation_history=[])
        WebsiteAvailability(self.context, [self.site]).annotate(data)
        self.assertEqual('root_changed', record['site_availability']['state'])


PHP = shutil.which('php') or next((str(p) for p in [Path('/usr/local/hestia/php/bin/php')] if p.is_file()), None)


@unittest.skipUnless(PHP, 'PHP interpreter is required for panel rendering')
class WebsiteHistoryRendering(unittest.TestCase):
    setUp = WebsiteAvailabilityTests.setUp

    def data(self):
        capabilities = dict.fromkeys(('scan', 'schedule', 'quarantine', 'restore', 'repair',
            'cleanup', 'exceptions', 'automatic', 'rule_trials'), True)
        site = self.site | dict(policy=dict(watch=False, frequency='never', time='03:00', timezone='UTC',
            weekday=0, monthday=1, rescan_updates=True), remediation=dict(site=dict(mode='inherit'), effective=dict(mode='report')))
        data = dict(context=self.context, sites=[site], findings=[self.record.copy()], jobs=[],
            summary=dict(open_findings=1,active_scans=0,quarantined=0),
            repairs=[], quarantine=[], remediation_history=[], history=[], wordpress=[], exceptions=[],
            notifications=[], rule_trials=[], rule_candidate=None, rules=dict(configured=False),
            engines=dict(clamav=dict(available=False, error='fixture'), yara=dict(available=False,
                error='fixture', rules_available=False)), website_permissions=dict(effective=capabilities, labels=capabilities),
            remediation_policy=dict(account=dict(mode='report')))
        return data

    def render(self, data):
        WebsiteAvailability(self.context, data['sites']).annotate(data)
        script = '''set_error_handler(function($severity,$message){throw new ErrorException($message,0,$severity);});
        $data=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
        $_SESSION=[];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];'''
        result = subprocess.run([PHP, '-d', 'display_errors=stderr', '-r', script,
            str(Path(__file__).resolve().parents[1]/'panel/view.php')], input=json.dumps(data),
            text=True, encoding='utf-8', capture_output=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)
        return result.stdout

    def test_available_site_offers_actions_and_tenant_has_no_server_scan(self):
        page = self.render(self.data())
        self.assertIn('data-action="quarantine"', page)
        self.assertIn('data-scope="account"', page)
        self.assertNotIn('data-scope="server"', page)

    def test_cards_render_full_scoped_totals_instead_of_bounded_preview_lengths(self):
        data=self.data();data['summary']=dict(open_findings=1234,active_scans=201,quarantined=456)
        page=self.render(data)
        self.assertIn('Open findings<div class="number">1234</div>',page)
        self.assertIn('id="cs-active-scans">201</div>',page)
        self.assertIn('Quarantined<div class="number">456</div>',page)

    def test_removed_site_keeps_open_finding_and_omits_file_mutations(self):
        data = self.data(); data['sites'] = []
        page = self.render(data)
        self.assertIn('Inert.Fixture', page)
        self.assertIn('>open</td>', page)
        self.assertIn('no longer in the account inventory', page)
        self.assertIn('Original root: /home/alice/site', page)
        for action in ('quarantine', 'cleanup-preview', 'repair-backup-preview', 'exception-add'):
            self.assertNotIn('data-action="'+action+'"', page)

    def test_suspended_site_disables_path_and_scan(self):
        data = self.data(); data['sites'][0]['suspended'] = True
        page = self.render(data)
        self.assertIn('placeholder="Whole website" disabled', page)
        self.assertIn('disabled title="Website is suspended" data-action="scan"', page)
        self.assertNotIn('data-action="quarantine"', page)

    def test_moved_site_keeps_private_original_and_repair_history_without_restore_or_apply(self):
        data = self.data()
        data['quarantine'] = [self.record | dict(kind='quarantine', status='quarantined', metadata=dict(root='/old/root', path='bad.php'))]
        data['repairs'] = [self.record | dict(root='/old/root', status='ready', target='bad.php', metadata={})]
        data['remediation_history'] = [self.record | dict(root='/old/root', created=1,
            status='quarantined', operation_status='quarantined', plan_status=None, error=None,
            detail=dict(policy=dict(mode='quarantine'), operation_id='private-original'))]
        page = self.render(data)
        self.assertIn('quarantine / quarantined', page)
        self.assertIn('>ready</strong>', page)
        self.assertIn('document root changed', page)
        self.assertNotIn('data-action="restore"', page)
        self.assertNotIn('data-action="repair-apply"', page)

    def test_unavailable_job_can_still_be_cancelled_and_untrusted_text_is_escaped(self):
        data = self.data(); data['sites'] = []
        data['findings'][0]['domain'] = '<script>alert(1)</script>'
        data['jobs'] = [self.record | dict(id='job-one', target='', status='queued', counters={}, error=None)]
        page = self.render(data)
        self.assertIn('data-action="cancel" data-job_id="job-one"', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)
        self.assertNotIn('<script>alert(1)</script>', page)
