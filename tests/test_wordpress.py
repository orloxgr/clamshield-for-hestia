import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
import zipfile
from concurrent.futures import ThreadPoolExecutor

from clamshield.application import Application
from clamshield.errors import AccessDenied
from clamshield.settings import Settings
from clamshield.store import Store
from clamshield.wordpress import WordPress, assignment
from clamshield.wordpress_sources import References, ReferenceUnavailable, archive_files, trusted_url
from clamshield.worker import Worker


class WordPressIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'site'; self.root.mkdir()
        self.settings = Settings(state=self.base / 'state'); self.settings.prepare()
        self.store = Store(self.settings.database)
        self.context = dict(actor='alice', owner='alice', identity='generation', admin=False)
        self.site = dict(owner='alice', identity='generation', domain='site.test', root=str(self.root), suspended=False)
        self.hestia = Mock(); self.hestia.authorize.return_value = self.context; self.hestia.sites.return_value = [self.site]
        self.references = Mock()
        self.references.manifest.side_effect = self.reference
        self.wp = WordPress(self.settings, self.store, self.hestia, self.references)
        self.write('blog/wp-includes/version.php', "<?php\n$wp_version = '6.8.3';\n$wp_local_package = 'en_US';\n")
        self.write('blog/wp-settings.php', 'official core')
        self.write('blog/wp-content/plugins/example/example.php', '<?php\n/*\nPlugin Name: Example\nVersion: 1.2\n*/')
        self.write('blog/wp-content/themes/example/style.css', '/*\nTheme Name: Example\nVersion: 1.2\n*/')

    def write(self, path, text):
        target = self.root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)

    def reference(self, component):
        paths = {'core': ['wp-includes/version.php', 'wp-settings.php'],
                 'plugin': ['example.php'], 'theme': ['style.css']}[component['kind']]
        return {'source': 'https://downloads.wordpress.org/test',
                'files': {p: {'algorithm': 'sha256', 'digest': hashlib.sha256((self.root / component['path'] / p).read_bytes()).hexdigest()}
                          for p in paths}}

    def run_job(self):
        job_id = self.store.enqueue(self.context, self.site, source='wordpress-integrity')
        job = self.store.claim('test-worker')
        self.wp.run(job)
        return self.store.job(self.context, job_id), self.wp.list(self.context)[0]

    def test_nested_installation_and_three_components_verified_without_php_execution(self):
        self.write('blog/wp-config.php', "<?php file_put_contents('/root/SHOULD-NOT-EXECUTE','x');")
        job, report = self.run_job()
        self.assertEqual('completed', job['status'])
        self.assertEqual(1, job['counters']['installations'])
        self.assertEqual(['core', 'plugin', 'theme'], [c['kind'] for c in report['report']['components']])
        self.assertTrue(all(c['status'] == 'verified' for c in report['report']['components']))

    def test_changed_missing_and_additional_are_distinct_and_not_malware_claims(self):
        core = self.reference(dict(kind='core', path='blog'))
        core['files']['wp-admin/missing.php'] = dict(algorithm='md5', digest='0'*32)
        self.write('blog/wp-settings.php', 'changed')
        self.write('blog/wp-includes/backdoor.php', 'extra file')
        original = self.reference
        self.references.manifest.side_effect = lambda c: core if c['kind'] == 'core' else original(c)
        job, report = self.run_job()
        self.assertEqual('completed', job['status'])
        self.assertEqual((1, 1, 1, 0), tuple(job['counters'][k] for k in ('modified', 'missing', 'additional', 'infected')))
        issues = self.wp.report(self.context, job['id'])['files']
        self.assertEqual({'modified', 'missing', 'additional'}, {f['status'] for f in issues})
        findings=self.store.list_findings(self.context)
        self.assertEqual(3, len(findings))
        missing=next(f for f in findings if f['signature'].endswith('.Missing'))
        self.assertTrue(missing['fingerprint']['missing'])
        self.assertEqual('wp-admin/missing.php', missing['fingerprint']['wordpress']['file'])
        self.assertIn('wordpress.integrity_issues', [n['event'] for n in self.store.notifications(self.context)])

    def test_official_variants_accept_all_listed_hashes_but_detect_unlisted_content(self):
        manifests={kind:self.reference(dict(kind=kind,path=path)) for kind,path in
          [('core','blog'),('plugin','blog/wp-content/plugins/example'),('theme','blog/wp-content/themes/example')]}
        expected=manifests['plugin']['files']['example.php'];expected['digest']=['0'*64,expected['digest']]
        self.references.manifest.side_effect=lambda component:manifests[component['kind']]
        job,_=self.run_job();self.assertEqual(0,job['counters']['modified'])
        self.write('blog/wp-content/plugins/example/example.php','<?php\n/*\nPlugin Name: Example\nVersion: 1.2\n*/ changed')
        job,_=self.run_job();self.assertEqual(1,job['counters']['modified'])

    def test_single_file_plugin_explains_unsupported_comparison_without_mapping_jargon(self):
        self.write('blog/wp-content/plugins/hello.php','<?php /* Plugin Name: Single file */')
        job,report=self.run_job();self.assertEqual(1,job['counters']['unverified'])
        component=next(c for c in report['report']['components'] if c['path'].endswith('hello.php'))
        self.assertIn('single PHP file',component['error']);self.assertIn('original plugin package',component['error'])
        self.assertNotIn('mapping',component['error'])

    def test_unavailable_reference_marks_partial_instead_of_verified(self):
        self.references.manifest.side_effect = ReferenceUnavailable('No official reference')
        job, report = self.run_job()
        self.assertEqual('partial', job['status'])
        self.assertEqual(3, job['counters']['unverified'])
        self.assertTrue(all(c['status'] == 'unverified' for c in report['report']['components']))

    def test_unknown_root_code_requires_review_but_site_config_and_content_do_not(self):
        self.write('blog/wp-config.php', '<?php /* private site configuration */')
        self.write('blog/custom-code.php', '<?php /* review code */')
        self.write('blog/wp-content/uploads/customer.txt', 'user content')
        job, _ = self.run_job()
        self.assertEqual(1, job['counters']['additional'])
        findings = self.store.list_findings(self.context)
        self.assertEqual(['blog/custom-code.php'], [f['path'] for f in findings])

    def test_symlinked_core_file_is_never_followed(self):
        core = self.reference(dict(kind='core', path='blog'))
        (self.root/'blog/wp-settings.php').unlink()
        (self.root/'blog/wp-settings.php').symlink_to('/etc/passwd')
        original = self.reference
        self.references.manifest.side_effect = lambda c: core if c['kind'] == 'core' else original(c)
        # A broken core marker does not hide an otherwise identifiable release.
        job, _ = self.run_job()
        self.assertEqual('partial', job['status'])
        self.assertEqual(1, job['counters']['installations'])
        self.assertEqual(1, job['counters']['errors'])

    def test_missing_version_file_does_not_make_broken_wordpress_disappear(self):
        self.write('blog/wp-load.php', 'release loader')
        (self.root/'blog/wp-includes/version.php').unlink()
        job, report = self.run_job()
        self.assertEqual('partial', job['status'])
        self.assertEqual(1, job['counters']['installations'])
        self.assertIn('error', report['report']['installations'][0])

    def test_cancelled_job_retains_partial_report(self):
        job_id = self.store.enqueue(self.context, self.site, source='wordpress-integrity')
        job = self.store.claim('test'); self.store.cancel(self.context, job_id)
        self.wp.run(job)
        self.assertEqual('cancelled', self.store.job(self.context, job_id)['status'])
        self.assertFalse(self.wp.list(self.context)[0]['report']['discovery_complete'])

    def test_report_and_findings_do_not_cross_account_generations(self):
        job, _ = self.run_job()
        other = self.context | {'identity': 'new-generation'}
        self.assertEqual([], self.wp.list(other))
        with self.assertRaises(AccessDenied): self.wp.report(other, job['id'])
        with self.assertRaises(AccessDenied): self.wp.report(self.context, job['id'], -1)

    def test_native_api_enqueues_owner_scoped_integrity_and_revalidates_worker(self):
        app = Application(self.settings, self.store, self.hestia)
        job_id = app.dispatch(dict(actor='alice', action='wordpress-scan', domain='site.test'))['jobs'][0]
        self.hestia.authorize.return_value = self.context | {'identity': 'recreated'}
        Worker(self.settings, self.store, self.hestia, []).once()
        self.assertEqual('failed', self.store.job(self.context, job_id)['status'])
        with self.assertRaises(AccessDenied):
            app.dispatch(dict(actor='alice', action='wordpress-scan', domain='site.test', path='../bob'))

    def test_repeated_and_concurrent_discovery_reuses_one_pending_check(self):
        app=Application(self.settings,self.store,self.hestia)
        request=dict(actor='alice',action='wordpress-scan',domain='site.test')
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:app.dispatch(request),range(12)))
        ids={result['jobs'][0] for result in results}
        self.assertEqual(1,len(ids));self.assertEqual(1,len(self.store.list_jobs(self.context)))
        self.assertTrue(all(result['job']['status']=='queued' for result in results))
        job=self.store.claim('fixture')
        self.assertEqual(job['id'],app.dispatch(request)['jobs'][0])
        self.wp.run(job)
        second=app.dispatch(request)['jobs'][0]
        self.assertNotEqual(job['id'],second);self.assertEqual(2,len(self.store.list_jobs(self.context)))

    def test_integrity_status_is_scoped_and_never_returns_an_unrelated_scan(self):
        job_id=self.store.enqueue(self.context,self.site,source='wordpress-integrity')
        initial=self.wp.status(self.context,job_id)['job']
        self.assertEqual('queued',initial['status']);self.assertFalse(initial['report_ready'])
        for changes in ({'owner':'bob'},{'identity':'recreated'}):
            with self.assertRaises(AccessDenied):self.wp.status(self.context|changes,job_id)
        manual=self.store.enqueue(self.context,self.site)
        with self.assertRaises(AccessDenied):self.wp.status(self.context,manual)
        job=self.store.claim('fixture');self.wp.run(job)
        final=self.wp.status(self.context,job_id)['job']
        self.assertEqual('completed',final['status']);self.assertTrue(final['report_ready'])
        self.assertTrue(final['discovery_complete']);self.assertEqual(1,final['counters']['installations'])
        # Retention updates terminal jobs directly; worker progress is running-only.
        with self.store.connection(True) as db:
            db.execute('UPDATE jobs SET counters=? WHERE id=?',
                       (json.dumps(final['counters']|{'history_expired':True}),job_id))
        self.assertFalse(self.wp.status(self.context,job_id)['job']['report_ready'])

    def test_ambiguous_release_assignments_are_not_evaluated_or_guessed(self):
        with self.assertRaises(ReferenceUnavailable): assignment("$wp_version='6.8';\n$wp_version='6.9';", 'wp_version')


class WordPressReferences(unittest.TestCase):
    def archive(self, entries):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as stream:
            for name, content in entries: stream.writestr(name, content)
        return data.getvalue()

    def test_archive_does_not_extract_paths_or_accept_traversal_duplicates_symlinks(self):
        self.assertEqual({'style.css': b'clean'}, archive_files(self.archive([('theme/style.css', 'clean')]), 'theme'))
        for entries in [[('theme/../outside', 'x')], [('elsewhere/file', 'x')], [('theme/file', 'a'), ('theme/file', 'b')]]:
            with self.subTest(entries=entries), self.assertRaises(ReferenceUnavailable): archive_files(self.archive(entries), 'theme')
        info = zipfile.ZipInfo('theme/link'); info.external_attr = 0o120777 << 16
        with self.assertRaises(ReferenceUnavailable): archive_files(self.archive([(info, '/etc/passwd')]), 'theme')

    def test_reference_network_cannot_redirect_to_arbitrary_hosts_or_plaintext(self):
        for url in ['http://api.wordpress.org/a', 'https://evil.example/a', 'https://user@api.wordpress.org/a', 'https://downloads.wordpress.org:444/a']:
            with self.assertRaises(ReferenceUnavailable): trusted_url(url)

    def test_replacement_archive_member_must_match_independent_release_checksum(self):
        for good in (True,False):
            with self.subTest(good=good),tempfile.TemporaryDirectory() as temp:
                content=b'official release';expected=dict(algorithm='md5',digest=hashlib.md5(content).hexdigest())
                archive=self.archive([('wordpress/wp-settings.php',content if good else b'changed')])
                def fetch(url,maximum):
                    return archive if url.endswith('.zip') else json.dumps({'checksums':{'wp-settings.php':expected['digest']}}).encode()
                references=References(Settings(state=Path(temp)),fetch)
                if good:
                    result,source=references.replacement(dict(kind='core',version='6.8.3'), 'wp-settings.php', expected)
                    self.assertEqual(content,result);self.assertEqual(hashlib.sha256(content).hexdigest(),source['sha256'])
                else:
                    with self.assertRaises(ReferenceUnavailable): references.replacement(dict(kind='core',version='6.8.3'), 'wp-settings.php', expected)

    def test_localized_core_replacement_uses_exact_locale_release(self):
        with tempfile.TemporaryDirectory() as temp:
            content=b'localized release';expected=dict(algorithm='md5',digest=hashlib.md5(content).hexdigest());urls=[]
            def fetch(url,maximum):
                urls.append(url)
                return self.archive([('wordpress/wp-settings.php',content)]) if url.endswith('.zip') else json.dumps({'checksums':{'wp-settings.php':expected['digest']}}).encode()
            references=References(Settings(state=Path(temp)),fetch)
            references.replacement(dict(kind='core',version='6.8.3',locale='de_DE'),'wp-settings.php',expected)
            self.assertIn('https://downloads.wordpress.org/release/de_DE/wordpress-6.8.3.zip',urls)

    def test_plugin_identity_and_digest_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(state=Path(temp)); component = dict(kind='plugin', slug='example', version='1.2')
            response = dict(plugin='other', version='1.2', files={'file.php': {'md5': 'a'*32}})
            references = References(settings, fetch=lambda *_: json.dumps(response).encode())
            with self.assertRaises(ReferenceUnavailable): references.manifest(component)

    def test_plugin_variant_lists_are_validated_and_both_replacement_paths_check_membership(self):
        from clamshield.recovery_references import RecoveryReferences
        from clamshield.wordpress_recovery import options
        content=b'official variant';digest=hashlib.sha256(content).hexdigest()
        component=dict(kind='plugin',slug='example',version='1.2',path='wp-content/plugins/example')
        response=dict(plugin='example',version='1.2',files={'file.php':{'md5':'0'*32,'sha256':['0'*64,digest]}})
        for recovery in (False,True):
            for good in (False,True):
                with self.subTest(recovery=recovery,good=good),tempfile.TemporaryDirectory() as temp:
                    archive=self.archive([('example/file.php',content if good else b'unlisted content')])
                    fetch=lambda url,maximum:archive if url.endswith('.zip') else json.dumps(response).encode()
                    settings=Settings(state=Path(temp))
                    refs=RecoveryReferences(settings,temp,options({'release_policy':'installed'}),fetch=fetch) if recovery else References(settings,fetch)
                    expected=refs.manifest(component)['files']['file.php']
                    self.assertEqual('sha256',expected['algorithm']);self.assertIn(digest,expected['digest'])
                    if good:self.assertEqual(content,refs.replacement(component,'file.php',expected)[0])
                    else:
                        with self.assertRaises(ReferenceUnavailable):refs.replacement(component,'file.php',expected)

    def test_malformed_or_empty_checksum_variants_cannot_downgrade_to_md5(self):
        component=dict(kind='plugin',slug='example',version='1.2')
        for value in ([],[None],[['a'*64]],['short'],['a'*64,'invalid'],['a'*64]*1025):
            with self.subTest(value=value[:2]),tempfile.TemporaryDirectory() as temp:
                response=dict(plugin='example',version='1.2',files={'file.php':{'md5':'a'*32,'sha256':value}})
                refs=References(Settings(state=Path(temp)),fetch=lambda *_:json.dumps(response).encode())
                with self.assertRaises(ReferenceUnavailable):refs.manifest(component)

    def test_reference_http_errors_explain_missing_release_separately_from_network_failure(self):
        from clamshield.wordpress_sources import download
        for code,message in [(404,'No WordPress.org reference'),(410,'No WordPress.org reference'),(429,'request limit'),(503,'HTTP 503')]:
            with self.subTest(code=code),patch('clamshield.wordpress_sources.build_opener') as opener:
                opener.return_value.open.side_effect=HTTPError('https://downloads.wordpress.org/fixture',code,'fixture',{},None)
                with self.assertRaisesRegex(ReferenceUnavailable,message):download('https://downloads.wordpress.org/fixture',1000)

    def test_core_content_is_not_compared_against_bundled_plugin_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            response = dict(checksums={'wp-settings.php': 'a'*32, 'wp-content/plugins/akismet/file.php': 'b'*32})
            references = References(Settings(state=Path(temp)), fetch=lambda *_: json.dumps(response).encode())
            result = references.manifest(dict(kind='core', version='6.8.3'))
            self.assertEqual(['wp-settings.php'], list(result['files']))
