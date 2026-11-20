import hashlib
import json
import unittest

from clamshield.errors import ClamShieldError
from clamshield.php_hosting_rules import fetch


class HostingRuleData(unittest.TestCase):
    def fixture(self, files=None, *, truncated=False, commit='a'*40, corrupt=None):
        files=files or {'data/php.yar':b'/* main notice */\ninclude "shared.yar"\nrule Public {condition:Helper}\n',
            'data/shared.yar':b'/* shared notice */\nprivate rule Helper {condition:true}\n',
            'LICENSE':b'GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3\n'}
        nodes=[dict(path=path,type='blob',size=len(data),sha=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()) for path,data in files.items()]
        calls=[]
        def download(url, maximum):
            calls.append(url)
            if '/commits/' in url:return json.dumps(dict(sha=commit)).encode()
            if '/git/trees/' in url:return json.dumps(dict(tree=nodes,truncated=truncated)).encode()
            path=url.split('/'+commit+'/',1)[1]
            return corrupt if corrupt is not None and path=='data/shared.yar' else files[path]
        return download,calls

    def test_verified_bundle_preserves_rule_bytes_notices_and_immutable_receipts(self):
        download,calls=self.fixture();content,meta=fetch(download)
        self.assertIn(b'/* main notice */',content);self.assertIn(b'/* shared notice */',content)
        self.assertIn(b'private rule Helper {condition:true}',content);self.assertIn(b'rule Public {condition:Helper}',content)
        self.assertNotIn(b'include ',content);self.assertTrue(meta['review_only']);self.assertEqual('website',meta['scope'])
        self.assertEqual('a'*40,meta['commit']);self.assertEqual(3,len(meta['dependencies']))
        self.assertEqual(hashlib.sha256(meta['license'].encode()).hexdigest(),meta['license_sha256'])
        self.assertTrue(all('raw.githubusercontent.com/jvoisin/php-malware-finder/'+('a'*40)+'/' in url for url in calls if '/git/trees/' not in url and '/commits/' not in url))

    def test_wrong_commit_truncated_tree_and_wrong_git_blob_are_rejected(self):
        for options in (dict(commit='master'),dict(truncated=True),dict(corrupt=b'not the recorded body')):
            with self.subTest(options=options),self.assertRaises(ClamShieldError):fetch(self.fixture(**options)[0])

    def test_includes_cannot_escape_data_tree_or_use_unknown_directives(self):
        for target in ('/etc/shadow','../../secret.yar','https://evil.invalid/x.yar','missing.yar','a\\b.yar'):
            files={'data/php.yar':('include "'+target+'"\n').encode(),'LICENSE':b'GNU LESSER GENERAL PUBLIC LICENSE'}
            with self.subTest(target=target),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])
        files={'data/php.yar':b'include "shared.yar" // unsupported directive shape\n','LICENSE':b'GNU LESSER GENERAL PUBLIC LICENSE'}
        with self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])

    def test_cycle_changed_license_and_non_utf8_dependency_are_rejected(self):
        cases=[{'data/php.yar':b'include "php.yar"\n','LICENSE':b'GNU LESSER GENERAL PUBLIC LICENSE'},
            {'data/php.yar':b'rule A {condition:true}','LICENSE':b'license changed'},
            {'data/php.yar':b'\xff','LICENSE':b'GNU LESSER GENERAL PUBLIC LICENSE'}]
        for files in cases:
            with self.subTest(files=files),self.assertRaises(ClamShieldError):fetch(self.fixture(files)[0])

    def test_downloader_cannot_return_oversized_document(self):
        with self.assertRaises(ClamShieldError):fetch(lambda *_:b'x'*(4*1024*1024+1))
