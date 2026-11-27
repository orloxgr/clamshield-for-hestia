import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from clamshield.errors import EngineError
from clamshield.native_admission import NativeAdmission


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root-owned Linux admission locks')
class NativeAdmissionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.admission=NativeAdmission(self.root,native_threads=12,maximum_seconds=.1,grace=.01)

    def test_website_occupancy_leaves_mail_slots_available(self):
        with self.admission.reserve('website',time.monotonic()+1) as website:
            website.started()
            with self.admission.reserve('mail',time.monotonic()+1) as mail:
                mail.started();mail.complete()
            with self.assertRaisesRegex(EngineError,'capacity is busy'), \
                    self.admission.reserve('website',time.monotonic()+.025):pass
            website.complete()
        with self.admission.reserve('website',time.monotonic()+1):pass

    def test_lost_client_retains_lease_until_native_scan_is_bounded_to_finish(self):
        with self.admission.reserve('website',time.monotonic()+1) as website:website.started()
        with self.assertRaisesRegex(EngineError,'capacity is busy'), \
                self.admission.reserve('website',time.monotonic()+.025):pass
        now=time.monotonic()+1
        with patch('clamshield.native_admission.time.monotonic',return_value=now), \
                self.admission.reserve('website',now+1) as website:website.complete()
        self.assertEqual(0,json.loads((self.root/'website-0.lock').read_text())['busy_until'])

    def test_busy_or_failed_client_cannot_consume_another_purposes_quota(self):
        for purpose in ('mail','native-mail'):
            with self.subTest(purpose=purpose),self.admission.reserve(purpose,time.monotonic()+1) as reservation:
                reservation.started()
        with self.admission.reserve('website',time.monotonic()+1) as website:website.complete()
        with self.assertRaisesRegex(EngineError,'reserved for mail'):
            NativeAdmission(self.root,native_threads=7)

    def test_hostile_or_invalid_capacity_records_fail_explicitly(self):
        path=self.root/'website-0.lock'
        for raw in ('[]','{"busy_until":true}','{"busy_until":1e9999}','{"busy_until":0,"other":1}'):
            path.write_text(raw);path.chmod(0o600)
            with self.subTest(raw=raw),self.assertRaises(EngineError), \
                    self.admission.reserve('website',time.monotonic()+1):pass
        path.unlink();other=self.root/'other';other.write_text('');other.chmod(0o600);os.link(other,path)
        with self.assertRaises(EngineError),self.admission.reserve('website',time.monotonic()+1):pass
        path.unlink();path.symlink_to(other)
        with self.assertRaises(EngineError),self.admission.reserve('website',time.monotonic()+1):pass
