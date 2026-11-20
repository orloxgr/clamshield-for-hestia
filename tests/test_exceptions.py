from pathlib import Path
import tempfile
import time
import unittest

from clamshield.errors import AccessDenied, ClamShieldError
from clamshield.exceptions import Exceptions
from clamshield.store import Store


class ScopedExceptions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store=Store(Path(self.temp.name)/'state.sqlite3')
        self.context=dict(actor='alice',owner='alice',identity='generation')
        site=dict(owner='alice',identity='generation',domain='alice.test',root='/srv/alice')
        self.store.enqueue(self.context,site)
        self.job=self.store.claim('worker')
        self.hit=dict(engine='yara',signature='Webshell',provider='local')
        self.finding=self.store.add_finding(self.job,'index.php',{'sha256':'original'},self.hit)
        self.exceptions=Exceptions(self.store)

    def test_content_trust_does_not_apply_after_file_changes(self):
        self.exceptions.add(self.context,self.finding,'file')
        visible,suppressed=self.exceptions.filter(self.job,'index.php',{'sha256':'original'},[self.hit])
        self.assertEqual([],visible);self.assertEqual(1,len(suppressed))
        visible,suppressed=self.exceptions.filter(self.job,'index.php',{'sha256':'changed'},[self.hit])
        self.assertEqual([self.hit],visible);self.assertEqual([],suppressed)

    def test_rule_exception_never_disables_rule_for_another_file_domain_or_account(self):
        self.exceptions.add(self.context,self.finding,'signature')
        for job,path in ((self.job,'other.php'),(self.job|{'domain':'bob.test'},'index.php'),
                         (self.job|{'owner':'bob'},'index.php'),(self.job|{'identity':'replacement'},'index.php'),
                         (self.job|{'root':'/srv/new-root'},'index.php')):
            visible,suppressed=self.exceptions.filter(job,path,{'sha256':'original'},[self.hit])
            self.assertEqual([self.hit],visible)

    def test_other_account_cannot_add_read_or_remove_exceptions(self):
        foreign=dict(actor='bob',owner='bob',identity='other')
        with self.assertRaises(AccessDenied):self.exceptions.add(foreign,self.finding)
        exception=self.exceptions.add(self.context,self.finding)
        self.assertEqual([],self.exceptions.list(foreign))
        with self.assertRaises(AccessDenied):self.exceptions.remove(foreign,exception)

    def test_expired_or_removed_exception_does_not_suppress_detection(self):
        exception=self.exceptions.add(self.context,self.finding,'file',expires=time.time()+60)
        self.exceptions.remove(self.context,exception)
        self.assertEqual([self.hit],self.exceptions.filter(self.job,'index.php',{'sha256':'original'},[self.hit])[0])
        with self.assertRaises(ClamShieldError):self.exceptions.add(self.context,self.finding,expires=float('nan'))
