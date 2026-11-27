import base64
import grp
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import AccessDenied,Conflict,EngineError
from clamshield.native_rejection import NativeRejection,flag
from clamshield.settings import Settings


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root native flag lifecycle')
class NativeRejectionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='cs-native-rejection-',dir='/root');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.home=self.root/'home';self.leaf=self.home/'nobody/conf/mail/fixture.test';self.leaf.mkdir(parents=True)
        os.chown(self.leaf,pwd.getpwnam('Debian-exim').pw_uid,grp.getgrnam('mail').gr_gid);self.leaf.chmod(0o771)
        self.flag=self.leaf/'reject_spam';self.flag.write_bytes(b'original flag\n');self.flag.chmod(0o660)
        os.chown(self.flag,pwd.getpwnam('Debian-exim').pw_uid,grp.getgrnam('mail').gr_gid)
        self.original=self.flag.read_bytes();self.metadata=self.flag.stat();self.identity='a'*64;self.reject=True
        self.native=Mock();self.native.identity.side_effect=lambda owner:self.identity
        self.native.birth.side_effect=lambda fd:(str(os.fstat(fd).st_ino),123)
        self.native.call.side_effect=lambda *args:{'fixture.test':{'REJECT':'yes' if self.reject else 'no'}}
        self.native.remaining.return_value=10
        self.native.root=self.root/'hestia';(self.native.root/'data').mkdir(parents=True)
        self.manager=NativeRejection(self.settings,self.native);self.operations=[]
        self.manager.ready=Mock()
        self.manager.command=Mock(side_effect=self.command)
        replacement=patch('clamshield.native_rejection.HOME',self.home);replacement.start();self.addCleanup(replacement.stop)

    def command(self,owner,identity,domain,enabled):
        # The journal must exist before any native mutation.
        rows=self.manager.ledger()['entries'];self.assertTrue(rows)
        self.assertTrue(any(row['state']==('restore_pending' if enabled else 'remove_pending') for row in rows.values()))
        self.operations.append(enabled);self.reject=enabled
        if enabled:self.flag.touch();self.flag.chmod(0o644)
        else:self.flag.unlink()

    def suppress(self):return self.manager.suppress('nobody',self.identity,'fixture.test')

    def rows(self):return [dict(owner='nobody',identity=self.identity,domain='fixture.test',native_reject_spam=self.reject)]

    def test_native_api_intent_precedes_change_and_restore_retains_original_bytes_and_metadata(self):
        self.assertTrue(self.suppress());self.assertFalse(self.flag.exists());self.assertFalse(self.reject)
        self.assertEqual({('nobody',self.identity,'fixture.test')},self.manager.delegated(self.rows()))
        self.assertEqual({'restored':1},self.manager.restore())
        info=self.flag.stat();self.assertEqual(self.original,self.flag.read_bytes())
        self.assertEqual((self.metadata.st_uid,self.metadata.st_gid,self.metadata.st_mode),(info.st_uid,info.st_gid,info.st_mode))
        self.assertEqual([False,True],self.operations)
        self.assertTrue(self.suppress());self.manager.restore();self.assertEqual([False,True,False,True],self.operations)

    def test_failed_or_uncertain_native_command_is_not_retried_by_suppress_or_restore(self):
        self.manager.command.side_effect=EngineError('Timed out')
        with self.assertRaises(EngineError):self.suppress()
        self.assertEqual('review',next(iter(self.manager.ledger()['entries'].values()))['state'])
        with self.assertRaises(Conflict):self.suppress()
        with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(1,self.manager.command.call_count)

    def test_native_administrator_reenable_is_preserved_and_not_suppressed_in_a_loop(self):
        self.suppress();self.flag.write_bytes(b'admin change');self.flag.chmod(0o660);self.reject=True
        self.assertEqual(set(),self.manager.delegated(self.rows()))
        self.assertEqual({'restored':0},self.manager.restore())
        self.assertEqual(b'admin change',self.flag.read_bytes());self.assertEqual([False],self.operations)

    def test_recreated_account_does_not_inherit_old_native_flag(self):
        self.suppress();self.identity='b'*64
        self.assertEqual({'restored':0},self.manager.restore());self.assertFalse(self.flag.exists())
        self.assertEqual([False],self.operations)

    def test_recreated_domain_does_not_inherit_old_native_flag(self):
        self.suppress();self.leaf.rename(self.leaf.with_name('old.test'));self.leaf.mkdir()
        os.chown(self.leaf,pwd.getpwnam('Debian-exim').pw_uid,grp.getgrnam('mail').gr_gid);self.leaf.chmod(0o771)
        self.assertEqual(set(),self.manager.delegated(self.rows()))
        self.assertEqual({'restored':0},self.manager.restore());self.assertFalse(self.flag.exists())

    def test_symlink_hardlink_and_tenant_writable_ancestor_are_refused_before_native_api(self):
        original=self.flag.read_bytes();self.flag.unlink();target=self.root/'target';target.write_bytes(original);target.chmod(0o600)
        self.flag.symlink_to(target)
        with self.assertRaises(OSError):self.suppress()
        self.flag.unlink();os.link(target,self.flag)
        with self.assertRaises(AccessDenied):self.suppress()
        self.flag.unlink();self.flag.write_bytes(original);self.flag.chmod(0o660);self.home.chmod(0o777)
        with self.assertRaises(AccessDenied):self.suppress()
        self.assertEqual([],self.operations)

    def test_inconsistent_native_inventory_or_flag_does_not_claim_delegation(self):
        self.reject=False
        with self.assertRaises(Conflict):self.suppress()
        self.flag.unlink();self.assertFalse(self.suppress());self.assertEqual([],self.operations)

    def test_restore_failure_retains_review_receipt_and_does_not_repeat_api(self):
        self.suppress();self.manager.command.side_effect=EngineError('Failed restore')
        with self.assertRaises(EngineError):self.manager.restore()
        with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(2,self.manager.command.call_count)

    def test_owned_extension_is_removed_on_disable_and_foreign_extension_is_never_replaced(self):
        from clamshield.native_rejection import EXTENSION
        path=self.native.root/'data/extensions'/EXTENSION
        self.manager.install_extension();self.assertEqual(0o755,path.stat().st_mode&0o777)
        original=path.read_bytes();self.manager.install_extension();self.assertEqual(original,path.read_bytes())
        self.manager.remove_extension();self.assertFalse(path.exists())
        path.write_text('# foreign extension\n');path.chmod(0o755)
        with self.assertRaises(Conflict):self.manager.install_extension()
        self.assertEqual('# foreign extension\n',path.read_text())

    def test_administrator_replacement_of_owned_extension_survives_disable(self):
        from clamshield.native_rejection import EXTENSION
        self.manager.install_extension();path=self.native.root/'data/extensions'/EXTENSION
        path.write_text('# administrator replacement\n')
        with self.assertRaises(Conflict):self.manager.install_extension()
        self.manager.remove_extension();self.assertEqual('# administrator replacement\n',path.read_text())

    def test_native_restoration_precedes_hook_detachment(self):
        from clamshield.mail_integration import MailIntegration
        from clamshield.atomic import write_json
        manager=MailIntegration(self.settings,None,self.native)
        manager.drain=Mock();manager.phase=Mock(side_effect=EngineError('stop before detach'))
        activation=self.settings.state/'native-rejection-activation.json'
        write_json(activation,dict(code_generation='fixture',phase='active'))
        with patch('clamshield.native_rejection.NativeRejection',return_value=self.manager):
            self.suppress()
            with self.assertRaises(EngineError):manager.finish_disabled({},dict(phase='disabled'))
        self.assertTrue(self.flag.exists());self.assertTrue(self.reject)
        self.assertFalse(activation.exists())

    def test_existing_enabled_server_defaults_delegate_once_after_update_without_retry_loop(self):
        from clamshield.mail_integration import MailIntegration
        from clamshield.store import Store
        manager=MailIntegration(self.settings,Store(self.settings.database),self.native)
        with patch('clamshield.mail_policy.MailPolicies.server_defaults',return_value={'enabled':True}), \
                patch('clamshield.native_rejection.NativeRejection.activate',return_value={'delegated_domains':1}) as activate:
            self.assertEqual({'delegated_domains':1},manager.native_policies())
            self.assertEqual({'configured':True},manager.native_policies());activate.assert_called_once()

    def test_automatic_failed_native_activation_is_not_repeated_even_after_code_update(self):
        from clamshield.mail_integration import MailIntegration
        from clamshield.store import Store
        manager=MailIntegration(self.settings,Store(self.settings.database),self.native)
        with patch('clamshield.mail_policy.MailPolicies.server_defaults',return_value={'enabled':True}), \
                patch('clamshield.native_rejection.NativeRejection.activate',side_effect=EngineError('Failed native API')) as activate:
            self.assertEqual({'review_required':True},manager.native_policies())
            with patch.object(manager,'code_identity',return_value='next-code'):
                self.assertEqual({'review_required':True},manager.native_policies())
            activate.assert_called_once()
