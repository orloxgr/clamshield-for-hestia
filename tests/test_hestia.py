from pathlib import Path
import unittest
from unittest.mock import Mock

from clamshield.errors import AccessDenied, ClamShieldError
from clamshield.hestia import Hestia


class NativeInventory(unittest.TestCase):
    def hestia(self):
        instance = Hestia()
        instance.identity = Mock(return_value='generation')
        return instance

    def test_custom_root_comes_from_native_single_domain_fallback(self):
        instance = self.hestia()
        instance.call = Mock(side_effect=[{'site.test': {'SUSPENDED': 'no'}},
                                          {'site.test': {'DOCUMENT_ROOT': '/srv/custom/public'}}])
        sites = instance.sites('alice')
        self.assertEqual('/srv/custom/public', sites[0]['root'])
        instance.call.assert_any_call('v-list-web-domain', 'alice', 'site.test', 'json')

    def test_missing_relative_and_parent_roots_fail_without_guessing(self):
        for root in (None, 'relative', '/home/alice/../bob/public'):
            instance = self.hestia()
            instance.call = Mock(return_value={'site.test': {'DOCUMENT_ROOT': root}})
            with self.subTest(root=root), self.assertRaises(ClamShieldError):
                instance.sites('alice')

    def test_user_cannot_choose_another_account(self):
        instance = self.hestia()
        instance.call = Mock(return_value={'alice': {'ROLE': 'user', 'SUSPENDED': 'no'}})
        with self.assertRaises(AccessDenied):
            instance.authorize('alice', 'bob')

    def test_suspended_admin_has_no_access(self):
        instance = self.hestia()
        instance.call = Mock(return_value={'alice': {'ROLE': 'admin', 'SUSPENDED': 'yes'}})
        with self.assertRaises(AccessDenied):
            instance.authorize('alice')


class NativePanelSession(unittest.TestCase):
    def setUp(self):
        import os,tempfile
        from unittest.mock import patch
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.hestia=Hestia(Path(self.temporary.name))
        self.sessions=self.hestia.root/'data/sessions';self.sessions.mkdir(parents=True)
        self.session_id='a'*32;self.path=self.sessions/('sess_'+self.session_id)
        self.path.write_bytes(b'Native private session fixture');self.path.chmod(0o600)
        self.identities={'alice':'alice-generation','operator_fixture':'admin-generation'}
        self.hestia.identity=Mock(side_effect=lambda owner:self.identities[owner])
        self.hestia.identity_details=Mock(side_effect=lambda owner:(self.identities[owner],100))
        self.hestia.birth=Mock(return_value=('unused',101))
        self.hestia.call=Mock(side_effect=lambda command,owner,*args:{owner:{'ROLE':'admin' if owner=='operator_fixture' else 'user','SUSPENDED':'no'}})
        lookup=patch('pwd.getpwnam',return_value=Mock(pw_uid=os.geteuid()));lookup.start();self.addCleanup(lookup.stop)

    def test_current_session_binds_actor_without_returning_session_material(self):
        self.assertEqual({'alice':'alice-generation'},self.hestia.panel_session('alice','alice',self.session_id))

    def test_same_name_recreation_rejects_older_or_tied_session_birth(self):
        for born in (99,100):
            self.hestia.birth.return_value=('unused',born)
            with self.subTest(born=born),self.assertRaisesRegex(AccessDenied,'predates'):
                self.hestia.panel_session('alice','alice',self.session_id)

    def test_administrator_impersonation_binds_both_native_generations(self):
        binding=self.hestia.panel_session('alice','operator_fixture',self.session_id)
        self.assertEqual(self.identities,binding)
        for owner in ('alice','operator_fixture'):
            previous=self.identities[owner];self.identities[owner]='replacement'
            with self.subTest(owner=owner),self.assertRaises(AccessDenied):self.hestia.verify_panel_session(binding)
            self.identities[owner]=previous

    def test_tenant_session_cannot_claim_another_native_actor(self):
        with self.assertRaises(AccessDenied):self.hestia.panel_session('operator_fixture','alice',self.session_id)

    def test_session_reference_cannot_be_a_path_or_missing_or_nonstring(self):
        for value in (None,{},'','../session','/tmp/session','a'*129,'with whitespace and length'):
            with self.subTest(value=value),self.assertRaises(AccessDenied):self.hestia.panel_session('alice','alice',value)

    def test_linked_shared_or_writable_session_is_refused(self):
        import os
        for kind in ('symlink','hardlink','writable'):
            self.path.unlink(missing_ok=True)
            other=self.sessions/('other-'+kind);other.write_bytes(b'Retained');other.chmod(0o600)
            if kind=='symlink':self.path.symlink_to(other)
            elif kind=='hardlink':os.link(other,self.path)
            else:self.path.write_bytes(b'Wrong permissions');self.path.chmod(0o644)
            with self.subTest(kind=kind),self.assertRaises((OSError,AccessDenied)):
                self.hestia.panel_session('alice','alice',self.session_id)
            self.assertEqual(b'Retained',other.read_bytes())

    def test_session_owned_by_another_uid_is_refused(self):
        import os
        from unittest.mock import patch
        with patch('pwd.getpwnam',return_value=Mock(pw_uid=os.geteuid()+1)):
            with self.assertRaises(AccessDenied):self.hestia.panel_session('alice','alice',self.session_id)

    def test_replacement_during_session_validation_is_refused(self):
        def changed(fd):
            self.identities['alice']='replacement';return ('unused',101)
        self.hestia.birth.side_effect=changed
        with self.assertRaises(AccessDenied):self.hestia.panel_session('alice','alice',self.session_id)

    def test_native_bridge_requires_session_fields_and_does_not_dispatch_on_failure(self):
        import os
        from unittest.mock import patch
        from clamshield.application import Application
        app=Application(Mock(),Mock(),self.hestia);app._dispatch=Mock()
        with patch.dict(os.environ,{'SUDO_USER':'hestiaweb'}):
            with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',action='dashboard'))
        app._dispatch.assert_not_called()

    def test_native_session_is_rechecked_after_authorizing_selected_owner(self):
        from clamshield.application import Application
        app=Application(Mock(),Mock(),self.hestia);app._dispatch=Mock()
        authorize=self.hestia.authorize;count=0
        def replace_after_authorization(*args):
            nonlocal count
            context=authorize(*args);count+=1
            if count==2:self.identities['alice']='replacement'
            return context
        self.hestia.authorize=replace_after_authorization
        with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',native_user='alice',native_session=self.session_id,action='dashboard'))
        app._dispatch.assert_not_called()

    def test_account_replaced_while_reading_cannot_publish_a_stale_response(self):
        from clamshield.application import Application
        app=Application(Mock(),Mock(),self.hestia)
        def changed(*args):
            self.identities['alice']='replacement';return {'private':'old account records'}
        app._dispatch=changed
        with self.assertRaises(AccessDenied):app.dispatch(dict(actor='alice',native_user='alice',native_session=self.session_id,action='dashboard'))


class NativeIdentityDescriptors(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.hestia=Hestia(Path(self.temporary.name));self.account=self.hestia.root/'data/users/root';self.account.mkdir(parents=True)

    def test_descriptor_birth_preserves_existing_identity_digest(self):
        import hashlib,pwd,subprocess
        info=self.account.stat();uid=pwd.getpwnam('root').pw_uid
        born=subprocess.check_output(['/usr/bin/stat','--format=%w','--',str(self.account)],text=True).strip()
        expected=hashlib.sha256(f'{uid}:{info.st_dev}:{info.st_ino}:{born}'.encode()).hexdigest()
        actual,nanoseconds=self.hestia.identity_details('root')
        self.assertEqual(expected,actual);self.assertGreater(nanoseconds,0)

    def test_identity_directory_replaced_during_birth_read_is_refused(self):
        from unittest.mock import patch
        birth=self.hestia.birth
        def replace(fd):
            result=birth(fd);self.account.rename(self.account.with_name('retired'));self.account.mkdir();return result
        with patch.object(self.hestia,'birth',side_effect=replace):
            with self.assertRaises(AccessDenied):self.hestia.identity('root')

    def test_symlinked_native_identity_directory_is_refused(self):
        self.account.rename(self.account.with_name('retired'));self.account.symlink_to(self.account.with_name('retired'))
        with self.assertRaises((OSError,AccessDenied)):self.hestia.identity('root')
