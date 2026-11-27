import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.atomic import write,write_json
from clamshield.errors import Conflict,EngineError
from clamshield.native_dnsbl import NativeDnsbl,ERRORS,LEGACY_ERRORS,entries,replacement
from clamshield.settings import Settings


class EntryTests(unittest.TestCase):
    def test_complete_operational_error_network_excludes_no_genuine_listing_codes(self):
        self.assertEqual(256,len(ERRORS));self.assertEqual('127.255.255.0',ERRORS[0]);self.assertEqual('127.255.255.255',ERRORS[-1])
        for code in ('127.255.255.250','127.255.255.251','127.255.255.253'):
            self.assertIn(code,replacement('zen.spamhaus.org'))
        for code in ('127.0.0.2','127.0.0.4','127.0.0.10','127.0.0.30'):
            self.assertNotIn(code,ERRORS)
        self.assertEqual([replacement('zen.spamhaus.org')],entries((replacement('zen.spamhaus.org')+'\n').encode()))

    def test_only_known_spamhaus_ip_lists_get_documented_error_exclusions(self):
        safe='!='+','.join(ERRORS)
        for zone in ('zen.spamhaus.org','sbl.spamhaus.org','xbl.spamhaus.org','pbl.spamhaus.org','private-key.zen.dq.spamhaus.net'):
            self.assertEqual(zone+safe,replacement(zone));self.assertEqual(zone+safe,replacement(zone+safe))
        self.assertEqual('zen.spamhaus.org!=127.0.0.10,'+','.join(ERRORS),replacement('zen.spamhaus.org!=127.0.0.10'))
        for other in ('bl.spamcop.net','zen.spamhaus.org.attacker.test','dbl.spamhaus.org','user.spamhaus.org','private-key.zen.dq.spamhaus.net.attacker.test'):
            self.assertEqual(other,replacement(other))

    def test_unsupported_native_syntax_and_invalid_addresses_are_not_rewritten(self):
        for content in (b'zen.spamhaus.org\nzen.spamhaus.org\n',b'zone.test=127.0.0.2\n',b'zone.test!=999.1.1.1',b'zone.test\x00',b'zone.test#suffix',b'\xff'):
            with self.subTest(content=content),self.assertRaises((Conflict,EngineError)):entries(content)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Root supported native configuration lifecycle')
class NativeDnsblTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='cs-native-dnsbl-',dir='/root');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare()
        self.native=self.root/'exim/dnsbl.conf';self.native.parent.mkdir()
        self.hestia=Mock(root=self.root/'hestia');(self.hestia.root/'conf').mkdir(parents=True)
        self.custom=self.hestia.root/'conf/dnsbl.conf';self.default=b'bl.spamcop.net\nzen.spamhaus.org\n'
        write(self.native,self.default,0o640)
        self.manager=NativeDnsbl(self.settings,self.hestia,native=self.native);self.operations=[]
        self.manager.command=Mock(side_effect=self.command)

    def command(self,add,entry):
        value=self.manager.ledger();self.assertIn(value['state'],('applying','restoring'))
        self.assertTrue(any(row['state'] in ('adding','removing','restoring') for row in value['rows']))
        self.assertEqual(0o600,stat.S_IMODE(self.manager.path.stat().st_mode))
        self.operations.append((add,entry))
        if not self.custom.exists():shutil.copyfile(self.native,self.custom)
        lines=self.custom.read_bytes().decode('utf-8',errors='surrogateescape').splitlines()
        if add:lines.append(entry)
        else:lines=[line for line in lines if not re.fullmatch(entry,line)]
        content=('\n'.join(lines)+'\n').encode('utf-8',errors='surrogateescape')
        if sorted(entries(content))==sorted(entries(self.default)):
            self.custom.unlink();self.native.write_bytes(self.default)
        else:self.custom.write_bytes(content);self.native.write_bytes(content)

    def configure(self,content):
        self.custom.write_bytes(content);self.native.write_bytes(content)

    def test_intent_precedes_native_api_and_repeatable_restore_keeps_bytes_metadata_and_absent_custom(self):
        before=self.native.stat()
        self.assertEqual({'protected_entries':1},self.manager.protect())
        self.assertEqual(2,len(self.operations));self.assertTrue(self.custom.exists())
        self.assertEqual({'protected_entries':1,'review_required':False},self.manager.protect())
        self.assertEqual(2,len(self.operations));self.assertEqual(1,self.manager.status()['protected_entries'])
        self.assertEqual({'restored_entries':1},self.manager.restore())
        self.assertFalse(self.custom.exists());self.assertEqual(self.default,self.native.read_bytes())
        self.assertEqual((before.st_uid,before.st_gid,before.st_mode),(self.native.stat().st_uid,self.native.stat().st_gid,self.native.stat().st_mode))
        self.assertEqual({'restored_entries':0},self.manager.restore());self.assertEqual(4,len(self.operations))
        self.manager.protect();self.assertEqual(6,len(self.operations))

    def test_original_custom_format_and_permissions_are_restored_even_when_api_removes_default_copy(self):
        self.custom.write_bytes(self.default);self.custom.chmod(0o600)
        self.manager.protect();self.manager.restore()
        self.assertEqual(self.default,self.custom.read_bytes());self.assertEqual(0o600,stat.S_IMODE(self.custom.stat().st_mode))
        custom=b'# administrator comment\nzen.spamhaus.org\nbl.spamcop.net\n'
        self.configure(custom);self.manager.protect();self.manager.restore()
        self.assertEqual(custom,self.custom.read_bytes());self.assertEqual(custom,self.native.read_bytes())

    def legacy_protection(self):
        original=replacement
        with patch('clamshield.native_dnsbl.replacement',side_effect=lambda entry,**kwargs:original(entry,errors=kwargs.get('errors',LEGACY_ERRORS))):
            self.manager.protect()
        return self.manager.ledger()

    def test_exact_owned_legacy_output_upgrades_once_and_original_uninstall_receipt_survives(self):
        old=self.legacy_protection();self.assertEqual(2,len(self.operations))
        self.assertEqual({'protected_entries':1,'review_required':False},self.manager.protect())
        now=self.manager.ledger();self.assertEqual(old['before'],now['before']);self.assertEqual(4,len(self.operations))
        self.assertEqual(replacement('zen.spamhaus.org'),now['rows'][0]['replacement'])
        self.assertNotIn('previous_replacement',now['rows'][0])
        self.manager.protect();self.assertEqual(4,len(self.operations))
        self.manager.restore();self.assertEqual(self.default,self.native.read_bytes());self.assertFalse(self.custom.exists())

    def test_legacy_upgrade_never_overwrites_later_administrator_output(self):
        self.legacy_protection();self.configure(self.native.read_bytes()+b'admin.example.test\n')
        self.assertTrue(self.manager.protect()['review_required']);self.assertEqual(2,len(self.operations))
        self.manager.restore();self.assertIn(b'admin.example.test',self.native.read_bytes());self.assertNotIn(b'!=',self.native.read_bytes())

    def test_uncertain_legacy_upgrade_keeps_both_receipts_and_never_retries(self):
        old=self.legacy_protection();command=self.command
        def fail_removal(add,entry):
            if not add:raise EngineError('Native upgrade removal failed')
            command(add,entry)
        self.manager.command.side_effect=fail_removal
        with self.assertRaises(EngineError):self.manager.protect()
        value=self.manager.ledger();self.assertEqual('review',value['state'])
        self.assertEqual(old['rows'][0]['replacement'],value['rows'][0]['previous_replacement'])
        attempts=self.manager.command.call_count
        for _ in range(2):
            with self.assertRaises(Conflict):self.manager.protect()
            with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(attempts,self.manager.command.call_count)

    def test_forged_active_upgrade_receipt_is_not_authority_to_mutate_native_settings(self):
        self.manager.protect();value=self.manager.ledger();value['rows'][0]['previous_replacement']=replacement('zen.spamhaus.org',errors=LEGACY_ERRORS)
        write_json(self.manager.path,value)
        with self.assertRaises(EngineError):self.manager.protect()
        self.assertEqual(2,len(self.operations))

    def test_legacy_comment_bytes_are_preserved_without_accepting_non_ascii_zone_entries(self):
        content=b'# administrator legacy comment \xff\nzen.spamhaus.org\nbl.spamcop.net\n'
        self.configure(content);self.manager.protect();self.manager.restore()
        self.assertEqual(content,self.native.read_bytes());self.assertEqual(content,self.custom.read_bytes())

    def test_other_administrator_entries_and_permissions_survive_restore(self):
        self.manager.protect();self.configure(self.native.read_bytes()+b'admin.example.test\n');self.native.chmod(0o600)
        self.manager.restore()
        self.assertIn(b'admin.example.test',self.native.read_bytes());self.assertIn(b'zen.spamhaus.org\n',self.native.read_bytes())
        self.assertNotIn(b'!=',self.native.read_bytes());self.assertTrue(self.custom.exists());self.assertEqual(0o600,stat.S_IMODE(self.native.stat().st_mode))

    def test_administrator_edited_owned_entry_is_never_overwritten_or_reapplied(self):
        self.manager.protect();self.configure(b'bl.spamcop.net\nzen.spamhaus.org!=127.0.0.2\n')
        self.assertTrue(self.manager.protect()['review_required']);self.assertEqual(2,len(self.operations))
        self.assertEqual({'restored_entries':0},self.manager.restore())
        self.assertEqual(b'bl.spamcop.net\nzen.spamhaus.org!=127.0.0.2\n',self.native.read_bytes())

    def test_administrator_readded_original_kept_but_our_replacement_removed(self):
        self.manager.protect();self.configure(self.native.read_bytes()+b'zen.spamhaus.org\n')
        self.assertTrue(self.manager.protect()['review_required']);self.manager.restore()
        self.assertEqual(self.default,self.native.read_bytes());self.assertEqual(3,len(self.operations))

    def test_administrator_added_another_same_zone_choice_kept_without_old_choice_returning(self):
        self.manager.protect();admin='zen.spamhaus.org!=127.0.0.2';self.configure(self.native.read_bytes()+admin.encode()+b'\n')
        self.manager.restore();self.assertIn(admin,entries(self.native.read_bytes()));self.assertNotIn('zen.spamhaus.org',entries(self.native.read_bytes()))
        self.assertEqual(3,len(self.operations))

    def test_native_api_failure_never_retries_in_protect_or_restore(self):
        self.manager.command.side_effect=EngineError('Native timeout')
        with self.assertRaises(EngineError):self.manager.protect()
        for _ in range(3):
            with self.assertRaises(Conflict):self.manager.protect()
            with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(1,self.manager.command.call_count);self.assertEqual('review',self.manager.ledger()['state'])

    def test_partial_native_removal_failure_is_durable_and_not_retried(self):
        command=self.command
        def fail(add,entry):
            if not add:raise EngineError('Removal failed')
            command(add,entry)
        self.manager.command.side_effect=fail
        with self.assertRaises(EngineError):self.manager.protect()
        self.assertEqual('review',self.manager.ledger()['state']);self.assertIn('zen.spamhaus.org',entries(self.native.read_bytes()))
        with self.assertRaises(Conflict):self.manager.protect()
        self.assertEqual(2,self.manager.command.call_count)

    def test_concurrent_entry_during_api_is_preserved_and_requires_review(self):
        def concurrent(add,entry):self.command(add,entry);self.configure(self.native.read_bytes()+b'admin.example.test\n')
        self.manager.command.side_effect=concurrent
        with self.assertRaises(Conflict):self.manager.protect()
        self.assertIn(b'admin.example.test',self.native.read_bytes());self.assertEqual('review',self.manager.ledger()['state'])
        with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual(1,len(self.operations))

    def test_regex_collision_is_refused_before_any_native_change(self):
        self.configure(self.default+b'zenXspamhausXorg\n')
        with self.assertRaisesRegex(Conflict,'another entry'):self.manager.protect()
        self.assertEqual([],self.operations);self.assertFalse(self.manager.path.exists())

    def test_whitespace_crlf_or_missing_final_newline_are_not_partially_changed_by_native_api(self):
        for content in (b' zen.spamhaus.org\n',b'zen.spamhaus.org\r\n',b'zen.spamhaus.org'):
            self.native.write_bytes(content)
            with self.subTest(content=content),self.assertRaisesRegex(Conflict,'formatting'):self.manager.protect()
            self.assertEqual(content,self.native.read_bytes());self.assertEqual([],self.operations)

    def test_symlinks_hardlinks_and_writable_parent_are_rejected_before_api(self):
        target=self.root/'outside';target.write_bytes(self.native.read_bytes());self.native.unlink();self.native.symlink_to(target)
        with self.assertRaises(OSError):self.manager.protect()
        self.native.unlink();os.link(target,self.native)
        with self.assertRaises(EngineError):self.manager.protect()
        self.native.unlink();self.native.write_bytes(self.default);self.native.parent.chmod(0o777)
        with self.assertRaises(EngineError):self.manager.protect()
        self.native.parent.chmod(0o755);self.assertEqual([],self.operations)

    def test_replaced_parent_after_api_is_not_blessed(self):
        def replaced(add,entry):
            self.command(add,entry);self.native.parent.rename(self.native.parent.with_name('old-exim'));self.native.parent.mkdir();self.native.write_bytes(b'foreign.example.test\n')
        self.manager.command.side_effect=replaced
        with self.assertRaises(Conflict):self.manager.protect()
        self.assertEqual(b'foreign.example.test\n',self.native.read_bytes());self.assertEqual('review',self.manager.ledger()['state'])

    def test_replaced_native_leaf_with_identical_content_is_not_blessed(self):
        def replaced(add,entry):
            self.command(add,entry);other=self.native.with_name('replacement');other.write_bytes(self.native.read_bytes());other.chmod(stat.S_IMODE(self.native.stat().st_mode));os.replace(other,self.native)
        self.manager.command.side_effect=replaced
        with self.assertRaisesRegex(Conflict,'replaced during API'):self.manager.protect()
        self.assertEqual('review',self.manager.ledger()['state']);self.assertEqual(1,len(self.operations))

    def test_restoration_api_failure_is_not_retried(self):
        self.manager.protect();self.manager.command.side_effect=EngineError('Native restore failed')
        with self.assertRaises(EngineError):self.manager.restore()
        with self.assertRaises(Conflict):self.manager.restore()
        self.assertEqual('review',self.manager.ledger()['state']);self.assertEqual(3,self.manager.command.call_count)

    def test_private_keys_are_not_exported_by_status_or_result(self):
        self.configure(b'private-key.zen.dq.spamhaus.net\n');result=self.manager.protect()
        self.assertNotIn('private-key',json.dumps(result));self.assertNotIn('private-key',json.dumps(self.manager.status()))
        self.assertIn('private-key',self.manager.path.read_text());self.assertEqual(0o600,stat.S_IMODE(self.manager.path.stat().st_mode))

    def test_forged_restore_file_attributes_are_rejected(self):
        self.manager.protect();value=self.manager.ledger();value['before']['native']['stamp']['st_uid']=1000;write_json(self.manager.path,value)
        with self.assertRaises(EngineError):self.manager.restore()
        self.assertEqual(2,len(self.operations))

    def test_split_native_source_is_not_automatically_repaired(self):
        self.custom.write_bytes(b'other.example.test\n')
        with self.assertRaisesRegex(Conflict,'disagree'):self.manager.protect()
        self.assertEqual([],self.operations)
