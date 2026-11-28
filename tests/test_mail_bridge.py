import array
import fcntl
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest

from clamshield.errors import AccessDenied, ClamShieldError
from clamshield.mail_bridge import Decision, MAX_MESSAGE, MAX_METADATA, SEALS, receive, respond, process_start


def envelope(**overrides):
    data = {'message_id': '1abcDE-00000000001-0001', 'sender': 'sender@example.net',
            'remote_ip': '192.0.2.5', 'authenticated_id': '', 'protocol': 'esmtp',
            'recipients': ['first@example.test', 'second@example.test']}
    data.update(overrides)
    fields = [data[k] for k in ('message_id', 'sender', 'remote_ip', 'authenticated_id', 'protocol')]
    tagged=data.get('fallback_tags_supported') is True
    mime='native_mime_blocked' in data or tagged
    dnsbl='native_dnsbl_zone' in data or 'native_dnsbl_value' in data or mime
    if 'native_spam_score' in data or dnsbl:fields.append(data.get('native_spam_score',''))
    if dnsbl:fields.extend([data.get('native_dnsbl_zone',''),data.get('native_dnsbl_value','')])
    if mime:fields.append(data.get('native_mime_blocked',''))
    fields.extend(data['recipients'])
    result = (b'CSMAIL05' if tagged else b'CSMAIL04' if mime else b'CSMAIL03' if dnsbl else b'CSMAIL02' if 'native_spam_score' in data else b'CSMAIL01') + struct.pack('!II', len(data['recipients']), data.get('flags',1))
    for field in fields:
        value = field.encode()
        result += struct.pack('!I', len(value)) + value
    return result


@unittest.skipUnless(sys.platform == 'linux', 'Linux sealed descriptors and native credentials')
class MailBridgeTests(unittest.TestCase):
    def test_fallback_marks_require_the_new_native_protocol_capability(self):
        for capability in (False,True):
            self.send(envelope(fallback_tags_supported=capability));request=self.get()
            try:self.assertIs(request.fallback_tags_supported,capability)
            finally:request.close()

    def test_native_fallback_mark_vector_is_bounded_and_cannot_transfer_custody(self):
        respond(self.server,Decision.TAGGED_FALLBACK,'a'*32,tags=[1,0,2,3,4])
        self.assertEqual(self.client.recv(100),b'CSMRSP01'+struct.pack('!I',6)+b'a'*32+struct.pack('!I',5)+bytes([1,0,2,3,4]))
        for tags in (None,[],[0,0],[True,0],[5],[-1],[1]*1001,['malware']):
            with self.subTest(tags=str(tags)[:25]),self.assertRaises(ClamShieldError):
                respond(self.server,Decision.TAGGED_FALLBACK,'a'*32,tags=tags)
        with self.assertRaises(ClamShieldError):respond(self.server,Decision.ACCEPT,'a'*32,tags=[1])
        with self.assertRaises(ClamShieldError):respond(self.server,Decision.TAGGED_FALLBACK,'a'*32,[True,False],tags=[1,0])

    def test_native_mime_match_is_versioned_bounded_and_absent_in_older_packets(self):
        for raw,expected in (('1',True),('0',False),('',False)):
            self.send(envelope(native_mime_blocked=raw));request=self.get()
            try:self.assertIs(expected,request.native_mime_blocked)
            finally:request.close()
        for raw in ('2','yes','\n'):
            self.send(envelope(native_mime_blocked=raw))
            with self.assertRaises(ClamShieldError):self.get()
        self.send(envelope(native_dnsbl_zone='',native_dnsbl_value=''));request=self.get()
        try:self.assertIs(False,request.native_mime_blocked)
        finally:request.close()
    def test_native_dnsbl_fields_are_bounded_versioned_and_not_read_from_rfc822_headers(self):
        self.send(envelope(native_dnsbl_zone='private-key.zen.dq.spamhaus.net',native_dnsbl_value='127.0.0.2, 127.255.255.251',native_spam_score='13'))
        request=self.get()
        try:
            self.assertEqual(('private-key.zen.dq.spamhaus.net','127.0.0.2, 127.255.255.251',1.3),
                             (request.native_dnsbl_zone,request.native_dnsbl_value,request.native_spam_score))
        finally:request.close()
        for values in (dict(native_dnsbl_zone='x'*257),dict(native_dnsbl_value='x'*2049),dict(native_dnsbl_zone='zone\nFORGED')):
            self.send(envelope(**values))
            with self.assertRaises(ClamShieldError):self.get()
        for packet in (envelope(),envelope(native_spam_score='0')):
            self.send(packet);request=self.get()
            try:self.assertEqual(('',''),(request.native_dnsbl_zone,request.native_dnsbl_value))
            finally:request.close()

    def test_native_score_is_a_bounded_authenticated_protocol_field_not_a_header(self):
        for raw,expected in [('10000',1000),('-23',-2.3),('0',0),('',None)]:
            self.send(envelope(native_spam_score=raw))
            request=self.get()
            try:self.assertEqual(expected,request.native_spam_score)
            finally:request.close()
        for raw in ('nan','inf','3.5','1e3','10000000000','0\nFORGED'):
            self.send(envelope(native_spam_score=raw))
            with self.assertRaises(ClamShieldError):self.get()
        self.send(envelope())
        request=self.get()
        try:self.assertIsNone(request.native_spam_score)
        finally:request.close()
    def setUp(self):
        self.client, self.server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.fds = []

    def tearDown(self):
        self.client.close()
        self.server.close()
        for fd in self.fds:
            os.close(fd)

    def snapshot(self, sealed=True):
        fd = os.memfd_create('test-mail', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        self.fds.append(fd)
        os.write(fd, b'To: forged-header@example.test\n\nA harmless body\n')
        if sealed:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        return fd

    def send(self, data=None, descriptors=None):
        fds = descriptors if descriptors is not None else [self.snapshot()]
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
        self.client.sendmsg([envelope() if data is None else data], ancillary)

    def get(self, **kwargs):
        return receive(self.server, expected_uid=kwargs.get('uid', os.getuid()),
                       expected_binary=kwargs.get('binary', sys.executable), timeout=1)

    def test_trusted_envelope_and_immutable_snapshot(self):
        self.send()
        request = self.get()
        try:
            self.assertEqual(request.recipients, ('first@example.test', 'second@example.test'))
            self.assertIn(b'forged-header', os.pread(request.fd, 1000, 0))
            self.assertFalse(os.get_inheritable(request.fd))
            self.assertEqual(os.getpid(),request.peer_pid)
            self.assertEqual(process_start(os.getpid()),request.peer_start)
            with self.assertRaises(OSError):
                os.pwrite(request.fd, b'changed', 0)
        finally:
            request.close()

    def test_untrusted_native_uid_and_executable(self):
        with self.assertRaises(AccessDenied):
            self.get(uid=os.getuid() + 1000)
        with self.assertRaises(AccessDenied):
            self.get(binary='/bin/true')

    def test_unsealed_linked_and_directory_descriptors_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            p = Path(path) / 'linked'; p.write_bytes(b'harmless')
            for fd in (self.snapshot(sealed=False), os.open(p, os.O_RDONLY), os.open(path, os.O_DIRECTORY)):
                if fd not in self.fds:
                    self.fds.append(fd)
                self.send(descriptors=[fd])
                with self.assertRaises((ClamShieldError, OSError)):
                    self.get()

    def test_missing_and_extra_descriptors_closed(self):
        for fds in ([], [self.snapshot(), self.snapshot()], [self.snapshot()] * 30):
            self.send(descriptors=fds)
            before = len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ClamShieldError):
                self.get()
            self.assertEqual(before, len(os.listdir('/proc/self/fd')))

    def test_trailing_truncated_control_and_unqualified_metadata_rejected(self):
        for data in (envelope() + b'extra', envelope()[:-1], b'CSMAIL03' + envelope()[8:],
                     envelope(sender='sender@example.test\nX-Forged: yes'),
                     envelope(recipients=['unqualified']), envelope(remote_ip='forged-ip'),
                     envelope(message_id='../../spool')):
            self.send(data)
            before = len(os.listdir('/proc/self/fd'))
            with self.assertRaises(ClamShieldError):
                self.get()
            self.assertEqual(before, len(os.listdir('/proc/self/fd')))

    def test_decisions_are_bounded_and_framed(self):
        for decision in Decision:
            if decision in (Decision.SELECTED,Decision.TAGGED_FALLBACK):
                continue
            respond(self.server, decision, 'a' * 32)
            self.assertEqual(self.client.recv(100), b'CSMRSP01' + struct.pack('!I', decision) + b'a' * 32)
        with self.assertRaises(ClamShieldError):
            respond(self.server, 0, 'a' * 32)
        with self.assertRaises(ClamShieldError):
            respond(self.server, Decision.ACCEPT, 'a' * 31 + '\n')

    def test_selected_custody_requires_a_strict_boolean_recipient_subset(self):
        respond(self.server, Decision.SELECTED, 'a' * 32, [True, False])
        self.assertEqual(self.client.recv(100), b'CSMRSP01' + struct.pack('!I', 4) + b'a' * 32 + struct.pack('!I', 2) + b'\x01\x00')
        for value in (None, [], [True], [False, False], [1, 0], [True, 'false']):
            with self.assertRaises(ClamShieldError):
                respond(self.server, Decision.SELECTED, 'a' * 32, value)

    def test_oversized_metadata_recipient_count_flags_and_text_rejected(self):
        bad_fields = b'CSMAIL01' + struct.pack('!II', 1, 1) + struct.pack('!I', 129) + b'a' * 129
        for data in (envelope() + b'x' * MAX_METADATA,
                     b'CSMAIL01' + struct.pack('!II', 1001, 1),
                     b'CSMAIL01' + struct.pack('!II', 1, 4), bad_fields,
                     envelope(sender='sender@example.test').replace(b'sender@', b'\xffender@', 1)):
            self.send(data)
            with self.assertRaises(ClamShieldError):
                self.get()

    def test_oversized_sparse_snapshot_rejected_without_reading(self):
        fd = self.snapshot(sealed=False)
        os.ftruncate(fd, MAX_MESSAGE + 1)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        self.send(descriptors=[fd])
        with self.assertRaises(ClamShieldError):
            self.get()
