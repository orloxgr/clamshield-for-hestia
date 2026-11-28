"""Bounded Exim local_scan transport; not yet an enabled mail policy service.

The Unix peer and sealed descriptor are authoritative. Browser fields and RFC822
headers never supply the SMTP envelope, native account or authenticated sender.
"""
import array
from dataclasses import dataclass, replace
from enum import IntEnum
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import struct

from .errors import AccessDenied, ClamShieldError

MAX_METADATA = 128 * 1024
MAX_MESSAGE = 65 * 1024 * 1024
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


class Decision(IntEnum):
    ACCEPT = 0
    REJECT = 1
    DEFER = 2
    HANDLED = 3  # Only after durable ownership of every envelope recipient.
    SELECTED = 4  # Durable custody of selected envelope recipients; others stay native.
    NATIVE_FALLBACK = 5  # Incomplete check; preserve Exim's original recipients.
    TAGGED_FALLBACK = 6  # Original native delivery, with per-recipient subject marks.


FALLBACK_TAGS = {'malware': 1, 'phishing': 2, 'spam': 3, 'blocked-sender': 4}


@dataclass(frozen=True)
class MailRequest:
    message_id: str
    sender: str
    remote_ip: str
    authenticated_id: str
    protocol: str
    recipients: tuple[str, ...]
    flags: int
    fd: int
    peer_pid: int | None = None
    peer_start: int | None = None
    native_spam_score: float | None = None
    native_dnsbl_zone: str = ''
    native_dnsbl_value: str = ''
    native_mime_blocked: bool = False
    fallback_tags_supported: bool = False

    def close(self):
        os.close(self.fd)


def validate_snapshot(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or
            not 1 <= info.st_size <= MAX_MESSAGE or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS):
        raise ClamShieldError('Mail bridge requires a sealed bounded snapshot')
    return info


def process_start(pid):
    """Kernel process birth marker; a PID alone can be reused."""
    if type(pid) is not int or pid<=0:
        raise AccessDenied('Invalid native process identity')
    try:
        value=Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
        return int(value)
    except (OSError,ValueError,IndexError) as exc:
        raise AccessDenied('Native process identity is unavailable') from exc


def _parse(data, fd):
    if len(data) < 16 or data[:8] not in (b'CSMAIL01', b'CSMAIL02', b'CSMAIL03',b'CSMAIL04',b'CSMAIL05'):
        raise ClamShieldError('Invalid mail bridge protocol')
    count, flags = struct.unpack('!II', data[8:16])
    if not 1 <= count <= 1000 or flags & ~3:
        raise ClamShieldError('Invalid mail bridge envelope')
    at = 16

    def field(limit):
        nonlocal at
        if at + 4 > len(data):
            raise ClamShieldError('Truncated mail bridge envelope')
        size = struct.unpack('!I', data[at:at + 4])[0]
        at += 4
        if size > limit or at + size > len(data):
            raise ClamShieldError('Oversized mail bridge envelope field')
        try:
            value = data[at:at + size].decode('utf-8')
        except UnicodeError as exc:
            raise ClamShieldError('Invalid mail bridge text') from exc
        at += size
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ClamShieldError('Control character in mail bridge envelope')
        return value

    message_id, sender, remote_ip, authenticated_id, protocol = (
        field(limit) for limit in (128, 1024, 128, 1024, 64))
    native_spam_score = None
    if data[:8] in (b'CSMAIL02',b'CSMAIL03',b'CSMAIL04',b'CSMAIL05'):
        raw_score = field(32)
        if raw_score:
            if not re.fullmatch(r'-?[0-9]{1,9}',raw_score):
                raise ClamShieldError('Invalid native SpamAssassin score')
            native_spam_score = int(raw_score) / 10
    native_dnsbl_zone,native_dnsbl_value=(field(256),field(2048)) if data[:8] in (b'CSMAIL03',b'CSMAIL04',b'CSMAIL05') else ('','')
    native_mime=field(1) if data[:8] in (b'CSMAIL04',b'CSMAIL05') else ''
    if native_mime not in ('','0','1'):raise ClamShieldError('Invalid native MIME policy observation')
    recipients = tuple(field(1024) for _ in range(count))
    if at != len(data) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', message_id):
        raise ClamShieldError('Invalid mail bridge envelope framing')
    if not all('@' in r and r.rsplit('@', 1)[1] for r in recipients):
        raise ClamShieldError('Unqualified mail bridge recipient')
    if remote_ip:
        try:
            ipaddress.ip_address(remote_ip)
        except ValueError as exc:
            raise ClamShieldError('Invalid mail bridge peer address') from exc
    return MailRequest(message_id, sender, remote_ip, authenticated_id, protocol,
                       recipients, flags, fd, native_spam_score=native_spam_score,
                       native_dnsbl_zone=native_dnsbl_zone,native_dnsbl_value=native_dnsbl_value,native_mime_blocked=native_mime=='1',
                       fallback_tags_supported=data[:8]==b'CSMAIL05')


def receive(connection, *, expected_uid, expected_binary, timeout=30):
    """Authenticate native Exim, then receive exactly one immutable message FD.

    The caller owns request.fd on success. Every received FD is closed on any
    validation failure, including extra descriptors and truncated control data.
    No filesystem path is accepted from the sender.
    """
    connection.settimeout(timeout)
    binary = Path(expected_binary).resolve(strict=True)
    expected = binary.stat()
    if expected.st_uid != 0 or expected.st_mode & 0o022 or not stat.S_ISREG(expected.st_mode):
        raise AccessDenied('Untrusted native mail executable')
    pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != expected_uid:
        raise AccessDenied('Mail bridge requires the native mail user')
    started=process_start(pid)
    peer = Path(f'/proc/{pid}/exe')

    def check_executable():
        try:
            info = peer.stat()
        except OSError as exc:
            raise AccessDenied('Native mail process is unavailable') from exc
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise AccessDenied('Mail bridge requires the native Exim executable')

    check_executable()
    descriptors = []
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_METADATA, socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                items = array.array('i')
                items.frombytes(payload[:len(payload) - len(payload) % items.itemsize])
                descriptors.extend(items)
        check_executable()
        if process_start(pid)!=started:
            raise AccessDenied('Native mail process identity changed')
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) != 1:
            raise ClamShieldError('Mail bridge requires exactly one complete snapshot')
        fd = descriptors[0]
        validate_snapshot(fd)
        request = _parse(data, fd)
        descriptors.clear()
        return replace(request,peer_pid=pid,peer_start=started)
    finally:
        for fd in descriptors:
            os.close(fd)


def respond(connection, decision, event_id, selected=None, *, tags=None):
    if not isinstance(decision, Decision) or not re.fullmatch(r'[0-9a-f]{32}', event_id):
        raise ClamShieldError('Invalid mail bridge decision')
    packet = b'CSMRSP01' + struct.pack('!I', decision.value) + event_id.encode('ascii')
    if decision == Decision.TAGGED_FALLBACK:
        if (selected is not None or not isinstance(tags, (list, tuple)) or not 1 <= len(tags) <= 1000 or
                any(type(value) is not int or not 0 <= value <= 4 for value in tags) or not any(tags)):
            raise ClamShieldError('Tagged native fallback requires bounded per-recipient classes')
        packet += struct.pack('!I', len(tags)) + bytes(tags)
    elif tags is not None:
        raise ClamShieldError('Subject marks are only valid for tagged native fallback')
    elif decision == Decision.SELECTED:
        if (not isinstance(selected, (list, tuple)) or not 1 <= len(selected) <= 1000 or
                any(type(value) is not bool for value in selected) or not any(selected) or all(selected)):
            raise ClamShieldError('Selected mail custody requires a proper recipient subset')
        packet += struct.pack('!I', len(selected)) + bytes(selected)
    elif selected is not None:
        raise ClamShieldError('Recipient selection is only valid for selected custody')
    if connection.send(packet, socket.MSG_NOSIGNAL) != len(packet):
        raise ClamShieldError('Incomplete mail bridge decision')
