"""Bounded mail-engine clients. No routing or SMTP acceptance takes place here.

Mail needs ALLMATCHSCAN: INSTREAM/FILDES may stop at a spam signature before a
malware signature is seen. A private immutable-input copy gives the daemon the
required path without granting it access to custody storage or browser paths.
"""
from contextlib import contextmanager
import base64
import binascii
import email.errors
import email.parser
import email.policy
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import tempfile
import time

from .errors import ClamShieldError, EngineError
from .mail_bridge import SEALS, validate_snapshot, process_start
from .signature_catalog import validate_origin

MAX_RESPONSE = 256 * 1024


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise EngineError('Mail engine exceeded its time limit')
    return value


def _read(connection, deadline, maximum=MAX_RESPONSE):
    result = bytearray()
    while True:
        connection.settimeout(_remaining(deadline))
        block = connection.recv(min(65536, maximum + 1 - len(result)))
        if not block:
            return bytes(result)
        result.extend(block)
        if len(result) > maximum:
            raise EngineError('Mail engine response exceeded its limit')


@contextmanager
def _connect(path, expected_uid, deadline):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(_remaining(deadline))
        connection.connect(str(path))
        _pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != expected_uid:
            raise EngineError('Mail engine socket has an unexpected owner')
        yield connection


def digest_snapshot(fd):
    info = validate_snapshot(fd)
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(fd, min(65536, info.st_size - offset), offset)
        if not chunk:
            raise EngineError('Mail snapshot is incomplete')
        offset += len(chunk)
        digest.update(chunk)
    return digest.hexdigest()


class SpamAssassin:
    """Read-only REPORT: no user preferences, message rewriting or training.

    The service configuration must disable user preferences and auto-learning.
    Only an application-selected protected Unix socket is supported.
    """
    def __init__(self, socket_path, *, expected_uid, timeout=45, report=True):
        self.socket_path, self.expected_uid, self.timeout = str(socket_path), expected_uid, timeout
        self.report = report

    def scan(self, fd, *, deadline=None):
        info = validate_snapshot(fd)
        deadline = min(deadline or float('inf'), time.monotonic() + self.timeout)
        try:
            with _connect(self.socket_path, self.expected_uid, deadline) as connection:
                peer_pid, _uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                peer = dict(pid=peer_pid, birth=process_start(peer_pid))
                connection.settimeout(_remaining(deadline))
                operation = 'REPORT' if self.report else 'SYMBOLS'
                connection.sendall((operation + ' SPAMC/1.5\r\nContent-length: ' + str(info.st_size) + '\r\n\r\n').encode('ascii'))
                offset = 0
                while offset < info.st_size:
                    connection.settimeout(_remaining(deadline))
                    block = os.pread(fd, min(65536, info.st_size - offset), offset)
                    if not block:
                        raise EngineError('Mail snapshot is incomplete')
                    connection.sendall(block)
                    offset += len(block)
                connection.shutdown(socket.SHUT_WR)
                response = _read(connection, deadline)
                if process_start(peer_pid) != peer['birth']:
                    raise EngineError('SpamAssassin process changed while scanning')
        except OSError as exc:
            raise EngineError('SpamAssassin is unavailable or timed out') from exc
        return self.parse(response, require_details=self.report) | {'_peer': peer}

    @staticmethod
    def parse(response, *, require_details=False):
        try:
            head, separator, body = response.partition(b'\r\n\r\n')
            if not separator or len(head) > 16384:
                raise ValueError()
            lines = head.decode('ascii').split('\r\n')
            if not re.fullmatch(r'SPAMD/1\.[0-5] 0 EX_OK', lines[0]):
                raise ValueError()
            headers = {}
            for line in lines[1:]:
                key, colon, value = line.partition(':')
                key = key.lower()
                if not colon or not re.fullmatch('[a-z-]+', key) or key in headers:
                    raise ValueError()
                headers[key] = value.strip()
            length = headers.get('content-length', '')
            if not re.fullmatch('[0-9]{1,6}', length) or int(length) != len(body):
                raise ValueError()
            score = re.fullmatch(r'(True|False)\s*;\s*([-+0-9.eE]+)\s*/\s*([-+0-9.eE]+)', headers.get('spam', ''))
            if not score:
                raise ValueError()
            value, threshold = float(score[2]), float(score[3])
            if any(not math.isfinite(n) or abs(n) > 1e6 for n in (value, threshold)):
                raise ValueError()
            if require_details or body.startswith(b'CLAMSHIELD/'):
                from .spam_report import parse
                report = parse(body)
                if abs(report['score'] - value) > .051 or abs(report['threshold'] - threshold) > .051:
                    raise ValueError('SpamAssassin header and contribution report disagree')
                return {key: report[key] for key in ('score', 'threshold', 'rules', 'revision', 'engine_version', 'rules_version', 'reporter_sha256')} | {
                    'symbols': sorted(rule['name'] for rule in report['rules']), 'dns_observations': report.get('dns_observations',[])}
            text = body.decode('ascii').strip('\r\n')
            symbols = text.split(',') if text else []
            if len(symbols) > 1000 or any(not re.fullmatch('[A-Za-z0-9_]{1,128}', symbol) for symbol in symbols):
                raise ValueError()
            return {'score': value, 'threshold': threshold, 'symbols': sorted(set(symbols))}
        except (ValueError, UnicodeError, IndexError) as exc:
            raise EngineError('SpamAssassin did not return a complete valid report') from exc


@contextmanager
def readable_snapshot(fd, directory, group):
    """Root-private parent, group-readable file, held inode and verified bytes.

    The directory is provisioned by the application, never by mail contents.
    Its read-only group may traverse but cannot list/create/replace snapshots.
    """
    source = validate_snapshot(fd)
    directory = Path(directory)
    if directory.resolve(strict=True) != directory:
        raise EngineError('Unsafe mail scan directory')
    parent = directory.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o067:
        raise EngineError('Unsafe mail scan directory permissions')
    handle, name = tempfile.mkstemp(prefix='message-', suffix='.eml', dir=directory)
    published = None
    try:
        os.fchown(handle, os.geteuid(), group)
        os.fchmod(handle, 0o440)
        digest, offset = hashlib.sha256(), 0
        while offset < source.st_size:
            chunk = os.pread(fd, min(65536, source.st_size - offset), offset)
            if not chunk:
                raise EngineError('Mail snapshot is incomplete')
            digest.update(chunk)
            offset += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(handle, view)
                if not written:
                    raise EngineError('Mail scan copy is incomplete')
                view = view[written:]
        os.fsync(handle)
        published = os.fstat(handle)

        def verify():
            current, linked = os.fstat(handle), os.stat(name, follow_symlinks=False)
            for info in (current, linked):
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                        (published.st_dev, published.st_ino, published.st_size, published.st_mtime_ns, published.st_ctime_ns)):
                    raise EngineError('Mail scan copy changed')
            actual, at = hashlib.sha256(), 0
            while at < current.st_size:
                chunk = os.pread(handle, min(65536, current.st_size-at), at)
                if not chunk:
                    raise EngineError('Mail scan copy is incomplete')
                at += len(chunk)
                actual.update(chunk)
            if actual.digest() != digest.digest():
                raise EngineError('Mail scan copy changed')

        verify()
        yield name
        verify()
    finally:
        try:
            linked = os.stat(name, follow_symlinks=False)
            current = os.fstat(handle)
            if (linked.st_dev, linked.st_ino) == (current.st_dev, current.st_ino):
                os.unlink(name)
        except FileNotFoundError:
            pass
        finally:
            os.close(handle)


class MailClamAV:
    all_matches=True
    def __init__(self, socket_path, directory, *, expected_uid, group, timeout=45):
        self.socket_path, self.directory = str(socket_path), Path(directory)
        self.expected_uid, self.group, self.timeout = expected_uid, group, timeout

    def scan(self, fd, *, deadline=None):
        deadline = min(deadline or float('inf'), time.monotonic() + self.timeout)
        try:
            with readable_snapshot(fd, self.directory, self.group) as name:
                with _connect(self.socket_path, self.expected_uid, deadline) as connection:
                    connection.settimeout(_remaining(deadline))
                    connection.sendall(b'zALLMATCHSCAN ' + os.fsencode(name) + b'\0')
                    response = _read(connection, deadline)
                results = self.parse(response, name)
            return results
        except OSError as exc:
            raise EngineError('Mail ClamAV is unavailable or timed out') from exc

    @staticmethod
    def parse(response, name, *, allow_coverage=False):
        prefix = os.fsencode(name) + b': '
        if not response.endswith(b'\0'):
            raise EngineError('Mail ClamAV returned a truncated report')
        records = response[:-1].split(b'\0')
        if records == [prefix + b'OK']:
            return []
        if not 1 <= len(records) <= 1000:
            raise EngineError('Mail ClamAV match limit exceeded')
        results = []
        for record in records:
            if not record.startswith(prefix) or not record.endswith(b' FOUND'):
                raise EngineError('Mail ClamAV did not complete the scan')
            try:
                signature = record[len(prefix):-6].decode('utf-8')
            except UnicodeError as exc:
                raise EngineError('Mail ClamAV returned an invalid signature') from exc
            # ExtendedDetectionInfo may append a content hash and size.
            signature = re.sub(r' \([0-9a-fA-F]{32}:[0-9]+\)$', '', signature)
            if not 1 <= len(signature) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in signature):
                raise EngineError('Mail ClamAV returned an invalid signature')
            if not allow_coverage and signature.startswith(('Heuristics.Limits.Exceeded', 'Heuristics.Encrypted')):
                raise EngineError('Mail ClamAV coverage is incomplete')
            if signature not in results:
                results.append(signature)
        return results


def mime_payloads(fd, *, max_parts=128, max_depth=12, max_decoded=50*1024*1024):
    """Decode MIME leaves only, never extract a filename or execute content.

    Malformed/unsupported encoding and exhausted limits are incomplete coverage.
    Archive/container formats inside a leaf remain the ClamAV engine's job.
    The hosting service must also enforce a process memory limit for parsing.
    """
    size = validate_snapshot(fd).st_size
    try:
        message = email.parser.BytesParser(policy=email.policy.default.clone(raise_on_defect=True)).parsebytes(os.pread(fd, size, 0))
        stack, count, decoded = [(message, 0)], 0, 0
        while stack:
            part, depth = stack.pop()
            count += 1
            if count > max_parts or depth > max_depth:
                raise EngineError('Mail MIME structure exceeded its limit')
            if any(len(part.get_all(header, [])) > 1 for header in ('Content-Type', 'Content-Transfer-Encoding')):
                raise EngineError('Mail MIME structure is ambiguous')
            if part.is_multipart():
                children = part.get_payload()
                if len(children) + len(stack) + count > max_parts:
                    raise EngineError('Mail MIME structure exceeded its limit')
                stack.extend((child, depth+1) for child in reversed(children))
                continue
            if part.get_content_maintype() in ('multipart', 'message'):
                raise EngineError('Mail MIME structure is incomplete or unsupported')
            encoding = str(part.get('Content-Transfer-Encoding', '7bit')).lower().strip()
            if encoding not in ('7bit', '8bit', 'binary', 'base64', 'quoted-printable'):
                raise EngineError('Mail MIME transfer encoding is unsupported')
            if encoding == 'base64':
                encoded = part.get_payload().encode('ascii')
                payload = base64.b64decode(b''.join(encoded.split()), validate=True)
            else:
                if encoding == 'quoted-printable' and re.search(r'=(?![0-9A-Fa-f]{2}|\r?\n)', part.get_payload()):
                    raise EngineError('Mail MIME transfer encoding is incomplete')
                payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                raise EngineError('Mail MIME payload is unavailable')
            decoded += len(payload)
            if decoded > max_decoded:
                raise EngineError('Mail MIME decoded size exceeded its limit')
            yield payload
    except (email.errors.MessageError, email.errors.MessageDefect, ValueError, UnicodeError, binascii.Error, RecursionError) as exc:
        raise EngineError('Mail MIME decoding did not complete') from exc


class MailScanner:
    """Combine trusted engine reports; a missing engine never becomes clean.

    resolve_signature must come from the active database generation, not names
    supplied by a sender. Uncatalogued signatures are conservatively malware.
    """
    def __init__(self, clamav, spamassassin, *, resolve_signature=None, yara=None, timeout=25):
        self.clamav, self.spamassassin, self.yara = clamav, spamassassin, yara
        self.resolve_signature = resolve_signature or (lambda name: {})
        self.timeout = timeout

    def scan(self, fd):
        started = time.monotonic()
        deadline = started + self.timeout
        result = {'complete': False, 'sha256': digest_snapshot(fd), 'spam_score': None,
                  'spam_symbols': [], 'detections': [], 'errors': []}
        try:
            for signature in self.clamav.scan(fd, deadline=deadline):
                origin = self.resolve_signature(signature)
                if origin is None:continue
                validate_origin(origin)
                result['detections'].append({'engine': 'clamav', 'signature': signature, 'category': 'malware',
                                             'provider': 'unclassified', **origin})
            spam = self.spamassassin.scan(fd, deadline=deadline)
            result.update(spam_score=spam['score'], spam_threshold=spam['threshold'], spam_symbols=spam['symbols'])
            if 'rules' in spam:
                result['spam_report'] = {key: spam[key] for key in
                                        ('score', 'threshold', 'rules', 'engine_version', 'rules_version', 'reporter_sha256')}
                result['spam_report']['dns_observations']=spam.get('dns_observations',[])
                result['spamassassin_revision'] = spam['revision']
            if self.yara is not None:
                seen = set()
                result['yara_targets_scanned'] = 0

                def yara_scan(target):
                    remaining = _remaining(deadline)
                    if remaining < 1:
                        raise EngineError('Mail YARA time budget is exhausted')
                    for hit in self.yara.scan('/proc/self/fd/' + str(target), timeout=remaining):
                        detection = {key: value for key, value in dict(hit, category='malware').items() if key in
                            ('engine', 'signature', 'category', 'provider', 'source_id', 'source_version') and value is not None}
                        key = tuple(sorted(detection.items()))
                        if key not in seen:
                            seen.add(key); result['detections'].append(detection)
                        if len(result['detections']) > 1000:
                            raise EngineError('Mail match limit exceeded')
                    result['yara_targets_scanned'] += 1

                yara_scan(fd)
                for payload in mime_payloads(fd):
                    _remaining(deadline)
                    target = os.memfd_create('clamshield-mail-mime', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
                    try:
                        view = memoryview(payload)
                        while view:
                            written = os.write(target, view)
                            if not written:
                                raise EngineError('Mail MIME snapshot is incomplete')
                            view = view[written:]
                        fcntl.fcntl(target, fcntl.F_ADD_SEALS, SEALS)
                        yara_scan(target)
                    finally:
                        os.close(target)
            if len(result['detections']) > 1000:
                raise EngineError('Mail match limit exceeded')
            _remaining(deadline)
            result['complete'] = True
        except (EngineError, ClamShieldError, OSError) as exc:
            # Only controlled error types; never include paths/message contents.
            result['errors'] = [type(exc).__name__]
        result['elapsed_seconds'] = time.monotonic() - started
        return result
