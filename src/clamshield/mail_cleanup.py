"""Remove private bodies only after durable, terminal recipient outcomes.

The cleanup journal is independent of delivery/acceptance proof. A missing file
is success only after the exact existing file was validated and a deleting
record committed. Unknown, failed, queued and quarantined messages are retained.
"""
import json
import os
import stat
import time

from .errors import ClamShieldError, Conflict
from .mail_custody import MailCustody, digest, identifier
from .paths import attributes
from .store import encode


class MailCleanup:
    def __init__(self, settings, store, hestia):
        self.store = store
        self.custody = MailCustody(settings, store, hestia)

    def _blocked(self, kind, subject):
        with self.store.connection(True) as db:
            row = db.execute('SELECT status,metadata FROM mail_body_cleanup WHERE kind=? AND subject=?', (kind, subject)).fetchone()
            metadata = json.loads(row['metadata'])
            # Preserve the durable validation boundary, including when the
            # pathname disappears after a validated unlink was interrupted.
            metadata['resume_status'] = row['status'] if row['status'] in ('validating', 'deleting') else metadata.get('resume_status', 'validating')
            db.execute("UPDATE mail_body_cleanup SET status='blocked',metadata=?,updated=?,error=? WHERE kind=? AND subject=?",
                       (encode(metadata), time.time(), 'Private body or terminal proof changed; retained for review', kind, subject))

    def retry(self, context, recipient_id, kind):
        if kind not in ('source', 'delivery'):
            raise Conflict('Invalid private mail cleanup kind')
        context = self.custody.authorize(context)
        with self.custody.locked() as root:
            context = self.custody.authorize(context)
            with self.store.connection(True) as db:
                recipient = self.custody.row(context, recipient_id, db)
                if kind == 'source':subject = recipient['transaction_id']
                else:
                    attempt = db.execute('SELECT id FROM mail_delivery_attempts WHERE recipient_id=?', (recipient['id'],)).fetchone()
                    if not attempt:raise Conflict('No private delivery copy requires review')
                    subject = attempt['id']
                entry = db.execute("SELECT * FROM mail_body_cleanup WHERE kind=? AND subject=? AND status='blocked'", (kind, subject)).fetchone()
                if not entry:raise Conflict('No blocked private body cleanup requires review')
                entry = dict(entry); metadata = json.loads(entry['metadata'])
                resume = metadata.get('resume_status', 'validating')
                if resume not in ('validating', 'deleting'):raise Conflict('Private body cleanup journal needs review')
                # Never adopt a new inode/hash or invent a missing-file proof.
                db.execute('UPDATE mail_body_cleanup SET status=?,updated=?,error=NULL WHERE kind=? AND subject=?', (resume, time.time(), kind, subject))
                self.store.audit(context, 'mail.body_cleanup_recheck', recipient['id'], {'kind': kind}, db)
                entry['status'] = resume
            try:
                self._finish(root, entry)
                state = 'purged'
            except (OSError, ClamShieldError):
                self._blocked(kind, subject); state = 'blocked'
        return {'state': state, 'kind': kind}

    def _eligible(self, kind, subject, db):
        identifier(subject)
        if kind == 'source':
            transaction = self.custody.transaction(subject, db)
            if transaction['status'] != 'committed':
                raise Conflict('Source is not committed private custody')
            recipients = db.execute('SELECT status FROM mail_recipients WHERE transaction_id=?', (subject,)).fetchall()
            if not recipients or any(row['status'] not in ('delivered', 'deleted') for row in recipients):
                raise Conflict('Other recipients still need the stored source')
            return transaction['metadata'] | {'sha256': transaction['sha256'], 'size': transaction['size']}
        if kind == 'delivery':
            row = db.execute('''SELECT a.status,a.metadata,r.status AS recipient_status
              FROM mail_delivery_attempts a JOIN mail_recipients r ON r.id=a.recipient_id
              WHERE a.id=?''', (subject,)).fetchone()
            if not row or row['status'] != 'delivered' or row['recipient_status'] != 'delivered':
                raise Conflict('Native recipient delivery is not proven complete')
            return json.loads(row['metadata'])
        raise Conflict('Invalid private mail cleanup kind')

    def _validate(self, root, name, metadata):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            info = os.fstat(fd); expected = metadata.get('fingerprint')
            if (not expected or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400 or
                any(attributes(info)[key] != expected[key] for key in
                    ('device', 'inode', 'size', 'mtime_ns', 'uid', 'gid', 'mode', 'links')) or
                digest(fd) != (metadata['sha256'], metadata['size'])):
                raise Conflict('Private body changed; cleanup requires review')
            # Bind the pathname too; a concurrently renamed replacement is never
            # removed merely because the opened descriptor was the expected file.
            current = os.stat(name, dir_fd=root, follow_symlinks=False)
            if attributes(current) != attributes(info):
                raise Conflict('Private body pathname changed during validation')
        finally:
            os.close(fd)

    def _finish(self, root, entry):
        kind, subject = entry['kind'], entry['subject']
        name = identifier(subject) + ('.eml' if kind == 'source' else '.delivery')
        with self.store.connection() as db:
            current = self._eligible(kind, subject, db)
        metadata = json.loads(entry['metadata'])
        for key in ('fingerprint', 'sha256', 'size'):
            if current.get(key) != metadata.get(key):
                raise Conflict('Private body cleanup recipe changed')
        try:
            self._validate(root, name, metadata)
        except FileNotFoundError:
            if entry['status'] != 'deleting':
                raise Conflict('Private body was missing before validated cleanup')
        else:
            if entry['status'] == 'validating':
                with self.store.connection(True) as db:
                    changed = db.execute("UPDATE mail_body_cleanup SET status='deleting',updated=?,error=NULL WHERE kind=? AND subject=? AND status='validating'",
                                         (time.time(), kind, subject)).rowcount
                    if changed != 1:
                        raise Conflict('Private body cleanup journal changed')
            # Validate again after the durable journal boundary. A failed or
            # interrupted unlink never permits a replacement inode to be removed.
            self._validate(root, name, metadata)
            os.unlink(name, dir_fd=root)
        os.fsync(root)
        with self.store.connection(True) as db:
            self._eligible(kind, subject, db)
            db.execute("UPDATE mail_body_cleanup SET status='purged',updated=?,error=NULL WHERE kind=? AND subject=? AND status='deleting'",
                       (time.time(), kind, subject))
            if kind == 'source':
                db.execute("UPDATE mail_transactions SET status='purged',updated=?,error=NULL WHERE id=? AND status='committed'", (time.time(), subject))
                rows = db.execute('SELECT id,owner,identity FROM mail_recipients WHERE transaction_id=?', (subject,)).fetchall()
            else:
                rows = db.execute('SELECT r.id,r.owner,r.identity FROM mail_recipients r JOIN mail_delivery_attempts a ON a.recipient_id=r.id WHERE a.id=?', (subject,)).fetchall()
            for row in rows:
                self.store.audit({'actor': 'clamshield-mail', 'owner': row['owner'], 'identity': row['identity']},
                                 'mail.body_purged', row['id'], {'kind': kind, 'sha256': metadata['sha256']}, db)

    def once(self):
        purged = failed = 0
        with self.custody.locked() as root:
            with self.store.connection(True) as db:
                # At most 100 new objects per pass; registered interruptions have
                # priority and cannot be silently converted into a fresh deletion.
                sources = db.execute("""SELECT t.id FROM mail_transactions t
                  WHERE t.status='committed' AND EXISTS(SELECT 1 FROM mail_recipients r WHERE r.transaction_id=t.id)
                  AND NOT EXISTS(SELECT 1 FROM mail_recipients r WHERE r.transaction_id=t.id AND r.status NOT IN ('delivered','deleted'))
                  AND NOT EXISTS(SELECT 1 FROM mail_body_cleanup c WHERE c.kind='source' AND c.subject=t.id)
                  ORDER BY t.created LIMIT 50""").fetchall()
                deliveries = db.execute("""SELECT a.id FROM mail_delivery_attempts a JOIN mail_recipients r ON r.id=a.recipient_id
                  WHERE a.status='delivered' AND r.status='delivered'
                  AND NOT EXISTS(SELECT 1 FROM mail_body_cleanup c WHERE c.kind='delivery' AND c.subject=a.id)
                  ORDER BY a.created LIMIT 50""").fetchall()
                for kind, rows in (('source', sources), ('delivery', deliveries)):
                    for row in rows:
                        metadata = self._eligible(kind, row['id'], db)
                        db.execute('INSERT INTO mail_body_cleanup VALUES(?,?,?,?,?,?,NULL)',
                                   (kind, row['id'], time.time(), time.time(), 'validating', encode({key: metadata.get(key) for key in ('fingerprint', 'sha256', 'size')})))
                pending = [dict(row) for row in db.execute("SELECT * FROM mail_body_cleanup WHERE status IN ('validating','deleting') ORDER BY created LIMIT 100")]
            for entry in pending:
                try:
                    self._finish(root, entry); purged += 1
                except (OSError, ClamShieldError):
                    self._blocked(entry['kind'], entry['subject'])
                    failed += 1
        return {'mail_bodies_purged': purged, 'mail_body_cleanup_blocked': failed}
