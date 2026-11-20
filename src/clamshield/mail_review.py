"""Account-scoped native-proof rechecks; no resend or force-delete operation."""
from .errors import ClamShieldError, Conflict
from .mail_acceptance import MailAcceptance
from .mail_cleanup import MailCleanup
from .mail_custody import MailCustody
from .mail_delivery import MailDelivery


class MailReview:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.custody = MailCustody(settings, store, hestia)

    def list(self, context, search='', offset=0):
        context = self.custody.authorize(context)
        if not isinstance(search, str) or len(search) > 300 or type(offset) is not int or not 0 <= offset <= 10000000:
            raise ClamShieldError('Invalid mail review search')
        common = " WHERE r.owner=? AND r.identity=? AND (instr(r.recipient,?)>0 OR instr(r.id,?)>0) AND "
        queries = [
            "SELECT r.id AS delivery_id,r.recipient,'source' AS stage,a.status,a.updated,a.error FROM mail_recipients r JOIN mail_acceptance a ON a.transaction_id=r.transaction_id JOIN mail_transactions t ON t.id=r.transaction_id" + common + "(a.status IN ('armed','response_sent','uncertain','proven') OR (a.status='rejected' AND t.status<>'aborted'))",
            "SELECT r.id,r.recipient,'delivery',a.status,a.updated,a.error FROM mail_recipients r JOIN mail_delivery_attempts a ON a.recipient_id=r.id" + common + "a.status IN ('submitting','uncertain','native_queued')",
            "SELECT r.id,r.recipient,'source_cleanup',c.status,c.updated,c.error FROM mail_recipients r JOIN mail_body_cleanup c ON c.kind='source' AND c.subject=r.transaction_id" + common + "c.status='blocked'",
            "SELECT r.id,r.recipient,'delivery_cleanup',c.status,c.updated,c.error FROM mail_recipients r JOIN mail_delivery_attempts a ON a.recipient_id=r.id JOIN mail_body_cleanup c ON c.kind='delivery' AND c.subject=a.id" + common + "c.status='blocked'",
        ]
        query = ' UNION ALL '.join(queries)
        values = (*self.store.scope(context), search, search) * len(queries)
        with self.store.connection() as db:
            total = db.execute('SELECT COUNT(*) FROM (' + query + ')', values).fetchone()[0]
            rows = db.execute('SELECT * FROM (' + query + ') ORDER BY updated DESC,delivery_id,stage LIMIT 100 OFFSET ?', (*values, offset)).fetchall()
        return dict(total=total, items=[dict(row) for row in rows], next_offset=offset+len(rows) if offset+len(rows)<total else None)

    def recheck(self, context, recipient_id, stage):
        context = self.custody.authorize(context)
        if stage in ('source_cleanup', 'delivery_cleanup'):
            return MailCleanup(self.settings, self.store, self.hestia).retry(context, recipient_id, stage.removesuffix('_cleanup'))
        if stage not in ('source', 'delivery'):raise ClamShieldError('Invalid mail review stage')
        worker = MailAcceptance(self.settings, self.store, self.hestia) if stage == 'source' else MailDelivery(self.settings, self.store, self.hestia)
        try:
            with worker.locked(False) if stage == 'source' else worker.locked():
                context = self.custody.authorize(context)
                with self.store.connection() as db:
                    recipient = self.custody.row(context, recipient_id, db)
                    if stage == 'source':subject = recipient['transaction_id']
                    else:
                        row = db.execute('SELECT id FROM mail_delivery_attempts WHERE recipient_id=?', (recipient['id'],)).fetchone()
                        if not row:raise Conflict('No native delivery attempt requires review')
                        subject = row['id']
                self.store.audit(context, 'mail.' + stage + '_proof_recheck', recipient['id'], {})
                state = worker._reconcile(subject) if stage == 'source' else worker.reconcile(subject)
                # Deliberately never prepare(), submit(), run_queue() or force a
                # terminal state. Only the original native proof can settle it.
                return dict(state=state, stage=stage)
        except BlockingIOError:
            raise Conflict('Mail recovery is active. Refresh and recheck after it finishes.') from None
