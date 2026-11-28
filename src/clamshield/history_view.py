"""User-facing mail outcomes; internal custody evidence remains in the audit."""
from .email_review import SOURCE

MAIL_INTERNAL_EVENTS = (
    'mail.capture_preparing', 'mail.smtp_handoff_armed', 'mail.captured',
    'mail.delivery_preparing', 'mail.reinjection_authorized',
    'mail.delivery_native_queued', 'mail.delivery_delivered',
    'mail.body_purged', 'mail.body_cleanup_recheck',
)


def meaningful(alias):
    return alias+".action NOT IN ("+','.join("'"+event+"'" for event in MAIL_INTERNAL_EVENTS)+")"


def mail_outcomes(records, db):
    events=[row for row in records if row['action']=='mail.decision']
    if not events:return records
    # Each lookup is bound to an already-authorized audit account generation.
    condition=' OR '.join('(r.decision_id=? AND r.owner=? AND r.identity=?)' for _ in events)
    args=[value for row in events for value in (row['subject'],row['owner'],row['identity'])]
    matches={(row['decision_id'],row['owner'],row['identity']):dict(row)
             for row in db.execute('SELECT r.decision_id,r.owner,r.identity,r.recipient,r.subject,r.action,r.classification,r.status,r.error FROM '+SOURCE+' WHERE '+condition,args)}
    for event in events:
        value=matches.get((event['subject'],event['owner'],event['identity']))
        if value:event['mail_outcome']=value
    return records
