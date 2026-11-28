"""One Review row per native message and scoped recipient, without changing custody."""

# Match the content and native account generation as well as the envelope. A retry
# can produce several decisions; only its latest evaluation belongs in this view.
_BOUND = """d.owner=m.owner AND d.identity=m.identity AND d.domain=m.domain
 AND d.mailbox=m.mailbox AND d.recipient=m.recipient
 AND d.exim_id=t.exim_id AND d.sha256=t.sha256"""
_DECISION_VISIBLE = """NOT EXISTS(SELECT 1 FROM review_deleted x
 WHERE x.kind='email-decisions' AND x.record_id=d.id
 AND x.owner=d.owner AND x.identity=d.identity)"""
_CONFIRMED = "t.status='committed' AND (a.status IS NULL OR a.status='accepted')"

SOURCE = f"""(
 SELECT 'stored:'||m.id AS id,m.id AS delivery_id,d.id AS decision_id,
 m.owner,m.identity,m.domain,m.mailbox,m.recipient,
 json_extract(t.metadata,'$.summary.Subject') AS subject,
 COALESCE(d.sender,json_extract(t.metadata,'$.envelope.sender'),'') AS sender,
 COALESCE(d.created,m.created) AS created,
 CASE WHEN n.id IS NOT NULL THEN 'native-fallback' ELSE COALESCE(d.action,m.action) END AS action,d.classification,
 CASE WHEN n.id IS NOT NULL THEN 'check_unavailable'
 WHEN a.status IS NOT NULL AND a.status!='accepted'
 AND m.status NOT IN ('deleted','aborted') THEN 'source_unconfirmed'
 ELSE m.status END AS status,m.error,
 CASE WHEN n.id IS NOT NULL THEN 'Native fallback was observed. The selected handling is not confirmed by this record.' ELSE COALESCE(json_extract(d.detail,'$.transport_note'),json_extract(m.detail,'$.transport_note')) END AS transport_note,
 CASE WHEN n.id IS NULL AND m.status='quarantined' AND {_CONFIRMED} THEN 1 ELSE 0 END AS can_deliver,
 CASE WHEN n.id IS NULL AND m.status IN ('quarantined','deleting') AND {_CONFIRMED} THEN 1 ELSE 0 END AS can_delete,
 n.native_id AS native_reference
 FROM mail_recipients m JOIN mail_transactions t ON t.id=m.transaction_id
 LEFT JOIN mail_acceptance a ON a.transaction_id=t.id
 LEFT JOIN native_mail_messages n ON n.native_id=t.exim_id
 LEFT JOIN mail_decisions d ON d.id=(SELECT d.id FROM mail_decisions d
 WHERE {_BOUND} AND {_DECISION_VISIBLE} ORDER BY d.created DESC,d.id DESC LIMIT 1)
 UNION ALL
 SELECT 'decision:'||d.id,NULL,d.id,d.owner,d.identity,d.domain,d.mailbox,d.recipient,
 NULL,d.sender,d.created,CASE WHEN n.id IS NOT NULL THEN 'native-fallback' ELSE d.action END,d.classification,
 CASE WHEN n.id IS NOT NULL THEN 'check_unavailable' WHEN d.action='reject' THEN 'rejected' WHEN d.action='defer' THEN 'deferred'
 ELSE 'not_retained' END,NULL,CASE WHEN n.id IS NOT NULL THEN 'Native fallback was observed. The selected handling is not confirmed by this record.' ELSE json_extract(d.detail,'$.transport_note') END,0,0,n.native_id
 FROM mail_decisions d LEFT JOIN native_mail_messages n ON n.native_id=d.exim_id WHERE {_DECISION_VISIBLE}
 AND NOT EXISTS(SELECT 1 FROM mail_recipients m JOIN mail_transactions t
 ON t.id=m.transaction_id WHERE {_BOUND})
 AND NOT EXISTS(SELECT 1 FROM mail_decisions newer
 WHERE newer.owner=d.owner AND newer.identity=d.identity AND newer.domain=d.domain
 AND newer.mailbox=d.mailbox AND newer.recipient=d.recipient
 AND newer.exim_id=d.exim_id AND newer.sha256=d.sha256
 AND (newer.created>d.created OR (newer.created=d.created AND newer.id>d.id))
 AND NOT EXISTS(SELECT 1 FROM review_deleted x WHERE x.kind='email-decisions'
 AND x.record_id=newer.id AND x.owner=newer.owner AND x.identity=newer.identity))
 UNION ALL
 SELECT 'native:'||n.id,NULL,NULL,'@admin','','','','Account not verified',
 'ClamShield check unavailable','',n.created,'native-fallback','incomplete',
 'check_unavailable',NULL,'The original message continued through native delivery. The ClamShield check was incomplete.',0,0,n.native_id
 FROM native_mail_messages n
 WHERE NOT EXISTS(SELECT 1 FROM mail_decisions d WHERE d.exim_id=n.native_id)
 AND NOT EXISTS(SELECT 1 FROM mail_transactions t WHERE t.exim_id=n.native_id)
) r"""
