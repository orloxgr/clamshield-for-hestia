<?php // Managed by clamshield
$cs_mail_global=($data['context']['view_scope']??'account')==='server';
?>
<div id="cs-mail" data-global="<?=$cs_mail_global?'true':'false'?>" data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>" data-admin="<?=$data['context']['admin']?'true':'false'?>">
<section data-page="mail" hidden><h2>Email protection</h2>
<?php if($data['context']['admin']): ?>
<article class="card" id="cs-mail-protection">
<p>Protect email across all server accounts. Existing domain and mailbox overrides remain in effect.</p>
<button class="button" type="button" id="cs-mail-protection-toggle">Enable mail protection</button>
<p id="cs-mail-protection-status" role="status" aria-live="polite">Checking protection status…</p>
</article>
<?php else: ?><p>Server connection is managed by your administrator. Domain and mailbox controls are available below.</p><?php endif ?>
<p><a href="#settings/mail-settings" data-tab="mail-settings">Email settings</a> · <a href="#review/email-review" data-tab="email-review">Review email activity</a></p></section>
<section data-page="mail-settings" hidden><h2>Email settings</h2>
<p>If a ClamShield check is unavailable, email continues through native delivery and the check remains incomplete. Verified detections follow the selected handling policy.</p>
<p>If recipients of the same message have different handling, a recipient set to Reject is quarantined instead of cancelling delivery to the other recipients. SMTP rejection applies when every recipient requires rejection.</p>
<?php require __DIR__.'/mail_global.php'; ?>
<div id="cs-mail-advanced"><button class="button" type="button" id="cs-mail-refresh">Refresh email controls</button>
<p id="cs-mail-status" role="status" aria-live="polite">Load email domains to view their policies.</p>
<?php if($data['context']['admin']): $integration=$data['mail_integration']; ?>
<?php
$cs_integration_phase=$integration['phase']??'needs-review';
$cs_integration_pending=!empty($integration['transition'])||in_array($cs_integration_phase,['starting','draining','recovering'],true);
$cs_integration_enabled=$cs_integration_phase==='active'&&!$cs_integration_pending&&!empty($integration['connected'])&&($integration['hook_enabled']??null)===true&&empty($integration['error']);
$cs_integration_off=in_array($cs_integration_phase,['disabled','unconfigured'],true)&&!$cs_integration_pending&&empty($integration['error']);
$cs_integration_label=$cs_integration_pending?'Transition pending':($cs_integration_enabled?'Enabled':($cs_integration_off?'Disabled':'Needs attention'));
?>
<details id="cs-mail-integration"><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Mail integration · <?=$escape($cs_integration_label)?></summary>
<div class="card" id="cs-mail-integration-controls">
<p id="cs-mail-integration-state" role="status"><strong>Mail integration: <?=$escape($cs_integration_label)?></strong></p>
<p><?=$escape($cs_integration_enabled?'Exim is connected to ClamShield. Managed recipients use their selected email policies.':($cs_integration_off?'ClamShield mail integration is disabled. Email uses native server handling.':($cs_integration_pending?'A mail integration transition is pending. Review its task in History before starting recovery.':'The current integration connection could not be verified. Review the error below or the integration history.')))?></p>
<div class="row">
<?php if($cs_integration_off): ?><button class="button" type="button" data-action="mail-integration-enable">Enable mail integration</button><?php endif ?>
<?php if($cs_integration_phase==='active'&&!$cs_integration_pending): ?><button class="button" type="button" data-action="mail-integration-refresh">Refresh mail integration</button><button class="button" type="button" data-action="mail-integration-disable">Drain and disable mail integration</button><?php endif ?>
<?php if($cs_integration_pending||$cs_integration_phase==='needs-review'): ?><button class="button" type="button" data-action="mail-integration-recover">Recover mail integration</button><?php endif ?>
<a href="#review/history" data-tab="history">View integration history</a>
</div></div>
<?php if(($integration['native_dnsbl']['state']??'')==='active' && empty($integration['native_dnsbl']['review_required'])): ?><p>Spamhaus error replies excluded for <?=(int)($integration['native_dnsbl']['protected_entries']??0)?> native DNSBL list(s). Genuine listing responses remain active.</p><?php elseif(!empty($integration['native_dnsbl']['review_required'])): ?><p class="alert alert-danger">Native DNSBL error-reply filters need review. Provider access errors can reject mail before ClamShield. No automatic retry will be attempted. <a href="https://www.spamhaus.org/resource-hub/dnsbl/using-our-public-mirrors-check-your-return-codes-now/" target="_blank" rel="noopener noreferrer">DNSBL guidance</a></p><?php endif ?>
<?php if(!empty($integration['native_spam_safety']['verified'])): ?><p>Native SpamAssassin verified: administrative DNS errors contribute zero points (<?=(int)($integration['native_spam_safety']['protected_rules']??0)?> rule overrides).</p><?php elseif(!empty($integration['native_spam_safety']['review_required']) || !empty($integration['native_spam_safety']['service_active'])): ?><p class="alert alert-danger">Native SpamAssassin administrative scores need verification. Check mail integration history for the failed operation.</p><?php elseif(($integration['native_spam_safety']['state']??'')==='active'): ?><p>Native SpamAssassin administrative score protection is configured. The native daemon is stopped.</p><?php endif ?>
<?php if(($integration['hook_enabled']??null)===false): ?><p>ClamShield mail checks are unavailable. Native mail delivery remains active. Refresh the mail integration to restore the selected policies.</p><?php endif ?>
<?php $native_delivery=$integration['native_delivery_observations']??[]; ?>
<h4>Native delivery fallback</h4>
<p>Recorded fallback means the ClamShield check was incomplete. These observations do not establish a clean verdict or the current health of the scanner.</p>
<?php if(!empty($native_delivery['error'])): ?><p class="alert alert-danger"><?=$escape($native_delivery['error'])?></p><?php endif ?>
<?php if(isset($native_delivery['last_fallback'])): ?><p>Last recorded fallback: <?=$escape(gmdate('Y-m-d H:i:s',(int)$native_delivery['last_fallback']))?> UTC · Recorded fallback events: <?=(int)$native_delivery['fallbacks']?>. <a href="#review/history">View history</a></p><?php else: ?><p><?=$escape(($native_delivery['collection']??'not-observed')==='observed'?'No fallback recorded in the observed log window.':'Native delivery observations have not been collected.')?></p><?php endif ?>
<?php if(isset($native_delivery['last_response'])): ?><p>Last observed ClamShield reply: <?=$escape(gmdate('Y-m-d H:i:s',(int)$native_delivery['last_response']))?> UTC. A reply confirms communication, not a complete or clean scan.</p><?php endif ?>
<?php if(!empty($native_delivery['history_limited'])): ?><p>Observation history is limited: an initial log tail, rotation, truncation or an unreadable interval may omit records.</p><?php endif ?>
<?php if(!empty($native_delivery['backlog'])): ?><p>More log data remains for the next background observation.</p><?php endif ?>
<h4>Native IP-list access — observed responses</h4><p>Diagnostic observations from native Exim, separate from SpamAssassin DNS checks. These rows are not enable/disable settings. No recorded response means access is unknown, not disabled. Provider access failures add no spam points.</p>
<?php if(!empty($integration['native_dnsbl_observations_error'])): ?><p class="alert alert-danger"><?=$escape($integration['native_dnsbl_observations_error'])?></p><?php endif ?>
<div class="scroll"><table><thead><tr><th>Provider</th><th>Last observation</th><th>Time (UTC)</th><th>Action</th></tr></thead><tbody><?php foreach(($integration['native_dnsbl_observations']??[]) as $observation): ?><tr><td><?=$escape($observation['label'])?></td><td><?=$escape(['blocked'=>'Provider access blocked','failed'=>'DNS lookup failed or unrecognized reply','response-observed'=>'Response observed','unknown'=>'No native observation recorded'][$observation['state']]??'Unknown')?></td><td><?=$escape(isset($observation['observed'])?gmdate('Y-m-d H:i:s',(int)$observation['observed']):'—')?></td><td><a href="<?=$escape($observation['help_url'])?>" target="_blank" rel="noopener noreferrer">Provider guidance</a></td></tr><?php endforeach ?></tbody></table></div>
<?php if(isset($integration['error'])): ?><p class="alert alert-danger"><?=$escape($integration['error'])?></p><?php endif ?>
<p>Activation starts the ClamShield mail services and adds its owned Exim hook. Managed local recipients follow their selected malware, phishing and spam handling. Native attachment and IP-list observations do not override that choice. Unmanaged recipients retain native handling; relay, authentication and recipient checks remain active.</p>
<p>Disabling keeps incoming messages in native delivery and drains known delivery work. Quarantine and uncertain messages are retained. Re-enable integration before releasing retained email.</p>
<p>Maintenance refreshes the adapter and owned mail services after a native package or ClamShield code change. During refresh, unavailable checks use native delivery and remain incomplete; retained deliveries resume after verification. Foreign hook or library changes require review.</p>
</details>
<?php endif ?>
<?php if($data['context']['admin']): $adapter=$data['mail_adapter']; ?>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Native Exim adapter</summary>
<p>Prepare the ClamShield API adapter against the exact installed Exim package. Preparation uses APT headers and an isolated native queue to verify loading.</p>
<p><?=$escape($adapter['error']??($adapter['compatible']?'Matching adapter candidate is ready':'No matching adapter candidate is ready'))?></p>
<?php if(!empty($adapter['candidate'])): ?><p class="path"><?=$escape($adapter['candidate']['generation'].' · '.$adapter['candidate']['native']['version'])?></p><?php endif ?>
<button class="button" type="button" data-action="mail-adapter-build">Prepare or refresh adapter</button>
<button class="button" type="button" data-action="mail-adapter-verify">Verify prepared adapter</button>
<p>Preparing an adapter leaves the active native mail configuration and services unchanged. Check maintenance history for the result.</p>
</details>
<?php endif ?>
<?php if(!$cs_mail_global): ?><div class="row"><label>Domain <select class="form-select" id="cs-mail-domain" aria-label="Email policy domain"></select></label><label>Mailbox <select class="form-select" id="cs-mail-box" aria-label="Email policy mailbox"><option value="">Domain policy</option></select></label></div>
<p id="cs-mail-native"></p>
<form id="cs-mail-policy" hidden><div id="cs-mail-fields"></div><p id="cs-mail-exceptions"></p><div class="row"><button class="button" type="submit">Save email policy</button><button class="button" type="button" id="cs-mail-reset">Reset to inherited settings</button></div></form>
<details id="cs-mail-retention-panel" hidden><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Quarantine retention</summary>
<p>Zero keeps quarantined email until manual deletion. A positive period applies to existing and future quarantine in the selected domain or mailbox. Expiry permanently removes the recipient's retained copy; copies still needed by other recipients and delivery proofs are kept.</p>
<p id="cs-mail-retention-status" role="status" aria-live="polite"></p>
<form id="cs-mail-retention-form"><div class="row"><label>Retention period (days) <input class="form-control" name="days" type="number" step="1" min="0" max="3650" required></label><button class="button" type="button" id="cs-mail-retention-preview">Preview retention</button><button class="button" type="button" id="cs-mail-retention-inherit" hidden>Preview domain inheritance</button><button class="button" type="submit" disabled>Apply retention period</button></div></form>
</details>
<?php if($data['context']['admin']): ?><details id="cs-mail-permissions"><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Hosting user email permissions</summary><p>These permissions apply to the selected hosting account.</p><form id="cs-mail-permission-form"><div id="cs-mail-permission-fields"></div><button class="button" type="submit">Save email permissions</button><button class="button" type="button" id="cs-mail-permission-reset">Use global permissions</button></form></details><?php endif ?>
<?php else: ?><p>Choose an account above for domain and mailbox overrides.</p><?php endif ?></div></section>
<section data-page="email-review" hidden><h2>Email</h2>
<?php require __DIR__.'/mail_activity.php'; ?>
<?php if(!$cs_mail_global): ?>
<p id="cs-mail-cleanup" role="status" aria-live="polite" hidden></p>
<details id="cs-mail-review-panel"><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Mail recovery and private-copy cleanup</summary>
<p>Review unresolved source acceptance, delivery confirmation and blocked cleanup for this hosting account. Recheck reads the mail server's original evidence; it never resends an uncertain message. Cleanup rechecks only remove the original private copy after its content and terminal delivery proofs pass again. A changed or unproven copy remains retained.</p>
<form id="cs-mail-review-search" class="row"><input class="form-control" name="search" maxlength="300" aria-label="Search mail recovery" placeholder="Recipient or retained-copy reference"><button class="button" type="submit">Search recovery items</button><button class="button" type="button" id="cs-mail-review-refresh">Refresh recovery items</button></form>
<p id="cs-mail-review-status" role="status" aria-live="polite"></p><p id="cs-mail-review-result" role="status" aria-live="polite"></p>
<div class="scroll"><table><thead><tr><th>Recipient</th><th>Last checked</th><th>Recovery stage / status</th><th>Action</th></tr></thead><tbody id="cs-mail-review-list"></tbody></table></div><button class="button" type="button" id="cs-mail-review-more" hidden>More recovery items</button></details>
<h4>Expiry activity for this hosting account</h4><form class="row" id="cs-mail-expiry-search"><input class="form-control" name="search" maxlength="300" aria-label="Search quarantine expiry activity" placeholder="Recipient or retained-copy reference"><button class="button" type="submit">Search expiry activity</button></form><p id="cs-mail-expiry-status" role="status"></p>
<div class="scroll"><table><thead><tr><th>Recipient</th><th>Deadline / last action</th><th>Outcome</th><th>Action</th></tr></thead><tbody id="cs-mail-expiry-history"></tbody></table></div><button class="button" type="button" id="cs-mail-expiry-more" hidden>More expiry activity</button><h3>Email decision history</h3><form id="cs-mail-history-form" class="row"><input class="form-control" name="search" placeholder="Envelope sender, recipient or mail reference" aria-label="Search email decision history" maxlength="300"><button class="button" type="submit">Search decisions</button></form><p id="cs-mail-history-status"></p>
<div class="scroll"><table><thead><tr><th>Time</th><th>Envelope sender / recipient</th><th>Decision</th><th>Detection</th></tr></thead><tbody id="cs-mail-history"></tbody></table></div><button class="button" type="button" id="cs-mail-more" hidden>More email decisions</button>
<?php endif ?></section>
<section data-page="quarantine" hidden><h2>Email quarantine</h2><?php if(!$cs_mail_global): ?><h3>Email quarantine</h3><p>Preview shows plain text and selected headers. Release queues the original email for its stored recipient; its status changes after delivery is confirmed.</p>
<form id="cs-mail-quarantine-form" class="row"><input class="form-control" name="search" placeholder="Subject, envelope sender, recipient or mail reference" aria-label="Search email quarantine" maxlength="300"><button class="button" type="submit">Search quarantine</button></form><p id="cs-mail-quarantine-status"></p>
<div class="scroll"><table><thead><tr><th>Time</th><th>Email</th><th>Status</th><th>Actions</th></tr></thead><tbody id="cs-mail-quarantine"></tbody></table></div><button class="button" type="button" id="cs-mail-quarantine-more" hidden>More quarantined email</button>
<?php else: ?><p>Choose an account above to preview or release quarantined email. <a href="#review/email-review" data-tab="email-review">View stored email across accounts</a></p><?php endif ?></section>
<section data-page="exceptions" hidden><h2 id="cs-mail-email-exceptions" tabindex="-1">Email exceptions</h2><?php if(!$cs_mail_global): ?><div class="row"><label>Domain <select class="form-select cs-mail-domain-mirror"></select></label><label>Mailbox <select class="form-select cs-mail-box-mirror"></select></label></div><details id="cs-mail-exception-panel" hidden><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Exact-content false-positive exceptions</summary>
<p id="cs-mail-exception-status" role="status" aria-live="polite"></p><div id="cs-mail-exception-list"></div>
<form id="cs-mail-exception-form"><h4>Add or renew an exception</h4><p>An exception suppresses one detected signature for identical email bytes in the selected domain or mailbox. Other detections, sender blocks and spam scoring still apply. Creating an exception does not release a stored message.</p>
<div class="row"><label>Engine <select class="form-select" name="engine"><option value="clamav">ClamAV</option><option value="yara">YARA</option></select></label><label>Exact signature <input class="form-control" name="signature" maxlength="512" required></label><label>Content SHA-256 <input class="form-control" name="sha256" pattern="[0-9a-f]{64}" minlength="64" maxlength="64" required></label><label>Expiry (UTC) <input class="form-control" name="expires" type="datetime-local" required></label></div><p><label>False-positive reason <input class="form-control" name="reason" maxlength="1000" required></label></p><button class="button" type="submit">Save exact-content exception</button></form>
<button class="button" type="button" id="cs-mail-exception-inherit" hidden>Use domain exceptions for this mailbox</button></details>
<?php else: ?><p>Choose an account above to manage its email exceptions.</p><?php endif ?></section></div>
<script><?php readfile(__DIR__.'/mail.js'); ?></script>
