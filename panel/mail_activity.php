<?php // Managed by clamshield; current-account or server-wide review.
?>
<?php if(($data['context']['view_scope']??'account')==='server'): ?>
<div class="row"><h3>Email across all accounts</h3><button class="button" type="button" id="cs-mail-activity-refresh">Refresh email activity</button></div><p id="cs-mail-server-totals"></p>
<div class="scroll"><table><thead><tr><th>Account</th><th>Mail domains</th><th>Stored recipient records</th><th>Decisions</th><th>Action</th></tr></thead><tbody id="cs-mail-server-accounts"></tbody></table></div>
<h3>Recent stored email and decisions</h3>
<p>Open an account for email previews, release, recovery and exceptions.</p>
<h4>Stored email</h4><div class="scroll"><table><thead><tr><th>Account / recipient</th><th>Time UTC</th><th>Status</th></tr></thead><tbody id="cs-mail-server-quarantine"></tbody></table></div>
<h4>Email decisions</h4><div class="scroll"><table><thead><tr><th>Account / recipient</th><th>Time UTC</th><th>Decision</th></tr></thead><tbody id="cs-mail-server-decisions"></tbody></table></div>
<?php endif ?>
