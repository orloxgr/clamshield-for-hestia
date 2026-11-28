<?php require __DIR__.'/notification_format.php'; ?>
<section data-page="notifications" hidden id="cs-notification-settings"><h2>Notification settings</h2><p><button class="button" type="button" data-tab="notices">View notifications</button></p><p id="cs-notification-scope">Preferences belong to your signed-in account, including when you view another hosting account.</p>
<form id="cs-notification-preferences"><fieldset id="cs-notification-choices" disabled><legend>My notification preferences</legend>
<article class="card"><h3>ClamShield notifications</h3><p>Choose the types shown by default in Review → Notifications. All recorded types remain available in its filter.</p><div id="cs-notification-categories" class="cs-notification-categories"></div></article>
<article class="card"><h3>HestiaCP notifications</h3><p><label><input type="checkbox" name="bell"> Enable HestiaCP notifications</label></p>
<p>Choose types independently for HestiaCP's notification menu. Changes apply to new events.</p><div id="cs-hestia-notification-categories" class="cs-notification-categories"></div>
<p>Clearing notifications in Review also removes matching notifications from your HestiaCP account shortly afterwards. Reading remains separate.</p></article>
<div class="row"><button class="button" type="submit">Save notification preferences</button></div></fieldset></form>
<div class="row"><button class="button" type="button" id="cs-notification-refresh">Refresh preferences</button><p id="cs-notification-preference-status" role="status" aria-live="polite">Open Notifications to load your preferences.</p></div>
</section>
<section data-page="notices" hidden id="cs-notifications" data-owner="<?=$escape($data['context']['owner'])?>" data-token="<?=$escape($_SESSION['token']??'')?>">
<h2>Notifications</h2>

<div class="row cs-controls-row"><label>Type <select class="form-select" id="cs-notification-type"><option value="selected">My selected types</option><option value="all">All recorded types</option></select></label><label>Status <select class="form-select" id="cs-notification-state"><option value="all">Read and unread</option><option value="unread">Unread only</option><option value="read">Read only</option></select></label><p id="cs-notification-count" role="status" aria-live="polite"></p></div>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Subject / details</th><th>Action</th></tr></thead><tbody id="cs-notification-list">
<?php require __DIR__.'/review_rows/notices.php'; ?></tbody></table></div><p id="cs-notification-empty" hidden>No notifications match these filters.</p></section>
<script><?php readfile(__DIR__.'/notifications.js'); ?></script>
