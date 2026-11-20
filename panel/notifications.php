<?php require __DIR__.'/notification_format.php'; ?>
<section data-page="notifications" hidden id="cs-notification-settings"><h2>Notification settings</h2><article class="card"><h3>My notification preferences</h3><p id="cs-notification-scope">Preferences belong to your signed-in account, including when you view another hosting account.</p>
<form id="cs-notification-preferences"><fieldset id="cs-notification-choices" disabled><legend>Notify me about</legend><div id="cs-notification-categories" class="cs-notification-categories"></div>
<p><label><input type="checkbox" name="bell"> Also notify me on Bell</label></p>
<p>Bell uses Hestia's native notification menu. Changes apply to new Bell notifications; old events are not resent. ClamShield and Hestia keep their own read status.</p>
<div class="row"><button class="button" type="submit">Save notification preferences</button></div></fieldset></form>
<div class="row"><button class="button" type="button" id="cs-notification-refresh">Refresh preferences</button><p id="cs-notification-preference-status" role="status" aria-live="polite">Open Notifications to load your preferences.</p></div>
</article></section>
<section data-page="notices" hidden id="cs-notifications" data-owner="<?=$escape($data['context']['owner'])?>" data-token="<?=$escape($_SESSION['token']??'')?>">
<h2>Notifications</h2>

<div class="row cs-controls-row"><label>Type <select class="form-select" id="cs-notification-type"><option value="selected">My selected types</option><option value="all">All recorded types</option></select></label><label>Status <select class="form-select" id="cs-notification-state"><option value="all">Read and unread</option><option value="unread">Unread only</option><option value="read">Read only</option></select></label><p id="cs-notification-count" role="status" aria-live="polite"></p></div>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Subject / details</th><th>Action</th></tr></thead><tbody id="cs-notification-list">
<?php require __DIR__.'/review_rows/notices.php'; ?></tbody></table></div><p id="cs-notification-empty" hidden>No notifications match these filters.</p></section>
<script><?php readfile(__DIR__.'/notifications.js'); ?></script>
