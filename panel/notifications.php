<?php // Managed by clamshield; native Hestia controls and theme.
$notification_labels = [
    'scan.malware_found'=>'Malware detected', 'scan.repeated_detection'=>'Detected again',
    'scan.failed'=>'Scan failed', 'scan.partial'=>'Incomplete scan',
    'scan.update_interrupted'=>'Scan stopped for ClamShield update',
    'wordpress.integrity_issues'=>'WordPress integrity issues',
    'health.problem'=>'Service or scanning-data problem', 'health.recovered'=>'Service or scanning data recovered',
    'maintenance.completed'=>'Update or maintenance completed', 'maintenance.failed'=>'Update or maintenance failed',
    'maintenance.recovered'=>'Interrupted maintenance recovered', 'installation.recovered'=>'Installation recovered',
    'rules.trial_finished'=>'Rule comparison finished', 'mail.refreshed'=>'Mail integration refreshed',
    'mail.refresh_failed'=>'Mail integration refresh failed', 'mail.expiry_blocked'=>'Email expiry needs attention',
    'automatic.cancelled'=>'Automatic action cancelled', 'automatic.cleaned'=>'Automatic cleaning completed',
    'automatic.needs_review'=>'Automatic action needs review', 'automatic.quarantined'=>'Automatically quarantined',
    'automatic.failed'=>'Automatic action failed',
    'cleanup.failed'=>'Cleaning failed', 'cleanup.undone'=>'Cleaning undone', 'cleanup.verified'=>'Cleaning verified',
    'cleanup.recheck_failed'=>'Cleaning recheck failed', 'cleanup.recovery_required'=>'Cleaning recovery required',
    'repair.failed'=>'Repair failed', 'repair.undone'=>'Repair undone', 'repair.verified'=>'Repair verified',
    'repair.recheck_failed'=>'Repair recheck failed', 'repair.recovery_required'=>'Repair recovery required',
];
$notification_subjects = [
    'clamav'=>'Website ClamAV', 'yara'=>'YARA engine', 'yara-rules'=>'YARA rules',
    'website-coverage'=>'Website scanning coverage', 'clamav-database-age'=>'ClamAV database age',
    'hestia-inventory'=>'Hestia account and website inventory',
    'provider-official'=>'Official ClamAV signatures', 'provider-securiteinfo'=>'SecuriteInfo signatures',
    'provider-sanesecurity'=>'SaneSecurity signatures',
    'signatures-update'=>'Signature update', 'signatures-activate'=>'Signature activation',
    'signatures-rollback'=>'Signature rollback', 'rules-web-hosting'=>'Web hosting rule update',
    'rules-php-hosting'=>'PHP hosting rule update', 'rules-update'=>'YARA Forge update',
    'rules-build'=>'Build rule selection', 'rules-fetch'=>'Rule source update',
    'rules-activate'=>'Rule activation', 'rules-rollback'=>'Rule rollback',
    'resources-save'=>'Resource limits', 'resources'=>'Resource limits',
    'website-engine-start'=>'Start website ClamAV', 'website-engine-stop'=>'Stop website ClamAV',
    'website-engine'=>'Website ClamAV', 'spamassassin-save'=>'SpamAssassin settings',
    'spamassassin'=>'SpamAssassin', 'mail-integration'=>'Mail integration',
];
$notification_states = ['healthy'=>'Ready', 'unavailable'=>'Unavailable', 'stale'=>'Out of date',
    'missing'=>'Missing', 'error'=>'Error', 'unknown'=>'Not verified', 'stopped'=>'Stopped'];
$notification_counts = ['scanned'=>'Scanned files', 'infected'=>'Files with detections',
    'detections'=>'Detections', 'skipped'=>'Skipped files', 'errors'=>'Errors',
    'modified'=>'Modified files', 'missing'=>'Missing files', 'additional'=>'Additional files',
    'candidate_matches'=>'Candidate matches', 'baseline_matches'=>'Active-rule matches'];
?>
<section data-page="notifications" hidden id="cs-notifications" data-owner="<?=$escape($data['context']['owner'])?>" data-token="<?=$escape($_SESSION['token']??'')?>">
<h2>Notifications</h2>
<article class="card"><h3>My notification preferences</h3><p id="cs-notification-scope">Preferences belong to your signed-in account, including when you view another hosting account.</p>
<form id="cs-notification-preferences"><fieldset id="cs-notification-choices" disabled><legend>Notify me about</legend><div id="cs-notification-categories" class="cs-notification-categories"></div>
<p><label><input type="checkbox" name="bell"> Also notify me on Bell</label></p>
<p>Bell uses Hestia's native notification menu. Changes apply to new Bell notifications; old events are not resent. ClamShield and Hestia keep their own read status.</p>
<div class="row"><button class="button" type="submit">Save notification preferences</button></div></fieldset></form>
<div class="row"><button class="button" type="button" id="cs-notification-refresh">Refresh preferences</button><p id="cs-notification-preference-status" role="status" aria-live="polite">Open Notifications to load your preferences.</p></div>
</article>
<div class="row cs-controls-row"><label>Type <select class="form-select" id="cs-notification-type"><option value="selected">My selected types</option><option value="all">All recorded types</option></select></label><label>Status <select class="form-select" id="cs-notification-state"><option value="all">Read and unread</option><option value="unread">Unread only</option><option value="read">Read only</option></select></label><p id="cs-notification-count" role="status" aria-live="polite"></p></div>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Subject / details</th><th>Action</th></tr></thead><tbody id="cs-notification-list">
<?php foreach($data['notifications'] as $notification):
    $detail = is_array($notification['detail']??null) ? $notification['detail'] : [];
    $parts = [];
    foreach(['message','error'] as $field) if(is_string($detail[$field]??null) && $detail[$field]!=='') $parts[]=$detail[$field];
    if(is_string($detail['state']??null)) $parts[]='State: '.($notification_states[$detail['state']]??$detail['state']);
    foreach(['path'=>'File', 'signature'=>'Detection', 'previous_detections'=>'Earlier detections'] as $field=>$label)
        if(isset($detail[$field]) && is_scalar($detail[$field])) $parts[]=$label.': '.$detail[$field];
    if(is_array($detail['counters']??null)) foreach($notification_counts as $field=>$label)
        if(isset($detail['counters'][$field]) && is_numeric($detail['counters'][$field]) && ($field==='scanned'||$detail['counters'][$field]>0)) $parts[]=$label.': '.number_format((int)$detail['counters'][$field]);
    $subject=(string)$notification['subject'];
    // Translate only known server components/operations; website and file
    // subjects retain their exact names even if they resemble an operation.
    if(in_array(explode('.',(string)$notification['event'],2)[0],['health','maintenance','installation'],true))
        $subject=$notification_subjects[$subject]??$subject;
    $title=$notification_labels[$notification['event']]??ucfirst(str_replace(['.','_'],' ',(string)$notification['event']));
?>
<tr data-owner="<?=$escape($notification['owner']??$data['context']['owner'])?>" data-notification="<?=$escape($notification['id'])?>" data-event="<?=$escape($notification['event'])?>" data-read="<?=$notification['read_at']?'true':'false'?>"><td><?php if($cs_global): ?><?=$escape(($notification['owner']??'@admin')==='@admin'?'Server':$notification['owner'])?><br><?php endif ?><?=$escape(gmdate('Y-m-d H:i:s',(int)$notification['created']))?></td>
<td><?=$escape($title)?></td><td><?=$escape($subject)?>
<?php foreach($parts as $part): ?><p><?=$escape($part)?></p><?php endforeach ?>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Technical details</summary><pre style="white-space:pre-wrap"><?=$escape(json_encode(['event'=>$notification['event'],'detail'=>$notification['detail']],JSON_PRETTY_PRINT))?></pre></details>
</td><td><?php if(!$notification['read_at']): ?><button type="button" class="button cs-notification-read">Mark read</button><?php else: ?><span>Read</span><?php endif ?><p class="cs-notification-read-status" role="status" aria-live="polite"></p></td></tr>
<?php endforeach ?>
</tbody></table></div><p id="cs-notification-empty" hidden>No notifications match these filters.</p></section>
<script><?php readfile(__DIR__.'/notifications.js'); ?></script>
