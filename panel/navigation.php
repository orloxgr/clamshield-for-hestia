<?php // Managed by clamshield; navigation structure, native Hestia appearance.
$cs_navigation = [
    'dashboard'=>['Dashboard', ['dashboard'=>'Overview']],
    'email'=>['Email Shield', ['mail'=>'Email protection']],
    'scan'=>['On-Demand Actions', ['sites'=>'Websites', 'jobs'=>'Scan progress', 'wordpress-recovery'=>'WordPress']],
    'scheduled'=>['Scheduled Scanner', ['scheduled'=>'Schedules and monitoring']],
    'review'=>['Review', ['findings'=>'Results', 'repairs'=>'Cleaning', 'exceptions'=>'Exceptions', 'quarantine'=>'Quarantine', 'email-review'=>'Email', 'history'=>'History', 'update-history'=>'Updates', 'notices'=>'Notifications']],
    'updates'=>['Updates', ['rules'=>'YARA rules', 'providers'=>'Signature providers']],
    'settings'=>['Settings', ['yara-settings'=>'YARA', 'provider-settings'=>'Signature providers', 'mail-settings'=>'Email', 'spamassassin'=>'SpamAssassin', 'automatic'=>'Automatic actions', 'notifications'=>'Notifications', 'retention'=>'History retention', 'resources'=>'Resources', 'permissions'=>'Website permissions', 'support'=>'Support Us']],
];
if (!$data['context']['admin']) {
    foreach (['review'=>['update-history'], 'updates'=>['providers'], 'settings'=>['yara-settings','provider-settings','spamassassin','resources','permissions']] as $group=>$pages) {
        foreach ($pages as $page) unset($cs_navigation[$group][1][$page]);
    }
}
?>
<nav id="cs-main-navigation" aria-label="ClamShield sections">
<?php foreach($cs_navigation as $group=>[$label,$pages]): ?><a class="button" href="#<?=$group?>" data-main-tab="<?=$group?>"><?=$escape($label)?></a><?php endforeach ?>
</nav>
<?php foreach($cs_navigation as $group=>[$label,$pages]): if(count($pages)<2)continue; ?>
<nav data-subnav="<?=$group?>" aria-label="<?=$escape($label)?> views" hidden>
<?php foreach($pages as $page=>$title): ?><a class="button" href="#<?=$group?>/<?=$page?>" data-tab="<?=$page?>"><?=$escape($title)?></a><?php endforeach ?>
</nav>
<?php endforeach ?>
<script type="application/json" id="cs-navigation-map"><?=json_encode(array_map(static fn($entry)=>array_keys($entry[1]),$cs_navigation),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
