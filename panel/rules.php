<?php // Managed by clamshield
$cs_rule_pending=(bool)array_filter($data['maintenance']??[],static fn($task)=>strpos($task['action'],'rules-')===0 && in_array($task['status'],['queued','running'],true));
$cs_rule_schedule=$data['rule_manager']['updates']??['automatic'=>true,'interval_minutes'=>1440,'next_allowed'=>0];
?>
<section data-page="rules" hidden><h2>YARA rule updates</h2>
<p id="cs-rules-active"><?php if($data['rules']['configured']): ?>Active: <?=$escape(ucfirst($data['rules']['profile']??'custom'))?> · <?=$escape($data['rules']['enabled']??$data['rules']['rules']??'Unknown')?> rules · <?=$escape($data['rules']['version']??'custom')?><?php else: ?>YARA rules are not installed.<?php endif ?></p>
<?php if($data['context']['admin']): ?>
<form id="cs-forge-install" class="row" data-configured="<?=$data['rules']['configured']?'true':'false'?>" data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>"><input type="hidden" name="profile" value="<?=$escape($cs_rule_schedule['profile']??$data['rules']['profile']??'core')?>"><button class="button" type="submit" <?=$cs_rule_pending?'disabled':''?>><?=$data['rules']['configured']?'Update rules':'Install rules'?></button><a href="#settings/yara-settings" data-tab="yara-settings">Configure YARA</a></form>
<p>Download, validation and activation run automatically.</p><p id="cs-forge-status" role="status" aria-live="polite"><?=$cs_rule_pending?'Rule work is in progress…':''?></p>
<div class="scroll"><table><thead><tr><th>Last attempt (UTC)</th><th>Last success (UTC)</th><th>Next permitted update (UTC)</th></tr></thead><tbody><tr>
<?php foreach(['last_attempt','last_success','next_allowed'] as $cs_time): $cs_timestamp=$cs_rule_schedule[$cs_time]??0; ?><td id="cs-yara-<?=$cs_time?>"><?=$escape($cs_timestamp?gmdate('Y-m-d H:i:s',(int)$cs_timestamp):($cs_time==='next_allowed'?'Due now':'Never'))?></td><?php endforeach ?>
</tr></tbody></table></div>
<p id="cs-yara-timing" role="status" aria-live="polite"></p>
<p><a href="#review/activity" data-tab="activity">View update history</a></p>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Recovery</summary><button class="button" data-action="rules-rollback">Restore previous rules</button></details>
<?php else: ?><p>Rule updates are managed by the administrator.</p><?php endif ?>
</section>
