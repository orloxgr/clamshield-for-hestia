<?php // Managed by clamshield
if(!$data['context']['admin'])return;
$cs_yara_policy=$data['yara_settings']??['enabled'=>true,'timeout_seconds'=>45,'max_file_mib'=>50];
$cs_yara_sources=[];foreach($data['rule_manager']['sources'] as $source)$cs_yara_sources[$source['id']]=$source;
?>
<section data-page="yara-settings" hidden id="cs-yara-settings" data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>">
<h2>YARA settings</h2><p>Server-wide settings for website scanning.</p>
<article class="card"><h3>YARA scanning</h3><form id="cs-yara-scanning" class="row cs-controls-row">
<label><input type="checkbox" name="enabled" <?=$cs_yara_policy['enabled']?'checked':''?>> Enable YARA scanning</label>
<label>Timeout per file (seconds) <input class="form-control" type="number" name="timeout_seconds" min="1" max="3600" required value="<?=$cs_yara_policy['timeout_seconds']?>"></label>
<label>Maximum file size (MiB) <input class="form-control" type="number" name="max_file_mib" min="1" max="50" required value="<?=$cs_yara_policy['max_file_mib']?>"></label>
<button class="button" type="submit">Save scanning settings</button></form>
<p>Applies to manual, scheduled and changed-file website scans. File repair and recovery keep their own validation checks. Email YARA is managed separately.</p></article>
<article class="card"><h3>Additional website rules</h3><form id="cs-yara-hosting">
<?php foreach(['php'=>'PHP hosting rules — PHP Malware Finder','web'=>'Additional web rules — JavaScript and phishing'] as $kind=>$title): $source=$cs_yara_sources[$kind.'_hosting']??[]; ?>
<p><label><input type="checkbox" name="<?=$kind?>_hosting" <?=!empty($source['enabled'])?'checked':''?>> <?=$escape($title)?></label></p>
<p><label><input type="checkbox" name="<?=$kind?>_automatic" <?=isset($source['review_only'])&&!$source['review_only']?'checked':''?>> Allow these matches to participate in automatic website actions</label></p>
<?php endforeach ?>
<p>New heuristic sources default to manual review. Your website action policy still controls quarantine and cleaning.</p><button class="button" type="submit">Save and apply rule settings</button></form></article>
<p id="cs-yara-settings-status" role="status" aria-live="polite"></p>
<?php require __DIR__.'/yara_update_preferences.php'; ?>
<details id="cs-rules-advanced"><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Custom sources and individual rules</summary>
<?php foreach($data['rule_manager']['sources'] as $source): if(in_array($source['kind'],['php-hosting','web-hosting','forge'],true))continue; ?>
<article class="card"><h4><?=$escape($source['name'])?></h4><p><?=$escape($source['version'])?> · <?=$source['enabled']?'Selected':'Disabled'?></p><button class="button" data-action="rules-source-toggle" data-source_id="<?=$escape($source['id'])?>" data-enabled="<?=$source['enabled']?'false':'true'?>" data-apply="true"><?=$source['enabled']?'Disable source':'Enable source'?></button></article>
<?php endforeach ?>
<?php require __DIR__.'/yara_advanced_sources.php'; ?>
</details>
<p><a href="#updates/rules" data-tab="rules">Install or update rules</a> · <a href="#settings/support" data-tab="support">Sources and acknowledgements</a></p>
</section><script><?php readfile(__DIR__.'/yara_settings.js'); ?></script>
