<?php // Managed by clamshield; native controls, server-authorized scan targets.
$cs_global=($data['context']['view_scope']??'account')==='server';
$cs_scan_sites=$cs_global?[]:array_map(static fn($site)=>['domain'=>$site['domain'],'suspended'=>$site['suspended']],$data['sites']);
$cs_scan_available=(bool)array_filter($data['sites'],static fn($site)=>!$site['suspended']);
?>
<section data-page="sites" hidden id="cs-on-demand">
<h2>On-demand website scan</h2>
<form id="cs-scan-target" data-actor-owner="<?=$escape($data['context']['owner'])?>" data-capability="scan" data-allowed="<?=$data['website_permissions']['effective']['scan']?'true':'false'?>" data-admin="<?=$data['context']['admin']?'true':'false'?>" data-token="<?=$escape($_SESSION['token']??'')?>">
<div class="row cs-controls-row">
<label>Scan account <select class="form-select" name="owner" <?=$data['context']['admin']?'':'disabled'?>>
<?php if($data['context']['admin']): ?><option value="" <?=$cs_global?'selected':''?>>Global / All accounts</option><?php foreach($data['accounts'] as $account): ?><option value="<?=$escape($account['owner'])?>" <?=!$cs_global && $account['owner']===$data['context']['owner']?'selected':''?> <?=!empty($account['suspended'])?'disabled':''?>><?=$escape($account['owner'])?><?=!empty($account['suspended'])?' (suspended)':''?></option><?php endforeach; else: ?><option value="<?=$escape($data['context']['owner'])?>"><?=$escape($data['context']['owner'])?></option><?php endif ?>
</select></label>
<label>Website <select class="form-select" name="domain" <?=$cs_scan_available?'':'disabled'?>>
<option value=""><?=$cs_global?'All websites on this server':($cs_scan_available?'All websites in this account':'No active websites')?></option>
<?php foreach($cs_global?[]:$data['sites'] as $site): ?><option value="<?=$escape($site['domain'])?>" <?=$site['suspended']?'disabled title="Website is suspended"':''?>><?=$escape($site['domain'])?><?=$site['suspended']?' (suspended)':''?></option><?php endforeach ?>
</select></label>
<button class="button" id="cs-scan-start" type="submit" data-scope="account" <?=$cs_scan_available?'':'disabled'?>>Scan</button>
<?php if($data['context']['admin']): ?><button class="button" id="cs-scan-all" type="button" data-scope="server">Scan all</button><?php endif ?>
</div>
<p>Scan checks the selected website, or all active websites in the selected account.<?php if($data['context']['admin']): ?> Scan all checks active websites across <strong>all accounts on this server</strong>.<?php endif ?> Suspended websites and suspended accounts are skipped by server-wide scans.</p>
<details id="cs-scan-path-options" hidden><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Scan a folder or file (optional)</summary>
<p><label>Path inside this website <input class="form-control" name="path" placeholder="e.g. wp-content/uploads" maxlength="4096" disabled aria-describedby="cs-scan-path-help"></label></p>
<p id="cs-scan-path-help">Leave empty to scan the whole website. A path is relative to its document root; for example, wp-content/uploads scans only that folder.</p>
</details>
</form>
<p id="cs-scan-target-status" role="status" aria-live="polite"></p><a class="button" id="cs-scan-target-progress" hidden>View progress</a>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Website paths for <?=$escape($cs_global?'all accounts':$data['context']['owner'])?></summary>
<div class="scroll"><table><thead><tr><th>Website</th><th>Document root</th><th>Status</th></tr></thead><tbody>
<?php foreach($data['sites'] as $site): ?><tr><td><?=$escape(($cs_global?($site['owner']??'').' / ':'').$site['domain'])?></td><td class="path"><?=$escape($site['root'])?></td><td><?=$site['suspended']?'Suspended':'Active'?></td></tr><?php endforeach ?>
</tbody></table></div></details>
<script type="application/json" id="cs-scan-initial-sites"><?=json_encode($cs_scan_sites,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
</section>
