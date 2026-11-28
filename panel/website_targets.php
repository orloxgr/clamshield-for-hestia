<?php // Managed by clamshield; shared native account and website selectors.
$cs_target_global=($data['context']['view_scope']??'account')==='server';
$cs_target_sites=$cs_target_global?[]:array_map(static fn($site)=>['domain'=>$site['domain'],'suspended'=>$site['suspended']],$data['sites']);
?>
<div class="row cs-controls-row">
<label>Account <select class="form-select" name="owner" <?=!empty($data['context']['admin'])?'':'disabled'?>>
<?php if(!empty($data['context']['admin'])): ?><option value="" <?=$cs_target_global?'selected':''?>>Global / All accounts</option><?php foreach($data['accounts'] as $account): ?><option value="<?=$escape($account['owner'])?>" <?=!$cs_target_global&&$account['owner']===$data['context']['owner']?'selected':''?> <?=!empty($account['suspended'])?'disabled':''?>><?=$escape($account['owner'])?><?=!empty($account['suspended'])?' (suspended)':''?></option><?php endforeach;else: ?><option value="<?=$escape($data['context']['owner'])?>"><?=$escape($data['context']['owner'])?></option><?php endif ?>
</select></label>
<label>Website <select class="form-select" name="domain" <?=$cs_target_global?'disabled':''?>>
<option value=""><?=$cs_target_bulk?($cs_target_global?'All websites on this server':'All websites in this account'):($cs_target_global?'Choose an account first':'Choose a website')?></option>
<?php foreach($cs_target_sites as $site): ?><option value="<?=$escape($site['domain'])?>" <?=$site['suspended']?'disabled':''?>><?=$escape($site['domain'])?><?=$site['suspended']?' (suspended)':''?></option><?php endforeach ?>
</select></label>
<?php if($cs_target_bulk): ?><button class="button" type="submit" data-target-start>Check</button><?php if(!empty($data['context']['admin'])): ?><button class="button" type="button" data-target-all>Check all</button><?php endif ?><?php endif ?>
</div>
<p data-target-status role="status" aria-live="polite"></p>
<script type="application/json" data-target-sites><?=json_encode($cs_target_sites,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
<script><?php readfile(__DIR__.'/api_response.js');readfile(__DIR__.'/website_targets.js'); ?></script>
