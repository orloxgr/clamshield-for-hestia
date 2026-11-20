<?php // Managed by clamshield; update state and timing belong only to Updates.
$cs_activation=$providers['status']['activation']??[];
$cs_update_tasks=array_filter($data['maintenance']??[],static fn($task)=>str_starts_with($task['action'],'signatures-')&&in_array($task['status'],['queued','running'],true));
?>
<section data-page="providers" hidden><h2>Signature updates</h2>
<p>Website and email scanners load their own selected databases. Updates download shared data once, validate both selections and activate them together.</p>
<p>Database activation: <strong><?=$escape($cs_activation['state']??'Not checked')?></strong><?php if(!empty($cs_activation['last_success'])): ?> · Last success <?=$escape(gmdate('Y-m-d H:i:s',(int)$cs_activation['last_success']))?> UTC<?php endif ?><?php if(!empty($cs_activation['error'])): ?><span class="error"> · <?=$escape($cs_activation['error'])?></span><?php endif ?></p>
<details><summary>Active generation</summary><p class="path"><?=$escape($data['signatures']['generation']??'Ubuntu official database directory')?></p></details>
<div class="row"><button class="button" id="cs-signature-update" data-action="signatures-update" data-provider="all">Update enabled providers</button><button class="button" data-action="signatures-activate">Validate and activate cached data</button><button class="button" data-action="signatures-rollback">Roll back databases</button></div>
<?php if($cs_update_tasks): ?><p role="status">Signature maintenance is <?=in_array('running',array_column($cs_update_tasks,'status'),true)?'running':'queued'?>. <a href="#review/history" data-tab="history" data-focus-id="cs-sa-tasks">View progress in History</a></p><?php endif ?>
<form id="cs-provider-update-settings">
<?php require __DIR__.'/provider_schedule.php'; ?>
<div class="row"><button class="button" type="submit" aria-describedby="cs-provider-update-save-status">Save update schedule</button><span id="cs-provider-update-save-status" role="status" aria-live="polite"></span></div>
</form>
<h3>Local signatures</h3><p><?=$providers['local']['enabled']?'Enabled':'Disabled'?> · <?=count($providers['local']['files'])?> local files. Validate and activate cached data to apply local changes.</p>
<p><a href="#settings/provider-settings" data-tab="provider-settings" data-focus-id="cs-local-signatures">Manage local signatures</a> · <a href="#review/history" data-tab="history" data-focus-id="cs-sa-tasks">View maintenance history</a></p>
</section>
