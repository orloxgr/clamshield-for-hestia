<?php // Managed by clamshield
?>
<?php $cs_rule_schedule=$data['rule_manager']['updates']??['automatic'=>true,'interval_minutes'=>1440,'next_allowed'=>0]; ?>
<article class="card" id="cs-yara-update-schedule">
<h3>Rule update preferences</h3>
<form id="cs-yara-schedule" class="row cs-controls-row"><label>Forge profile <select class="form-select" name="profile"><?php foreach(['core','extended','full'] as $profile): ?><option value="<?=$profile?>" <?=($cs_rule_schedule['profile']??$data['rules']['profile']??'core')===$profile?'selected':''?>><?=ucfirst($profile)?></option><?php endforeach ?></select></label>
<label><input type="checkbox" name="automatic" <?=!empty($cs_rule_schedule['automatic'])?'checked':''?>> Automatically update the selected profile</label>
<label>Check every (minutes) <input class="form-control" type="number" name="interval_minutes" min="60" max="525600" step="1" required value="<?=$escape($cs_rule_schedule['interval_minutes'])?>"></label>
<button class="button" type="submit">Save update preferences</button>
</form>
<p>Minimum interval: 60 minutes. Longer GitHub cooldowns take precedence.</p>
<p>The selected profile applies on the next update. Engine updates come from Ubuntu APT.</p>
<p id="cs-yara-schedule-status" role="status" aria-live="polite"></p>

<script type="application/json" id="cs-yara-schedule-data"><?=json_encode($cs_rule_schedule,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
</article>
