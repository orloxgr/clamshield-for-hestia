<?php // Managed by clamshield ?>
<section data-page="scheduled" hidden><h2>Scheduled Scanner</h2><p>Set scan times and changed-file monitoring for each website. Times use the saved timezone; suspended websites are skipped.</p>
<?php if(!$data['sites']): ?><p>No websites are available for this account.</p><?php endif ?>
<?php foreach($data['sites'] as $site): ?>
<details open><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i><?=$escape($site['domain'])?></summary><form data-capability="schedule" class="cs-policy" data-domain="<?=$escape($site['domain'])?>">
<div class="row"><label><input type="checkbox" name="watch" <?=$site['policy']['watch']?'checked':''?>> Scan new and changed files</label><label>Schedule <select class="form-select" name="frequency"><?php foreach(['never','daily','weekly','monthly'] as $frequency): ?><option <?=$site['policy']['frequency']===$frequency?'selected':''?>><?=$frequency?></option><?php endforeach ?></select></label><label>Time <input class="form-control" type="time" name="time" value="<?=$escape($site['policy']['time'])?>" required></label><label>Timezone <input class="form-control" name="timezone" value="<?=$escape($site['policy']['timezone'])?>" required></label></div>
<div class="row"><label>Weekday (Mon=0) <input class="form-control" type="number" name="weekday" min="0" max="6" value="<?=$site['policy']['weekday']?>"></label><label>Day of month <input class="form-control" type="number" name="monthday" min="1" max="31" value="<?=$site['policy']['monthday']?>"></label><label><input type="checkbox" name="rescan_updates" <?=$site['policy']['rescan_updates']?'checked':''?>> Full recheck after rule updates</label><button class="button" type="submit">Save policy</button></div>
</form></details>
<?php endforeach ?>
</section>
