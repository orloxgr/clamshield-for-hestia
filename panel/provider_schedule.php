<?php // Managed by clamshield; public eligibility, never provider credentials.
$cs_provider_names=['official'=>'Official ClamAV','securiteinfo'=>'SecuriteInfo','sanesecurity'=>'SaneSecurity'];
$cs_provider_sources=[
    'official'=>['Conservative hourly floor for CDN access','https://docs.clamav.net/faq/faq-troubleshoot.html'],
    'securiteinfo'=>['Provider permits one download per hour, for all plans','https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml'],
    'sanesecurity'=>['Conservative hourly floor; excessive mirror requests are prohibited','https://sanesecurity.com/usage/linux-scripts/'],
];
$cs_provider_time=static fn($value)=>is_numeric($value)&&$value>0?gmdate('Y-m-d H:i:s',(int)$value).' UTC':'Not recorded';
?>
<h3>Update schedule</h3>
<p><label><input type="checkbox" name="automatic" <?=$providers['automatic']?'checked':''?>> Automatic provider updates</label></p>
<p>Choose the interval for each provider in minutes. Minimum intervals apply to automatic and manual updates. A longer provider cooldown takes precedence. Save update schedule below to apply changes.</p>
<div class="scroll"><table id="cs-provider-schedule"><thead><tr><th>Provider / interval</th><th>Status</th><th>Minimum</th><th>Last attempt</th><th>Last success</th><th>Next permitted update</th><th>Action</th></tr></thead><tbody>
<?php foreach($cs_provider_names as $name=>$title):
    $record=$providers['status'][$name]??[];
    $interval=$providers[$name]['interval_minutes']??60;
    $enabled=$providers[$name]['enabled']??($name==='official');
    $schedule=$providers['schedule'][$name]??['minimum_minutes'=>60,'next_allowed'=>max(($record['last_attempt']??0),($record['last_success']??0))+$interval*60,'retry_after'=>$record['retry_after']??null];
?>
<tr data-provider="<?=$name?>"><td><label for="cs-interval-<?=$name?>"><?=$title?> - every (minutes)</label><input class="form-control" type="number" id="cs-interval-<?=$name?>" name="<?=$name?>_interval_minutes" min="<?=$schedule['minimum_minutes']?>" max="525600" step="1" required value="<?=$interval?>"><?php if($name==='official'): ?><p>Required · updated with Ubuntu freshclam.</p><?php else: ?><p data-provider-counts>Website: <?=count($providers[$name]['website_databases']??$providers[$name]['databases'])?> databases · Email: <?=count($providers[$name]['mail_databases']??$providers[$name]['databases'])?> databases</p><?php endif ?></td>
<td data-provider-state><?=$enabled?'Enabled':'Disabled'?><?php if($enabled): ?><p><?=$escape($record['state']??'Not checked')?></p><?php endif ?><?php if(!empty($record['error'])): ?><p class="error"><?=$escape($record['error'])?></p><?php endif ?></td>
<td><?=$schedule['minimum_minutes']?> minutes<p><?=$escape($cs_provider_sources[$name][0])?></p><a href="<?=$escape($cs_provider_sources[$name][1])?>" target="_blank" rel="noopener noreferrer">Provider guidance</a></td>
<td><?=$escape($cs_provider_time($record['last_attempt']??null))?></td><td><?=$escape($cs_provider_time($record['last_success']??null))?></td>
<td><span data-provider-next><?php if(!$enabled): ?>Disabled<?php elseif($schedule['next_allowed']<=time()): ?>Due now<?php else: ?><?=$escape($cs_provider_time($schedule['next_allowed']))?><?php endif ?></span><?php if(($schedule['retry_after']??0)>time()): ?><p>Freshclam provider cooldown</p><?php endif ?><p data-provider-automatic-off <?=$providers['automatic']?'hidden':''?>>Automatic updates off</p></td>
<td><button class="button" type="button" data-action="signatures-update" data-provider="<?=$name?>" <?=!$enabled||$schedule['next_allowed']>time()?'disabled':''?>>Update now</button><?php if($name!=='official'): ?><a href="#settings/provider-settings" data-tab="provider-settings" data-focus-provider="<?=$name?>">Provider settings</a><?php endif ?></td></tr>
<?php endforeach ?>
</tbody></table></div>
<p>These times show the earliest permitted check; queued tasks and downloads may finish later. Validate and activate cached data does not download signatures.</p>
