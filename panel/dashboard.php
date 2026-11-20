<?php // Managed by clamshield; all values describe recorded runtime state.
$cs_date=static fn($value)=>is_numeric($value)?gmdate('Y-m-d H:i:s',(int)$value).' UTC':'Not recorded';
$cs_rules=$data['rules']; $cs_admin=$data['context']['admin'];
$cs_providers=$data['providers']??[]; $cs_sa=$data['spamassassin']??[];
?>
<section data-page="dashboard" id="cs-dashboard">
<h2>Dashboard</h2>
<div class="cs-dashboard-panels">
<article class="card"><h3>Engine info</h3><dl class="cs-engine-info">
<?php foreach(['clamav'=>'ClamAV version','yara'=>'YARA engine'] as $engine=>$title): $info=$data['engines'][$engine]; ?>
<dt><?=$escape($title)?></dt><dd><?=$escape($info['available']?$info['version']:($info['error']??'Unavailable'))?></dd>
<?php if($engine==='clamav'): ?>
<dt>ClamAV signatures</dt><dd class="cs-dashboard-value"><?php if($cs_admin): ?><span><?=$escape($cs_date($cs_providers['status']['official']['last_success']??null))?></span><a href="#updates/providers" data-tab="providers">Manage</a><?php else: ?>Managed by administrator<?php endif ?></dd>
<?php endif; endforeach ?>
<dt>YARA rules</dt><dd class="cs-dashboard-value"><span id="cs-dashboard-yara-status"><?php if($cs_rules['configured']): ?><?=$escape($cs_rules['profile']??'Custom')?> · <?=$escape($cs_rules['enabled']??$cs_rules['rules']??'Unknown')?> rules<br><?=$escape($cs_date($cs_rules['created']??null))?><?php else: ?>Not installed<?php endif ?></span><a href="#updates/rules" data-tab="rules">Manage</a></dd>
<?php foreach(['securiteinfo'=>'SecuriteInfo','sanesecurity'=>'SaneSecurity'] as $provider=>$title): ?>
<dt><?=$title?></dt><dd class="cs-dashboard-value"><?php if($cs_admin): ?><span><?=$escape(!empty($cs_providers[$provider]['enabled'])?$cs_date($cs_providers['status'][$provider]['last_success']??null):'Disabled')?><?php if(!empty($cs_providers['status'][$provider]['error'])): ?><br><?=$escape($cs_providers['status'][$provider]['error'])?><?php endif ?></span><a href="#settings/provider-settings" data-tab="provider-settings" data-focus-provider="<?=$provider?>">Manage</a><?php else: ?>Managed by administrator<?php endif ?></dd>
<?php endforeach ?>
</dl><p>Rule build times and the last successful provider downloads are shown in UTC. Downloaded data may still require activation; check Updates and scanner readiness.</p></article>
<article class="card"><div class="row cs-dashboard-heading"><h3>SpamAssassin</h3><a href="<?=$cs_admin?'#settings/spamassassin':'#email'?>" data-tab="<?=$cs_admin?'spamassassin':'mail'?>">Manage</a></div>
<?php if(!$cs_admin): ?><p>Email protection follows your domain and mailbox policies.</p><a href="#email" data-tab="mail">View email protection</a>
<?php elseif(isset($cs_sa['error'])): ?><p class="alert alert-warning"><?=$escape($cs_sa['error'])?></p>
<?php else: ?><dl class="cs-engine-info">
<dt>Scanner service</dt><dd><?=!empty($cs_sa['service_active'])?'Running':'Stopped'?></dd>
<dt>Mail integration</dt><dd><?=$escape($data['mail_integration']['phase']??'Unknown')?></dd>
<dt>Configuration</dt><dd><?=!empty($cs_sa['daemon_verified'])?'Verified for current process':(!empty($cs_sa['configured'])?'Applied; runtime verification pending':'Not applied')?></dd>
<dt>Required spam score</dt><dd><?=$escape($cs_sa['policy']['required_score']??'Not configured')?></dd>
<dt>RBL / URIBL</dt><dd><?=!empty($cs_sa['policy']['rbl_enabled'])?'On':'Off'?> / <?=!empty($cs_sa['policy']['uribl_enabled'])?'On':'Off'?><?php if(($cs_sa['local_mode']??null)===true): ?> · Local mode: DNS checks are inactive<?php endif ?></dd>
<?php $cs_sa_tasks=array_values(array_filter($data['maintenance']??[],static fn($task)=>$task['action']==='spamassassin-save' && in_array($task['status'],['queued','running'],true))); ?>
<dt>Pending recent configuration tasks</dt><dd class="cs-dashboard-value"><span><?=count($cs_sa_tasks)?></span><a href="#review/activity" data-tab="activity" data-focus-id="cs-sa-tasks">View queue</a></dd>
</dl><p>DNS list access depends on the resolver and provider. Domain policies determine how final spam scores are handled.</p><?php endif ?>
</article></div>
<article class="card cs-activity" aria-labelledby="cs-activity-heading">
<h3 id="cs-activity-heading"><i class="fas fa-chart-line" aria-hidden="true"></i> Activity overview</h3>
<dl>
<div class="cs-activity-row"><dt><i class="fas fa-globe" aria-hidden="true"></i> Websites</dt><dd><a href="#scan" data-tab="sites">View websites</a><strong><?=count($data['sites'])?></strong></dd></div>
<div class="cs-activity-row"><dt><i class="fas fa-exclamation-triangle" aria-hidden="true"></i> Open findings</dt><dd><a href="#review" data-tab="findings">View results</a><strong><?=$data['summary']['open_findings']?></strong></dd></div>
<div class="cs-activity-row"><dt><i class="fas fa-tasks" aria-hidden="true"></i> Active scans</dt><dd><a href="#scan/jobs" data-tab="jobs">View progress</a><strong id="cs-active-scans"><?=$data['summary']['active_scans']?></strong></dd></div>
<div class="cs-activity-row"><dt><i class="fas fa-archive" aria-hidden="true"></i> Quarantined</dt><dd><a href="#review/quarantine" data-tab="quarantine">View files</a><strong><?=$data['summary']['quarantined']?></strong></dd></div>
</dl></article>
<?php $coverage=$data['website_readiness']??['state'=>'unknown','message'=>'Website readiness has not been verified yet.','checked'=>null]; ?>
<p id="cs-website-coverage" class="notice alert <?=$coverage['state']==='healthy'?'alert-success':($coverage['state']==='checking'?'alert-info':'alert-warning')?>" role="status"><?=$escape($coverage['message'])?><?php if($coverage['checked']!==null): ?><br><small>Last checked: <?=$escape($cs_date($coverage['checked']))?></small><?php endif ?></p>
<?php if($cs_admin): ?><a href="#settings/resources" data-tab="resources">Manage scanner services and resources</a><?php endif ?>
</section>
