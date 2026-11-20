<?php // Managed by clamshield; native controls and owner-scoped live feedback.
$cs_integrity_latest=[];$cs_integrity_initial=[];$cs_integrity_reports=[];
foreach($data['wordpress'] as $report)$cs_integrity_reports[$report['job_id']]=$report;
foreach($data['jobs'] as $job){
    if(($job['source']??'')!=='wordpress-integrity')continue;
    $key=($job['owner']??$data['context']['owner'])."\0".$job['domain']."\0".$job['root'];
    if(!isset($cs_integrity_latest[$key])||$job['created']>$cs_integrity_latest[$key]['created'])$cs_integrity_latest[$key]=$job;
}
?>
<section data-page="wordpress" hidden id="cs-integrity" data-token="<?=$escape($_SESSION['token']??'')?>" data-allowed="<?=$data['website_permissions']['effective']['scan']?'true':'false'?>">
<div class="row"><h2>WordPress integrity</h2><button type="button" class="button" id="cs-integrity-refresh">Refresh checks</button></div>
<p>Find WordPress installations and compare core, plugins and themes with official releases. Checking reads your files without changing them. Differences require review; unavailable references are marked unverified.</p>
<p id="cs-integrity-notice" role="status" aria-live="polite"></p>
<div class="scroll"><table id="cs-integrity-sites"><colgroup><col style="width:22%"><col style="width:16%"><col style="width:38%"><col style="width:24%"></colgroup><thead><tr><th scope="col">Website</th><th scope="col">Last check</th><th scope="col">Status / coverage</th><th scope="col">Actions</th></tr></thead><tbody>
<?php $cs_integrity_count=0;foreach($data['sites'] as $index=>$site): if($site['suspended'])continue;$cs_integrity_count++;
    $job=$cs_integrity_latest[$cs_owner($site)."\0".$site['domain']."\0".$site['root']]??null;
    $pending=$job&&in_array($job['status'],['queued','running'],true);
    if($job){
        $initial=array_intersect_key($job,array_flip(['id','owner','domain','target','status','created','started','finished','heartbeat','cancel_requested','counters','error']));
        $initial['report_ready']=isset($cs_integrity_reports[$job['id']])&&empty($job['counters']['history_expired']);
        $initial['discovery_complete']=!empty($cs_integrity_reports[$job['id']]['report']['discovery_complete']);
        $cs_integrity_initial[(string)$index]=$initial;
    }
?>
<tr class="cs-integrity-row" data-index="<?=$index?>" data-owner="<?=$escape($cs_owner($site))?>" data-domain="<?=$escape($site['domain'])?>">
<td><strong><?=$escape($site['domain'])?></strong><?php if($cs_global): ?><p><?=$escape($cs_owner($site))?></p><?php endif ?>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Folder (optional)</summary><label for="cs-integrity-path-<?=$index?>">Folder inside this website</label><input class="form-control" id="cs-integrity-path-<?=$index?>" name="path" form="cs-integrity-form-<?=$index?>" maxlength="4096" placeholder="e.g. blog" aria-describedby="cs-integrity-help-<?=$index?>" value="<?=$pending?$escape($job['target']):''?>"><p id="cs-integrity-help-<?=$index?>">Leave empty to search the whole website, including WordPress installations in subfolders.</p></details></td>
<td class="cs-integrity-time"><?=$job?$escape(gmdate('Y-m-d H:i:s',(int)$job['created']).' UTC'):'Not checked yet'?></td>
<td><p class="cs-integrity-status" role="status" aria-live="polite"><?=$job?$escape(ucfirst($job['status'])):'Ready to discover WordPress'?></p><p class="cs-integrity-counts"></p><p class="cs-integrity-error" role="status"></p></td>
<td><form class="row cs-integrity-form" id="cs-integrity-form-<?=$index?>" data-capability="scan"><button class="button cs-integrity-start" type="submit" <?=$pending||!$data['website_permissions']['effective']['scan']?'disabled':''?>><?=$pending?'Check in progress':'Discover and verify'?></button></form><div class="row"><a class="button cs-integrity-progress" href="#scan/jobs" data-tab="jobs" <?=$pending?'':'hidden'?>>View progress</a><button class="button cs-integrity-show-report" type="button" hidden>View report</button></div></td>
</tr><tr class="cs-integrity-report-row" data-index="<?=$index?>" hidden><td colspan="4"><article class="card"><div class="row"><h3>Integrity report: <?=$escape($cs_label($site))?></h3><button class="button cs-integrity-close-report" type="button">Close report</button></div><p class="cs-integrity-report-status" role="status" aria-live="polite"></p><div class="cs-integrity-issues"></div><button class="button cs-integrity-more" type="button" hidden>More report entries</button></article></td></tr>
<?php endforeach;if(!$cs_integrity_count): ?><tr><td colspan="4">No active websites are available in this view.</td></tr><?php endif ?>
</tbody></table></div>
<script type="application/json" id="cs-integrity-initial"><?=json_encode((object)$cs_integrity_initial,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
<?php if($data['wordpress']): ?><details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Previous integrity reports</summary>
<?php foreach($data['wordpress'] as $integrity): ?><details data-owner="<?=$escape($cs_owner($integrity))?>"><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i><?=$escape($cs_label($integrity))?> · <?=$escape(gmdate('Y-m-d H:i:s',(int)$integrity['created']))?> UTC · <?=$escape($integrity['status'])?></summary>
<p><?=$escape(json_encode($integrity['counters']))?></p><?php if(!$integrity['report']['installations']): ?><p>No WordPress installation was identified in the checked paths.</p><?php endif ?>
<?php foreach($integrity['report']['installations'] as $installation): ?><p class="path"><?=$escape($installation['path']?:'/')?> · <?=$escape($installation['version']??'Unknown version')?> · <?=$escape($installation['locale']??'')?> <?=$escape($installation['error']??'')?></p><?php endforeach ?>
<div class="scroll"><table><thead><tr><th>Component</th><th>Version</th><th>Result</th><th>Coverage</th></tr></thead><tbody><?php foreach($integrity['report']['components'] as $component): ?><tr><td><?=$escape($component['kind'].' / '.($component['slug']??''))?><div class="path"><?=$escape($component['path'])?></div></td><td><?=$escape($component['version']??'Unknown')?></td><td><?=$escape($component['status'])?><br><?=$escape($component['error']??'')?></td><td><?=$escape(json_encode($component['counts']))?></td></tr><?php endforeach ?></tbody></table></div>
<button class="button cs-wp-report" data-job="<?=$escape($integrity['job_id'])?>" data-offset="0">Show issues</button><pre class="cs-wp-issues" style="white-space:pre-wrap" aria-live="polite"></pre></details><?php endforeach ?>
</details><?php endif ?>
</section>
<script><?php readfile(__DIR__.'/wordpress_integrity.js'); ?></script>
