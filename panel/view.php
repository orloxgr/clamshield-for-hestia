<?php // Managed by clamshield
$cs_compact_notices=static function($value) use (&$cs_compact_notices){
    if(!is_array($value))return $value;
    foreach($value as $key=>$item){
        if(in_array($key,['license','licenses','upstream_notice'],true)&&(is_array($item)||(is_string($item)&&strlen($item)>200)))$value[$key]='Upstream notice retained with installed data. See Settings / Support Us.';
        else $value[$key]=$cs_compact_notices($item);
    }
    return $value;
};
$data=$cs_compact_notices($data);
$cs_global=($data['context']['view_scope']??'account')==='server';
$cs_owner=static fn($row)=>$row['owner']??$data['context']['owner'];
$cs_label=static fn($row)=>($cs_global?($row['owner']??$data['context']['owner']).' / ':'').($row['domain']??'');
?>
<style>
/* Hestia owns control appearance, including the active navigation accent. */
.cs{margin:28px auto;padding:0 20px}
.cs .sub{margin:2px 0 24px}
.cs .card{padding:12px;margin-bottom:12px}.cs section{padding:20px 0;margin-bottom:20px}
.cs :is(h2,h3,h4,p,form,details,.row,.scroll,pre,dl,ul,ol):not(:empty){margin-bottom:12px}
.cs .button{margin-inline-end:12px;margin-bottom:12px}
.cs p>.button{margin-bottom:0}
.cs :is(.row,nav,.cs-native-backups)>.button{margin:0}
.cs .row>:is(h2,h3,h4,p){margin-bottom:0}
.cs :is(.form-control,.form-select)+.button{margin-inline-start:12px}
.cs :is(.row,nav,.cs-native-backups)>:is(.form-control,.form-select)+.button{margin-inline-start:0}
.cs .cs-activity h3{display:flex;align-items:center;gap:10px}
.cs .cs-activity-row{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0}
.cs .cs-activity dt{display:flex;align-items:center;gap:10px}.cs .cs-activity dd{display:flex;justify-content:flex-end;align-items:center;gap:16px;margin:0;text-align:right}
.cs .cs-activity dd a{min-width:8em}.cs .cs-activity strong{min-width:3ch;overflow-wrap:anywhere}
.cs .cs-dashboard-panels{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:28px;margin-bottom:12px}.cs .cs-engine-info{display:grid;grid-template-columns:minmax(9em,1fr) minmax(0,2fr);gap:12px}.cs .cs-engine-info dd{margin:0;overflow-wrap:anywhere}
.cs .cs-dashboard-value{display:flex;align-items:flex-start;gap:12px}.cs .cs-dashboard-value>span{min-width:0}
.cs :is(.cs-dashboard-value,.cs-dashboard-heading)>a{margin-inline-start:auto;flex-shrink:0;white-space:nowrap}
.cs #cs-dashboard-clamav-enable{margin:0 0 0 auto;flex-shrink:0}.cs #cs-dashboard-clamav-status:not(:empty){display:block;margin-top:12px}
.cs details>summary.cs-disclosure{display:inline-flex;align-items:center;gap:8px;max-width:100%;margin:0;white-space:normal;list-style:none}
.cs details[open]>summary.cs-disclosure{margin-bottom:12px}
.cs summary.cs-disclosure::-webkit-details-marker{display:none}
.cs .cs-disclosure-icon{flex-shrink:0}.cs details[open]>summary.cs-disclosure>.cs-disclosure-icon{transform:rotate(90deg)}
.cs nav{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}
.cs #cs-main-navigation .button[aria-current="page"],.cs nav[data-subnav] .button[aria-current="page"]{border-bottom-color:var(--color-text-link-hover)}
.cs table{width:100%;border-collapse:collapse}.cs td,.cs th{text-align:left;padding:10px;overflow-wrap:anywhere}
.cs .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.cs [hidden]{display:none}
.cs .cs-controls-row{align-items:flex-end}
.cs :is(th,td).cs-review-selection-heading,.cs td.cs-review-selection-cell{width:44px}
.cs .cs-notification-categories{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-bottom:12px}
.cs .notice{display:block;margin:14px 0}.cs .path{font-family:monospace;overflow-wrap:anywhere}.cs .scroll{overflow:auto}
.cs .form-control,.cs .form-select{max-width:100%;width:auto}.cs textarea.form-control{width:100%}
.cs .cs-native-backups{display:flex;flex-direction:column;align-items:flex-start;gap:12px;max-width:20rem}
.cs .cs-native-backups select{width:20rem;max-width:100%;min-width:0;box-sizing:border-box}.cs .cs-native-backups button{white-space:normal}
.cs .scroll table{min-width:760px}.cs th{white-space:nowrap}.cs td{vertical-align:top}
.cs #cs-mail-fields>p{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px}
.cs #cs-mail-fields>p>label:first-child{min-width:220px}.cs #cs-mail-fields textarea{min-width:min(500px,65vw)}
.cs #cs-mail-retention-status{overflow-wrap:anywhere}
.cs #cs-mail-expiry-history td{white-space:pre-line}
.cs #cs-scans-list td{white-space:pre-line}
.cs #cs-scans-list td:nth-child(2){min-width:9em}
.cs #cs-integrity-sites{table-layout:fixed}
.cs #cs-history-events{table-layout:fixed}.cs .cs-history-summary{margin-bottom:12px}
@media(max-width:750px){.cs .cs-dashboard-panels{grid-template-columns:1fr}.cs .cs-engine-info{grid-template-columns:1fr}.cs .cs-engine-info dd{margin-bottom:12px}}
@media(max-width:450px){.cs .cs-activity-row{align-items:flex-start}.cs .cs-activity dd{flex-direction:column;align-items:flex-end;gap:4px}.cs .cs-activity dd a{min-width:0}}
</style>
<main class="container cs" id="cs-review-root" data-scope="<?=$cs_global?'server':'account'?>" data-owner="<?=$escape($data['context']['owner'])?>" data-identity="<?=$escape($data['context']['identity']??'')?>" data-token="<?=$escape($_SESSION['token']??'')?>">
<div class="row"><div><h1>ClamShield <small style="font-size:14px;font-weight:400">for Hestia</small></h1><p class="sub">Website malware scanning &amp; email protection</p></div>
<?php if($data['context']['admin']): ?><label style="margin-left:auto">Viewing account <select class="form-select" id="cs-owner"><option value="" <?=$cs_global?'selected':''?>>Global</option><?php foreach($data['accounts'] as $account): ?><option <?= !$cs_global && $account['owner']===$data['context']['owner']?'selected':'' ?>><?= $escape($account['owner']) ?></option><?php endforeach ?></select></label><?php endif ?></div>
<?php require __DIR__.'/navigation.php'; ?>
<?php if(($data['yara_enabled']??true)&&!$data['engines']['yara']['rules_available']): ?><p id="cs-yara-warning" class="notice alert alert-warning">YARA scanning is enabled and needs active rules. <a href="#updates/rules" data-tab="rules">Set up YARA rules</a></p><?php endif ?>
<?php if(!$data['context']['admin'] && in_array(false,$data['website_permissions']['effective'],true)): ?><p class="notice alert alert-info">Some website actions are disabled by your administrator. Results and history remain available; disabled controls explain the required permission.</p><?php endif ?>
<p id="cs-message" role="status" aria-live="polite"></p>
<?php require __DIR__.'/dashboard.php'; ?>
<?php require __DIR__.'/on_demand.php'; ?>
<?php require __DIR__.'/scheduled.php'; ?>
<?php require __DIR__.'/scans.php'; ?>
<section data-page="findings" hidden><h2>Findings</h2><p>Findings retain their recorded status when a website is removed, suspended or moved. Unavailable website actions require the original site configuration to be restored and reviewed; this does not establish that a file is clean.</p><div class="scroll"><table><thead><tr><th>Site / file</th><th>Detection</th><th>Engine</th><th>Status</th><th>Action</th></tr></thead><tbody id="cs-review-findings-rows">
<?php require __DIR__.'/review_rows/findings.php'; ?>
</tbody></table></div></section>
<section data-page="exceptions" hidden><h2>Exceptions</h2><p>Website exceptions are listed here. <a href="#review/exceptions" data-tab="exceptions" data-focus-id="cs-mail-email-exceptions">Manage email exceptions</a></p><p>Content exceptions apply only while the file hash matches. Signature exceptions apply to the selected file within this website. Engine scans still run and record suppressed matches.</p><div class="scroll"><table><thead><tr><th>Site / file</th><th>Type</th><th>Signature or hash</th><th>Status</th><th>Action</th></tr></thead><tbody id="cs-review-exceptions-rows"><?php require __DIR__.'/review_rows/exceptions.php'; ?></tbody></table></div></section>
<?php require __DIR__.'/notifications.php'; ?>
<section data-page="quarantine" hidden><h2>Quarantine</h2><p>Website files are listed here. <a href="#review/email-review" data-tab="email-review">Manage quarantined email</a></p><p>Restoring a file does not establish that it is clean. Re-scan after remediation.</p><div class="scroll"><table><thead><tr><th>File</th><th>Status</th><th>Action</th></tr></thead><tbody id="cs-review-quarantine-rows">
<?php require __DIR__.'/review_rows/quarantine.php'; ?>
</tbody></table></div></section>
<section data-page="repairs" hidden><h2>Repairs</h2><p>Prepare a preview from a verified WordPress release, a backup, or targeted infection cleaning chosen in Findings. Review the source, hashes and differences before applying it. Repairs retain the original content or a record that the file was absent. Published files receive a ClamAV/YARA recheck. Undo restores the original content or absence; created folders and other files are retained.</p><button class="button" id="cs-refresh-repairs">Refresh results</button>
<div id="cs-review-repairs-rows"><?php require __DIR__.'/review_rows/repairs.php'; ?></div></section>
<section data-page="history" hidden><div class="row"><h2>History</h2><button class="button" type="button" id="cs-history-lists-refresh">Refresh history</button></div><h3>Events</h3><?php require __DIR__.'/history_events.php'; require __DIR__.'/activity.php'; ?></section>
<?php require __DIR__.'/wordpress_recovery.php'; ?>
<?php require __DIR__.'/rules.php'; ?>
<?php if($data['context']['admin']): $providers=$data['providers']; ?>
<?php require __DIR__.'/provider_updates.php'; ?>
<section data-page="provider-settings" hidden><h2>Signature provider settings</h2>
<p>Choose databases independently for website files and email. Risk labels use the provider's published ratings; Not rated means no per-database rating is published.</p>
<form id="cs-providers">
<div class="row"><button type="button" class="button" id="cs-provider-recommended">Recommended defaults</button><span id="cs-provider-recommended-status" role="status">Presets exclude High risk and PUA. Existing saved selections remain until you save.</span></div>
<h3 id="cs-provider-securiteinfo" tabindex="-1">SecuriteInfo</h3>
<div class="row"><label><input type="checkbox" name="si_enabled" <?=$providers['securiteinfo']['enabled']?'checked':''?>> Enabled</label><label>Plan <select class="form-select" name="si_plan"><?php foreach(['basic','professional','gold','reseller'] as $plan): ?><option <?=$providers['securiteinfo']['plan']===$plan?'selected':''?>><?=$plan?></option><?php endforeach ?></select></label><div><div class="row"><label for="cs-si-key">Account key</label><a href="https://www.securiteinfo.com/clients/customers/account?src=clamshield" target="_blank" rel="noopener noreferrer">Get a key</a></div><input class="form-control" id="cs-si-key" type="password" name="si_key" autocomplete="new-password" placeholder="<?=$providers['securiteinfo']['has_key']?'Saved; leave empty to keep':'Account installation key'?>"></div></div>
<p>Use your provider account's installation key. Basic and paid plans provide different database access.</p>
<?php $cs_provider_name='securiteinfo'; $cs_provider_title='SecuriteInfo'; $cs_provider_prefix='si'; require __DIR__.'/provider_databases.php'; ?>
<h3 id="cs-provider-sanesecurity" tabindex="-1">SaneSecurity</h3><p><label><input type="checkbox" name="sane_enabled" <?=$providers['sanesecurity']['enabled']?'checked':''?>> Enabled · rsync downloads with pinned GPG verification</label></p>
<p>Mixed databases can contain several threat types. Email classification uses the verified source and documented signature groups; unknown mixed matches keep the malware policy.</p>
<?php $cs_provider_name='sanesecurity'; $cs_provider_title='SaneSecurity'; $cs_provider_prefix='sane'; require __DIR__.'/provider_databases.php'; ?>
<p><label><input type="checkbox" name="local_enabled" <?=$providers['local']['enabled']?'checked':''?>> Enable local signatures</label></p>
<div class="row"><button type="submit" class="button" aria-describedby="cs-provider-save-status">Save provider settings</button><span id="cs-provider-save-status" role="status" aria-live="polite"></span><a id="cs-provider-activate-link" href="#updates/providers" data-tab="providers" data-focus-id="cs-signature-update" hidden>Update signature databases</a></div>
</form>
<h3>Local signatures</h3><?php if(!$providers['local']['files']): ?><p>No local signature files.</p><?php endif ?><?php foreach($providers['local']['files'] as $file): ?><p><?=$escape($file)?> <button class="button" data-action="signature-local-delete" data-name="<?=$escape($file)?>">Remove from selected data</button></p><?php endforeach ?>
<form id="cs-local-signatures"><div class="row"><label>Filename <input class="form-control" name="name" placeholder="hosting.hdb" required></label></div><p><textarea class="form-control" name="content" rows="5" style="width:100%" maxlength="45000" aria-label="Local signature content" required></textarea></p><button class="button" type="submit">Save local signature file</button></form>
<p><a href="#review/history" data-tab="history" data-focus-id="cs-sa-tasks">View maintenance history</a></p>
</section>
<?php endif ?>
<?php require __DIR__.'/mail.php'; ?>
<?php require __DIR__.'/spamassassin.php'; ?>
<?php require __DIR__.'/resources.php'; ?>
<?php require __DIR__.'/remediation.php'; ?>
<?php require __DIR__.'/permissions.php'; require __DIR__.'/yara_settings.php'; require __DIR__.'/support.php'; ?>
<section data-page="retention" hidden><h2>History retention settings</h2><?php require __DIR__.'/history.php'; require __DIR__.'/server_history.php'; ?></section>
</main>
<script>
(() => {'use strict';
 const token=<?=json_encode($_SESSION['token']??'',JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 const owner=<?=json_encode($data['context']['owner'],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 const ownerFor=node=>{const value=node.closest('[data-owner]')?.dataset.owner;return value&&!value.startsWith('@')?value:owner;};
 const websitePermissions=<?=json_encode($data['website_permissions']['effective'])?>;
 const websitePermissionLabels=<?=json_encode($data['website_permissions']['labels'])?>;
 const websiteActions={"initial-monitoring-resume":"schedule","scan":"scan","wordpress-scan":"scan","policy-save":"schedule","quarantine":"quarantine","restore":"restore","repair-preview":"repair","repair-backup-preview":"repair","repair-hestia-preview":"repair","cleanup-preview":"cleanup","repair-undo":"restore","exception-add":"exceptions","exception-remove":"exceptions","remediation-policy-save":"automatic","repair-apply":null};
 const ruleOverrides=<?=json_encode($data['context']['admin']?$data['rule_manager']['disabled']:[],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 document.getElementById('cs-rules-refresh')?.addEventListener('click',()=>location.reload());
 document.getElementById('cs-history-lists-refresh').addEventListener('click',()=>{for(const kind of ['history','activity','automatic'])document.dispatchEvent(new CustomEvent('clamshield-review-refresh',{detail:kind}));});
 function prepareReviewControls(scope=document){
 scope.querySelectorAll('[data-action]').forEach(control=>{const capability=control.dataset.capability||websiteActions[control.dataset.action];if(capability)control.dataset.capability=capability;});
 scope.querySelectorAll('[data-capability]').forEach(container=>{if(websitePermissions[container.dataset.capability]!==false)return;container.title=websitePermissionLabels[container.dataset.capability]+' is disabled by the administrator';const controls=container.matches('button,input,select,textarea')?[container]:container.querySelectorAll('button,input,select,textarea');controls.forEach(control=>{control.disabled=true;control.setAttribute('aria-disabled','true');control.title=container.title;});});
 }
 prepareReviewControls();
 <?php readfile(__DIR__.'/navigation.js'); ?>
 <?php readfile(__DIR__.'/rule_updates.js'); ?>
 <?php readfile(__DIR__.'/on_demand.js'); ?>
 <?php readfile(__DIR__.'/mail_protection.js'); ?>
 document.addEventListener('clamshield-mail-protection-changed',()=>location.reload());
 document.getElementById('cs-refresh-repairs').addEventListener('click',()=>document.dispatchEvent(new CustomEvent('clamshield-review-refresh',{detail:'repairs'})));
 function bindReviewRows(scope=document){
 scope.querySelectorAll('.cs-native-backups').forEach(container=>{if(container.dataset.reviewBound)return;container.dataset.reviewBound='true';
  const list=container.querySelector('.cs-backup-list'),select=container.querySelector('select'),prepare=container.querySelector('.cs-backup-prepare'),status=container.querySelector('[role="status"]');
  list.addEventListener('click',async()=>{list.disabled=true;status.textContent='Reading native backup catalog...';try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner:ownerFor(container),action:'repair-backups',finding_id:container.dataset.finding})});const result=await response.json();if(!result.ok)throw new Error(result.error);select.replaceChildren();for(const backup of result.backups){const option=document.createElement('option');option.value=backup.name;option.textContent=backup.name+(backup.available?'':' · '+backup.error);option.disabled=!backup.available;select.append(option);}select.hidden=prepare.hidden=result.backups.length===0;const first=result.backups.find(backup=>backup.available);if(first)select.value=first.name;prepare.disabled=!first||!websitePermissions.repair;status.textContent=result.backups.length?'Choose a backup to scan and review.':'No native backups include this website.';}catch(error){status.textContent=error.message;}finally{list.disabled=false;}});
  prepare.addEventListener('click',async()=>{prepare.disabled=true;try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner:ownerFor(container),action:'repair-hestia-preview',finding_id:container.dataset.finding,name:select.value})});const result=await response.json();if(!result.ok)throw new Error(result.error);location.reload();}catch(error){status.textContent=error.message;prepare.disabled=false;}});
 });
 scope.querySelectorAll('.cs-repair-review').forEach(button=>{if(button.dataset.reviewBound)return;button.dataset.reviewBound='true';button.addEventListener('click',async()=>{
  const output=button.nextElementSibling;button.disabled=true;
  try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner:ownerFor(button),action:'repair-plan',plan_id:button.dataset.plan})});const result=await response.json();if(!result.ok)throw new Error(result.error);const repair=result.repair;output.textContent=repair.metadata.preview.diff+(repair.metadata.preview.truncated?'\n[Preview truncated]':'');const apply=button.closest('article').querySelector('.cs-repair-apply');if(apply)apply.disabled=repair.status!=='ready'||!websitePermissions[apply.dataset.capability];}
  catch(error){output.textContent=error.message;}finally{button.disabled=false;}
 });});
 }
 bindReviewRows();
 document.addEventListener('clamshield-review-rows',event=>{prepareReviewControls(event.detail);bindReviewRows(event.detail);});
 document.getElementById('cs-owner')?.addEventListener('change',e=>{const url=new URL(location.href);if(e.target.value){url.searchParams.set('owner',e.target.value);url.searchParams.delete('scope');}else{url.searchParams.delete('owner');url.searchParams.set('scope','server');}url.searchParams.delete('scan_scope');location.href=url.href;});
 document.getElementById('cs-rule-source')?.addEventListener('submit',async event=>{event.preventDefault();const source=Object.fromEntries(new FormData(event.target));try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'rules-source-save',apply:'true',source:JSON.stringify(source)})});const result=await response.json();if(!result.ok)throw new Error(result.error);location.reload();}catch(error){document.getElementById('cs-message').textContent=error.message;}});
 let catalogOffset=0,catalogSearch='';
 async function catalogPage(reset){const body=document.getElementById('cs-catalog-body'),status=document.getElementById('cs-catalog-status'),more=document.getElementById('cs-catalog-more');if(reset){body.replaceChildren();catalogOffset=0;}try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'rules-catalog',search:catalogSearch,offset:String(catalogOffset)})});const result=await response.json();if(!result.ok)throw new Error(result.error);status.textContent=result.total+' rules · '+(result.generation||'Build a candidate to create its catalog');for(const rule of result.rules){const row=document.createElement('tr');for(const value of [rule.name+'\n'+rule.source_id+' · '+(rule.source.version||''),'Source: '+rule.source_id+' · '+(rule.source.version||'')+'\nTags: '+(rule.tags||[]).join(', ')+'\nDependencies: '+(rule.dependencies||[]).join(', ')]){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}const cell=document.createElement('td'),button=Object.assign(document.createElement('button'),{className:'button'});button.textContent=rule.selected?'Disable rule':'Enable rule';button.addEventListener('click',async()=>{button.disabled=true;try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'rules-rule-toggle',apply:'true',rule_id:rule.id,enabled:String(!rule.selected)})});const result=await response.json();if(!result.ok)throw new Error(result.error);location.reload();}catch(error){status.textContent=error.message;button.disabled=false;}});const stateLabel=document.createElement('small');stateLabel.textContent=(rule.enabled?'Compiled: enabled':'Compiled: disabled')+(rule.selected!==rule.enabled?' · selection changed':'');cell.append(stateLabel,document.createElement('br'),button);if(rule.selected){const cascade=Object.assign(document.createElement('button'),{className:'button'});cascade.textContent='Disable with referencing rules';cascade.addEventListener('click',async()=>{cascade.disabled=true;try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'rules-rule-toggle',apply:'true',rule_id:rule.id,enabled:'false',cascade:'true'})});const result=await response.json();if(!result.ok)throw new Error(result.error);location.reload();}catch(error){status.textContent=error.message;cascade.disabled=false;}});cell.append(cascade);}row.append(cell);body.append(row);}more.hidden=result.next_offset===null;catalogOffset=result.next_offset??0;}catch(error){status.textContent=error.message;}}
 document.getElementById('cs-rule-catalog')?.addEventListener('submit',event=>{event.preventDefault();catalogSearch=new FormData(event.target).get('search');catalogPage(true);});document.getElementById('cs-catalog-more')?.addEventListener('click',()=>catalogPage(false));
 function showOverrides(){const list=document.getElementById('cs-override-list');if(!list)return;const search=document.getElementById('cs-override-search').value.toLowerCase(),matches=ruleOverrides.filter(id=>id.toLowerCase().includes(search));list.replaceChildren();const count=document.createElement('p');count.textContent=matches.length+' matching overrides · showing up to 100';list.append(count);for(const id of matches.slice(0,100)){const row=document.createElement('p'),label=document.createElement('span'),button=Object.assign(document.createElement('button'),{className:'button'});label.textContent=id+' ';button.textContent='Clear override';button.addEventListener('click',async()=>{button.disabled=true;try{const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'rules-rule-toggle',apply:'true',rule_id:id,enabled:'true'})});const result=await response.json();if(!result.ok)throw new Error(result.error);location.reload();}catch(error){document.getElementById('cs-message').textContent=error.message;button.disabled=false;}});row.append(label,button);list.append(row);}}
 document.getElementById('cs-override-search')?.addEventListener('input',showOverrides);showOverrides();
 document.addEventListener('click',async event=>{const button=event.target.closest('button[data-action]');if(!button||button.disabled)return;
  button.disabled=true;const message=document.getElementById('cs-message');message.textContent='Working...';
  const body=new URLSearchParams({token,owner:ownerFor(button),...button.dataset});
  if(button.dataset.pathInput) body.set('path',document.getElementById(button.dataset.pathInput).value);
  try{const response=await fetch(location.pathname,{method:'POST',body,credentials:'same-origin'});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Operation failed');location.reload();}
  catch(error){message.textContent=error.message;message.className='error';button.disabled=false;}
 });
 document.querySelectorAll('.cs-policy').forEach(form=>form.addEventListener('submit',async event=>{
  event.preventDefault();const data=new FormData(form);const policy={watch:data.has('watch'),frequency:data.get('frequency'),time:data.get('time'),timezone:data.get('timezone'),weekday:Number(data.get('weekday')),monthday:Number(data.get('monthday'))};
  const message=document.getElementById('cs-message');message.textContent='Saving policy...';
  try{const response=await fetch(location.pathname,{method:'POST',body:new URLSearchParams({token,owner:ownerFor(form),action:form.dataset.saveAction||'policy-save',scope:form.dataset.scope||'site',domain:form.dataset.domain||'',policy:JSON.stringify(policy)}),credentials:'same-origin'});const result=await response.json();if(!result.ok)throw new Error(result.error);message.textContent='Policy saved.';}catch(error){message.textContent=error.message;}
 }));
 async function saveForm(fields){const message=document.getElementById('cs-message');message.textContent='Saving...';try{const response=await fetch(location.pathname,{method:'POST',body:new URLSearchParams({token,owner,...fields}),credentials:'same-origin'});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Operation failed');message.textContent='Saved. Activate the selected data when ready.';}catch(error){message.textContent=error.message;message.className='error';}}
 const providerRecommendations=<?=json_encode($providers['recommended']??new stdClass(),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 document.getElementById('cs-provider-recommended')?.addEventListener('click',()=>{
  const form=document.getElementById('cs-providers'),preset=providerRecommendations[form.elements.si_plan.value];if(!preset)return;
  for(const [provider,prefix] of [['securiteinfo','si'],['sanesecurity','sane']])for(const profile of ['website','mail','shared']){
   const selected=new Set(profile==='shared'?[...preset[provider].website_databases,...preset[provider].mail_databases]:preset[provider][profile+'_databases']);
   for(const input of form.querySelectorAll('input[name="'+prefix+'_'+profile+'_databases"]'))input.checked=selected.has(input.value);
  }
  for(const details of form.querySelectorAll('details'))details.open=true;
  form.dispatchEvent(new Event('change',{bubbles:true}));
  document.getElementById('cs-provider-recommended-status').textContent='Recommended selections applied to this form. Review and save provider settings; provider switches, account key and update intervals are unchanged.';
 });
 <?php readfile(__DIR__.'/provider_settings.js'); ?>
 document.getElementById('cs-local-signatures')?.addEventListener('submit',event=>{event.preventDefault();const f=new FormData(event.target);saveForm({action:'signature-local-save',name:f.get('name'),content:f.get('content')});});
})();
</script>

<script><?php readfile(__DIR__.'/review.js'); ?></script>
