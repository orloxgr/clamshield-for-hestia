<?php // Managed by clamshield
if (!$data['context']['admin']) return;
$sa = $data['spamassassin']; ?>
<section data-page="spamassassin" hidden><h2>SpamAssassin</h2>
<p>Server settings for the ClamShield mail scanner. Domain and mailbox policies in Email choose what to do with the resulting score.</p>
<?php if(isset($sa['error'])): ?><p class="alert alert-danger"><?=$escape($sa['error'])?></p>
<?php else: $sap=$sa['policy']; ?>
<p>ClamShield daemon: <strong><?=$sa['service_active']?'Running':'Stopped'?></strong>
<?php if($sa['local_mode']===true): ?> · Local tests only: DNS blocklists are not queried.<?php endif ?></p>
<?php if($sa['configured'] && $sa['service_active']): ?><p><?=$sa['daemon_verified']?'Current daemon configuration verified':'Current daemon needs a configuration check before its score can be used'?></p><?php endif ?>
<p><?=$sa['configured']?'Validated configuration applied':'Initial settings; no UI activation recorded'?><?php if($sa['applied_at']): ?> · <?=$escape(gmdate('Y-m-d H:i:s',(int)$sa['applied_at']))?> UTC<?php endif ?></p>
<?php if($sa['recovery_pending']): ?><p class="alert alert-danger">An interrupted activation requires recovery. Mail scans will defer until recovery finishes.</p><?php endif ?>
<form id="cs-spamassassin">
<label>Required spam score <input class="form-control" type="number" name="required_score" min="0.1" max="100" step="0.1" required value="<?=$escape($sap['required_score'])?>"></label>
<p>This is SpamAssassin's own classification threshold. The domain's spam and high-spam thresholds apply to its final score, including additional signature weights.</p>
<p><label><input type="checkbox" name="rbl_enabled" <?=$sap['rbl_enabled']?'checked':''?>> Enable IP/sender DNS blocklist checks (RBL)</label></p>
<p><label><input type="checkbox" name="uribl_enabled" <?=$sap['uribl_enabled']?'checked':''?>> Enable URI DNS blocklist checks (URIBL)</label></p>
<p>DNS checks use the installed SpamAssassin rules and the server resolver. Public lists may return blocked-query or rate-limit responses; configured checks do not prove access to a provider.</p>
<p><label>Disable DNS zones (one per line)<br><textarea class="form-control" name="blocked_zones" rows="5" cols="48" placeholder="zen.spamhaus.org"><?=$escape(implode("\n",$sap['blocked_zones']))?></textarea></label></p>
<p>Disabling a zone applies a DNS query restriction to it and its subdomains, subject to more specific restrictions already present in the native configuration.</p>
<p><label>Rule score overrides (one NAME=score per line)<br><textarea class="form-control" name="scores" rows="7" cols="48" placeholder="RULE_NAME=3.5"><?php foreach($sap['scores'] as $name=>$amount) echo $escape($name.'='.$amount)."\n"; ?></textarea></label></p>
<p>Only installed rules are accepted. A score of zero disables that rule. Remove a line to restore its installed score. Optional Pyzor, Razor2 and DCC checks are disabled pending configuration.</p>
<button type="submit" class="button">Validate and apply settings</button>
<p id="cs-sa-result" role="status" aria-live="polite"></p>
</form>
<p>Validation and application run in maintenance. A running ClamShield SpamAssassin daemon is restarted and checked; a stopped daemon stays stopped. Check maintenance history for the result.</p>
<button class="button" id="cs-sa-catalog" type="button">Load installed rule scores and DNS restrictions</button>
<label>Filter rules <input class="form-control" id="cs-sa-search" type="search" placeholder="Rule or description"></label>
<p id="cs-sa-catalog-status" role="status"></p>
<p>Installed scores are shown for local tests and network tests, with Bayes disabled. UI overrides replace both values when applied.</p>
<div class="scroll"><table><thead><tr><th>Rule</th><th>Local score</th><th>Network score</th><th>Description</th></tr></thead><tbody id="cs-sa-rules"></tbody></table></div>
<?php endif ?>
<h3 id="cs-sa-tasks" tabindex="-1">Configuration tasks</h3><button type="button" class="button" id="cs-sa-refresh-tasks">Refresh task status</button>
<div class="scroll"><table><thead><tr><th>Requested (UTC)</th><th>Status</th><th>Result</th></tr></thead><tbody>
<?php foreach(array_filter($data['maintenance']??[],static fn($task)=>$task['action']==='spamassassin-save') as $task): ?><tr><td><?=$escape(gmdate('Y-m-d H:i:s',(int)$task['created']))?></td><td><?=$escape($task['status'])?></td><td><?=$escape($task['error']??($task['result']['revision']??''))?></td></tr><?php endforeach ?>
</tbody></table></div>
</section>
<script>
(() => {'use strict';
 document.getElementById('cs-sa-refresh-tasks').addEventListener('click',()=>location.reload());
 const form=document.getElementById('cs-spamassassin');if(!form)return;
 const token=<?=json_encode($_SESSION['token']??'',JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 const owner=<?=json_encode($data['context']['owner'],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 async function request(fields){const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,...fields})});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Operation failed');return result;}
 form.addEventListener('submit',async event=>{event.preventDefault();const out=document.getElementById('cs-sa-result'),button=form.querySelector('button');button.disabled=true;out.textContent='Queuing validation…';
 try{const fields=new FormData(form),scores={};for(const line of fields.get('scores').split(/\r?\n/).map(s=>s.trim()).filter(Boolean)){const match=line.match(/^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(-?(?:\d+(?:\.\d+)?|\.\d+))$/);if(!match||Object.hasOwn(scores,match[1]))throw new Error('Use one unique RULE_NAME=score per line.');scores[match[1]]=Number(match[2]);}
 const policy={required_score:Number(fields.get('required_score')),rbl_enabled:fields.has('rbl_enabled'),uribl_enabled:fields.has('uribl_enabled'),blocked_zones:fields.get('blocked_zones').split(/\r?\n/).map(s=>s.trim()).filter(Boolean),scores};const result=await request({action:'spamassassin-save',policy:JSON.stringify(policy)});out.textContent='Validation queued. Task '+result.task_id+'. Refresh after maintenance finishes to see applied settings.';
 }catch(error){out.textContent=error.message;}finally{button.disabled=false;}});
 let rules=[];function show(){const filter=document.getElementById('cs-sa-search').value.toLowerCase(),body=document.getElementById('cs-sa-rules');body.replaceChildren();const matches=rules.filter(rule=>(rule.name+' '+rule.description).toLowerCase().includes(filter));for(const rule of matches.slice(0,100)){const row=document.createElement('tr');for(const value of [rule.name,rule.score_local,rule.score_network,rule.description]){const cell=document.createElement('td');cell.textContent=String(value);row.append(cell);}body.append(row);}}
 document.getElementById('cs-sa-search').addEventListener('input',show);
 document.getElementById('cs-sa-catalog').addEventListener('click',async event=>{const button=event.currentTarget,out=document.getElementById('cs-sa-catalog-status');button.disabled=true;out.textContent='Reading the installed rule set…';try{const result=await request({action:'spamassassin-catalog'});rules=result.rules;out.textContent='SpamAssassin '+result.version+' · '+rules.length+' installed rules, showing up to 100. Native DNS restrictions: '+JSON.stringify(result.dns_query_blocked||{});show();}catch(error){out.textContent=error.message;}finally{button.disabled=false;}});
})();
</script>
