<?php // Managed by clamshield
if (!$data['context']['admin']) return;
$resources=$data['resources']; $native_clamav=$resources['native_clamav']??null; $resource_labels=['cpu_percent'=>'CPU percentage','memory_mib'=>'Memory MiB','io_weight'=>'I/O weight']; ?>
<section data-page="resources" hidden><h2>Scanner resources</h2>
<p>Website scanning, email scanning and signature maintenance have separate service budgets. CPU 100% is one core. Memory limits are upper bounds, not reservations. I/O weight sets relative priority when storage is busy.</p>
<?php if(isset($resources['error'])): ?><p class="alert alert-danger"><?=$escape($resources['error'])?></p>
<?php else: ?>
<p>Server RAM: <?=$escape(round(($resources['memory']['MemTotal']??0)/1048576))?> MiB · Available now: <?=$escape(round(($resources['memory']['MemAvailable']??0)/1048576))?> MiB</p>
<?php if($native_clamav): ?><h3>Native ClamAV — websites and email</h3>
<p><?=$native_clamav['active']?'Running':'Stopped'?> · One shared native engine</p>
<dl><?php foreach(['memory_current'=>'Service RAM now','memory_peak'=>'Service peak since start','rss_bytes'=>'Process resident memory (RSS)','pss_bytes'=>'Process proportional memory (PSS)'] as $key=>$title): ?><dt><?=$escape($title)?></dt><dd><?=isset($native_clamav[$key])?$escape(round($native_clamav[$key]/1048576)).' MiB':'Unavailable'?></dd><?php endforeach ?>
<dt>Configured service memory limit</dt><dd><?=$native_clamav['memory_bytes']===null?'Unlimited':$escape(round($native_clamav['memory_bytes']/1048576)).' MiB'?></dd></dl>
<p>The recorded peak includes this service since its last start. It is not a per-provider estimate. A database reload can temporarily increase memory usage.</p><?php endif ?>
<?php require __DIR__.'/signature_memory.php'; ?>
<?php if($resources['recovery_pending']): ?><p class="alert alert-danger">A resource or website-engine transition needs recovery. New website scans wait until it is resolved.</p><?php endif ?>
<form id="cs-resources"><div class="scroll"><table><thead><tr><th>Service</th><th>CPU %</th><th>Memory MiB</th><th>I/O weight</th><th>Current state</th></tr></thead><tbody>
<?php foreach($resources['policy'] as $key=>$limits): $service=$resources['services'][$key]; if($native_clamav&&in_array($key,['website_clamav','mail_clamav'],true)): ?><tr hidden><td colspan="5"><?php foreach($limits as $field=>$limit): ?><input type="hidden" name="<?=$escape($key.'.'.$field)?>" value="<?=$escape($limit)?>"><?php endforeach ?></td></tr><?php continue; endif; ?><tr><td><?=$escape($service['title'])?></td>
<?php foreach(['cpu_percent'=>[1,10000],'memory_mib'=>[128,1048576],'io_weight'=>[1,10000]] as $field=>$range): ?><td><input class="form-control" style="width:7em" type="number" step="1" required min="<?=$range[0]?>" max="<?=$range[1]?>" name="<?=$escape($key.'.'.$field)?>" aria-label="<?=$escape($service['title'].' '.$resource_labels[$field])?>" value="<?=$escape($limits[$field])?>"></td><?php endforeach ?>
<td><?=$service['active']?'Running':'Stopped'?><?php if($service['active']): ?><br>Using <?=$escape(round(($service['memory_current']??0)/1048576))?> MiB<?php endif ?><br><small>Effective CPU: <?=$escape($service['cpu_percent']??'unlimited')?>% · Memory: <?=$service['memory_bytes']===null?'unlimited':$escape(round($service['memory_bytes']/1048576)).' MiB'?> · I/O: <?=$escape($service['io_weight']??'system default')?></small></td></tr><?php endforeach ?>
</tbody></table></div><button class="button" type="submit">Apply resource limits</button><p id="cs-resources-result" role="status" aria-live="polite"></p></form>
<p>Limits apply live and persist across restarts. A change waits for the current website job. Memory limits below current usage plus headroom are refused. See maintenance history for the result.</p>
<h3><?=$native_clamav?'Website ClamAV scanning':'Website ClamAV engine'?></h3><p>Activate selected databases in Signature providers before enabling website scanning. Enabling verifies the active signature data; YARA rule configuration remains visible in the dashboard.</p>
<p>Saved startup choice: <?=$resources['website_policy']===null?'Default':($resources['website_policy']['enabled']?'Enabled':'Stopped')?>. Your choice persists through signature and plugin updates.</p>
<button class="button" data-action="website-engine-start"><?=$native_clamav?'Enable website ClamAV scanning':'Start website ClamAV'?></button><button class="button" data-action="website-engine-stop"><?=$native_clamav?'Disable website ClamAV scanning':'Stop website ClamAV'?></button>
<p><?=$native_clamav?'Disabling website ClamAV scanning leaves the native daemon running for email. YARA scanning remains available.':'Email services follow the protection controls in Email. Stopping website ClamAV leaves YARA scanning available and reports incomplete ClamAV coverage.'?></p>
<?php endif ?>
<button class="button" data-action="resources-recover">Recover resource or engine transition</button>
<p><a href="#review/update-history" data-tab="update-history" data-focus-id="cs-sa-tasks">View update history</a></p></section>
<script>
(() => {'use strict';const form=document.getElementById('cs-resources');if(!form)return;
 const token=<?=json_encode($_SESSION['token']??'',JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>,owner=<?=json_encode($data['context']['owner'],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 form.addEventListener('submit',async event=>{event.preventDefault();const button=form.querySelector('button'),output=document.getElementById('cs-resources-result');button.disabled=true;output.textContent='Queuing resource limits…';try{const policy={};for(const [name,value] of new FormData(form)){const [service,field]=name.split('.');(policy[service]??={})[field]=Number(value);}const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'resources-save',policy:JSON.stringify(policy)})});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Resource update failed');output.textContent='Task '+result.task_id+' queued. Refresh after maintenance completes to see effective limits.';}catch(error){output.textContent=error.message;}finally{button.disabled=false;}});
})();
</script>
