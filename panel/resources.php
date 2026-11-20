<?php // Managed by clamshield
if (!$data['context']['admin']) return;
$resources=$data['resources']; $resource_labels=['cpu_percent'=>'CPU percentage','memory_mib'=>'Memory MiB','io_weight'=>'I/O weight']; ?>
<section data-page="resources" hidden><h2>Scanner resources</h2>
<p>Website scanning, email scanning and signature maintenance have separate service budgets. CPU 100% is one core. Memory limits are upper bounds, not reservations. I/O weight sets relative priority when storage is busy.</p>
<?php if(isset($resources['error'])): ?><p class="alert alert-danger"><?=$escape($resources['error'])?></p>
<?php else: ?>
<p>Server RAM: <?=$escape(round(($resources['memory']['MemTotal']??0)/1048576))?> MiB · Available now: <?=$escape(round(($resources['memory']['MemAvailable']??0)/1048576))?> MiB</p>
<?php if($resources['recovery_pending']): ?><p class="alert alert-danger">A resource or website-engine transition needs recovery. New website scans wait until it is resolved.</p><?php endif ?>
<form id="cs-resources"><div class="scroll"><table><thead><tr><th>Service</th><th>CPU %</th><th>Memory MiB</th><th>I/O weight</th><th>Current state</th></tr></thead><tbody>
<?php foreach($resources['policy'] as $key=>$limits): $service=$resources['services'][$key]; ?><tr><td><?=$escape($service['title'])?></td>
<?php foreach(['cpu_percent'=>[1,10000],'memory_mib'=>[128,1048576],'io_weight'=>[1,10000]] as $field=>$range): ?><td><input class="form-control" style="width:7em" type="number" step="1" required min="<?=$range[0]?>" max="<?=$range[1]?>" name="<?=$escape($key.'.'.$field)?>" aria-label="<?=$escape($service['title'].' '.$resource_labels[$field])?>" value="<?=$escape($limits[$field])?>"></td><?php endforeach ?>
<td><?=$service['active']?'Running':'Stopped'?><?php if($service['active']): ?><br>Using <?=$escape(round(($service['memory_current']??0)/1048576))?> MiB<?php endif ?><br><small>Effective CPU: <?=$escape($service['cpu_percent']??'unlimited')?>% · Memory: <?=$service['memory_bytes']===null?'unlimited':$escape(round($service['memory_bytes']/1048576)).' MiB'?> · I/O: <?=$escape($service['io_weight']??'system default')?></small></td></tr><?php endforeach ?>
</tbody></table></div><button class="button" type="submit">Apply resource limits</button><p id="cs-resources-result" role="status" aria-live="polite"></p></form>
<p>Limits apply live and persist across restarts. A change waits for the current website job. Memory limits below current usage plus headroom are refused. See maintenance history for the result.</p>
<h3>Website ClamAV engine</h3><p>Activate selected databases in Signature providers before starting the website engine. Starting verifies the active signature data; YARA rule configuration remains visible in the dashboard.</p>
<p>Saved startup choice: <?=$resources['website_policy']===null?'Default':($resources['website_policy']['enabled']?'Enabled':'Stopped')?>. Your choice persists through signature and plugin updates.</p>
<button class="button" data-action="website-engine-start">Start website ClamAV</button><button class="button" data-action="website-engine-stop">Stop website ClamAV</button>
<p>Email services follow the protection controls in Email. Stopping website ClamAV leaves YARA scanning available and reports incomplete ClamAV coverage.</p>
<?php endif ?>
<button class="button" data-action="resources-recover">Recover resource or engine transition</button>
<h3>Resource control history</h3><div class="scroll"><table><thead><tr><th>Time UTC</th><th>Action</th><th>Status</th><th>Requested limits / result</th></tr></thead><tbody>
<?php $resource_actions=['resources-save'=>'Apply resource limits','website-engine-start'=>'Start website ClamAV','website-engine-stop'=>'Stop website ClamAV','resources-recover'=>'Recover controls']; foreach($data['maintenance'] as $task): if(!isset($resource_actions[$task['action']])) continue; ?><tr><td><?=$escape(gmdate('Y-m-d H:i:s',(int)$task['created']))?></td><td><?=$escape($resource_actions[$task['action']])?></td><td><?=$escape($task['status'])?></td><td><?=$escape($task['error']??($task['result']['revision']??''))?><?php if(isset($task['payload']['policy'])): ?><details><summary>Requested limits</summary><pre style="white-space:pre-wrap"><?=$escape(json_encode($task['payload']['policy'],JSON_PRETTY_PRINT))?></pre></details><?php endif ?></td></tr><?php endforeach ?>
</tbody></table></div>
</section>
<script>
(() => {'use strict';const form=document.getElementById('cs-resources');if(!form)return;
 const token=<?=json_encode($_SESSION['token']??'',JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>,owner=<?=json_encode($data['context']['owner'],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?>;
 form.addEventListener('submit',async event=>{event.preventDefault();const button=form.querySelector('button'),output=document.getElementById('cs-resources-result');button.disabled=true;output.textContent='Queuing resource limits…';try{const policy={};for(const [name,value] of new FormData(form)){const [service,field]=name.split('.');(policy[service]??={})[field]=Number(value);}const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner,action:'resources-save',policy:JSON.stringify(policy)})});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Resource update failed');output.textContent='Task '+result.task_id+' queued. Refresh after maintenance completes to see effective limits.';}catch(error){output.textContent=error.message;}finally{button.disabled=false;}});
})();
</script>
