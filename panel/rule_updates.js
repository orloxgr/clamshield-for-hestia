/* Managed by clamshield; one asynchronous download/check/activate operation. */
(() => {
  'use strict';
  const form=document.getElementById('cs-forge-install');if(!form)return;
  const root=form.closest('[data-page]'),button=form.querySelector('button'),profile=form.elements.namedItem('profile');
  const status=document.getElementById('cs-forge-status'),active=document.getElementById('cs-rules-active');
  let configured=form.dataset.configured==='true',pending=button.disabled,submitting=false,inFlight=false,timer=null,closed=false;
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  function controls(){button.disabled=profile.disabled=pending||submitting;button.textContent=pending||submitting?'Installing…':(configured?'Update rules':'Install rules');}
  async function request(action,values={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:form.dataset.token,owner:form.dataset.owner,action,...values})});
    const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Rule service is unavailable');return result;
  }
  function show(value){
    pending=value.pending;configured=value.active.configured;
    active.textContent=configured?'Active: '+(value.active.profile||'Custom')+' · '+(value.active.enabled??value.active.rules??'Unknown')+' rules · '+(value.active.version||'Custom'):'YARA rules are not installed.';
    document.getElementById('cs-yara-warning')?.toggleAttribute('hidden',configured);
    const dashboard=document.getElementById('cs-dashboard-yara-status');
    if(dashboard){
      const built=Number.isFinite(value.active.created)?new Date(value.active.created*1000).toISOString().slice(0,19).replace('T',' ')+' UTC':'Build time unavailable';
      dashboard.textContent=configured?(value.active.profile||'Custom')+' · '+(value.active.enabled??value.active.rules??'Unknown')+' rules · '+built:'Not installed';
    }
    const task=value.latest,working=task&&['queued','running'].includes(task.status);
    if(working){
      status.textContent=task.status==='queued'?'Waiting to start…':({downloading:'Downloading rules…',checking:'Checking rules…',activating:'Activating rules…'}[task.phase]||'Installing rules…');
      if(['core','extended','full'].includes(task.profile))profile.value=task.profile;
    }else if(pending)status.textContent='Finishing other rule work…';
    else if(task?.status==='failed')status.textContent='Installation failed: '+(task.error||'Please try again.')+(configured?' Current active rules are shown above.':'');
    else if(task?.status==='completed'&&task.activated&&configured&&task.generation===value.active.generation)status.textContent='Rules installed and active.';
    else status.textContent=configured?'YARA rules are active.':'Choose a profile and click Install rules.';
    controls();
  }
  async function refresh(){
    if(inFlight||submitting||!visible())return;stop();inFlight=true;
    try{const value=await request('rules-status');if(!submitting&&!closed)show(value);}
    catch(error){if(!submitting&&!closed)status.textContent='Cannot refresh rule status: '+error.message;}
    finally{inFlight=false;if(visible()&&(pending||status.textContent.startsWith('Cannot refresh')))timer=setTimeout(refresh,3000);}
  }
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(button.disabled)return;stop();submitting=true;controls();status.textContent='Starting installation…';
    try{await request('rules-install',{profile:profile.value});pending=true;status.textContent='Waiting to start…';
      document.querySelectorAll('[data-action="rules-activate"]').forEach(control=>control.disabled=true);
    }catch(error){status.textContent='Could not start installation: '+error.message;}
    finally{submitting=false;controls();if(pending)refresh();}
  });
  function visibility(){stop();if(visible())refresh();}
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;stop();});
  window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  controls();if(visible())refresh();
})();
