/* Managed by clamshield; enabled means verified transport and active defaults. */
(() => {
  'use strict';
  const root=document.getElementById('cs-mail'),button=document.getElementById('cs-mail-protection-toggle');if(!button)return;
  const output=document.getElementById('cs-mail-protection-status');
  let enabled=false,connected=false,pending=true,loading=false,submitting=false,timer=null,closed=false,changed=false;
  const visible=()=>!closed&&!document.querySelector('[data-page="mail"]').hidden&&!window.ClamShieldApiResponse.unavailable&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  function controls(){button.disabled=pending||submitting;button.textContent=pending||submitting?'Please wait…':(enabled?'Disable mail protection':'Enable mail protection');}
  async function api(action){
    const response=await window.ClamShieldApiResponse.fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action})});
    const result=await window.ClamShieldApiResponse.read(response,"Mail protection is unavailable");if(!response.ok||!result.ok)throw new Error(result.error||'Mail protection is unavailable');return result;
  }
  function show(value){
    const state=value.protection,task=value.latest;enabled=state.enabled;connected=state.connected;pending=value.pending;
    if(task&&['queued','running'].includes(task.status)){
      changed=true;output.textContent=task.action==='mail-protection-disable'?'Safely disabling mail protection…':({signatures:'Preparing antivirus signatures…',rules:'Preparing YARA rules…',preparing:'Preparing mail protection…',verifying:'Verifying mail protection…',policies:'Applying protection defaults…','native-policies':'Applying native mail delivery policies…'}[task.phase]||'Waiting to start…');
    }else if(pending)output.textContent='Finishing mail service work…';
    else if(task?.status==='failed')output.textContent='Could not complete the change: '+(task.error||'Please try again.');
    else if(state.error)output.textContent=state.error;
    else output.textContent=enabled?'Mail protection is enabled.':(connected?'Mail service is connected using custom domain policies.':'Mail protection is off.');
    controls();
    if(!pending&&task?.status==='completed'&&changed){changed=false;document.dispatchEvent(new CustomEvent('clamshield-mail-protection-changed'));}
  }
  async function refresh(){
    if(loading||submitting||!visible())return;stop();loading=true;
    try{const value=await api('mail-protection-status');if(!submitting&&!closed)show(value);}
    catch(error){if(!submitting&&!closed)output.textContent='Cannot check protection status: '+error.message;}
    finally{loading=false;if(visible()&&(pending||output.textContent.startsWith('Cannot check')))timer=setTimeout(refresh,5000);}
  }
  button.addEventListener('click',async()=>{
    if(button.disabled)return;stop();submitting=true;controls();output.textContent=enabled?'Disabling protection…':'Enabling protection…';
    try{await api(enabled?'mail-protection-disable':'mail-protection-enable');pending=true;changed=true;}
    catch(error){output.textContent=error.message;}
    finally{submitting=false;controls();if(pending)refresh();}
  });
  function visibility(){stop();if(visible())refresh();}
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;stop();});window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  controls();if(visible())refresh();
})();
