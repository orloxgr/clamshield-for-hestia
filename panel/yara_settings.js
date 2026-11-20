/* Managed by clamshield; saved settings are applied by the root maintenance queue. */
(() => {
  const root=document.getElementById('cs-yara-settings');if(!root)return;
  const status=document.getElementById('cs-yara-settings-status'),forms=[document.getElementById('cs-yara-scanning'),document.getElementById('cs-yara-hosting')];
  let pending=false,sending=false,reading=false,timer=null,closed=false;
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  function controls(){for(const form of forms)form.querySelector('button').disabled=pending||sending;}
  async function api(action,policy){const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...(policy?{policy:JSON.stringify(policy)}:{})})});const value=await response.json();if(!response.ok||!value.ok)throw Error(value.error||'YARA settings are unavailable');return value;}
  async function refresh(){
    stop();if(!visible()||reading||sending)return;reading=true;
    try{const value=await api('yara-settings-status');pending=value.pending;
      const task=value.task;if(pending)status.textContent='Applying YARA settings… Current rules remain in use until validation completes.';
      else if(task?.status==='failed')status.textContent='Settings were not applied: '+task.error;
      else if(task?.status==='completed')status.textContent='YARA settings applied.';
      controls();
    }catch(error){status.textContent=error.message;}
    finally{reading=false;if(visible()&&pending)timer=setTimeout(refresh,3000);}
  }
  for(const form of forms)form.addEventListener('submit',async event=>{
    event.preventDefault();if(pending||sending||!form.reportValidity())return;stop();sending=true;controls();status.textContent='Saving YARA settings…';
    const policy={};for(const input of form.querySelectorAll('input'))policy[input.name]=input.type==='checkbox'?input.checked:Number(input.value);
    try{await api(form.id==='cs-yara-scanning'?'yara-settings-save':'rules-options-save',policy);pending=true;}
    catch(error){status.textContent='Could not save settings: '+error.message;}
    finally{sending=false;controls();if(pending)refresh();}
  });
  document.addEventListener('clamshield-tab-change',()=>{stop();if(visible())refresh();});
  document.addEventListener('visibilitychange',()=>{stop();if(visible())refresh();});
  window.addEventListener('pagehide',()=>{closed=true;stop();});if(visible())refresh();
})();
