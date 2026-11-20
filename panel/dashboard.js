/* Managed by clamshield; start the owned website engine through the admin queue. */
(() => {
  'use strict';
  const root=document.getElementById('cs-dashboard'),button=document.getElementById('cs-dashboard-clamav-enable');
  if(!button)return;
  const version=document.getElementById('cs-dashboard-clamav-version'),output=document.getElementById('cs-dashboard-clamav-status');
  let pending=button.dataset.pending==='true',available=button.hidden,loading=false,submitting=false,timer=null,closed=false,phase='queued';
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  function controls(){button.hidden=available&&!pending;button.disabled=pending||submitting||loading;button.textContent=submitting?'Queuing…':pending?({'queued':'Queued…','waiting-scan':'Waiting for scan…',starting:'Starting…',stopping:'Stopping…',verifying:'Checking…'}[phase]||'Working…'):'Enable';}
  async function api(action){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:button.dataset.token,owner:button.dataset.owner,action})});
    const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Website ClamAV is unavailable');return value;
  }
  async function refresh(){
    if(loading||submitting||!visible())return;stop();loading=true;controls();
    try{
      const value=await api('website-engine-status');if(closed)return;
      available=value.engine.available;pending=value.pending;version.textContent=available?value.engine.version:'ClamAV is unavailable';
      const task=value.latest;
      phase=task?.status==='queued'?'queued':task?.phase||'starting';
      if(pending){
        if(phase==='queued')output.textContent=value.blocking_action?.startsWith('signatures-')?'Startup queued: waiting for the current signature update to finish.':'Service change queued: waiting for maintenance to start it.';
        else output.textContent=({'waiting-scan':'Waiting for the current file to finish. A full scan will be queued again after the service change.',starting:'Starting website ClamAV…',stopping:'Stopping website ClamAV…',verifying:'Checking loaded ClamAV signatures…'}[task?.phase]||'Starting website ClamAV and checking signatures…');
      }
      else if(task?.status==='failed')output.textContent='Could not complete the change: '+(task.error||'Please try again.');
      else output.textContent=available?'Website ClamAV is running.':'Enable website ClamAV to scan with its signatures.';
    }catch(error){if(!closed)output.textContent='Cannot check website ClamAV: '+error.message;}
    finally{loading=false;controls();if(visible()&&pending)timer=setTimeout(refresh,3000);}
  }
  button.addEventListener('click',async()=>{
    if(button.disabled)return;stop();submitting=true;controls();output.textContent='Queuing website ClamAV startup…';
    try{await api('website-engine-start');pending=true;phase='queued';output.textContent='Website ClamAV startup queued…';}
    catch(error){output.textContent=error.message;}
    finally{submitting=false;controls();if(pending)refresh();}
  });
  function visibility(){stop();if(visible()&&pending)refresh();}
  document.addEventListener('clamshield-engine-observed',event=>{available=event.detail.available;version.textContent=available?event.detail.version:'ClamAV is unavailable';controls();});
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;stop();});
  window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  controls();
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',visibility,{once:true});else visibility();
})();
