/* Managed by clamshield; a check probes readiness without changing service state. */
(() => {
  'use strict';
  const button=document.getElementById('cs-readiness-check'),engineButton=document.getElementById('cs-dashboard-clamav-enable');
  if(!button||!engineButton)return;
  const notice=document.getElementById('cs-website-coverage'),message=document.getElementById('cs-readiness-message'),checked=document.getElementById('cs-readiness-time');
  button.addEventListener('click',async()=>{
    if(button.disabled)return;button.disabled=true;button.textContent='Checking…';
    message.textContent='Checking website engines and active scanning data…';
    document.querySelectorAll('[data-readiness-action]').forEach(link=>link.hidden=true);
    try{
      const response=await window.ClamShieldApiResponse.fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:engineButton.dataset.token,owner:engineButton.dataset.owner,action:'website-readiness-check'})});
      const value=await window.ClamShieldApiResponse.read(response,"Readiness check failed");if(!response.ok||!value.ok)throw new Error(value.error||'Readiness check failed');
      const coverage=value.coverage;
      message.textContent=value.busy?'Readiness verification waits for an active scan or update.':coverage.message;
      notice.className='notice alert '+(coverage.state==='healthy'?'alert-success':value.busy||coverage.state==='checking'?'alert-info':'alert-warning');
      checked.replaceChildren();checked.hidden=coverage.checked===null;
      if(!checked.hidden)checked.append(document.createElement('br'),'Last checked: '+new Date(coverage.checked*1000).toISOString().replace('T',' ').replace(/\.\d{3}Z$/,' UTC'));
      document.querySelectorAll('[data-readiness-action]').forEach(link=>link.hidden=!(value.actions||[]).includes(link.dataset.readinessAction));
      document.dispatchEvent(new CustomEvent('clamshield-engine-observed',{detail:value.engine}));
    }catch(error){message.textContent='Could not check website readiness: '+error.message;notice.className='notice alert alert-warning';}
    finally{button.disabled=false;button.textContent='Check now';}
  });
})();
