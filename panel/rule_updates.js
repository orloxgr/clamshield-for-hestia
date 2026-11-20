/* Managed by clamshield; download/build never implies active rules. */
(() => {
  'use strict';
  const form=document.getElementById('cs-forge-install');if(!form)return;
  const button=form.querySelector('button'),status=document.getElementById('cs-forge-status');
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(button.disabled)return;button.disabled=true;
    let queued=false;const profile=form.elements.namedItem('profile').value;
    status.textContent='Queuing '+profile+' rules for download and validation…';
    try{
      const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({
        token:form.dataset.token,owner:form.dataset.owner,action:'rules-update',profile
      })});
      const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Rule update could not be queued');
      queued=true;status.textContent='Task '+result.task_id+' queued. Use Refresh rule status to follow its result. When complete, activate the validated candidate below. Active rules have not changed.';
      document.querySelectorAll('[data-action="rules-activate"]').forEach(control=>control.disabled=true);
    }catch(error){status.textContent=error.message;}
    finally{button.disabled=queued;}
  });
})();
