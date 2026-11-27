/* Managed by clamshield: independent provider choices and update schedules. */
(() => {
  'use strict';
  const activation=document.getElementById('cs-provider-activate-link');
  function refreshSavedState(providers){
    if(!providers)return;
    for(const row of document.querySelectorAll('#cs-provider-schedule tr[data-provider]')){
      const name=row.dataset.provider,config=providers[name],schedule=providers.schedule?.[name];if(!config||!schedule)continue;
      const record=providers.status?.[name]||{},enabled=config.enabled;
      row.querySelector('[data-provider-state]').textContent=(enabled?'Enabled · '+(record.state||'Not checked'):'Disabled')+(record.error?' · '+record.error:'');
      row.querySelector('[data-provider-next]').textContent=!enabled?'Disabled':schedule.next_allowed<=Date.now()/1000?'Due now':new Date(schedule.next_allowed*1000).toISOString().slice(0,19).replace('T',' ')+' UTC';
      row.querySelector('[data-provider-automatic-off]').hidden=providers.automatic;
      row.querySelector('[data-action="signatures-update"]').disabled=!enabled||schedule.next_allowed>Date.now()/1000;
      const counts=row.querySelector('[data-provider-counts]');
      if(counts)counts.textContent='Website: '+(config.website_databases||config.databases).length+' databases · Email: '+(config.mail_databases||config.databases).length+' databases';
    }
  }
  function bind(id,statusId,label,serialize,onSuccess){
    const form=document.getElementById(id);if(!form)return;
    const button=form.querySelector('button[type="submit"]'),message=document.getElementById(statusId);
    let saving=false;
    function feedback(text,error=false){message.textContent=text;message.className=error?'error':'';}
    function dirty(){if(!saving){feedback('Unsaved changes.');if(id==='cs-providers')activation.hidden=true;}}
    form.addEventListener('input',dirty);form.addEventListener('change',dirty);
    form.addEventListener('submit',async event=>{
      event.preventDefault();if(saving||!form.reportValidity())return;
      const providers=serialize(new FormData(form));
      const controls=[...form.querySelectorAll('button,input,select,textarea')].map(control=>[control,control.disabled]);
      const controller=new AbortController();let timedOut=false,confirmed=null;
      const timer=setTimeout(()=>{timedOut=true;controller.abort();},30000);
      saving=true;form.setAttribute('aria-busy','true');if(id==='cs-providers')activation.hidden=true;
      for(const [control] of controls)control.disabled=true;
      button.textContent='Saving…';feedback('Saving '+label+'…');
      try{
        const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',signal:controller.signal,
          body:new URLSearchParams({token,owner,action:'providers-save',providers:JSON.stringify(providers)})});
        const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Operation failed');
        confirmed=result;
        feedback(onSuccess(form,result));
      }catch(error){
        feedback(timedOut?'Save confirmation timed out. Reload to check whether the settings were saved, or retry.':
          'Could not confirm the save: '+error.message,true);
      }finally{
        clearTimeout(timer);saving=false;form.setAttribute('aria-busy','false');
        for(const [control,disabled] of controls)control.disabled=disabled;
        button.textContent=id==='cs-providers'?'Save provider settings':'Save update schedule';
        refreshSavedState(confirmed?.providers);
      }
    });
  }
  bind('cs-providers','cs-provider-save-status','provider settings',f=>({
    securiteinfo:{enabled:f.has('si_enabled'),plan:f.get('si_plan'),key:f.get('si_key'),
      website_databases:f.getAll('si_website_databases'),mail_databases:f.getAll('si_mail_databases'),shared_databases:f.getAll('si_shared_databases')},
    sanesecurity:{enabled:f.has('sane_enabled'),website_databases:f.getAll('sane_website_databases'),mail_databases:f.getAll('sane_mail_databases'),shared_databases:f.getAll('sane_shared_databases')},
    local:{enabled:f.has('local_enabled')}
  }),(form,result)=>{
    activation.hidden=false;const key=form.elements.si_key;
    if(key.value||result.providers?.securiteinfo?.has_key){key.value='';key.placeholder='Saved; leave empty to keep';}
    document.getElementById('cs-provider-recommended-status').textContent='Provider selections saved.';
    return 'Provider settings saved. To apply database changes, update signature databases.';
  });
  bind('cs-provider-update-settings','cs-provider-update-save-status','update schedule',f=>({
    automatic:f.has('automatic'),official:{interval_minutes:Number(f.get('official_interval_minutes'))},
    securiteinfo:{interval_minutes:Number(f.get('securiteinfo_interval_minutes'))},
    sanesecurity:{interval_minutes:Number(f.get('sanesecurity_interval_minutes'))}
  }),()=> 'Update schedule saved.');
})();
