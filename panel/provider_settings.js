/* Managed by clamshield: keep save feedback beside the provider controls. */
(() => {
  'use strict';
  const form=document.getElementById('cs-providers');if(!form)return;
  const button=form.querySelector('button[type="submit"]'),message=document.getElementById('cs-provider-save-status');
  const activation=document.getElementById('cs-provider-activate-link');
  let saving=false;
  function feedback(text,error=false){message.textContent=text;message.className=error?'error':'';}
  function dirty(){if(!saving){feedback('Unsaved changes.');activation.hidden=true;}}
  form.addEventListener('input',dirty);form.addEventListener('change',dirty);
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(saving)return;
    const f=new FormData(form),providers={automatic:f.has('automatic'),
      official:{interval_minutes:Number(f.get('official_interval_minutes'))},
      securiteinfo:{enabled:f.has('si_enabled'),plan:f.get('si_plan'),key:f.get('si_key'),
        website_databases:f.getAll('si_website_databases'),mail_databases:f.getAll('si_mail_databases'),interval_minutes:Number(f.get('securiteinfo_interval_minutes'))},
      sanesecurity:{enabled:f.has('sane_enabled'),website_databases:f.getAll('sane_website_databases'),
        mail_databases:f.getAll('sane_mail_databases'),interval_minutes:Number(f.get('sanesecurity_interval_minutes'))},
      local:{enabled:f.has('local_enabled')}};
    const controls=[...form.querySelectorAll('button,input,select,textarea')].map(control=>[control,control.disabled]);
    const controller=new AbortController();let timedOut=false;
    const timer=setTimeout(()=>{timedOut=true;controller.abort();},30000);
    saving=true;form.setAttribute('aria-busy','true');activation.hidden=true;
    for(const [control] of controls)control.disabled=true;
    button.textContent='Saving…';feedback('Saving provider settings…');
    try{
      const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',signal:controller.signal,
        body:new URLSearchParams({token,owner,action:'providers-save',providers:JSON.stringify(providers)})});
      const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Operation failed');
      feedback('Provider settings saved. To apply database changes, update signature databases.');activation.hidden=false;
      const key=form.elements.si_key;
      if(key.value||result.providers?.securiteinfo?.has_key){key.value='';key.placeholder='Saved; leave empty to keep';}
      document.getElementById('cs-provider-recommended-status').textContent='Provider selections saved.';
    }catch(error){
      feedback(timedOut?'Save confirmation timed out. Reload to check whether the settings were saved, or retry.':
        'Could not confirm the save: '+error.message,true);
    }finally{
      clearTimeout(timer);saving=false;form.setAttribute('aria-busy','false');
      for(const [control,disabled] of controls)control.disabled=disabled;
      button.textContent='Save provider settings';
    }
  });
})();
