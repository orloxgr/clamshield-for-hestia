/* Managed by clamshield; choosing a target never starts a scan. */
(() => {
  'use strict';
  const form=document.getElementById('cs-scan-target');if(!form)return;
  const owner=form.elements.owner,domain=form.elements.domain,path=form.elements.path;
  const start=document.getElementById('cs-scan-start'),all=document.getElementById('cs-scan-all');
  const status=document.getElementById('cs-scan-target-status'),progress=document.getElementById('cs-scan-target-progress');
  const options=document.getElementById('cs-scan-path-options'),allowed=form.dataset.allowed==='true',admin=form.dataset.admin==='true';
  let sites=JSON.parse(document.getElementById('cs-scan-initial-sites').textContent),serial=0,loading=false,busy=false,failed=false;
  function controls(){
    owner.disabled=!allowed||!admin||busy;domain.disabled=!allowed||loading||busy||failed||!owner.value||!sites.some(site=>!site.suspended);
    if(domain.options.length)domain.options[0].text=loading?'Loading websites…':failed?'Websites unavailable':!owner.value?'All websites on this server':sites.some(site=>!site.suspended)?'All websites in this account':'No active websites';
    start.disabled=!allowed||loading||busy||failed||(!!owner.value&&domain.disabled);start.dataset.scope=!owner.value?'server':(domain.value?'site':'account');if(all)all.disabled=!allowed||loading||busy||failed;
    options.hidden=!domain.value;path.disabled=!allowed||loading||busy||!domain.value;
  }
  function populate(values){
    sites=values;domain.replaceChildren();
    domain.append(new Option(!owner.value?'All websites on this server':(sites.some(site=>!site.suspended)?'All websites in this account':'No active websites'),''));
    for(const site of sites){const option=new Option(site.domain+(site.suspended?' (suspended)':''),site.domain);option.disabled=site.suspended;domain.append(option);}
    path.value='';controls();
  }
  async function api(action,account,values={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:form.dataset.token,owner:account,action,...values})});
    return window.ClamShieldApiResponse.read(response,'Scan request failed');
  }
  owner.addEventListener('change',async()=>{
    const version=++serial,account=owner.value;failed=false;if(!account){loading=false;populate([]);status.textContent='All active websites across all accounts.';progress.hidden=true;return;}loading=true;sites=[];populate([]);status.textContent='Loading websites…';progress.hidden=true;
    try{const result=await api('scan-targets',account);if(version===serial){populate(result.sites);status.textContent=result.sites.some(site=>!site.suspended)?'':'No active websites in this account.';}}
    catch(error){if(version===serial){failed=true;window.ClamShieldApiResponse.showError(status,error);}}
    finally{if(version===serial){loading=false;controls();}}
  });
  domain.addEventListener('change',()=>{path.value='';progress.hidden=true;controls();});
  async function scan(server=false){
    if(!allowed||busy||loading||(server?!admin:start.disabled))return;
    busy=true;controls();progress.hidden=true;status.textContent='Queuing scans…';
    server=server||!owner.value;const account=owner.value||form.dataset.actorOwner,scope=server?'server':(domain.value?'site':'account');
    const values=scope==='site'?{scope,domain:domain.value,path:path.value}:{scope};
    try{const result=await api('scan',account,values);status.textContent='Queued '+result.jobs.length+' website scan(s).';
      const url=new URL(location.href);if(server){url.searchParams.delete('owner');url.searchParams.set('scope','server');}else{url.searchParams.set('owner',account);url.searchParams.delete('scope');}url.searchParams.set('scan_scope',server?'server':'account');url.hash='scan/jobs';progress.href=url.href;progress.hidden=false;
    }catch(error){if(error.reloadPanel)failed=true;window.ClamShieldApiResponse.showError(status,error);}
    finally{busy=false;controls();}
  }
  form.addEventListener('submit',event=>{event.preventDefault();scan();});all?.addEventListener('click',()=>scan(true));controls();
})();
