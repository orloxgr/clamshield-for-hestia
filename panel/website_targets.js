/* Managed by clamshield; shared selection never starts work. */
window.ClamShieldWebsiteTargets ||= function(form,{allowed,admin,bulk,owner:actorOwner,token,onChange=()=>{}}){
  const owner=form.elements.owner,domain=form.elements.domain,status=form.querySelector('[data-target-status]');
  const start=form.querySelector('[type=submit]'),all=form.querySelector('[data-target-all]');
  let sites=JSON.parse(form.querySelector('[data-target-sites]').textContent),serial=0,loading=false,busy=false,failed=false;
  function controls(){
    owner.disabled=!allowed||!admin||busy;domain.disabled=!allowed||busy||loading||!owner.value||failed||!sites.some(site=>!site.suspended);
    if(domain.options.length)domain.options[0].text=loading?'Loading websites…':failed?'Websites unavailable':!owner.value?(bulk?'All websites on this server':'Choose an account first'):sites.some(site=>!site.suspended)?(bulk?'All websites in this account':'Choose a website'):'No active websites';
    start.disabled=!allowed||busy||loading||failed||(bulk?(!!owner.value&&domain.disabled):!domain.value);
    if(all)all.disabled=!allowed||busy||loading||failed;
    const options=form.querySelector('[data-target-path-options]');if(options)options.hidden=!domain.value;
    if(form.elements.path)form.elements.path.disabled=!allowed||busy||loading||!domain.value;
  }
  function populate(values){
    sites=values;domain.replaceChildren();
    domain.append(new Option(!owner.value?(bulk?'All websites on this server':'Choose an account first'):(sites.some(site=>!site.suspended)?(bulk?'All websites in this account':'Choose a website'):'No active websites'),''));
    for(const site of sites){const option=new Option(site.domain+(site.suspended?' (suspended)':''),site.domain);option.disabled=site.suspended;domain.append(option);}
    if(form.elements.path)form.elements.path.value='';controls();onChange({owner:owner.value,domain:domain.value,sites});
  }
  owner.addEventListener('change',async()=>{
    const version=++serial,account=owner.value;failed=false;loading=!!account;populate([]);
    status.textContent=account?'Loading websites…':(bulk?'All active websites across all accounts.':'Choose an account, then a website to analyze.');
    if(!account)return;
    try{
      const response=await window.ClamShieldApiResponse.fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token,owner:account,action:'scan-targets'})});
      const value=await window.ClamShieldApiResponse.read(response,'Could not load websites');if(version!==serial)return;
      populate(value.sites);status.textContent=sites.some(site=>!site.suspended)?'':'No active websites in this account.';
    }catch(error){if(version===serial){failed=true;window.ClamShieldApiResponse.showError(status,error);}}
    finally{if(version===serial){loading=false;controls();}}
  });
  domain.addEventListener('change',()=>{if(form.elements.path)form.elements.path.value='';controls();onChange({owner:owner.value,domain:domain.value,sites});});
  controls();
  return {get ready(){return !start.disabled;},get account(){return owner.value||actorOwner;},get domain(){return domain.value;},get scope(){return !owner.value?'server':domain.value?'site':'account';},setBusy(value){busy=value;controls();}};
};
