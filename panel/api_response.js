/* Managed by clamshield; native authentication redirects are not API data. */
window.ClamShieldApiResponse ||= {
  async read(response,fallback){
    const failure=(message,reload=false)=>Object.assign(new Error(message),{reloadPanel:reload});
    let login=false;
    if(response.redirected&&response.url){
      const url=new URL(response.url,location.href);
      login=url.origin===location.origin&&/^\/login(?:\/|$)/.test(url.pathname);
    }
    if(login||response.status===401)throw failure('Your Hestia session has expired. Reload the panel and sign in again.',true);
    const invalid=()=>failure('ClamShield returned an unexpected response. Reload the panel and try again.',true);
    if(response.headers?.get('content-type')?.includes('text/html'))throw invalid();
    let value;
    try{value=await response.json();}catch(error){throw invalid();}
    if(!value||Array.isArray(value)||typeof value!=='object'||typeof value.ok!=='boolean')throw invalid();
    if(!response.ok||!value.ok)throw failure(typeof value.error==='string'?value.error:fallback);
    return value;
  },
  showError(status,error){
    status.textContent=error.message;
    if(!error.reloadPanel)return;
    const button=document.createElement('button');
    button.type='button';button.className='button';button.textContent='Reload panel';
    button.dataset.panelReload='true';button.addEventListener('click',()=>location.reload());
    status.append(document.createTextNode(' '),button);
  }
};
