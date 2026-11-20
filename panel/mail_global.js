/* Managed by clamshield; server policy editing with revision checks. */
(() => {
  'use strict';
  const root=document.getElementById('cs-mail-server');if(!root)return;
  const by=id=>document.getElementById('cs-mail-server-'+id),form=by('form'),status=by('status');
  const labels={malware_action:'Malware',phishing_action:'Phishing',spam_action:'Spam',spam_high_action:'High-score spam',block_action:'Blocked sender',spam_threshold:'Spam score threshold',spam_high_threshold:'High spam score threshold',signature_spam_score:'Score per spam signature',allow_senders:'Allowed envelope senders (one per line)',block_senders:'Blocked envelope senders (one per line)'};
  const permissions={manage_policy:'Edit domain and mailbox policies',manage_exceptions:'Manage exact-content exceptions',release:'Release quarantined email',delete:'Delete quarantined email'};
  const prefix=root.dataset.scope==='server'?'mail-server-':'mail-account-';
  let current=null,loaded=false,busy=false;
  async function api(action,fields={}){const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...fields})});const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Server mail settings could not be loaded');return value;}
  function render(value){
    current=value;by('fields').replaceChildren();by('permissions').replaceChildren();
    const account=root.dataset.scope==='account',groups={};
    for(const kind of ['action','number','list']){const row=document.createElement('div');row.className='row';groups[kind]=row;by('fields').append(row);}
    for(const [key,title]of Object.entries(labels)){
      const label=document.createElement('label');label.textContent=title+' ';let input;
      if(key.endsWith('_action')){input=document.createElement('select');input.className='form-select';for(const action of ['reject','quarantine','junk','tag']){if(key==='malware_action'&&action==='junk')continue;input.append(new Option({reject:'SMTP rejection',quarantine:'Quarantine',junk:'Junk',tag:'Tag and deliver'}[action],action));}input.value=value.defaults[key];}
      else if(key.endsWith('_senders')){input=document.createElement('textarea');input.className='form-control';input.rows=3;input.maxLength=161000;input.value=value.defaults[key].join('\n');}
      else{input=document.createElement('input');input.className='form-control';input.type='number';input.min='0';input.max='100';input.step='0.1';input.required=true;input.value=value.defaults[key];}
      input.name=key;label.append(input);
      if(account){const choice=document.createElement('input');choice.type='checkbox';choice.dataset.mailDefaultOverride=key;choice.checked=Object.hasOwn(value.overrides||{},key);input.disabled=!choice.checked;choice.addEventListener('change',()=>{input.disabled=!choice.checked;});label.append(' ',choice,' Override global setting');}
      groups[key.endsWith('_action')?'action':key.endsWith('_senders')?'list':'number'].append(label);
    }
    let permissionOverride=null;
    if(account){const label=document.createElement('label'),row=document.createElement('p');permissionOverride=document.createElement('input');permissionOverride.type='checkbox';permissionOverride.name='override_permissions';permissionOverride.checked=!value.permissions_inherited;label.append(permissionOverride,' Override global email permissions for this account');row.append(label);by('permissions').append(row);}
    for(const [key,title]of Object.entries(permissions)){const label=document.createElement('label'),row=document.createElement('p'),input=document.createElement('input');input.type='checkbox';input.name=key;input.checked=value.permissions[key];if(permissionOverride){input.disabled=!permissionOverride.checked;permissionOverride.addEventListener('change',()=>{input.disabled=!permissionOverride.checked;});}label.append(input,' '+title);row.append(label);by('permissions').append(row);}
    form.hidden=false;
  }
  function rows(id,values){const body=by(id);if(!body)return;body.replaceChildren();for(const valuesRow of values){const row=document.createElement('tr');for(const value of valuesRow){const cell=document.createElement('td');if(value instanceof Node)cell.append(value);else cell.textContent=String(value);row.append(cell);}body.append(row);}}
  function accountLink(owner){const link=document.createElement('a'),url=new URL(location.href);url.searchParams.set('owner',owner);url.searchParams.delete('scope');url.hash='email';link.href=url.href;link.textContent='Manage account';return link;}
  async function activity(){if(root.dataset.global!=='true')return;const value=await api('mail-server-activity');by('totals').textContent=value.totals.domains+' mail domains · '+value.totals.quarantine+' stored recipient records · '+value.totals.decisions+' decisions';rows('accounts',value.accounts.map(row=>[row.owner,row.domains,row.quarantine,row.decisions,accountLink(row.owner)]));for(const key of ['quarantine','decisions'])rows(key,value[key].map(row=>[row.owner+' / '+row.recipient,new Date(row.created*1000).toISOString(),key==='quarantine'?row.status:row.action+' · '+row.classification]));}
  async function load(){if(busy)return;busy=true;by('refresh').disabled=true;status.textContent='Loading server email settings…';try{render(await api(prefix+'get'));loaded=true;await activity();status.textContent=root.dataset.scope==='server'?'Defaults apply across all accounts. Customers inherit the permissions shown above.':'Account overrides apply to its existing and future domains. Domain and mailbox overrides remain in effect.';}catch(error){status.textContent=error.message;}finally{busy=false;by('refresh').disabled=false;}}
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(!current||busy)return;busy=true;
    const button=form.querySelector('[type=submit]');button.disabled=true;const defaults={},grants={};
    for(const key of Object.keys(labels)){
      const choice=form.querySelector('[data-mail-default-override="'+key+'"]');if(choice&&!choice.checked)continue;
      const input=form.elements.namedItem(key);defaults[key]=key.endsWith('_action')?input.value:key.endsWith('_senders')?input.value.split('\n').map(line=>line.trim()).filter(Boolean):Number(input.value);
    }
    for(const key of Object.keys(permissions))grants[key]=form.elements.namedItem(key).checked;
    const inheritPermissions=root.dataset.scope==='account'&&!form.elements.override_permissions.checked;
    try{render(await api(prefix+'save',{revision:current.revision,policy:JSON.stringify({defaults,permissions:inheritPermissions?null:grants})}));status.textContent=root.dataset.scope==='server'?'Server email settings saved for all accounts.':'Account email defaults and permissions saved.';}
    catch(error){status.textContent=error.message;}
    finally{busy=false;button.disabled=false;}
  });
  by('reset')?.addEventListener('click',async()=>{if(!current||busy)return;busy=true;try{render(await api('mail-account-reset',{revision:current.revision}));status.textContent='Account inherits global email defaults and permissions.';}catch(error){status.textContent=error.message;}finally{busy=false;}});
  by('refresh').addEventListener('click',load);
  document.addEventListener('clamshield-tab-change',event=>{if(event.detail==='mail'&&!loaded)load();});
  if(sessionStorage.getItem('clamshield-tab')==='mail')queueMicrotask(load);
})();
