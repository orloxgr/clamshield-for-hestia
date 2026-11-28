/* Managed by clamshield; personal preferences and account-bound AJAX read state. */
(() => {
  'use strict';
  const root=document.getElementById('cs-notifications');if(!root)return;
  const form=document.getElementById('cs-notification-preferences'),choices=document.getElementById('cs-notification-choices');
  const categories=document.getElementById('cs-notification-categories'),hestiaCategories=document.getElementById('cs-hestia-notification-categories'),status=document.getElementById('cs-notification-preference-status');
  const refresh=document.getElementById('cs-notification-refresh'),type=document.getElementById('cs-notification-type'),state=document.getElementById('cs-notification-state');
  const rows=()=>[...document.querySelectorAll('#cs-notification-list tr')];
  let preferences=null,loading=false,saving=false;
  function category(event){
    if(['scan.malware_found','scan.repeated_detection'].includes(event))return 'detections';
    if(event==='wordpress.integrity_issues')return 'integrity';
    if(event.startsWith('scan.'))return 'scan_problems';
    if(event.startsWith('health.'))return 'health';
    if(event.startsWith('maintenance.')||event.startsWith('installation.'))return 'maintenance';
    if(event.startsWith('mail.'))return 'mail';
    if(['automatic.','repair.','cleanup.','quarantine.'].some(prefix=>event.startsWith(prefix)))return 'actions';
    return 'other';
  }
  function filter(){
    let shown=0,unread=0;
    for(const row of rows()){const kind=category(row.dataset.event),read=row.dataset.read==='true';
      row.hidden=!(type.value==='all'||(type.value==='selected'?(!preferences||preferences.categories.includes(kind)):type.value===kind))||
        (state.value==='unread'&&read)||(state.value==='read'&&!read);
      if(!row.hidden){shown++;if(!read)unread++;}
    }
    document.getElementById('cs-notification-count').textContent=shown+' shown · '+unread+' unread';
    document.getElementById('cs-notification-empty').hidden=shown!==0;
  }
  async function api(action,fields={},owner=root.dataset.owner){
    const response=await window.ClamShieldApiResponse.fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner,action,...fields})});
    const result=await window.ClamShieldApiResponse.read(response,"Notification request failed");if(!response.ok||!result.ok)throw new Error(result.error||'Notification request failed');return result;
  }
  function show(value){
    preferences=value.settings;categories.replaceChildren();hestiaCategories.replaceChildren();
    const selected=type.value;while(type.options.length>2)type.remove(2);
    for(const [key,title] of Object.entries(value.categories)){
      const label=document.createElement('label'),input=document.createElement('input');input.type='checkbox';input.name='category';input.value=key;input.checked=preferences.categories.includes(key);
      label.append(input,document.createTextNode(' '+title));categories.append(label);
      const bellLabel=document.createElement('label'),bellInput=document.createElement('input');bellInput.type='checkbox';bellInput.name='bell_category';bellInput.value=key;bellInput.checked=(preferences.bell_categories||preferences.categories).includes(key);
      bellLabel.append(bellInput,document.createTextNode(' '+title));hestiaCategories.append(bellLabel);
      const option=document.createElement('option');option.value=key;option.textContent=title;type.append(option);
    }
    if([...type.options].some(option=>option.value===selected))type.value=selected;
    form.elements.bell.checked=preferences.bell;choices.disabled=false;
    document.getElementById('cs-notification-scope').textContent='Personal preferences for '+value.account+'. '+(value.server?'HestiaCP notifications cover selected events across all server accounts.':'HestiaCP notifications cover only your own hosting account.');
    root.dataset.categories=JSON.stringify(preferences.categories);
    filter();document.dispatchEvent(new CustomEvent('clamshield-notification-preferences'));
  }
  async function load(){
    if(loading||saving)return;loading=true;refresh.disabled=true;choices.disabled=true;status.textContent='Loading notification preferences…';
    try{show(await api('notification-settings-get'));status.textContent=preferences.error||'Preferences loaded.';}
    catch(error){status.textContent=error.message+' Use Refresh preferences to retry.';}
    finally{loading=false;refresh.disabled=false;}
  }
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(!preferences||loading||saving)return;
    const policy={bell:form.elements.bell.checked,categories:[...categories.querySelectorAll('input:checked')].map(input=>input.value),bell_categories:[...hestiaCategories.querySelectorAll('input:checked')].map(input=>input.value)};
    saving=true;choices.disabled=true;refresh.disabled=true;status.textContent='Saving notification preferences…';
    try{show(await api('notification-settings-save',{revision:preferences.revision,policy:JSON.stringify(policy)}));status.textContent='Notification preferences saved.'+(preferences.error?' '+preferences.error:'');}
    catch(error){status.textContent=error.message;}
    finally{saving=false;choices.disabled=false;refresh.disabled=false;}
  });
  root.addEventListener('click',async event=>{const button=event.target.closest('.cs-notification-read');if(!button)return;const row=button.closest('tr');
      if(button.disabled)return;button.disabled=true;button.textContent='Marking read…';const message=row.querySelector('.cs-notification-read-status');message.textContent='';
      const owner=row.dataset.owner&&!row.dataset.owner.startsWith('@')?row.dataset.owner:root.dataset.owner;
      try{await api('notification-read',{notification_id:row.dataset.notification},owner);row.dataset.read='true';const label=document.createElement('span');label.textContent='Read';button.replaceWith(label);filter();document.dispatchEvent(new CustomEvent('clamshield-review-refresh',{detail:'notices'}));}
      catch(error){message.textContent=error.message;button.disabled=false;button.textContent='Mark read';}
  });
  type.addEventListener('change',filter);state.addEventListener('change',filter);refresh.addEventListener('click',load);
  const visible=()=>!root.hidden||!document.getElementById('cs-notification-settings').hidden;
  document.addEventListener('clamshield-tab-change',()=>{if(visible()&&!preferences)load();});
  document.addEventListener('clamshield-review-rows',event=>{if(event.detail.id==='cs-notification-list')filter();});
  filter();if(visible())load();
})();
