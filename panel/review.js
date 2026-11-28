/* Managed by clamshield; bounded server pagination with native Hestia controls. */
(() => {
 'use strict';
 const root=document.getElementById('cs-review-root');if(!root)return;
 const config={
  findings:['cs-review-findings-rows','findings','Engine','Provider'],repairs:['cs-review-repairs-rows','repairs','Source'],
  exceptions:['cs-review-exceptions-rows','exceptions','Type','Engine'],quarantine:['cs-review-quarantine-rows','quarantine','Type'],
  history:['cs-review-history-rows','history','Event'],notices:['cs-notification-list','notices','Event'],
  activity:['cs-review-activity-rows','history','Operation'],automatic:['cs-review-automatic-rows','history','Policy'],
  'email-messages':['cs-mail-messages','email-review','Classification','Decision'],
  'email-stored':['cs-mail-server-quarantine','email-review','Action'],'email-decisions':['cs-mail-server-decisions','email-review','Classification']
 };
 const labels={'email-messages':['Clear list','Clear selected records','email list records','Quarantined messages, unresolved deliveries and internal recovery evidence are retained.'],findings:['Clear all findings','Clear selected findings','finding records','Website files and protection policies are unchanged.'],repairs:['Clear all repair records','Clear selected repair records','repair records','Running work and recovery items are retained. Undo evidence is kept internally.'],exceptions:['Remove all exceptions','Remove selected exceptions','exceptions','Removed exceptions stop suppressing detections on future scans.'],quarantine:['Delete quarantine files','Delete selected quarantine files','quarantine files','Permanently deletes verified private quarantine copies. Restore will no longer be available. Website files are unchanged.'],history:['Clear all history','Clear selected history','history events','Scan results, quarantine and recovery evidence are kept.'],notices:['Clear all notifications','Clear selected notifications','ClamShield notifications','Matching notifications in your HestiaCP account will also be removed shortly.'],activity:['Clear completed tasks','Clear selected tasks','completed maintenance records','Queued and running tasks are retained and continue normally.'],automatic:['Clear automatic action history','Clear selected action history','automatic action records','Running actions and recovery evidence are retained.'], 'email-stored':['Delete quarantined email','Delete selected quarantined email','quarantined recipient records','Permanently deletes accepted quarantined email for these recipients. Messages with uncertain acceptance or delivery are retained. Shared content is kept while another recipient needs it.'],'email-decisions':['Clear all email decisions','Clear selected email decisions','email decision records','Delivery and recovery evidence is kept internally.']};
 const states=new Map();
 const element=(tag,properties={})=>Object.assign(document.createElement(tag),properties);
 const option=(value,title)=>element('option',{value,textContent:title});
 const words=value=>String(value).replace(/[._-]/g,' ').replace(/^./,v=>v.toUpperCase());
 async function api(action,fields={}){
  const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,scope:root.dataset.scope,action,...fields})});
  const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Review request failed');return value;
 }
 function addField(form,name,title,control){const label=element('label',{textContent:title+' '});control.name=name;control.className=control.tagName==='SELECT'?'form-select':'form-control';label.append(control);form.append(label);return control;}
 function selection(title){const select=element('select');select.append(option('',title));return select;}
 function key(state){return 'clamshield-review:'+root.dataset.owner+':'+root.dataset.identity+':'+root.dataset.scope+':'+state.kind;}
 function remember(state){try{sessionStorage.setItem(key(state),JSON.stringify({fields:Object.fromEntries(new FormData(state.form)),offset:state.offset}));}catch{}}
 function filters(state){
  const values=Object.fromEntries(new FormData(state.form));delete values.rows;
  if(state.kind==='notices'){
   const kind=document.getElementById('cs-notification-type').value,status=document.getElementById('cs-notification-state').value;
   if(status!=='all')values.status=status;
   if(kind==='selected'){const selected=document.getElementById('cs-notifications').dataset.categories;if(selected)values.categories=JSON.parse(selected);}
   else if(kind!=='all')values.categories=[kind];
  }
  return values;
 }
 function controls(state){
  state.previous.disabled=state.loading||state.offset===0;state.next.disabled=state.loading||state.nextOffset===null;
  state.search.disabled=state.loading;state.clear&&(state.clear.disabled=state.loading||state.mutating||!state.canClear);
  state.read&&(state.read.disabled=state.loading||state.mutating);
  if(state.clearSelected)state.clearSelected.disabled=state.loading||state.mutating||!state.canClear||!state.selection.size;
  if(state.purge)state.purge.disabled=state.loading||state.mutating||!state.canClear;
  if(state.purgeSelected)state.purgeSelected.disabled=state.loading||state.mutating||!state.canClear||!deliverySelection(state).length;
  if(state.selectedCount)state.selectedCount.textContent=state.selection.size+' selected';
  if(state.selectPage)state.selectPage.disabled=state.loading||state.mutating||!state.canClear;
  for(const check of state.body.querySelectorAll('.cs-review-select'))check.disabled=state.loading||state.mutating||!state.canClear||check.dataset.allowed!=='true';
 }
 function options(select,values,human=true){if(!select)return;const selected=select.value,title=select.options[0].textContent;select.replaceChildren(option('',title));for(const value of values)select.append(option(String(value),value==='@admin'?'Server':human?words(value):String(value)));if(selected&&!values.map(String).includes(selected))select.append(option(selected,words(selected)));select.value=selected;}
 async function load(state,reset=false){
  if(reset)state.offset=0;state.revision++;state.queued=true;
  if(state.loading||state.mutating)return;
  state.loading=true;state.queued=false;const version=state.revision;controls(state);state.status.textContent='Loading…';
  const offset=state.offset,limit=Number(state.form.elements.rows.value),query=filters(state);remember(state);
  try{
   const value=await api('review-list',{list:state.kind,offset:String(offset),limit:String(limit),filters:JSON.stringify(query)});
   if(version!==state.revision)return;
   if(typeof value.html!=='string')throw new Error('Review rows are unavailable');
   if(!state.native)state.body.innerHTML=value.html;state.offset=value.offset;state.nextOffset=value.next_offset;state.canClear=Boolean(value.can_clear);state.loaded=true;
   selectRows(state,value.selection||[]);
   for(const name of ['status','type','provider'])options(state.form.elements.namedItem(name),value.options[name]||[]);
   options(state.form.elements.namedItem('account'),value.accounts||[],false);
   const first=value.total?value.offset+1:0,last=Math.min(value.offset+value.limit,value.total);
   state.count.textContent='Showing '+first+'–'+last+' of '+value.total+' · Page '+(Math.floor(value.offset/value.limit)+1)+' / '+Math.max(1,Math.ceil(value.total/value.limit));
   state.status.textContent=[state.outcome||(value.total?'':'No records match these filters.'),value.bell_delivery_error,value.bell_cleanup_error].filter(Boolean).join(' ');state.outcome=null;remember(state);
   if(!state.native)document.dispatchEvent(new CustomEvent('clamshield-review-rows',{detail:state.body}));
  }catch(error){if(version===state.revision)state.status.textContent=error.message+' The last loaded rows are kept. Use Search to retry.';}
  finally{state.loading=false;controls(state);if(state.queued)load(state);}
 }
 function deliverySelection(state){return [...state.selection].map(id=>state.records.get(id)).filter(row=>row?.can_delete&&row.delivery_id).map(row=>row.delivery_id);}
 async function previewClear(state,selected=false,kind=state.kind){
  if(state.mutating||state.loading)return;state.mutating=true;controls(state);state.status.textContent='Preparing deletion…';
  try{const value=await api('review-bulk-preview',{list:kind,...(selected?{selected:JSON.stringify(kind==='email-stored'&&state.kind==='email-messages'?deliverySelection(state):[...state.selection])}:{})});state.proof=value.token;state.proofKind=kind;state.confirmation.replaceChildren();
   const scope=value.scope==='server'?'all current server accounts':'the selected hosting account';
   const text=(selected?'Process the selected ':'Process all ')+value.count+' '+labels[kind][2]+' for '+scope+(selected?'?':', including records hidden by filters?')+' '+labels[kind][3]+(value.retained?' '+value.retained+' active or protected records will be retained.':'');
   state.confirmation.append(element('p',{textContent:text}));
   const confirm=element('button',{className:'button',type:'button',textContent:'Confirm '+(selected?labels[kind][1]:labels[kind][0]).toLowerCase(),disabled:value.count===0}),cancel=element('button',{className:'button',type:'button',textContent:'Cancel'});
   confirm.addEventListener('click',()=>clear(state,confirm,cancel));cancel.addEventListener('click',()=>{state.proof=null;state.confirmation.hidden=true;});
   state.confirmation.append(confirm,cancel);state.confirmation.hidden=false;state.status.textContent='';
  }catch(error){state.status.textContent=error.message;}
  finally{state.mutating=false;controls(state);}
 }
 async function clear(state,confirm,cancel){
  if(state.mutating||!state.proof)return;state.mutating=true;confirm.disabled=cancel.disabled=true;controls(state);
  try{let value;do{value=await api('review-bulk-clear',{list:state.proofKind||state.kind,confirmation:state.proof});state.status.textContent=value.changed+' processed'+(value.failed?' · '+value.failed+' retained after errors':'')+(value.pending?'…':'');}while(value.pending);
   state.proof=null;state.confirmation.hidden=true;state.selection.clear();state.offset=0;state.queued=true;
   state.outcome=value.failed?value.changed+' processed; '+value.failed+' retained. '+(value.failures||[]).map(item=>item.error).join(' · '):value.changed+' records processed.'+(value.bell_pending?' Matching HestiaCP notifications will be cleared shortly.':'');
   if(state.native)document.dispatchEvent(new CustomEvent('clamshield-mail-refresh',{detail:state.kind}));
  }
  catch(error){state.status.textContent=error.message;confirm.disabled=cancel.disabled=false;}
  finally{state.mutating=false;controls(state);if(state.queued)load(state);}
 }
 for(const [kind,[id,page,typeTitle,providerTitle]] of Object.entries(config)){
  const body=document.getElementById(id)||(kind==='email-stored'?document.getElementById('cs-mail-quarantine'):kind==='email-decisions'?document.getElementById('cs-mail-history'):null);if(!body)continue;const native=body.id!==id;if(!native)body.dataset.reviewManaged='true';
  const form=element('form',{className:'row cs-controls-row'});form.dataset.reviewList=kind;
  addField(form,'search','Search',element('input',{type:'search',maxLength:300,placeholder:kind==='email-messages'?'Subject, sender or recipient':'Account, website, file or event'}));
  if(root.dataset.scope==='server')addField(form,'account','Account',selection('All accounts'));
  if(kind!=='history'&&kind!=='notices')addField(form,'status','Status',selection('All statuses'));
  addField(form,'type',typeTitle,selection('All '+typeTitle.toLowerCase()+'s'));
  if(providerTitle)addField(form,'provider',providerTitle,selection('All '+providerTitle.toLowerCase()+'s'));
  addField(form,'from','From (UTC)',element('input',{type:'date'}));addField(form,'to','To (UTC)',element('input',{type:'date'}));
  const order=element('select');order.append(option('newest','Newest first'),option('oldest','Oldest first'));addField(form,'order','Sort',order);
  const size=element('select');for(const n of [25,50,100])size.append(option(String(n),String(n)));size.value='50';addField(form,'rows','Rows',size);
  const search=element('button',{className:'button',type:'submit',textContent:'Search'}),reset=element('button',{className:'button',type:'button',textContent:'Reset filters'});form.append(search,reset);
  const bar=element('div',{className:'row'}),count=element('p',{role:'status'}),previous=element('button',{className:'button',type:'button',textContent:'Previous',disabled:true}),next=element('button',{className:'button',type:'button',textContent:'Next',disabled:true});bar.dataset.reviewPager=kind;previous.dataset.reviewCommand='previous';next.dataset.reviewCommand='next';bar.append(count,previous,next);
  const status=element('p',{role:'status'}),confirmation=element('article',{className:'card',hidden:true});status.setAttribute('aria-live','polite');
  const container=body.closest('.scroll')||body;container.before(...(native?[bar,status,confirmation]:[form,bar,status,confirmation]));
  confirmation.dataset.reviewConfirmation=kind;
  const state={kind,page:body.closest('[data-page]').dataset.page,native,selection:new Set(),records:new Map(),body,form,bar,count,status,confirmation,previous,next,search,offset:0,nextOffset:null,revision:0,loading:false,mutating:false,queued:false,loaded:false,canClear:false};states.set(kind,state);
  {
   state.clear=element('button',{className:'button',type:'button',textContent:labels[kind][0],disabled:true});state.clear.dataset.reviewCommand='delete-all';bar.append(state.clear);state.clear.addEventListener('click',()=>previewClear(state));
   state.clearSelected=element('button',{className:'button',type:'button',textContent:labels[kind][1],disabled:true});state.clearSelected.dataset.reviewCommand='clear-selected';state.clearSelected.addEventListener('click',()=>previewClear(state,true));
   state.selectedCount=element('span',{textContent:'0 selected'});const label=element('label');state.selectPage=element('input',{type:'checkbox'});state.selectPage.setAttribute('aria-label','Select this page');label.append(state.selectPage,' Select this page');bar.append(label,state.selectedCount,state.clearSelected);
   state.selectPage.addEventListener('change',()=>{for(const check of state.body.querySelectorAll('.cs-review-select'))if(!check.disabled&&!check.closest('tr,article').hidden){check.checked=state.selectPage.checked;if(check.checked)state.selection.add(check.value);else state.selection.delete(check.value);}controls(state);});
   if(kind==='email-messages'){
    state.purge=element('button',{className:'button',type:'button',textContent:labels['email-stored'][0],disabled:true});state.purge.dataset.reviewCommand='purge-all';
    state.purgeSelected=element('button',{className:'button',type:'button',textContent:labels['email-stored'][1],disabled:true});state.purgeSelected.dataset.reviewCommand='purge-selected';
    bar.append(state.purge,state.purgeSelected);state.purge.addEventListener('click',()=>previewClear(state,false,'email-stored'));state.purgeSelected.addEventListener('click',()=>previewClear(state,true,'email-stored'));
   }
   if(kind==='notices'){state.read=element('button',{className:'button',type:'button',textContent:'Mark all read'});state.read.dataset.reviewCommand='read-all';bar.append(state.read);state.read.addEventListener('click',async()=>{
    if(state.loading||state.mutating)return;state.mutating=true;controls(state);
    try{const value=await api('review-read-all',{list:'notices'});state.status.textContent=value.changed+' notifications marked read.';state.queued=true;}
    catch(error){state.status.textContent=error.message;}
    finally{state.mutating=false;controls(state);if(state.queued)load(state);}
   });}
  }
  if(native){previous.hidden=next.hidden=count.hidden=true;}if(body.tagName==='TBODY'){const header=element('th',{textContent:'Select'});header.className='cs-review-selection-heading';body.closest('table').querySelector('thead tr').prepend(header);}
  try{const saved=JSON.parse(sessionStorage.getItem(key(state))||'null');if(saved&&saved.fields){for(const [name,value] of Object.entries(saved.fields)){const input=form.elements.namedItem(name);if(!input||typeof value!=='string')continue;if(input.tagName==='SELECT'&&![...input.options].some(option=>option.value===value))input.append(option(value,words(value)));input.value=value;}if(Number.isSafeInteger(saved.offset)&&saved.offset>=0)state.offset=saved.offset;}}catch{}
  form.addEventListener('submit',event=>{event.preventDefault();load(state,true);});form.addEventListener('change',()=>load(state,true));
  reset.addEventListener('click',()=>{form.reset();size.value='50';load(state,true);});
  previous.addEventListener('click',()=>{if(previous.disabled)return;state.offset=Math.max(0,state.offset-Number(size.value));load(state);});
  next.addEventListener('click',()=>{if(next.disabled||state.nextOffset===null)return;state.offset=state.nextOffset;load(state);});
 }
 function selectRows(state,values=[]){
  state.selection.clear();state.records=new Map(values.map(row=>[row.id,row]));state.selectPage.checked=false;state.selectPage.indeterminate=false;
  const rows=[...state.body.children].filter(row=>row.dataset.reviewDetail!=='true');for(let i=0;i<rows.length;i++){
   const row=rows[i];row.querySelector('.cs-review-selection-cell')?.remove();
   const value=state.native?{id:row.dataset.reviewId,allowed:row.dataset.reviewAllowed==='true'}:values[i];if(!value?.id)continue;
   const check=element('input',{type:'checkbox',value:value.id,className:'cs-review-select',disabled:!state.canClear||!value.allowed});check.dataset.allowed=String(Boolean(value.allowed));check.setAttribute('aria-label','Select record '+(i+1));
   const cell=element(state.body.tagName==='TBODY'?'td':'label',{className:'cs-review-selection-cell'});cell.append(check);if(cell.tagName==='LABEL')cell.append(' Select repair record');row.prepend(cell);
   check.addEventListener('change',()=>{if(check.checked)state.selection.add(check.value);else state.selection.delete(check.value);const enabled=[...state.body.querySelectorAll('.cs-review-select:not(:disabled)')];state.selectPage.checked=enabled.length>0&&enabled.every(v=>v.checked);state.selectPage.indeterminate=state.selection.size>0&&!state.selectPage.checked;controls(state);});
  }
  controls(state);
 }
 document.addEventListener('clamshield-mail-rows',event=>{for(const state of states.values())if(state.native&&state.body===event.detail)selectRows(state);});
 document.addEventListener('submit',async event=>{
  const form=event.target;if(!form.matches('.cs-review-email-deliver'))return;event.preventDefault();
  const button=form.querySelector('button'),status=form.querySelector('.cs-review-email-status');if(button.disabled||!form.reportValidity())return;
  button.disabled=true;status.textContent='Queueing delivery to the stored recipient…';
  try{await api('mail-release',{owner:form.closest('[data-owner]').dataset.owner,delivery_id:form.dataset.delivery,note:form.elements.note.value});
   const state=states.get('email-messages')||states.get('email-stored');state.outcome='Email queued for its stored recipient. Delivery is not confirmed yet.';load(state);
  }catch(error){status.textContent=error.message;button.disabled=false;}
 });
 function selected(){for(const state of states.values())if(!state.body.closest('[data-page]').hidden&&!state.loaded)load(state);}
 document.getElementById('cs-email-messages-refresh')?.addEventListener('click',()=>{const state=states.get('email-messages');if(state)load(state);});
 document.addEventListener('clamshield-tab-change',selected);
 document.addEventListener('clamshield-review-refresh',event=>{for(const state of states.values())if(state.kind===event.detail)load(state);});
 document.addEventListener('clamshield-notification-preferences',()=>{const state=states.get('notices');if(state&&!state.body.closest('[data-page]').hidden)load(state,true);});
 for(const id of ['cs-notification-type','cs-notification-state'])document.getElementById(id)?.addEventListener('change',()=>{const state=states.get('notices');if(state)load(state,true);});
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',selected,{once:true});else selected();
})();
