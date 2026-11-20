/* Managed by clamshield */
(() => {
  'use strict';
  const root=document.getElementById('cs-scans'),form=document.getElementById('cs-scans-filter');
  const body=document.getElementById('cs-scans-list'),status=document.getElementById('cs-scans-status');
  const checked=document.getElementById('cs-scans-checked'),refresh=document.getElementById('cs-scans-refresh');
  const prev=document.getElementById('cs-scans-prev'),next=document.getElementById('cs-scans-next');
  let offset=0,nextOffset=null,version=0,inFlight=false,dirty=false,timer=null,failures=0;
  const active=()=>!root.hidden&&document.visibilityState==='visible';
  function stop(){if(timer!==null)clearTimeout(timer);timer=null;}
  async function api(action,values={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...values})});
    const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||'Scan operation failed');return result;
  }
  function text(node,value){if(node.textContent!==String(value))node.textContent=String(value);}
  function makeRow(id){
    const row=document.createElement('tr');row.dataset.job=id;
    for(let n=0;n<5;n++)row.append(document.createElement('td'));
    const cancel=document.createElement('button');cancel.type='button';cancel.className='button';cancel.textContent='Cancel scan';
    const message=document.createElement('p');message.setAttribute('role','status');row.children[4].append(cancel,message);wireRow(row);return row;
  }
  function wireRow(row){
    const cancel=row.children[4].querySelector('button'),message=row.children[4].querySelector('p');
    cancel.removeAttribute('data-action');cancel.removeAttribute('data-job_id');
    cancel.addEventListener('click',async()=>{
      if(row.dataset.cancelling)return;version++;stop();row.dataset.cancelling='true';cancel.disabled=true;text(message,'Requesting cancellation…');
      try{await api('scan-cancel',{job_id:row.dataset.job,scope:row.dataset.scope});row.dataset.cancelRequested='true';text(message,'Cancellation requested. Waiting for the recorded scan state.');}
      catch(error){text(message,error.message);}
      finally{delete row.dataset.cancelling;load();}
    });
  }
  function render(value){
    const existing=new Map([...body.children].map(row=>[row.dataset.job,row]));
    let position=body.firstElementChild;
    for(const job of value.jobs){
      const row=existing.get(job.id)||makeRow(job.id);existing.delete(job.id);row.dataset.scope=value.scope;
      text(row.children[0],job.owner+' / '+job.domain+'\n'+(job.target||'Whole website')+'\n'+job.source+(row.dataset.availability?'\n'+row.dataset.availability:''));
      text(row.children[1],job.status+(job.cancel_requested&&['queued','running'].includes(job.status)?' · cancellation requested':'')+(job.error?'\n'+job.error:''));
      const c=job.counters;
      const base=new Set(['seen','scanned','skipped','errors','bytes','detections','history_expired','history_prune_pending']);
      const labels={installations:'WordPress installations',modified:'Modified',missing:'Missing',additional:'Additional',unverified:'Unverified',
        candidate_matches:'Candidate matches',baseline_matches:'Baseline matches',new_signatures:'New signatures',removed_signatures:'Removed signatures',candidate_seconds:'Candidate seconds',baseline_seconds:'Baseline seconds'};
      const extra=Object.entries(c).filter(([key])=>!base.has(key)).map(([key,value])=>(labels[key]||key.replaceAll('_',' '))+': '+(value!==null&&typeof value==='object'?JSON.stringify(value):value)).join(' · ');
      text(row.children[2],'Seen: '+(c.seen??0)+' · Checked: '+(c.scanned??0)+' · Skipped: '+(c.skipped??0)+' · Errors: '+(c.errors??0)+
        ' · Bytes: '+(c.bytes??0)+(extra?'\n'+extra:'')+(c.history_expired?'\nDetailed history expired':'')+(job.heartbeat?'\nLast progress: '+new Date(job.heartbeat*1000).toISOString():''));
      text(row.children[3],c.detections??0);
      const cancel=row.children[4].querySelector('button');cancel.hidden=!['queued','running'].includes(job.status);
      cancel.disabled=!job.can_cancel||!!row.dataset.cancelling;
      if(!['queued','running'].includes(job.status)&&row.dataset.cancelRequested){text(row.children[4].querySelector('p'),'Cancellation outcome: '+job.status+'.');delete row.dataset.cancelRequested;}
      if(row!==position)body.insertBefore(row,position);position=row.nextElementSibling;
    }
    for(const row of existing.values())row.remove();
    text(status,(value.scope==='server'?'All accounts':root.dataset.owner)+': '+value.summary.queued+' queued, '+value.summary.running+' running. '+value.total+' matching scans.');
    text(checked,'Last updated: '+new Date(value.checked*1000).toISOString());
    const card=document.getElementById('cs-active-scans');if(card)text(card,value.account_active);
    nextOffset=value.next_offset;prev.disabled=offset===0;next.disabled=nextOffset===null;
  }
  async function load(){
    stop();if(!active())return;
    if(inFlight){dirty=true;return;}
    const selected=version;inFlight=true;dirty=false;refresh.disabled=true;
    let delay=15000;
    try{
      const value=await api('scans-status',{scope:form.elements.scope.value,kind:form.elements.kind.value,search:form.elements.search.value,offset:String(offset)});
      if(selected!==version||!active())return;
      failures=0;render(value);delay=value.summary.queued+value.summary.running>0?5000:15000;
    }catch(error){if(selected===version&&active()){failures++;text(status,error.message+(body.children.length?' Showing the last received scan state; refresh will retry.':' No scan state could be loaded; refresh will retry.'));delay=Math.min(30000,5000*2**Math.min(failures,3));}}
    finally{
      inFlight=false;refresh.disabled=false;
      if(active()){if(dirty)queueMicrotask(load);else timer=setTimeout(load,delay);}
    }
  }
  function change(){version++;offset=0;nextOffset=null;for(const button of body.querySelectorAll('button'))button.disabled=true;load();}
  form.addEventListener('submit',event=>{event.preventDefault();change();});
  form.elements.scope.addEventListener('change',change);form.elements.kind.addEventListener('change',change);
  refresh.addEventListener('click',()=>{version++;load();});
  prev.addEventListener('click',()=>{offset=Math.max(0,offset-100);version++;load();});
  next.addEventListener('click',()=>{if(nextOffset!==null){offset=nextOffset;version++;load();}});
  function visibility(){version++;stop();if(active())load();}
  document.addEventListener('visibilitychange',visibility);document.addEventListener('clamshield-tab-change',visibility);
  for(const row of body.children)wireRow(row);
  window.addEventListener('pagehide',()=>{version++;stop();body.replaceChildren();text(checked,'');text(status,'Open Scans to refresh current progress.');});
  window.addEventListener('pageshow',event=>{if(event.persisted)visibility();});
  if(sessionStorage.getItem('clamshield-tab')==='jobs')queueMicrotask(load);
})();
