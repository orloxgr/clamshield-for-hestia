/* Managed by clamshield; queue once, show progress, keep account-bound reports. */
(() => {
  'use strict';
  const root=document.getElementById('cs-integrity');if(!root)return;
  const allowed=root.dataset.allowed==='true',refresh=document.getElementById('cs-integrity-refresh');
  const initial=JSON.parse(document.getElementById('cs-integrity-initial').textContent);
  const states=[...root.querySelectorAll('.cs-integrity-row')].map(row=>({row,job:initial[row.dataset.index]||null,busy:false,reading:false,reportBusy:false,reportJob:null,next:null}));
  let timer=null,polling=false,closed=false,epoch=0;
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const pending=state=>state.job&&['queued','running'].includes(state.job.status);
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  const reportRow=state=>root.querySelector('.cs-integrity-report-row[data-index="'+state.row.dataset.index+'"]');
  function text(state,selector,value){state.row.querySelector(selector).textContent=value;}
  async function api(state,action,fields={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:state.row.dataset.owner,action,...fields})});
    const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Integrity request failed');return value;
  }
  function render(state){
    const job=state.job,c=job?.counters||{},working=state.busy||pending(state);
    state.row.setAttribute('aria-busy',String(state.busy));
    const start=state.row.querySelector('.cs-integrity-start');start.disabled=!allowed||working;
    start.textContent=state.busy?'Starting check…':pending(state)?(job.status==='queued'?'Queued…':'Checking…'):job?'Check again':'Discover and verify';
    state.row.querySelector('input[name="path"]').disabled=!allowed||working;
    state.row.querySelector('.cs-integrity-progress').hidden=!pending(state);
    state.row.querySelector('.cs-integrity-show-report').hidden=!job||pending(state)||!job.report_ready;
    if(state.busy){text(state,'.cs-integrity-status','Submitting the integrity check…');return;}
    if(!job)return;
    text(state,'.cs-integrity-time',new Date((job.finished||job.created)*1000).toISOString().replace('T',' ').replace(/\.\d{3}Z$/,' UTC'));
    let label;
    if(job.cancel_requested&&pending(state))label='Cancellation requested; waiting for the worker.';
    else if(job.status==='queued')label='Queued. Waiting for the scanner; you can leave this page.';
    else if(job.status==='running')label=c.installations?'Checking WordPress files against official releases…':'Discovering WordPress installations…';
    else if(job.status==='completed'&&job.discovery_complete&&c.installations===0)label='Completed — no WordPress installation found.';
    else if(job.status==='completed')label=(c.modified||c.missing||c.additional)?'Completed — differences need review.':job.discovery_complete?'Completed — checked files match their references.':'Completed — see retained coverage below.';
    else label={partial:'Incomplete — some files or references could not be verified.',failed:'Check failed — review the error before retrying.',cancelled:'Check cancelled — coverage is incomplete.'}[job.status]||job.status;
    text(state,'.cs-integrity-status',label);
    const issues=Object.entries({modified:'modified',missing:'missing',additional:'additional',unverified:'unverified components',errors:'errors',skipped:'skipped'}).filter(([key])=>c[key]>0).map(([key,label])=>c[key]+' '+label);
    text(state,'.cs-integrity-counts',(job.target?'Folder: '+job.target+' · ':'')+(c.seen??0)+' entries inspected · '+(c.installations??0)+' WordPress '+(c.installations===1?'installation':'installations')+' · '+(c.scanned??0)+' files checked'+
      (pending(state)||!issues.length?'':' · '+issues.join(' · '))+
      (c.history_expired?' · Detailed report expired':''));
    text(state,'.cs-integrity-error',job.error||'');
  }
  async function update(state){
    if(!state.job||state.reading||state.busy)return;
    const id=state.job.id,version=epoch;state.reading=true;
    try{const value=await api(state,'wordpress-status',{job_id:id});if(version!==epoch||closed||state.job?.id!==id)return;
      if(value.job.id!==id||value.job.domain!==state.row.dataset.domain)throw new Error('Unexpected integrity check response');
      state.job=value.job;render(state);
    }catch(error){if(version===epoch&&!closed)text(state,'.cs-integrity-error',error.message+' Showing the last recorded state. Use Refresh checks to retry.');}
    finally{state.reading=false;}
  }
  async function poll(all=false){
    stop();if(!visible()||polling)return;polling=true;refresh.disabled=true;
    const todo=states.filter(state=>state.job&&(all||pending(state)));
    // Bound simultaneous requests on large Global inventories.
    try{for(let offset=0;offset<todo.length&&visible();offset+=3)await Promise.all(todo.slice(offset,offset+3).map(update));}
    finally{polling=false;refresh.disabled=false;if(visible()&&states.some(pending))timer=setTimeout(()=>poll(),5000);}
  }
  function schedule(){stop();if(visible()&&!polling&&states.some(pending))timer=setTimeout(()=>poll(),5000);}
  async function report(state,append=false){
    if(!state.job||state.reportBusy)return;
    const id=state.job.id,box=reportRow(state),status=box.querySelector('.cs-integrity-report-status'),list=box.querySelector('.cs-integrity-issues'),more=box.querySelector('.cs-integrity-more');
    state.reportBusy=true;box.hidden=false;more.disabled=true;status.textContent='Loading integrity report…';
    if(!append){list.replaceChildren();state.next=null;state.reportJob=id;}
    try{const value=await api(state,'wordpress-report',{job_id:id,offset:String(append?state.next||0:0)});if(state.job?.id!==id||state.reportJob!==id)return;
      for(const file of value.files){const entry=document.createElement('p'),title=document.createElement('strong');
        title.textContent=({modified:'Modified',missing:'Missing',additional:'Additional file',unverified:'Unverified',errors:'Read error',error:'Read error',skipped:'Skipped'}[file.status]||file.status)+': '+file.path;
        entry.append(title);if(file.detail.message)entry.append(document.createElement('br'),document.createTextNode(file.detail.message));
        const component=file.detail.component;if(component)entry.append(document.createElement('br'),document.createTextNode([component.kind,component.slug,component.version].filter(Boolean).join(' · ')));
        list.append(entry);
      }
      state.next=value.next_offset;more.hidden=state.next===null;
      const c=value.job.counters||{};status.textContent='Check '+value.job.status+' · '+(c.installations||0)+' WordPress installations · '+(c.scanned||0)+' files checked.'+
        (!list.children.length?(value.job.status==='completed'?(c.installations===0?' No WordPress installation was found in the checked paths.':' No integrity differences were recorded in the checked paths.'):' Coverage is incomplete; no conclusion can be drawn from an empty report.'):' Differences and unverified entries require review.');
    }catch(error){status.textContent=error.message;}
    finally{state.reportBusy=false;more.disabled=false;}
  }
  for(const state of states){
    render(state);
    state.row.querySelector('form').addEventListener('submit',async event=>{
      event.preventDefault();if(!allowed||state.busy||pending(state))return;
      state.busy=true;render(state);text(state,'.cs-integrity-error','');let failure=null;
      try{const value=await api(state,'wordpress-scan',{domain:state.row.dataset.domain,path:state.row.querySelector('input[name="path"]').value});
        if(!value.job||value.job.domain!==state.row.dataset.domain)throw new Error('The integrity check could not be confirmed. Refresh checks or retry.');
        state.job=value.job;reportRow(state).hidden=true;state.reportJob=null;
      }catch(error){failure=error.message;}
      finally{state.busy=false;if(state.job)render(state);else{state.row.setAttribute('aria-busy','false');state.row.querySelector('.cs-integrity-start').disabled=!allowed;state.row.querySelector('.cs-integrity-start').textContent='Retry check';state.row.querySelector('input[name="path"]').disabled=!allowed;}if(failure){text(state,'.cs-integrity-status','The request could not be completed.');text(state,'.cs-integrity-error',failure);}schedule();}
    });
    state.row.querySelector('.cs-integrity-show-report').addEventListener('click',()=>report(state));
    const box=reportRow(state);box.querySelector('.cs-integrity-close-report').addEventListener('click',()=>{box.hidden=true;});box.querySelector('.cs-integrity-more').addEventListener('click',()=>report(state,true));
  }
  refresh.addEventListener('click',()=>{if(!states.some(state=>state.job)){document.getElementById('cs-integrity-notice').textContent='No checks have been started in this view. Choose Discover and verify beside a website.';return;}poll(true);});
  function visibility(){epoch++;stop();if(visible())poll();}
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;epoch++;stop();});window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  if(visible())poll();
})();
