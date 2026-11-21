/* Managed by clamshield; server-derived recovery identities, native controls. */
(() => {
  'use strict';
  const root=document.getElementById('cs-wp-recovery');if(!root)return;
  const by=id=>document.getElementById('cs-wp-'+id),form=by('analyze'),output=by('status'),plans=by('plans');
  const owners=new Map();
  let plan=null,selected=new Set(),recommended=[],edits={},sources={},rows=new Map(),next=null,dirty=false,busy=false,loading=false,timer=null,closed=false,loaded=false,initialized=null,epoch=0,refreshWanted=false,workId=null,offset=0,previous=[],selectable=[],versionDirty=false;
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  const text=(tag,value)=>{const node=document.createElement(tag);node.textContent=value;return node;};
  async function api(action,fields={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:owners.get(fields.plan_id||plan?.id)||root.dataset.owner,action,...fields})});
    const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Recovery request failed');return value;
  }
  function controls(){
    const pending=busy||['analyzing','preparing','applying','undoing'].includes(plan?.status);
    targets.setBusy(pending);
    form.elements.release_policy.disabled=pending;
    by('prepare-versions').disabled=!plan||pending||!['ready','reviewed','preview-failed'].includes(plan.status);
    by('previous').disabled=pending||loading||!previous.length;by('next').disabled=pending||loading||next===null;
    by('review').disabled=!plan||loading||pending||!['ready','reviewed','preview-failed'].includes(plan.status)||versionDirty||selected.size===0;
    by('apply').disabled=!plan||loading||pending||dirty||versionDirty||!['reviewed','interrupted'].includes(plan.status);
    by('apply').textContent=plan?.status==='interrupted'?'Resume selected changes':'Apply selected changes';
    by('apply-help').textContent=versionDirty?'Prepare the selected recovery version, select its actions and preview them before applying.':plan?.status==='interrupted'?'Resume applies remaining reviewed changes. Completed changes are retained for undo.':plan?.status==='reviewed'&&!dirty?'Review ready. Apply will change the selected website files/database entries; file removals go to quarantine.':'Use Preview selected changes to prepare your selection before applying. Analysis and review leave your website unchanged.';
    by('undo').hidden=!plan||!['applied','interrupted','undo-interrupted','undone'].includes(plan.status);
    by('undo').disabled=pending;by('recommended').disabled=by('clear').disabled=pending||loading;
    by('selected').textContent=selected.size+' selected actions'+(versionDirty?' · Prepare the selected recovery version before previewing.':dirty?' · Review the changed selection before applying.':'');
  }
  function change(){dirty=true;controls();}
  function detail(label){const node=document.createElement('details'),summary=text('summary',label);summary.className='button cs-disclosure';const icon=document.createElement('i');icon.className='fas fa-caret-right cs-disclosure-icon';icon.setAttribute('aria-hidden','true');summary.prepend(icon);node.append(summary);return node;}
  function renderItem(item){
    const row=document.createElement('tr'),choice=document.createElement('input');choice.type='checkbox';choice.checked=selected.has(item.id);choice.setAttribute('aria-label','Select '+item.path);choice.disabled=item.status==='blocked';
    choice.addEventListener('change',()=>{if(choice.checked)selected.add(item.id);else selected.delete(item.id);change();});
    const select=document.createElement('td');select.append(choice);const evidence=document.createElement('td');
    evidence.append(text('p',({replace:'Replace with clean file',quarantine:'Move to quarantine',database:'Apply reviewed database edit'}[item.action]||item.action)+' · '+item.detail.reason));
    if(item.detail.error)evidence.append(text('p',item.detail.error));
    if(item.detail.replacement)evidence.append(text('p','Source: '+item.detail.replacement.source+' · SHA-256: '+item.detail.replacement.sha256));
    if(item.detail.detections?.length)evidence.append(text('pre',JSON.stringify(item.detail.detections,null,2)));
    if(item.detail.preview?.diff!==undefined){const review=detail('Review exact changes');review.append(text('pre',item.detail.preview.diff+(item.detail.preview.truncated?'\n[Preview truncated]':'')));evidence.append(review);}
    if(item.kind==='database'){
      const database=detail('Database evidence and exact change');database.append(text('pre',item.detail.excerpt||''));
      database.append(text('p',(item.detail.evidence||[]).map(value=>value.kind+': '+value.match).join('\n')));
      database.append(text('p','Matches require review. No automatic database deletion. Serialized string lengths are recalculated; objects/references require manual review.'));
      const find=document.createElement('textarea'),replace=document.createElement('textarea');find.className=replace.className='form-control';
      find.setAttribute('aria-label','Exact fragment to replace in '+item.path);replace.setAttribute('aria-label','Replacement text for '+item.path);
      find.placeholder='Exact fragment to replace';replace.placeholder='Replacement text; blank removes the selected fragment';
      find.value=edits[item.id]?.find||'';replace.value=edits[item.id]?.replace||'';find.disabled=replace.disabled=!item.detail.editable;
      for(const input of [find,replace])input.addEventListener('input',()=>{edits[item.id]={find:find.value,replace:replace.value};change();});
      database.append(find,replace);evidence.append(database);
    }
    row.append(select,text('td',item.path),evidence,text('td',item.status));return row;
  }
  function draw(items,append=false){
    if(!append){by('items').replaceChildren();rows.clear();}for(const item of items){rows.set(item.id,item);by('items').append(renderItem(item));}
  }
  function show(value,append=false){
    const first=initialized!==value.plan.id;plan=value.plan;recommended=value.recommended||recommended;selectable=value.selectable||value.items.filter(item=>item.status!=='blocked').map(item=>item.id);next=value.next_offset;offset=value.offset??offset;
    if(first){initialized=plan.id;selected=new Set(value.selection||[]);offset=value.offset||0;previous=[];form.elements.release_policy.value=plan.options?.release_policy||'installed';versionDirty=false;sources={};for(const component of new Set([...Object.keys(plan.options?.versions||{}),...Object.keys(plan.options?.packages||{})]))sources[component]={version:plan.options?.versions?.[component]||'',path:plan.options?.packages?.[component]||''};renderSources();edits={};rows.clear();dirty=false;}
    if(plan.status==='reviewed'&&!dirty)selected=new Set(value.selection||[]);
    const phases={analyzing:'Analysis '+(value.work?.status==='queued'?'queued':'running')+'. Website unchanged.',ready:'Analysis ready. Review proposed changes below. Website unchanged.',preparing:'Preparing the review. Website unchanged.',reviewed:'Review ready. Apply selected changes when ready.',applying:'Applying selected changes…',applied:'Selected changes applied.',undoing:'Undoing recovery…',undone:'Recovery undone.','analysis-failed':'Analysis failed. Website unchanged.','preview-failed':'Review preparation failed. Website unchanged.',interrupted:'Recovery interrupted. Completed changes are retained for undo.','undo-interrupted':'Undo interrupted. Review retained changes.'};
    by('report').hidden=false;output.textContent=(phases[plan.status]||plan.status)+(value.work?' · '+value.work.status+' · '+(value.work.counters.scanned||0)+' actions/files checked':'');
    workId=value.work&&['queued','running'].includes(value.work.status)?value.work.id:null;by('cancel').hidden=!workId;by('cancel').textContent=plan.status==='analyzing'?'Cancel analysis':'Cancel pending work';
    by('summary').textContent=plan.domain+' · '+(plan.target||'Whole website')+' · '+value.total+' proposed actions';
    const coverage=plan.report.coverage||{};by('coverage').textContent=(plan.report.comparison==='installed'?'Compared with installed versions. ':plan.report.components?.length?'Older analysis used recovery releases as its comparison; run a new analysis. ':'')+'Coverage: '+(coverage.scanned||0)+' checks · '+(coverage.errors||0)+' errors · '+(coverage.skipped||0)+' skipped · '+(coverage.unverified||0)+' unverified components. Recovery state does not certify the entire site clean.';
    const integrity=plan.report.integrity;if(integrity)by('coverage').textContent+=' Installed files: '+(integrity.scanned||0)+' compared · '+(integrity.modified||0)+' modified · '+(integrity.missing||0)+' missing · '+(integrity.additional||0)+' additional.';
    by('error').textContent=plan.error||'';by('database').textContent=JSON.stringify(plan.report.database||[],null,2);
    const versions=by('versions');versions.replaceChildren();
    for(const component of plan.report.components||[]){const row=document.createElement('tr');for(const value of [component.kind+' / '+(component.slug||component.path||'WordPress core'),component.version||'Unknown',component.recovery_version||'Unavailable',(component.status==='unverified'?('Not compared: '+(component.error||'Reference unavailable')):component.status==='review'?'Installed version has file differences':'Installed-version comparison: '+component.status)+(component.recovery_error?' · Recovery unavailable: '+component.recovery_error:'')])row.append(text('td',value));versions.append(row);}
    by('version-summary').hidden=!versions.children.length;
    by('investigation').textContent=JSON.stringify({errors:plan.report.errors||[],components:plan.report.components||[],recent_files:plan.report.investigation||[],processes:plan.report.processes||[],packages:plan.report.packages||{}},null,2);
    by('rechecks').textContent=(value.rechecks||[]).map(check=>check.source+': '+check.status+' · '+(check.counters.errors||0)+' errors · '+(check.counters.infected||0)+' files flagged · '+(check.counters.unverified||0)+' unverified components').join('\n');
    draw(value.items);
    const count=value.filtered_total??value.total;by('page').textContent='Showing '+(count?offset+1:0)+'–'+(offset+value.items.length)+' of '+count+' · Page '+(previous.length+1);
    const labels={replace:'Replace files',quarantine:'Move to quarantine',database:'Database edit',integrity:'Integrity differences','version-update':'Version updates','uploads-policy':'Uploads cleanup',scanner:'Scanner detection',configuration:'Configuration review'};
    for(const key of ['action','type','state']){const control=by('filter').elements.namedItem(key),current=control.value,title=control.options[0].textContent;control.replaceChildren(text('option',title));control.firstChild.value='';for(const option of value.choices?.[key]||[]){const node=text('option',labels[option]||option.replaceAll('-',' '));node.value=option;control.append(node);}if(current&&![...control.options].some(node=>node.value===current)){const node=text('option',labels[current]||current);node.value=current;control.append(node);}control.value=current;}

    by('empty').hidden=value.total!==0;by('empty').textContent=plan.status==='analyzing'?'Analysis is in progress. Proposed changes will appear here.':coverage.errors||coverage.skipped||coverage.unverified?'No changes could be prepared for the unverified content. Review the coverage and errors above.':'No changes were proposed by this analysis.';controls();
  }
  async function list(){
    const version=epoch,account=form.elements.owner.value,domain=targets.domain,scope=account?'account':'server';
    const value=await api('wordpress-recovery-list',{owner:account||root.dataset.owner,scope}),current=plans.value;if(version!==epoch||closed)return;
    plans.replaceChildren(text('option','Choose a previous analysis'));plans.firstChild.value='';
    for(const item of value.plans){if(domain&&item.domain!==domain)continue;owners.set(item.id,item.owner||account||root.dataset.owner);const option=text('option',(scope==='server'?item.owner+' / ':'')+item.domain+' · '+item.status+' · '+new Date(item.created*1000).toLocaleString());option.value=item.id;plans.append(option);}plans.value=current;by('history').hidden=plans.options.length<=1;loaded=true;
  }
  async function refresh(){
    if(loading||busy){refreshWanted=true;return;}if(!visible())return;stop();loading=true;controls();const current=epoch;
    try{if(!loaded)await list();if(current!==epoch||closed)return;const id=plans.value||plan?.id;if(id){const value=await api('wordpress-recovery-status',{plan_id:id,offset,limit:by('filter').elements.limit.value,filters:JSON.stringify(Object.fromEntries([...new FormData(by('filter'))].filter(([key])=>key!=='limit')))});if(current===epoch&&!closed)show(value);}}
    catch(error){output.textContent=error.message;}
    finally{loading=false;controls();if(refreshWanted&&visible()&&!busy){refreshWanted=false;refresh();}else if(visible()&&plan&&(['analyzing','preparing','applying','undoing'].includes(plan.status)||by('rechecks').textContent.includes('queued')||by('rechecks').textContent.includes('running')))timer=setTimeout(refresh,5000);}
  }
  async function request(operation,policy){
    if(busy||!plan)return;stop();busy=true;controls();let failure=null;
    try{await api('wordpress-recovery-'+operation,{plan_id:plan.id,revision:plan.revision,...(policy?{policy:JSON.stringify(policy)}:{})});dirty=false;output.textContent='Recovery '+operation+' queued.';}
    catch(error){failure=error.message;}
    finally{busy=false;controls();await refresh();if(failure)output.textContent=failure;}
  }
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!targets.ready)return;busy=true;controls();stop();output.textContent='Queuing WordPress analysis…';let failure=null;
    try{const values=new FormData(form),policy={versions:{},packages:{},release_policy:form.elements.release_policy.value};for(const key of ['uploads_php','uploads_js','additional','database'])policy[key]=values.has(key);
      for(const [component,value]of Object.entries(sources)){if(value.version)policy.versions[component]=value.version;if(value.path)policy.packages[component]=value.path;}
      const result=await api('wordpress-recovery-analyze',{owner:targets.account,domain:targets.domain,path:form.elements.path.value,policy:JSON.stringify(policy)});
      epoch++;offset=0;previous=[];owners.set(result.plan_id,targets.account);plan={id:result.plan_id};initialized=null;await list();plans.value=result.plan_id;
    }catch(error){failure=error.message;}
    finally{busy=false;controls();await refresh();if(failure)output.textContent=failure;}
  });
  by('prepare-versions').addEventListener('click',async()=>{
    if(busy||!plan)return;stop();busy=true;controls();output.textContent='Preparing selected recovery version… Website unchanged.';let failure=null;
    try{const policy={...plan.options,release_policy:form.elements.release_policy.value,versions:{},packages:{}};
      for(const [component,value]of Object.entries(sources)){if(value.version)policy.versions[component]=value.version;if(value.path)policy.packages[component]=value.path;}
      const result=await api('wordpress-recovery-analyze',{domain:plan.domain,path:plan.target,policy:JSON.stringify(policy)});
      epoch++;owners.set(result.plan_id,owners.get(plan.id)||root.dataset.owner);offset=0;previous=[];plan={id:result.plan_id};initialized=null;await list();plans.value=result.plan_id;
    }catch(error){failure=error.message;}
    finally{busy=false;controls();await refresh();if(failure)output.textContent=failure;}
  });
  function renderSources(){
    by('sources').replaceChildren();
    for(const [key,value]of Object.entries(sources)){const row=text('li',(key||'Root WordPress core')+' · '+(value.version||(value.path?'Version from vendor ZIP':'Recovery version policy'))+' · '+(value.path||'WordPress.org'));const remove=text('button','Remove selection');remove.className='button';remove.type='button';remove.addEventListener('click',()=>{delete sources[key];row.remove();if(plan){versionDirty=true;controls();}});row.append(remove);by('sources').append(row);}
  }
  by('add-source').addEventListener('click',()=>{
    const component=by('component').value.trim(),version=by('version').value.trim(),path=by('package').value.trim();if(!version&&!path)return;
    sources[component]={version,path};renderSources();if(plan){versionDirty=true;controls();}
  });
  form.elements.release_policy.addEventListener('change',()=>{versionDirty=!!plan&&form.elements.release_policy.value!==(plan.options?.release_policy||'installed');controls();});
  plans.addEventListener('change',()=>{epoch++;offset=0;previous=[];initialized=null;plan=null;by('report').hidden=true;refresh();});by('refresh').addEventListener('click',()=>{loaded=false;refresh();});by('previous').addEventListener('click',()=>{if(loading||busy||!previous.length)return;offset=previous.pop();refresh();});
  by('next').addEventListener('click',()=>{if(loading||busy||next===null)return;previous.push(offset);offset=next;refresh();});
  const filter=by('filter');function resetPage(){epoch++;offset=0;previous=[];refresh();}filter.addEventListener('submit',event=>{event.preventDefault();resetPage();});filter.addEventListener('change',resetPage);
  by('recommended').addEventListener('click',()=>{for(const id of selectable)selected.add(id);draw(Array.from(rows.values()));change();});
  by('clear').addEventListener('click',()=>{selected.clear();draw(Array.from(rows.values()));change();});
  by('review').addEventListener('click',()=>{const changes=Object.fromEntries(Object.entries(edits).filter(([id])=>selected.has(id)));request('preview',{items:[...selected],edits:changes});});
  by('apply').addEventListener('click',()=>request('apply'));by('undo').addEventListener('click',()=>request('undo'));
  by('cancel').addEventListener('click',async()=>{if(!workId)return;by('cancel').disabled=true;try{await api('cancel',{job_id:workId});output.textContent='Cancellation requested. Completed changes remain available for undo.';}catch(error){output.textContent=error.message;}finally{by('cancel').disabled=false;}});
  function visibility(){stop();if(visible())refresh();}
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;stop();});window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  const targets=window.ClamShieldWebsiteTargets(form,{allowed:root.dataset.scanAllowed!=='false',admin:root.dataset.admin==='true',bulk:false,owner:root.dataset.owner,token:root.dataset.token,onChange(){
    epoch++;offset=0;previous=[];versionDirty=false;stop();sources={};by('sources').replaceChildren();loaded=false;plan=null;initialized=null;workId=null;plans.replaceChildren(text('option','Choose a previous analysis'));plans.firstChild.value='';by('history').hidden=true;by('report').hidden=true;by('cancel').hidden=true;output.textContent='';controls();if(visible())refresh();
  }});
  controls();if(visible())refresh();
})();
