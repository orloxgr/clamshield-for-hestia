/* Managed by clamshield; server-derived recovery identities, native controls. */
(() => {
  'use strict';
  const root=document.getElementById('cs-wp-recovery');if(!root)return;
  const by=id=>document.getElementById('cs-wp-'+id),form=by('analyze'),output=by('status'),plans=by('plans');
  let plan=null,selected=new Set(),recommended=[],edits={},sources={},rows=new Map(),next=null,dirty=false,busy=false,loading=false,timer=null,closed=false,loaded=false,initialized=null;
  const visible=()=>!closed&&!root.hidden&&document.visibilityState!=='hidden';
  const stop=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
  const text=(tag,value)=>{const node=document.createElement(tag);node.textContent=value;return node;};
  async function api(action,fields={}){
    const response=await fetch(location.pathname,{method:'POST',credentials:'same-origin',body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...fields})});
    const value=await response.json();if(!response.ok||!value.ok)throw new Error(value.error||'Recovery request failed');return value;
  }
  function controls(){
    const pending=busy||['analyzing','preparing','applying','undoing'].includes(plan?.status);
    form.querySelector('[type=submit]').disabled=busy||!form.elements.domain.value||root.dataset.scanAllowed==='false';
    by('review').disabled=!plan||pending||!['ready','reviewed','preview-failed'].includes(plan.status)||selected.size===0;
    by('apply').disabled=!plan||pending||dirty||!['reviewed','interrupted'].includes(plan.status);
    by('apply').textContent=plan?.status==='interrupted'?'Resume reviewed recovery':'Apply reviewed recovery';
    by('undo').hidden=!plan||!['applied','interrupted','undo-interrupted','undone'].includes(plan.status);
    by('undo').disabled=pending;by('recommended').disabled=by('clear').disabled=pending;
    by('selected').textContent=selected.size+' selected actions'+(dirty?' · Review the changed selection before applying.':'');
  }
  function change(){dirty=true;controls();}
  function detail(label){const node=document.createElement('details'),summary=text('summary',label);summary.className='button cs-disclosure';const icon=document.createElement('i');icon.className='fas fa-caret-right cs-disclosure-icon';icon.setAttribute('aria-hidden','true');summary.prepend(icon);node.append(summary);return node;}
  function renderItem(item){
    const row=document.createElement('tr'),choice=document.createElement('input');choice.type='checkbox';choice.checked=selected.has(item.id);choice.setAttribute('aria-label','Select '+item.path);choice.disabled=item.status==='blocked';
    choice.addEventListener('change',()=>{if(choice.checked)selected.add(item.id);else selected.delete(item.id);change();});
    const select=document.createElement('td');select.append(choice);const evidence=document.createElement('td');
    evidence.append(text('p',item.action+' · '+item.detail.reason));
    if(item.detail.error)evidence.append(text('p',item.detail.error));
    if(item.detail.replacement)evidence.append(text('p','Source: '+item.detail.replacement.source+' · SHA-256: '+item.detail.replacement.sha256));
    if(item.detail.detections?.length)evidence.append(text('pre',JSON.stringify(item.detail.detections,null,2)));
    if(item.detail.preview){const review=detail('Review exact changes');review.append(text('pre',item.detail.preview.diff+(item.detail.preview.truncated?'\n[Preview truncated]':'')));evidence.append(review);}
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
    if(!append)by('items').replaceChildren();for(const item of items){rows.set(item.id,item);by('items').append(renderItem(item));}
  }
  function show(value,append=false){
    const first=initialized!==value.plan.id;plan=value.plan;recommended=value.recommended||recommended;next=value.next_offset;
    if(first){initialized=plan.id;selected=new Set(value.selection?.length?value.selection:recommended);edits={};rows.clear();dirty=false;}
    if(plan.status==='reviewed'&&!dirty)selected=new Set(value.selection||[]);
    by('report').hidden=false;output.textContent='Recovery '+plan.status+(value.work?' · '+value.work.status+' · '+(value.work.counters.scanned||0)+' actions/files checked':'');
    by('summary').textContent=plan.domain+' · '+(plan.target||'Whole website')+' · '+value.total+' proposed actions';
    const coverage=plan.report.coverage||{};by('coverage').textContent='Coverage: '+(coverage.scanned||0)+' checks · '+(coverage.errors||0)+' errors · '+(coverage.skipped||0)+' skipped · '+(coverage.unverified||0)+' unverified components. Recovery state does not certify the entire site clean.';
    by('error').textContent=plan.error||'';by('database').textContent=JSON.stringify(plan.report.database||[],null,2);
    by('investigation').textContent=JSON.stringify({errors:plan.report.errors||[],components:plan.report.components||[],recent_files:plan.report.investigation||[],processes:plan.report.processes||[],packages:plan.report.packages||{}},null,2);
    by('rechecks').textContent=(value.rechecks||[]).map(check=>check.source+': '+check.status+' · '+(check.counters.errors||0)+' errors · '+(check.counters.infected||0)+' files flagged · '+(check.counters.unverified||0)+' unverified components').join('\n');
    draw(value.items,append);by('more').hidden=next===null;controls();
  }
  async function list(){
    const value=await api('wordpress-recovery-list'),current=plans.value;plans.replaceChildren(text('option','Choose a plan'));plans.firstChild.value='';
    for(const item of value.plans){const option=text('option',item.domain+' · '+item.status+' · '+new Date(item.created*1000).toLocaleString());option.value=item.id;plans.append(option);}plans.value=current;loaded=true;
  }
  async function refresh(append=false){
    if(loading||busy||!visible())return;stop();loading=true;
    try{if(!loaded)await list();const id=plans.value||plan?.id;if(id){const value=await api('wordpress-recovery-status',{plan_id:id,offset:append?next||0:0});show(value,append);}}
    catch(error){output.textContent=error.message;}
    finally{loading=false;if(visible()&&plan&&(['analyzing','preparing','applying','undoing'].includes(plan.status)||by('rechecks').textContent.includes('queued')||by('rechecks').textContent.includes('running')))timer=setTimeout(refresh,5000);}
  }
  async function request(operation,policy){
    if(busy||!plan)return;stop();busy=true;controls();
    try{await api('wordpress-recovery-'+operation,{plan_id:plan.id,revision:plan.revision,...(policy?{policy:JSON.stringify(policy)}:{})});dirty=false;output.textContent='Recovery '+operation+' queued.';}
    catch(error){output.textContent=error.message;}
    finally{busy=false;controls();await refresh();}
  }
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;busy=true;controls();stop();output.textContent='Queuing WordPress analysis…';
    try{const values=new FormData(form),policy={versions:{},packages:{}};for(const key of ['uploads_php','uploads_js','additional','database'])policy[key]=values.has(key);
      for(const [component,value]of Object.entries(sources)){if(value.version)policy.versions[component]=value.version;if(value.path)policy.packages[component]=value.path;}
      const result=await api('wordpress-recovery-analyze',{domain:values.get('domain'),path:values.get('path'),policy:JSON.stringify(policy)});
      await list();plans.value=result.plan_id;plan=null;initialized=null;
    }catch(error){output.textContent=error.message;}
    finally{busy=false;controls();await refresh();}
  });
  by('add-source').addEventListener('click',()=>{
    const component=by('component').value.trim(),version=by('version').value.trim(),path=by('package').value.trim();if(!version&&!path)return;
    sources[component]={version,path};by('sources').replaceChildren();
    for(const [key,value]of Object.entries(sources)){const row=text('li',(key||'Root WordPress core')+' · '+(value.version||'Installed version')+' · '+(value.path||'WordPress.org'));const remove=text('button','Remove');remove.className='button';remove.type='button';remove.addEventListener('click',()=>{delete sources[key];row.remove();});row.append(remove);by('sources').append(row);}
  });
  plans.addEventListener('change',()=>{initialized=null;plan=null;by('report').hidden=true;refresh();});by('refresh').addEventListener('click',()=>{loaded=false;refresh();});by('more').addEventListener('click',()=>refresh(true));
  by('recommended').addEventListener('click',()=>{selected=new Set(recommended);draw([...rows.values()]);change();});
  by('clear').addEventListener('click',()=>{selected.clear();draw([...rows.values()]);change();});
  by('review').addEventListener('click',()=>{const changes=Object.fromEntries(Object.entries(edits).filter(([id])=>selected.has(id)));request('preview',{items:[...selected],edits:changes});});
  by('apply').addEventListener('click',()=>request('apply'));by('undo').addEventListener('click',()=>request('undo'));
  function visibility(){stop();if(visible())refresh();}
  document.addEventListener('clamshield-tab-change',visibility);document.addEventListener('visibilitychange',visibility);
  window.addEventListener('pagehide',()=>{closed=true;stop();});window.addEventListener('pageshow',event=>{if(event.persisted){closed=false;visibility();}});
  controls();if(visible())refresh();
})();
