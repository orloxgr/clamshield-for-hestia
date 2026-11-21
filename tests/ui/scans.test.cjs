const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..'),source=fs.readFileSync(path.join(root,'panel/scans.js'),'utf8');
async function until(predicate){for(let n=0;n<100;n++){await new Promise(resolve=>setImmediate(resolve));if(predicate())return;}throw new Error('Scan UI did not settle');}
async function fixture(options={}){
  const php=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',"$data=['context'=>['owner'=>'alice','admin'=>"+(options.admin?'true':'false')+"]];$data['jobs']=json_decode($argv[2],true);$_SESSION=['token'=>'fixture-token'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.join(root,'panel/scans.php'),JSON.stringify(options.initialJobs||[])],{encoding:'utf8'});
  assert.equal(php.status,0,php.stderr);
  const dom=new JSDOM('<div id="cs-active-scans"></div>'+php.stdout,{url:'https://panel.test/plugins/clamshield/'+(options.query||''),runScripts:'outside-only',pretendToBeVisual:true});
  const w=dom.window,requests=[],timers=new Map();let timerId=0,snapshot=0,cancelled=false,concurrent=0,maxConcurrent=0;
  w.setTimeout=(callback,delay)=>{timers.set(++timerId,{callback,delay});return timerId;};w.clearTimeout=id=>timers.delete(id);
  w.fetch=async(_url,request)=>{
    const body=Object.fromEntries(request.body);requests.push(body);
    if(body.action==='scan-cancel'){
      if(options.cancelError)return {ok:false,json:async()=>({ok:false,error:options.cancelError})};
      cancelled=true;return {ok:true,json:async()=>({ok:true,cancel_requested:true,initial_monitoring_paused:!!options.monitoringPaused})};
    }
    if(body.action==='review-bulk-preview'){
      if(options.previewWait)await options.previewWait;
      return {ok:true,json:async()=>({ok:true,count:3,retained:2,token:'proof-token',scope:body.scope})};
    }
    if(body.action==='review-bulk-clear'){
      if(options.clearWait)await options.clearWait;
      if(options.clearError)return {ok:false,json:async()=>({ok:false,error:options.clearError})};
      return {ok:true,json:async()=>({ok:true,changed:3})};
    }
    const index=snapshot++;concurrent++;maxConcurrent=Math.max(maxConcurrent,concurrent);
    if(index===0&&options.wait)await options.wait;
    concurrent--;
    if(index===1&&options.refreshError)throw new Error(options.refreshError);
    const job={id:'a'.repeat(32),owner:'alice',domain:options.domain||'alice.test',target:'',source:options.source||'manual',status:cancelled?'running':options.jobStatus||'running',
      queue:options.queue,cancel_requested:cancelled?1:0,created:1,heartbeat:2,counters:{seen:10,scanned:7+index,errors:1,skipped:2,...options.counters},error:null,can_cancel:!cancelled};
    const total=options.total??1,offset=Number(body.offset),limit=Number(body.limit);
    return {ok:true,json:async()=>({ok:true,jobs:[job],scope:body.scope,total,offset,limit,summary:{recorded:total,queued:job.status==='queued'?1:0,running:job.status==='running'?1:0},account_active:1,checked:3+index,next_offset:offset+limit<total?offset+limit:null})};
  };
  const section=w.document.getElementById('cs-scans');section.hidden=false;w.sessionStorage.setItem('clamshield-tab','jobs');w.eval(source);
  if(!options.wait)await until(()=>section.querySelector('tbody tr'));
  return {w,requests,timers,section,byId:id=>w.document.getElementById('cs-scans-'+id),maxConcurrent:()=>maxConcurrent,
    tick:async()=>{const [key,value]=timers.entries().next().value;timers.delete(key);await value.callback();await until(()=>!w.document.getElementById('cs-scans-refresh').disabled);},close:()=>w.close()};
}

test('progress links select server scope only when the native administrator option is present',async()=>{
  for(const admin of [true,false]){const f=await fixture({admin,query:'?scan_scope=server'});try{
    assert.equal(f.requests[0].scope,admin?'server':'account');
  }finally{f.close();}}
});

test('queued scans show the actual blocker, global position and elapsed wait without extra actions',async()=>{
  const f=await fixture({admin:true,jobStatus:'queued',queue:{code:'scan-running',position:2,wait_seconds:83,message:'Waiting for automatic scan after signature updates: bob / bob.test.'}});try{
    const cell=f.byId('list').querySelector('tr').children[1];assert.match(cell.textContent,/Queue position: 2.*Waiting: 1m 23s/);assert.match(cell.textContent,/automatic scan after signature updates: bob/);
    assert.equal(f.requests.length,1);assert.equal(f.requests[0].action,'scans-status');assert.equal([...f.timers.values()][0].delay,5000);
    await f.tick();assert.match(cell.textContent,/Queue position: 2/);assert.equal(f.byId('list').querySelector('button').disabled,false);
  }finally{f.close();}
});

test('queue failures render as text and maintenance blockers link to the canonical History tab',async()=>{
  const f=await fixture({admin:true,jobStatus:'queued',queue:{code:'signature-activation',position:1,wait_seconds:6,message:'Waiting <img src=x> for signature activation.',action:'history'}});try{
    const cell=f.byId('list').querySelector('tr').children[1];assert.equal(cell.querySelector('img'),null);assert.match(cell.textContent,/Waiting <img src=x>/);
    assert.equal(cell.querySelector('a').getAttribute('href'),'#review/history');assert.equal(cell.querySelector('a').dataset.tab,'history');
  }finally{f.close();}
});

test('visible scans poll current counters without replacing focused native controls',async()=>{
  const f=await fixture();try{
    const row=f.byId('list').firstElementChild,button=row.querySelector('button');button.focus();
    assert.match(row.textContent,/Checked: 7/);assert.equal([...f.timers.values()][0].delay,5000);
    await f.tick();assert.match(row.textContent,/Checked: 8/);assert.equal(f.byId('list').firstElementChild,row);
    assert.equal(f.w.document.activeElement,button);assert.equal(button.className,'button');
    assert.equal(f.w.document.getElementById('cs-active-scans').textContent,'1');
    assert.equal(f.section.querySelector('option[value=server]'),null);
  }finally{f.close();}
});

test('retained post-update jobs are labelled as retired',async()=>{
  const f=await fixture({source:'signature-update'});try{
    const cell=f.byId('list').querySelector('tr').children[0];assert.match(cell.textContent,/Retired automatic scan/);assert.doesNotMatch(cell.textContent,/signature-update/);
    assert.equal(f.requests[0].action,'scans-status');assert.equal(f.requests.some(row=>row.action==='signatures-update'),false);
  }finally{f.close();}
});

test('cancel binds the recorded job/scope and retains running state until worker outcome',async()=>{
  const f=await fixture({admin:true});try{
    f.byId('filter').elements.scope.value='server';f.byId('filter').elements.scope.dispatchEvent(new f.w.Event('change'));
    await until(()=>f.requests.some(r=>r.action==='scans-status'&&r.scope==='server'));
    f.byId('list').querySelector('button').click();
    await until(()=>f.byId('list').textContent.includes('cancellation requested'));
    const request=f.requests.find(r=>r.action==='scan-cancel');assert.equal(request.job_id,'a'.repeat(32));assert.equal(request.scope,'server');
    assert.deepEqual(Object.keys(request).sort(),['action','job_id','owner','scope','token']);
    assert.match(f.byId('list').textContent,/running/);assert.equal(f.byId('list').querySelector('button').disabled,true);
  }finally{f.close();}
});

test('cancelling initial monitoring explains its persistent pause without duplicate requests',async()=>{
  const f=await fixture({source:'watch-initial',monitoringPaused:true});try{
    const button=f.byId('list').querySelector('button');button.click();button.click();
    await until(()=>f.byId('list').textContent.includes('Initial monitoring paused'));
    assert.match(f.byId('list').textContent,/Resume in Scheduled Scanner/);
    assert.equal(f.requests.filter(r=>r.action==='scan-cancel').length,1);
  }finally{f.close();}
});

test('hidden views stop polling and resume a fresh snapshot when visible',async()=>{
  const f=await fixture();try{
    const count=f.requests.length;f.section.hidden=true;f.w.document.dispatchEvent(new f.w.CustomEvent('clamshield-tab-change'));
    assert.equal(f.timers.size,0);assert.equal(f.requests.length,count);
    f.section.hidden=false;f.w.document.dispatchEvent(new f.w.CustomEvent('clamshield-tab-change'));
    await until(()=>f.requests.length>count);assert.equal(f.maxConcurrent(),1);
  }finally{f.close();}
});

test('changed filters discard in-flight snapshots without overlapping requests',async()=>{
  let release;const wait=new Promise(resolve=>release=resolve),f=await fixture({admin:true,wait});try{
    await until(()=>f.requests.length===1);
    const form=f.byId('filter');form.elements.scope.value='server';form.elements.scope.dispatchEvent(new f.w.Event('change'));
    form.elements.search.value='new search';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.requests.length,1);release();
    await until(()=>f.requests.length===2&&f.byId('list').children.length===1);
    assert.equal(f.requests[1].scope,'server');assert.equal(f.requests[1].search,'new search');assert.equal(f.maxConcurrent(),1);
  }finally{release();f.close();}
});

test('refresh failures preserve coverage and mark last state stale rather than clean',async()=>{
  const f=await fixture({refreshError:'Native status temporarily unavailable'});try{
    await f.tick();assert.match(f.byId('status').textContent,/Showing the last received/);
    assert.match(f.byId('list').textContent,/Errors: 1/);assert.match(f.byId('list').textContent,/Checked: 7/);
    assert.equal([...f.timers.values()][0].delay,10000);
  }finally{f.close();}
});

test('hostile strings are escaped and specialized/expired coverage remains visible',async()=>{
  const f=await fixture({domain:'<img src=x onerror=alert(1)>',counters:{modified:2,missing:3,history_expired:true,candidate_matches:4}});try{
    assert.equal(f.byId('list').querySelector('img'),null);assert.match(f.byId('list').textContent,/Modified: 2/);
    assert.match(f.byId('list').textContent,/Missing: 3/);assert.match(f.byId('list').textContent,/Candidate matches: 4/);
    assert.match(f.byId('list').textContent,/Detailed history expired/);
  }finally{f.close();}
});

test('initial unavailable-site history keeps its warning and can still cancel through the live controls',async()=>{
  const f=await fixture({initialJobs:[{id:'a'.repeat(32),owner:'alice',domain:'alice.test',target:'',status:'queued',counters:{},error:null,
    site_availability:{available:false,message:'This website document root changed since the scan.'}}]});try{
    assert.match(f.byId('list').textContent,/document root changed/);
    const button=f.byId('list').querySelector('button');assert.equal(button.disabled,false);assert.equal(button.hasAttribute('data-action'),false);
    button.click();await until(()=>f.requests.some(r=>r.action==='scan-cancel'));
    assert.equal(f.requests.filter(r=>r.action==='scan-cancel').length,1);
  }finally{f.close();}
});

test('browser history restoration resumes polling after a frozen page',async()=>{
  const f=await fixture();try{
    const count=f.requests.length;f.w.dispatchEvent(new f.w.PageTransitionEvent('pagehide',{persisted:true}));
    assert.equal(f.timers.size,0);assert.equal(f.byId('list').children.length,0);assert.equal(f.byId('checked').textContent,'');
    f.w.dispatchEvent(new f.w.PageTransitionEvent('pageshow',{persisted:true}));
    await until(()=>f.requests.length>count&&f.byId('list').children.length===1);assert.equal(f.maxConcurrent(),1);
  }finally{f.close();}
});

test('scans page sizes, page counts and filter changes use server pagination',async()=>{
  const f=await fixture({total:126});try{
    const form=f.byId('filter');assert.equal(f.requests[0].limit,'50');assert.match(f.byId('page').textContent,/Showing 1–50 of 126.*Page 1 \/ 3/);
    f.byId('next').click();await until(()=>f.byId('page').textContent.includes('51–100'));
    assert.equal(f.requests.at(-1).offset,'50');f.byId('prev').click();await until(()=>f.byId('page').textContent.includes('1–50'));
    for(const size of ['25','100']){
      form.elements.rows.value=size;form.elements.rows.dispatchEvent(new f.w.Event('change'));
      await until(()=>f.requests.at(-1).limit===size&&!f.byId('refresh').disabled);
      assert.equal(f.requests.at(-1).offset,'0');assert.match(f.byId('page').textContent,new RegExp('1–'+size+' of 126'));
    }
    f.byId('next').click();await until(()=>f.byId('page').textContent.includes('101–126'));
    assert.equal(f.byId('next').disabled,true);assert.equal(f.byId('prev').disabled,false);
  }finally{f.close();}
});

test('clear non-active scans confirms an exact scope and refreshes without reloading',async()=>{
  let release;const clearWait=new Promise(resolve=>release=resolve),f=await fixture({admin:true,query:'?scan_scope=server',total:126,clearWait});try{
    f.byId('next').click();await until(()=>f.byId('page').textContent.includes('51–100'));
    f.byId('clear').click();f.byId('clear').click();await until(()=>f.byId('clear-confirmation').querySelector('button'));
    assert.equal(f.requests.filter(r=>r.action==='review-bulk-preview').length,1);
    assert.equal(f.requests.filter(r=>r.action==='review-bulk-clear').length,0);
    const card=f.byId('clear-confirmation');assert.match(card.textContent,/3 non-active scans from all current server accounts/);assert.match(card.textContent,/Queued and running scans are kept/);
    const apply=card.querySelector('button');apply.click();apply.click();await until(()=>f.requests.some(r=>r.action==='review-bulk-clear'));
    assert.equal(f.requests.filter(r=>r.action==='review-bulk-clear').length,1);assert.equal(f.byId('list').children.length,1);
    const request=f.requests.find(r=>r.action==='review-bulk-clear');assert.equal(request.list,'scans');assert.equal(request.scope,'server');assert.equal(request.confirmation,'proof-token');
    release();await until(()=>card.textContent.includes('3 non-active scans cleared')&&!f.byId('clear').disabled&&!f.byId('refresh').disabled);
    assert.equal(f.requests.at(-1).offset,'0');assert.equal(f.w.location.pathname,'/plugins/clamshield/');
  }finally{release();f.close();}
});

test('changing scope invalidates an in-flight clear preview and tenants have no clear action',async()=>{
  let release;const previewWait=new Promise(resolve=>release=resolve),f=await fixture({admin:true,previewWait});try{
    f.byId('clear').click();const form=f.byId('filter');form.elements.scope.value='server';form.elements.scope.dispatchEvent(new f.w.Event('change'));
    release();await until(()=>!f.byId('clear').disabled);assert.equal(f.byId('clear-confirmation').hidden,true);
    assert.equal(f.byId('clear-confirmation').querySelector('button'),null);assert.equal(f.requests.some(r=>r.action==='review-bulk-clear'),false);
  }finally{release();f.close();}
  const tenant=await fixture();try{assert.equal(tenant.byId('clear'),null);assert.equal(tenant.requests.some(r=>r.action.startsWith('review-bulk')),false);}finally{tenant.close();}
});

test('clear errors stay readable and retryable with existing scan rows retained',async()=>{
  const f=await fixture({admin:true,clearError:'Failed <img src=x>'});try{
    f.byId('clear').click();await until(()=>f.byId('clear-confirmation').querySelector('button'));
    const apply=f.byId('clear-confirmation').querySelector('button');apply.click();await until(()=>f.byId('clear-confirmation').textContent.includes('Failed'));
    assert.equal(f.byId('clear-confirmation').querySelector('img'),null);assert.equal(apply.disabled,false);assert.equal(f.byId('list').children.length,1);
  }finally{f.close();}
});
