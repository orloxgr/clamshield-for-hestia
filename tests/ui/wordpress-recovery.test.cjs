const {test}=require('node:test'),assert=require('node:assert/strict');
const path=require('node:path'),{spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const item={id:'file-one',path:'wp-content/uploads/custom.js',kind:'uploads-policy',action:'quarantine',status:'proposed',detail:{reason:'Selected uploads cleanup policy',recommended:true}};
function snapshot(status,options={}){return {plan:{id:'plan-one',domain:'site.test',target:'',created:1,status,revision:'revision-'+status,report:{coverage:{scanned:5,errors:0,skipped:0,unverified:0}},error:null},items:[item],recommended:[item.id],selection:status==='ready'?[]:[item.id],next_offset:null,total:1,work:['analyzing','preparing','applying'].includes(status)?{id:'job',status:'running',counters:{scanned:2}}:null,rechecks:[],...options};}
function fixture(snapshots,options={}){
  const data={context:{owner:'alice',admin:options.admin!==false,view_scope:options.global?'server':'account'},accounts:[{owner:'alice'},{owner:'bob'}],sites:[{owner:options.global?'bob':'alice',domain:'site.test',suspended:false}],website_permissions:{effective:{scan:options.scan!==false}}};
  const rendered=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',"set_error_handler(function($s,$m){throw new ErrorException($m,0,$s);});$data=json_decode(stream_get_contents(STDIN),true);$_SESSION=['token'=>'csrf'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.resolve(__dirname,'../../panel/wordpress_recovery.php')],{input:JSON.stringify(data),encoding:'utf8'});
  assert.equal(rendered.status,0,rendered.stderr);const dom=new JSDOM(rendered.stdout,{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'});
  const w=dom.window,requests=[],timers=new Map();let index=0,id=0;
  w.setTimeout=fn=>{timers.set(++id,fn);return id;};w.clearTimeout=id=>timers.delete(id);
  w.fetch=async(url,request)=>{const body=Object.fromEntries(request.body);requests.push(body);if(options.api){const custom=await options.api(body);if(custom)return custom;}
    const value=body.action==='scan-targets'?{sites:[{domain:'site.test',suspended:false}]}:body.action==='wordpress-recovery-list'?{plans:[{id:'plan-one',domain:'site.test',status:'ready',created:1}]}:body.action==='wordpress-recovery-status'?snapshots[Math.min(index++,snapshots.length-1)]:{jobs:['job'],plan_id:'plan-one'};
    return {ok:true,json:async()=>({ok:true,...value})};};
  if(!options.hidden)w.document.getElementById('cs-wp-recovery').hidden=false;
  for(const script of w.document.querySelectorAll('script:not([type="application/json"])'))w.eval(script.textContent);
  return {w,requests,timers,by:id=>w.document.getElementById('cs-wp-'+id),close:()=>w.close(),
    select:async()=>{await settle();const select=w.document.getElementById('cs-wp-plans');select.value='plan-one';select.dispatchEvent(new w.Event('change'));await settle();},
    tick:async()=>{const [id,fn]=timers.entries().next().value;timers.delete(id);await fn();await settle();}};
}
test('analysis sends separate PHP/JS policies and never automatically applies a recovery',async()=>{
  const f=fixture([snapshot('analyzing'),snapshot('ready')]);
  try{await settle();const form=f.by('analyze');assert.equal(form.elements.uploads_php.checked,true);assert.equal(form.elements.uploads_js.checked,false);
    form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));await settle();
    form.elements.uploads_js.checked=true;form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(value=>value.action==='wordpress-recovery-analyze');assert.deepEqual(JSON.parse(request.policy),{versions:{},packages:{},release_policy:'latest',uploads_php:true,uploads_js:true,additional:true,database:true});
    assert.equal(request.domain,'site.test');assert.equal(request.owner,'alice');assert.equal(f.by('apply').disabled,true);
    await f.tick();assert.match(f.by('status').textContent,/ready/);assert.equal(f.requests.some(value=>value.action==='wordpress-recovery-apply'),false);
    assert.equal(f.by('items').querySelector('input').checked,true);
  }finally{f.close();}
});

test('recovery explains three stages, keeps empty history hidden and opens a new analysis automatically',async()=>{
  let analyzed=false;
  const f=fixture([snapshot('ready')],{api:body=>{
    if(body.action==='wordpress-recovery-analyze')analyzed=true;
    if(body.action==='wordpress-recovery-list')return {ok:true,json:async()=>({ok:true,plans:analyzed?[{id:'plan-one',owner:'alice',domain:'site.test',status:'ready',created:1}]:[]})};
    return null;
  }});try{
    await settle();assert.equal(f.by('history').hidden,true);assert.equal(f.by('report').hidden,true);
    const page=f.w.document.getElementById('cs-wp-recovery');assert.match(page.textContent,/1\. Analyze website/);assert.match(page.textContent,/2\. Review proposed changes/);assert.match(page.textContent,/3\. Apply selected changes/);
    assert.doesNotMatch(page.textContent,/Remove PHP|Also remove all|Without a selection, repair uses the installed version|Recovery plans/);
    const form=f.by('analyze');assert.equal(form.elements.release_policy.value,'latest');form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));await settle();
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();assert.equal(f.by('report').hidden,false);assert.equal(f.by('plans').value,'plan-one');assert.equal(f.by('history').hidden,false);
    assert.match(f.by('status').textContent,/Website unchanged/);assert.equal(f.by('apply').disabled,true);
    assert.equal(f.requests.some(r=>r.action==='wordpress-recovery-preview'||r.action==='wordpress-recovery-apply'),false);
  }finally{f.close();}
});

test('installed release policy is explicit and pinned component versions render as escaped text',async()=>{
  const value=snapshot('ready');value.plan.report.components=[{kind:'plugin',slug:'example',version:'1.0',recovery_version:'2.0',status:'different'},{kind:'theme',slug:'<img src=x>',version:'1.0',recovery_version:null,status:'unverified',error:'Reference unavailable'}];
  const f=fixture([value]);try{
    const form=f.by('analyze');form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));await settle();form.elements.release_policy.value='installed';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(JSON.parse(f.requests.find(r=>r.action==='wordpress-recovery-analyze').policy).release_policy,'installed');
    const rows=f.by('versions').querySelectorAll('tr');assert.deepEqual([...rows[0].children].map(td=>td.textContent),['plugin / example','1.0','2.0','Verified release reference']);assert.match(rows[1].textContent,/Unavailable.*Reference unavailable/);assert.equal(f.by('versions').querySelector('img'),null);
    assert.equal(f.by('version-summary').hidden,false);assert.equal(f.by('apply').disabled,true);f.by('review').click();await settle();assert.equal(f.requests.filter(r=>r.action==='wordpress-recovery-preview').length,1);assert.equal(f.requests.some(r=>r.action==='wordpress-recovery-apply'),false);
  }finally{f.close();}
});
test('review then apply bind the server revision and changing selection invalidates review',async()=>{
  const f=fixture([snapshot('ready'),snapshot('reviewed'),snapshot('applied')]);
  try{await f.select();assert.equal(f.by('apply').disabled,true);f.by('review').click();await settle();
    const request=f.requests.find(value=>value.action==='wordpress-recovery-preview');assert.deepEqual(JSON.parse(request.policy),{items:['file-one'],edits:{}});assert.equal(request.revision,'revision-ready');
    assert.equal(f.by('apply').disabled,false);
    f.by('items').querySelector('input').click();assert.equal(f.by('apply').disabled,true);
    f.by('recommended').click();assert.equal(f.by('apply').disabled,true);
  }finally{f.close();}
});
test('apply and undo queue only their plan identity and exact revision',async()=>{
  const f=fixture([snapshot('reviewed'),snapshot('applied'),snapshot('undone')]);
  try{await f.select();f.by('apply').click();await settle();
    assert.deepEqual(f.requests.find(value=>value.action==='wordpress-recovery-apply'),{token:'csrf',owner:'alice',action:'wordpress-recovery-apply',plan_id:'plan-one',revision:'revision-reviewed'});
    assert.equal(f.by('undo').hidden,false);f.by('undo').click();await settle();assert.equal(f.requests.at(-2).action,'wordpress-recovery-undo');
  }finally{f.close();}
});
test('database evidence is escaped and a change requires an explicit exact fragment',async()=>{
  const database={id:'db-one',path:'wp_options.option_value',kind:'database',action:'database',status:'proposed',detail:{reason:'Review',recommended:false,editable:true,excerpt:'<script>bad()</script>',evidence:[{kind:'script',match:'<script>bad()</script>'}]}};
  const f=fixture([snapshot('ready',{items:[database],recommended:[]})]);
  try{await f.select();assert.equal(f.by('items').querySelector('script'),null);assert.equal(f.by('items').querySelector('input').checked,false);
    const [find,replace]=f.by('items').querySelectorAll('textarea');find.value='<script>bad()</script>';find.dispatchEvent(new f.w.Event('input'));replace.value='';
    f.by('items').querySelector('input').click();f.by('review').click();await settle();
    const body=f.requests.find(value=>value.action==='wordpress-recovery-preview');assert.deepEqual(JSON.parse(body.policy),{items:['db-one'],edits:{'db-one':{find:'<script>bad()</script>',replace:''}}});
  }finally{f.close();}
});
test('permission or stale revision errors remain visible as text after refresh',async()=>{
  const f=fixture([snapshot('ready')],{api:body=>body.action==='wordpress-recovery-preview'?{ok:false,json:async()=>({ok:false,error:'<b>Permission revoked</b>'})}:null});
  try{await f.select();f.by('review').click();await settle();assert.equal(f.by('status').textContent,'<b>Permission revoked</b>');assert.equal(f.by('status').children.length,0);assert.equal(f.by('apply').disabled,true);}finally{f.close();}
});
test('hidden recovery view makes no request and delegated scan denial stays disabled',async()=>{
  const f=fixture([snapshot('ready')],{hidden:true,scan:false});
  try{await settle();assert.equal(f.requests.length,0);assert.equal(f.by('analyze').querySelector('[type=submit]').disabled,true);
    f.w.document.getElementById('cs-wp-recovery').hidden=false;f.w.document.dispatchEvent(new f.w.CustomEvent('clamshield-tab-change'));await settle();
    assert.equal(f.by('analyze').querySelector('[type=submit]').disabled,true);
  }finally{f.close();}
});

test('Global recovery analysis and retained plans use their native hosting owner',async()=>{
  const f=fixture([snapshot('ready'),snapshot('reviewed')],{global:true,api:async body=>body.action==='wordpress-recovery-list'?{ok:true,json:async()=>({ok:true,plans:[{id:'plan-one',owner:'bob',domain:'site.test',status:'ready',created:1}]})}:null});
  try{await f.select();
    assert.equal(f.requests.find(row=>row.action==='wordpress-recovery-list').scope,'server');
    assert.equal(f.requests.find(row=>row.action==='wordpress-recovery-status').owner,'bob');
    f.by('review').click();await settle();assert.equal(f.requests.find(row=>row.action==='wordpress-recovery-preview').owner,'bob');
    const form=f.by('analyze');form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));
    f.by('analyze').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(f.requests.find(row=>row.action==='wordpress-recovery-analyze').owner,'bob');
  }finally{f.close();}
});

test('recovery requires account and website selection and does not analyze on dropdown changes',async()=>{
  const f=fixture([snapshot('ready')],{global:true});try{
    const form=f.by('analyze'),button=form.querySelector('[type=submit]');assert.equal(form.elements.owner.value,'');assert.equal(form.elements.domain.disabled,true);assert.equal(button.disabled,true);
    form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();
    assert.equal(form.elements.domain.disabled,false);assert.equal(button.disabled,true);assert.equal(f.requests.filter(r=>r.action==='scan-targets').length,1);
    form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));assert.equal(button.disabled,false);
    assert.equal(f.requests.some(r=>r.action==='wordpress-recovery-analyze'),false);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();assert.equal(f.requests.find(r=>r.action==='wordpress-recovery-analyze').owner,'bob');
  }finally{f.close();}
});

test('failed or stale recovery account discovery cannot enable analysis or reuse a folder',async()=>{
  let release;const f=fixture([snapshot('ready')],{api:body=>body.action==='scan-targets'?new Promise(resolve=>{release=()=>resolve({ok:true,json:async()=>({ok:true,sites:[{domain:'old.test',suspended:false}]})});}):null});try{
    const form=f.by('analyze');form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));form.elements.path.value='blog';
    form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();assert.equal(form.querySelector('[type=submit]').disabled,true);assert.equal(form.elements.path.value,'');
    form.elements.owner.value='';form.elements.owner.dispatchEvent(new f.w.Event('change'));release();await settle();assert.equal(form.elements.domain.querySelector('option[value="old.test"]'),null);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();assert.equal(f.requests.some(r=>r.action==='wordpress-recovery-analyze'),false);
  }finally{release?.();f.close();}
  const denied=fixture([snapshot('ready')],{api:body=>body.action==='scan-targets'?{ok:false,json:async()=>({ok:false,error:'Denied <img src=x>'})}:null});try{
    const form=denied.by('analyze');form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new denied.w.Event('change'));await settle();
    assert.equal(form.querySelector('[type=submit]').disabled,true);assert.equal(form.querySelector('[data-target-status] img'),null);assert.match(form.querySelector('[data-target-status]').textContent,/Denied/);
  }finally{denied.close();}
});

test('an account-view administrator can analyze another account and load its new plan',async()=>{
  const f=fixture([snapshot('ready')],{api:body=>body.action==='wordpress-recovery-list'?{ok:true,json:async()=>({ok:true,plans:body.owner==='bob'?[{id:'plan-one',owner:'bob',domain:'site.test',status:'ready',created:1}]:[]})}:null});try{
    await settle();const form=f.by('analyze');form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();
    form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));form.elements.path.value='blog';await settle();
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(r=>r.action==='wordpress-recovery-analyze');assert.equal(request.owner,'bob');assert.equal(request.path,'blog');
    assert.equal(f.requests.find(r=>r.action==='wordpress-recovery-status').owner,'bob');assert.equal(f.by('report').hidden,false);
    assert.equal(f.requests.filter(r=>r.action==='wordpress-recovery-list').at(-1).scope,'account');
    form.elements.owner.value='alice';form.elements.owner.dispatchEvent(new f.w.Event('change'));assert.equal(f.by('report').hidden,true);assert.equal(f.by('apply').disabled,true);await settle();
    assert.equal(f.by('plans').querySelector('option[value="plan-one"]'),null);
  }finally{f.close();}
});
