const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..');
const source=fs.readFileSync(path.resolve(__dirname,'../../panel/api_response.js'),'utf8')+'\n'+fs.readFileSync(path.join(root,'panel/server_history.js'),'utf8');
async function until(predicate){for(let n=0;n<100;n++){await new Promise(resolve=>setImmediate(resolve));if(predicate())return;}throw new Error('Server history UI did not settle');}
async function fixture(options={}){
  const admin=options.admin!==false;
  const php=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',"$data=['context'=>['owner'=>'selected-account','admin'=>"+(admin?'true':'false')+"]];$_SESSION=['token'=>'fixture-token'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.join(root,'panel/server_history.php')],{encoding:'utf8'});
  assert.equal(php.status,0,php.stderr);
  const dom=new JSDOM(php.stdout,{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'}),w=dom.window,requests=[];
  let policy={event_days:0,maintenance_days:0},revision='original';
  w.fetch=async(_url,request)=>{
    const body=Object.fromEntries(request.body);requests.push(body);
    if(body.action==='server-history-preview'&&options.wait)await options.wait;
    if(body.action==='server-history-save'){
      if(options.conflict)return {ok:false,json:async()=>({ok:false,error:'Server history retention changed. Preview it again before saving.'})};
      policy=JSON.parse(body.policy);revision='saved';
    }
    if(body.action==='server-history-reset'){policy={event_days:0,maintenance_days:0};revision='reset';}
    return {ok:true,json:async()=>({ok:true,policy,revision,last_run:null,error:null,blocked:options.blocked||null,
      preview:{server_events:2,read_server_notifications:3,maintenance_details:4}})};
  };
  w.sessionStorage.setItem('clamshield-tab','retention');w.eval(source);
  if(admin)await until(()=>!w.document.getElementById('cs-server-history-refresh').disabled);
  return {w,requests,byId:id=>w.document.getElementById('cs-server-history-'+id),close:()=>w.close()};
}

test('tenant template has no global controls and script makes no privileged request',async()=>{
  const f=await fixture({admin:false});try{assert.equal(f.byId('form'),null);assert.deepEqual(f.requests,[]);}finally{f.close();}
});

test('server policy preview/save/reset keeps scope root-derived and uses revisions',async()=>{
  const f=await fixture();try{
    const form=f.byId('form');assert.equal(form.querySelector('button[type=submit]').disabled,true);
    form.elements.event_days.value='90';form.elements.maintenance_days.value='30';form.dispatchEvent(new f.w.Event('input',{bubbles:true}));
    f.byId('preview').click();await until(()=>!form.querySelector('button[type=submit]').disabled);
    assert.match(f.byId('preview-result').textContent,/Old maintenance details: 4/);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await until(()=>f.byId('status').textContent.includes('Saved'));
    const request=f.requests.find(r=>r.action==='server-history-save');assert.equal(request.revision,'original');
    assert.deepEqual(JSON.parse(request.policy),{event_days:90,maintenance_days:30});
    assert.deepEqual(Object.keys(request).sort(),['action','owner','policy','revision','token']);
    assert.equal([...form.querySelectorAll('button,input')].every(e=>e.matches('.button,.form-control')),true);
    f.byId('reset').click();await until(()=>f.requests.some(r=>r.action==='server-history-reset'));
    assert.equal(f.requests.find(r=>r.action==='server-history-reset').revision,'saved');
  }finally{f.close();}
});

test('changed periods invalidate an in-flight server preview',async()=>{
  let release;const wait=new Promise(resolve=>release=resolve);const f=await fixture({wait});try{
    f.byId('preview').click();await until(()=>f.requests.some(r=>r.action==='server-history-preview'));
    f.byId('form').elements.event_days.value='30';f.byId('form').dispatchEvent(new f.w.Event('input',{bubbles:true}));release();
    await until(()=>!f.byId('preview').disabled);assert.equal(f.byId('form').querySelector('button[type=submit]').disabled,true);
    assert.equal(f.byId('preview-result').textContent,'');
  }finally{release();f.close();}
});

test('deferred maintenance and stale save errors remain visible as text',async()=>{
  const f=await fixture({blocked:'<img src=x> Pending service recovery',conflict:true});try{
    assert.equal(f.byId('status').querySelector('img'),null);assert.match(f.byId('status').textContent,/Pending service recovery/);
    f.byId('preview').click();await until(()=>!f.byId('form').querySelector('button[type=submit]').disabled);
    f.byId('form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.byId('status').textContent.includes('Preview it again'));
    assert.equal(f.byId('form').querySelector('button[type=submit]').disabled,true);
  }finally{f.close();}
});
