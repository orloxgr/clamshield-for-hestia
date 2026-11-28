const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname,'../..');
const source = fs.readFileSync(path.resolve(__dirname,'../../panel/api_response.js'),'utf8')+'\n'+fs.readFileSync(path.join(root,'panel/history.js'),'utf8');
async function until(predicate) {
  for(let n=0;n<100;n++){await new Promise(resolve=>setImmediate(resolve));if(predicate())return;}
  throw new Error('History UI did not settle');
}
async function fixture(options={}) {
  const php=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',
    "$data=['context'=>['owner'=>'alice','admin'=>"+(options.admin?'true':'false')+"]];$_SESSION=['token'=>'fixture-token'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",
    path.join(root,'panel/history.php')],{encoding:'utf8'});
  assert.equal(php.status,0,php.stderr);
  const dom=new JSDOM(php.stdout,{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'});
  const w=dom.window,requests=[];let revision='original',policy={scan_days:0,mail_days:0,event_days:0},canManage=options.canManage!==false;
  w.fetch=async(_url,request)=>{
    const body=Object.fromEntries(request.body);requests.push(body);
    if(body.action==='history-retention-preview'&&options.previewWait)await options.previewWait;
    if(body.action==='history-retention-save'){
      if(options.conflict)return {ok:false,json:async()=>({ok:false,error:'History retention changed. Preview it again before saving.'})};
      policy=JSON.parse(body.policy);revision='saved';
    }
    if(body.action==='history-retention-reset'){policy={scan_days:0,mail_days:0,event_days:0};revision='reset';}
    if(body.action==='history-retention-permission'){canManage=true;revision='permission';}
    return {ok:true,json:async()=>({ok:true,policy,can_manage:canManage,user_allowed:canManage,revision,last_run:null,error:options.error||null,
      preview:{scan_reports:2,scan_file_rows:503,mail_decisions:1,audit_events:3,read_notifications:4}})};
  };
  w.sessionStorage.setItem('clamshield-tab','retention');w.eval(source);
  await until(()=>requests.length&&!w.document.getElementById('cs-history-refresh').disabled);
  return {w,requests,form:w.document.getElementById('cs-history-form'),byId:id=>w.document.getElementById('cs-history-'+id),close:()=>w.close()};
}

test('history policy needs a matching preview and sends only owner/revision/periods',async()=>{
  const f=await fixture();try{
    const apply=f.form.querySelector('button[type=submit]');assert.equal(apply.disabled,true);
    f.form.elements.scan_days.value='30';f.form.dispatchEvent(new f.w.Event('input',{bubbles:true}));
    f.byId('preview').click();await until(()=>!apply.disabled);
    assert.match(f.byId('preview-result').textContent,/503 file rows/);
    f.form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.byId('status').textContent.includes('Saved.'));
    const request=f.requests.find(v=>v.action==='history-retention-save');
    assert.equal(request.owner,'alice');assert.equal(request.token,'fixture-token');assert.equal(request.revision,'original');
    assert.deepEqual(JSON.parse(request.policy),{scan_days:30,mail_days:0,event_days:0});
    assert.equal(apply.disabled,true);
    assert.equal([...f.form.querySelectorAll('button,input')].every(e=>e.matches('.button,.form-control')),true);
  }finally{f.close();}
});

test('typing invalidates an in-flight preview instead of authorizing a different period',async()=>{
  let release;const wait=new Promise(resolve=>{release=resolve;});
  const f=await fixture({previewWait:wait});try{
    f.byId('preview').click();await until(()=>f.requests.some(v=>v.action==='history-retention-preview'));
    f.form.elements.mail_days.value='90';f.form.dispatchEvent(new f.w.Event('input',{bubbles:true}));release();
    await until(()=>!f.byId('preview').disabled);
    assert.equal(f.form.querySelector('button[type=submit]').disabled,true);
    assert.equal(f.byId('preview-result').textContent,'');
    f.form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.requests.some(v=>v.action==='history-retention-save'),false);
  }finally{release();f.close();}
});

test('permission denial leaves periods read-only and renders stored errors as text',async()=>{
  const f=await fixture({canManage:false,error:'<img src=x onerror=alert(1)> changed authority'});try{
    assert.equal(f.byId('preview').disabled,true);assert.equal(f.byId('reset').disabled,true);
    assert.equal(f.form.elements.scan_days.disabled,true);assert.equal(f.byId('status').querySelector('img'),null);
    assert.match(f.byId('status').textContent,/changed authority/);
  }finally{f.close();}
});

test('stale save remains visible and reset uses the current server revision',async()=>{
  const f=await fixture({conflict:true});try{
    f.byId('preview').click();await until(()=>!f.form.querySelector('button[type=submit]').disabled);
    f.form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.byId('status').textContent.includes('Preview it again'));
    assert.equal(f.form.querySelector('button[type=submit]').disabled,true);
    f.byId('reset').click();await until(()=>f.requests.some(v=>v.action==='history-retention-reset'));
    assert.equal(f.requests.find(v=>v.action==='history-retention-reset').revision,'original');
  }finally{f.close();}
});

test('administrator can change delegation with its revision and no supplied authority',async()=>{
  const f=await fixture({admin:true});try{
    const form=f.byId('permission');form.elements.allowed.checked=false;
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(v=>v.action==='history-retention-permission'));
    const request=f.requests.find(v=>v.action==='history-retention-permission');
    assert.equal(request.revision,'original');assert.deepEqual(JSON.parse(request.policy),{allowed:false});
    assert.equal(Object.hasOwn(request,'actor'),false);assert.equal(Object.hasOwn(request,'admin'),false);
  }finally{f.close();}
});
