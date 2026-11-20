const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.resolve(__dirname,'../../panel/mail_protection.js'),'utf8');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const off={enabled:false,connected:false,defaults_enabled:false,phase:'unconfigured'};
function fixture(snapshots,options={}){
  const dom=new JSDOM(`<section id="cs-mail" data-token="csrf" data-owner="selected-account" ${options.hidden?'hidden':''}>${options.tenant?'':'<button id="cs-mail-protection-toggle">Enable mail protection</button><p id="cs-mail-protection-status"></p>'}<details id="cs-mail-advanced"><summary>Advanced</summary></details></section>`,{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'});
  const w=dom.window,requests=[],timers=new Map();let index=0,id=0,events=0;
  w.setTimeout=fn=>{timers.set(++id,fn);return id;};w.clearTimeout=id=>timers.delete(id);
  w.document.addEventListener('clamshield-mail-protection-changed',()=>events++);
  w.fetch=async(url,request)=>{
    const body=Object.fromEntries(request.body);requests.push(body);
    let value=body.action==='mail-protection-status'?snapshots[Math.min(index++,snapshots.length-1)]:{queued:true};
    if(options.failAction===body.action)value={error:'<b>Cannot activate</b>'};
    return {ok:!value.error,json:async()=>({ok:!value.error,...value})};
  };
  w.eval(source);
  return {w,requests,timers,get events(){return events;},button:w.document.getElementById('cs-mail-protection-toggle'),output:w.document.getElementById('cs-mail-protection-status'),
    tick:async()=>{const [id,fn]=timers.entries().next().value;timers.delete(id);await fn();await settle();},close:()=>w.close()};
}
const state=(protection=off,latest=null,pending=false)=>({protection,latest,pending});
test('one click queues activation, follows progress and enables only after verified completion',async()=>{
  const task={action:'mail-protection-enable',status:'running',phase:'preparing'};
  const f=fixture([state(),state(off,task,true),state(off,{...task,phase:'verifying'},true),state({...off,enabled:true,connected:true,phase:'active'},{...task,status:'completed'})]);
  try{await settle();assert.equal(f.button.disabled,false);assert.equal(f.events,0);
    assert.equal(f.w.document.getElementById('cs-mail-advanced').open,false);
    f.button.click();await settle();assert.equal(f.button.disabled,true);assert.match(f.output.textContent,/Preparing mail protection/);
    assert.deepEqual(f.requests[1],{token:'csrf',owner:'selected-account',action:'mail-protection-enable'});
    await f.tick();assert.match(f.output.textContent,/Verifying/);assert.equal(f.events,0);
    await f.tick();assert.equal(f.button.textContent,'Disable mail protection');assert.equal(f.button.disabled,false);
    assert.equal(f.output.textContent,'Mail protection is enabled.');assert.equal(f.events,1);assert.equal(f.timers.size,0);
  }finally{f.close();}
});
test('failed activation displays plain text and allows another attempt',async()=>{
  const f=fixture([state(),state(off,{action:'mail-protection-enable',status:'failed',error:'<script>invalid</script>'})]);
  try{await settle();f.button.click();await settle();assert.equal(f.button.textContent,'Enable mail protection');assert.equal(f.button.disabled,false);
    assert.match(f.output.textContent,/<script>invalid/);assert.equal(f.output.children.length,0);assert.equal(f.events,0);
  }finally{f.close();}
});
test('existing custom connection can enable inherited protection with the same button',async()=>{
  const f=fixture([state({...off,connected:true})],{failAction:'mail-protection-enable'});
  try{await settle();assert.equal(f.button.textContent,'Enable mail protection');f.button.click();await settle();
    assert.equal(f.requests.at(-1).action,'mail-protection-enable');assert.equal(f.button.disabled,false);
    assert.equal(f.output.textContent,'<b>Cannot activate</b>');assert.equal(f.output.children.length,0);
  }finally{f.close();}
});
test('Disable queues the safe server lifecycle and displays completion',async()=>{
  const f=fixture([state({...off,enabled:true,connected:true}),state(off,{action:'mail-protection-disable',status:'completed'})]);
  try{await settle();f.button.click();await settle();assert.equal(f.requests[1].action,'mail-protection-disable');
    assert.equal(f.button.textContent,'Enable mail protection');assert.equal(f.events,1);
  }finally{f.close();}
});
test('hidden email page pauses status checks and resumes when selected',async()=>{
  const f=fixture([state()],{hidden:true});
  try{await settle();assert.equal(f.requests.length,0);
    f.w.document.getElementById('cs-mail').hidden=false;f.w.document.dispatchEvent(new f.w.CustomEvent('clamshield-tab-change'));
    await settle();assert.equal(f.requests[0].action,'mail-protection-status');
  }finally{f.close();}
});
test('tenant view has no server activation requests',async()=>{
  const f=fixture([state()],{tenant:true});
  try{await settle();assert.equal(f.requests.length,0);assert.equal(f.button,null);}finally{f.close();}
});
