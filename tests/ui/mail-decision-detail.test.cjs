'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process');const {test}=require('node:test');const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..'),source=fs.readFileSync(path.resolve(__dirname,'../../panel/api_response.js'),'utf8')+'\n'+fs.readFileSync(path.join(root,'panel/mail.js'),'utf8');
const php=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',
  "$data=['context'=>['admin'=>true],'email-messages'=>[['owner'=>'alice','recipient'=>'inbox@alice.test','created'=>1,'sender'=>'sender@remote.test','classification'=>'incomplete','action'=>'deliver','status'=>'not_retained','decision_id'=>str_repeat('a',32)]]];"+
  "$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.join(root,'panel/review_rows/email-messages.php')],{encoding:'utf8'});
assert.equal(php.status,0,php.stderr);
const nativePhp=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',
  "$data=['context'=>['admin'=>true],'email-messages'=>[['owner'=>'@admin','recipient'=>'Account not verified','created'=>1,'subject'=>'ClamShield check unavailable','sender'=>'','classification'=>'incomplete','action'=>'native-fallback','status'=>'check_unavailable','native_reference'=>'1xX62m-000000005eO-0000']]];"+
  "$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.join(root,'panel/review_rows/email-messages.php')],{encoding:'utf8'});
assert.equal(nativePhp.status,0,nativePhp.stderr);
async function until(predicate){for(let i=0;i<100;i++){await new Promise(resolve=>setImmediate(resolve));if(predicate())return;}throw new Error('Decision detail UI did not settle');}
function fixture(options={}){
  const dom=new JSDOM('<div id="cs-mail" data-global="true" data-owner="admin" data-token="fixture-token"></div><table><tbody>'+(options.nativeOnly?nativePhp.stdout:php.stdout)+'</tbody></table>',{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'});
  const w=dom.window,requests=[];
  w.fetch=async(_url,request)=>{
    requests.push(Object.fromEntries(request.body));if(options.wait)await options.wait;
    if(options.error)return {ok:false,json:async()=>({ok:false,error:options.error})};
    return {ok:true,json:async()=>({ok:true,decision:{action:'deliver',classification:'incomplete',...(options.nativeObservation?{native_fallback:{native_reference:'1xX62m-000000005eO-0000'}}:{}),detail:{scan_complete:false,spam_score:1.25,
      native_dnsbl:{zone:'zen.spamhaus.org',state:'failed',score_contribution:0},
      ...(options.fallbackTag?{native_fallback_tag_requested:options.fallbackTag}:{}),
      spamassassin:{score:1.25,required_score:5,rules:[{name:'Historical.Rule',score:1.25,description:options.blankDescription?'':'<img src=x onerror=alert(1)>'}],engine_version:'4.0.2',rules_version:'historical'},
      ...(options.historical?{}:{policy_thresholds:{spam_threshold:7,spam_high_threshold:12,signature_spam_score:2}})}}})};
  };
  w.eval(source);return {w,requests,button:w.document.querySelector('.cs-mail-decision-show'),output:w.document.querySelector('.cs-mail-decision-output'),close:()=>w.close()};
}
test('Global native row opens scoped historical explanation on demand and toggles without repeated requests',async()=>{
  let release;const wait=new Promise(resolve=>release=resolve);const f=fixture({wait});
  try{
    assert.deepEqual(f.requests,[]);assert.equal(f.output.hidden,true);assert.ok(f.button.classList.contains('button'));
    const record=f.button.closest('tr');const selection=f.w.document.createElement('td');record.prepend(selection);
    f.button.click();f.button.click();assert.equal(f.requests.length,1);assert.equal(f.button.disabled,true);
    const details=record.nextElementSibling;assert.equal(details.dataset.reviewDetail,'true');
    assert.equal(details.cells[0].colSpan,record.cells.length);assert.equal(details.cells[0].colSpan,7);
    assert.equal(f.output.closest('tr'),details);assert.equal(record.contains(f.output),false);
    assert.equal(f.button.getAttribute('aria-controls'),f.output.id);assert.equal(f.button.getAttribute('aria-expanded'),'true');
    assert.deepEqual(f.requests[0],{token:'fixture-token',owner:'alice',action:'mail-decision-get',decision_id:'a'.repeat(32)});
    release();await until(()=>f.button.dataset.loaded==='true');
    assert.match(f.output.textContent,/DNS lookup failed; check incomplete/);assert.match(f.output.textContent,/Native DNSBL score contribution: 0/);
    assert.match(f.output.textContent,/Applied policy thresholds: spam 7 · high spam 12/);assert.match(f.output.textContent,/SpamAssassin: 1\.25 \/ 5/);
    assert.match(f.output.textContent,/Historical.Rule: \+1.25/);assert.equal(f.output.querySelector('img,script'),null);
    f.button.click();assert.equal(f.output.hidden,true);assert.equal(details.hidden,true);assert.equal(f.button.getAttribute('aria-expanded'),'false');
    f.button.click();assert.equal(f.output.hidden,false);assert.equal(details.hidden,false);assert.equal(f.requests.length,1);
    assert.equal(f.w.document.querySelectorAll('[data-review-detail]').length,1);
  }finally{release();f.close();}
});
test('historical decision without applied thresholds does not substitute current defaults',async()=>{
  const f=fixture({historical:true});try{f.button.click();await until(()=>f.button.dataset.loaded==='true');assert.match(f.output.textContent,/Policy thresholds: not recorded/);assert.doesNotMatch(f.output.textContent,/Applied policy thresholds/);}finally{f.close();}
});

test('individual native fallback expands full width with unavailable values and no scanner API call',async()=>{
  const f=fixture({nativeOnly:true});try{
    assert.match(f.button.closest('tr').textContent,/Server/);assert.match(f.button.closest('tr').textContent,/Check unavailable/);
    f.button.click();await until(()=>f.button.dataset.loaded==='true');
    assert.equal(f.requests.length,0);assert.match(f.output.textContent,/Scanner decision details are unavailable/);
    assert.match(f.output.textContent,/Spam score: not recorded/);assert.match(f.output.textContent,/Applied thresholds: not recorded/);
    assert.match(f.output.textContent,/does not confirm final delivery/);assert.match(f.output.textContent,/Native reference: 1xX62m/);
    assert.equal(f.output.closest('td').colSpan,f.button.closest('tr').cells.length);
    f.button.click();assert.equal(f.button.textContent,'Show check details');assert.equal(f.output.hidden,true);
    f.button.click();assert.equal(f.button.textContent,'Hide check details');assert.equal(f.requests.length,0);
  }finally{f.close();}
});

test('native fallback keeps genuine recorded scores and distinguishes them from final handling',async()=>{
  const f=fixture({nativeObservation:true});try{
    f.button.click();await until(()=>f.button.dataset.loaded==='true');
    assert.equal(f.requests.length,1);assert.match(f.output.textContent,/Recorded policy action: Deliver/);
    assert.match(f.output.textContent,/Classification: incomplete/);assert.match(f.output.textContent,/Native fallback observed/);
    assert.match(f.output.textContent,/Historical.Rule: \+1.25/);assert.match(f.output.textContent,/Applied policy thresholds: spam 7/);
    assert.match(f.output.textContent,/Native reference: 1xX62m/);assert.equal(f.button.textContent,'Hide decision details');
  }finally{f.close();}
});

test('historical empty description stays explicit without reconstructing the old explanation',async()=>{
  const f=fixture({blankDescription:true});try{
    f.button.click();await until(()=>f.button.dataset.loaded==='true');
    assert.match(f.output.textContent,/Historical.Rule: \+1.25 · Description not recorded for this decision/);
  }finally{f.close();}
});

test('fallback subject marking is a requested native action, never a completed clean verdict',async()=>{
  const f=fixture({fallbackTag:'malware'});try{
    f.button.click();await until(()=>f.button.dataset.loaded==='true');
    assert.match(f.output.textContent,/Native fallback subject tag requested: MALWARE/);
    assert.match(f.output.textContent,/Check incomplete/);assert.match(f.output.textContent,/Action: Deliver/);
    assert.doesNotMatch(f.output.textContent,/Subject tag applied|Check complete/);
  }finally{f.close();}
});
test('failed detail request stays readable and requires explicit user retry',async()=>{
  const f=fixture({error:'<script>Decision unavailable</script>'});try{f.button.click();await until(()=>!f.button.disabled);assert.equal(f.output.textContent,'<script>Decision unavailable</script>');assert.equal(f.output.querySelector('script'),null);assert.equal(f.requests.length,1);assert.notEqual(f.button.dataset.loaded,'true');}finally{f.close();}
});
