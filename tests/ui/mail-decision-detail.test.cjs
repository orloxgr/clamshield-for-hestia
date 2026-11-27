'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process');const {test}=require('node:test');const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..'),source=fs.readFileSync(path.join(root,'panel/mail.js'),'utf8');
const php=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',
  "$data=['context'=>['admin'=>true],'email-messages'=>[['owner'=>'alice','recipient'=>'inbox@alice.test','created'=>1,'sender'=>'sender@remote.test','classification'=>'incomplete','action'=>'deliver','status'=>'not_retained','decision_id'=>str_repeat('a',32)]]];"+
  "$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",path.join(root,'panel/review_rows/email-messages.php')],{encoding:'utf8'});
assert.equal(php.status,0,php.stderr);
async function until(predicate){for(let i=0;i<100;i++){await new Promise(resolve=>setImmediate(resolve));if(predicate())return;}throw new Error('Decision detail UI did not settle');}
function fixture(options={}){
  const dom=new JSDOM('<div id="cs-mail" data-global="true" data-owner="admin" data-token="fixture-token"></div><table><tbody>'+php.stdout+'</tbody></table>',{url:'https://panel.test/plugins/clamshield/',runScripts:'outside-only'});
  const w=dom.window,requests=[];
  w.fetch=async(_url,request)=>{
    requests.push(Object.fromEntries(request.body));if(options.wait)await options.wait;
    if(options.error)return {ok:false,json:async()=>({ok:false,error:options.error})};
    return {ok:true,json:async()=>({ok:true,decision:{action:'deliver',classification:'incomplete',detail:{scan_complete:false,spam_score:1.25,
      native_dnsbl:{zone:'zen.spamhaus.org',state:'failed',score_contribution:0},
      spamassassin:{score:1.25,required_score:5,rules:[{name:'Historical.Rule',score:1.25,description:'<img src=x onerror=alert(1)>'}],engine_version:'4.0.2',rules_version:'historical'},
      ...(options.historical?{}:{policy_thresholds:{spam_threshold:7,spam_high_threshold:12,signature_spam_score:2}})}}})};
  };
  w.eval(source);return {w,requests,button:w.document.querySelector('.cs-mail-decision-show'),output:w.document.querySelector('.cs-mail-decision-output'),close:()=>w.close()};
}
test('Global native row opens scoped historical explanation on demand and toggles without repeated requests',async()=>{
  let release;const wait=new Promise(resolve=>release=resolve);const f=fixture({wait});
  try{
    assert.deepEqual(f.requests,[]);assert.equal(f.output.hidden,true);assert.ok(f.button.classList.contains('button'));
    f.button.click();f.button.click();assert.equal(f.requests.length,1);assert.equal(f.button.disabled,true);
    assert.deepEqual(f.requests[0],{token:'fixture-token',owner:'alice',action:'mail-decision-get',decision_id:'a'.repeat(32)});
    release();await until(()=>f.button.dataset.loaded==='true');
    assert.match(f.output.textContent,/DNS lookup failed; check incomplete/);assert.match(f.output.textContent,/Native DNSBL score contribution: 0/);
    assert.match(f.output.textContent,/Applied policy thresholds: spam 7 · high spam 12/);assert.match(f.output.textContent,/SpamAssassin: 1\.25 \/ 5/);
    assert.match(f.output.textContent,/Historical.Rule: \+1.25/);assert.equal(f.output.querySelector('img,script'),null);
    f.button.click();assert.equal(f.output.hidden,true);f.button.click();assert.equal(f.output.hidden,false);assert.equal(f.requests.length,1);
  }finally{release();f.close();}
});
test('historical decision without applied thresholds does not substitute current defaults',async()=>{
  const f=fixture({historical:true});try{f.button.click();await until(()=>f.button.dataset.loaded==='true');assert.match(f.output.textContent,/Policy thresholds: not recorded/);assert.doesNotMatch(f.output.textContent,/Applied policy thresholds/);}finally{f.close();}
});
test('failed detail request stays readable and requires explicit user retry',async()=>{
  const f=fixture({error:'<script>Decision unavailable</script>'});try{f.button.click();await until(()=>!f.button.disabled);assert.equal(f.output.textContent,'<script>Decision unavailable</script>');assert.equal(f.output.querySelector('script'),null);assert.equal(f.requests.length,1);assert.notEqual(f.button.dataset.loaded,'true');}finally{f.close();}
});
