const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path'),{spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..');
function data(admin=true){
  const permissions=Object.fromEntries(['scan','schedule','quarantine','restore','repair','cleanup','exceptions','automatic','rule_trials'].map(key=>[key,true]));
  return {context:{owner:'alice',admin},accounts:[{owner:'alice'}],
    sites:[{domain:'site.test',root:'/home/alice/web/site.test/public_html',suspended:false,
      policy:{watch:false,frequency:'never',time:'03:00',timezone:'UTC',weekday:0,monthday:1,rescan_updates:true},
      remediation:{site:{mode:'inherit'},effective:{mode:'report'}}}],
    summary:{open_findings:0,active_scans:0,quarantined:0},findings:[],jobs:[],repairs:[],quarantine:[],history:[],wordpress:[],exceptions:[],notifications:[],rule_trials:[],remediation_history:[],
    remediation_policy:{account:{mode:'report'}},website_permissions:{effective:permissions,permissions,labels:permissions},
    engines:{clamav:{available:true,version:'ClamAV fixture'},yara:{available:true,version:'YARA fixture',rules_available:true}},
    rules:{configured:true,provider:'managed',profile:'core',version:'fixture-release',sha256:'a'.repeat(64),enabled:42,rules:45,created:1},
    rule_candidate:{generation:'generation-candidate',enabled:43,rules:46,compile_seconds:.1,stale_overrides:[]},rule_manager:{sources:[],disabled:[]},
    providers:{automatic:false,status:{official:{last_success:2},securiteinfo:{last_success:3}},
      securiteinfo:{enabled:true,plan:'basic',has_key:true,databases:[]},sanesecurity:{enabled:false,databases:[]},
      local:{enabled:false,files:[]},catalog:{securiteinfo:[],sanesecurity:[]}},signatures:{configured:true,generation:'generation-fixture'},
    spamassassin:{configured:true,service_active:false,daemon_verified:false,local_mode:null,recovery_pending:false,applied_at:1,
      policy:{required_score:5,rbl_enabled:true,uribl_enabled:false,blocked_zones:[],scores:{}}},
    resources:{error:'Fixture services unavailable'},mail_integration:{phase:'disabled'},mail_adapter:{compatible:false},
    maintenance:[{action:'spamassassin-save',status:'queued',created:1,result:null,error:null}]};
}
function fixture(options={}){
  const values=data(options.admin!==false);options.change?.(values);
  const rendered=spawnSync(process.env.CLAMSHIELD_PHP||'php',['-r',
    "set_error_handler(function($s,$m){throw new ErrorException($m,0,$s);});$data=json_decode(stream_get_contents(STDIN),true);$_SESSION=['token'=>'fixture-token'];$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",
    path.join(root,'panel/view.php')],{input:JSON.stringify(values),encoding:'utf8'});
  assert.equal(rendered.status,0,rendered.stderr);assert.equal(rendered.stderr,'');
  const dom=new JSDOM(rendered.stdout,{url:'https://panel.test/plugins/clamshield/'+(options.hash||''),runScripts:'outside-only'});
  const w=dom.window,requests=[];if(options.saved)w.sessionStorage.setItem('clamshield-tab',options.saved);
  w.setTimeout=()=>1;w.clearTimeout=()=>{};
  w.fetch=async(url,request)=>{requests.push(Object.fromEntries(request.body));return options.response||{ok:false,json:async()=>({ok:false,error:'Fixture API unavailable'})};};
  for(const script of w.document.querySelectorAll('script:not([type="application/json"])'))w.eval(script.textContent);
  return {w,requests,document:w.document,close:async()=>{await new Promise(resolve=>setImmediate(resolve));w.close();},click:selector=>w.document.querySelector(selector).click(),
    visible:()=>[...w.document.querySelectorAll('[data-page]')].filter(section=>!section.hidden).map(section=>section.dataset.page)};
}
const labels=['Dashboard','Email Shield','On-demand Scan','Scheduled Scanner','Results','Exceptions','Quarantine','Updates','History','Settings'];
test('full panel opens Dashboard and keeps the ten native menu links while navigating every view',async()=>{
  const f=fixture();try{
    assert.deepEqual(f.visible(),['dashboard']);const menu=f.document.getElementById('cs-main-navigation');
    assert.deepEqual([...menu.children].map(link=>link.textContent),labels);
    for(const link of menu.children){link.click();assert.equal(f.visible().length,1);assert.equal(menu.hidden,false);assert.equal(link.getAttribute('aria-current'),'page');
      for(const sub of f.document.querySelectorAll('[data-subnav]:not([hidden]) [data-tab]')){sub.click();assert.deepEqual(f.visible(),[sub.dataset.tab]);}}
    assert.equal(f.document.querySelector('[data-page=scheduled] .cs-policy').dataset.domain,'site.test');
    assert.equal(f.document.querySelector('[data-page=sites] .cs-policy'),null);
    assert.equal(f.document.querySelectorAll('[id]').length,new Set([...f.document.querySelectorAll('[id]')].map(node=>node.id)).size);
  }finally{await f.close();}
});
test('Manage links select the right group, preserve leaf refresh state and load lazy email/history views',async()=>{
  const f=fixture();try{
    f.click('#cs-dashboard [data-tab=rules]');assert.deepEqual(f.visible(),['rules']);assert.equal(f.w.location.hash,'#updates');
    f.click('[data-main-tab=dashboard]');f.click('#cs-dashboard [data-focus-provider=securiteinfo]');
    assert.deepEqual(f.visible(),['providers']);assert.equal(f.document.activeElement.id,'cs-provider-securiteinfo');
    f.click('[data-main-tab=email]');f.click('[data-main-tab=history]');
    await new Promise(resolve=>setImmediate(resolve));
    assert.ok(f.requests.some(request=>request.action==='mail-dashboard'));assert.ok(f.requests.some(request=>request.action==='history-retention-get'));
    assert.equal(f.w.sessionStorage.getItem('clamshield-tab'),'history');
  }finally{await f.close();}
});
test('direct links, old saved leaf tabs and unavailable administrator views have deterministic fallbacks',async()=>{
  for(const [options,page] of [[{hash:'#updates/providers'},'providers'],[{saved:'jobs'},'jobs'],[{saved:'retired-view'},'dashboard'],[{admin:false,hash:'#settings/resources'},'automatic']]){
    const f=fixture(options);try{assert.deepEqual(f.visible(),[page]);}finally{await f.close();}
  }
});
test('tenant retains all ten sections without privileged forms or navigation targets',async()=>{
  const f=fixture({admin:false});try{
    assert.deepEqual([...f.document.querySelector('#cs-main-navigation').children].map(link=>link.textContent),labels);
    for(const page of ['providers','resources','permissions','spamassassin'])assert.equal(f.document.querySelector('[data-page="'+page+'"],[data-tab="'+page+'"]'),null);
    assert.equal(f.document.querySelector('#cs-forge-install'),null);
    assert.match(f.document.getElementById('cs-dashboard').textContent,/Managed by administrator/);
  }finally{await f.close();}
});
test('dashboard reports stopped and unapplied states with escaped values and real task counts',async()=>{
  const f=fixture({change:values=>{values.engines.yara.version='<img src=x onerror=alert(1)>';values.rules={configured:false};values.engines.yara.rules_available=false;}});
  try{const dashboard=f.document.getElementById('cs-dashboard');assert.equal(dashboard.querySelector('img'),null);
    assert.match(dashboard.textContent,/Not installed/);assert.match(dashboard.textContent,/Stopped/);assert.match(dashboard.textContent,/Applied; runtime verification pending/);
    assert.match(dashboard.textContent,/Pending recent configuration tasks\s*1/);assert.match(dashboard.textContent,/SaneSecurity\s*Disabled/);
    assert.equal(f.document.querySelector('#cs-forge-install button').textContent,'Install rules');
  }finally{await f.close();}
});
test('YARA dropdown queues the selected profile and never treats download as activation',async()=>{
  const f=fixture({hash:'#updates',response:{ok:true,json:async()=>({ok:true,queued:true,task_id:'task-fixture'})}});
  try{const form=f.document.getElementById('cs-forge-install');assert.equal(form.querySelector('button').textContent,'Update rules');
    form.elements.profile.value='extended';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await new Promise(resolve=>setImmediate(resolve));
    assert.deepEqual(f.requests,[{token:'fixture-token',owner:'alice',action:'rules-update',profile:'extended'}]);
    assert.match(f.document.getElementById('cs-forge-status').textContent,/Active rules have not changed/);
    assert.equal(f.document.querySelector('[data-action=rules-activate]').disabled,true);
    assert.equal(form.querySelector('button').disabled,true);
    assert.equal(f.document.querySelector('[data-page=rules] [data-action=rules-update]'),null);
  }finally{await f.close();}
});
test('pending builds cannot apply an older candidate and an activated candidate is clearly marked',async()=>{
  const pending=fixture({change:values=>values.maintenance.push({action:'rules-update',status:'running',created:1,result:null,error:null})});
  try{assert.equal(pending.document.querySelector('#cs-forge-install button').disabled,true);
    assert.equal(pending.document.querySelector('[data-action=rules-activate]').disabled,true);
    assert.match(pending.document.getElementById('cs-forge-status').textContent,/rule task is pending/);
  }finally{await pending.close();}
  const active=fixture({change:values=>values.rules.generation=values.rule_candidate.generation});
  try{assert.equal(active.document.querySelector('[data-action=rules-activate]'),null);
    assert.match(active.document.querySelector('[data-page=rules]').textContent,/This validated ruleset is active/);
  }finally{await active.close();}
});
test('failed rule download remains visible, escaped and retryable',async()=>{
  const f=fixture({hash:'#updates',response:{ok:false,json:async()=>({ok:false,error:'<b>Provider unavailable</b>'})}});
  try{const form=f.document.getElementById('cs-forge-install');form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await new Promise(resolve=>setImmediate(resolve));const status=f.document.getElementById('cs-forge-status');
    assert.equal(status.textContent,'<b>Provider unavailable</b>');assert.equal(status.querySelector('b'),null);assert.equal(form.querySelector('button').disabled,false);
    assert.equal(f.document.querySelector('[data-action=rules-activate]').disabled,false);
  }finally{await f.close();}
});
