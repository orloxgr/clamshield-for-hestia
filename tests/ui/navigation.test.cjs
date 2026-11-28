const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path'),{spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..');

test('native fallback observations show recorded times without claiming clean mail or current recovery',()=>{
  const f=fixture({hash:'#settings/mail-settings',change:v=>{v.context.view_scope='server';v.mail_integration={phase:'active',
    native_delivery_observations:{collection:'unavailable',last_fallback:1,last_response:2,fallbacks:3,history_limited:true,backlog:true,error:'<b>Log unavailable</b>'}};}});
  try{
    const panel=f.document.getElementById('cs-mail-advanced'),text=panel.textContent;
    assert.match(text,/Last recorded fallback: 1970-01-01 00:00:01 UTC/);assert.match(text,/Recorded fallback events: 3/);
    assert.match(text,/Last observed ClamShield reply: 1970-01-01 00:00:02 UTC/);
    assert.match(text,/not a complete or clean scan/);assert.match(text,/Observation history is limited/);
    assert.match(text,/More log data remains/);assert.equal(panel.querySelector('.alert-danger').textContent,'<b>Log unavailable</b>');
    assert.equal(panel.querySelector('.alert-danger b'),null);
    assert.ok([...panel.querySelectorAll('a')].some(a=>a.getAttribute('href')==='#review/history'));
  }finally{f.close();}
});

test('native provider diagnostics remain distinct from SpamAssassin and explain managed handling',()=>{
  const f=fixture({hash:'#settings/mail-settings',change:v=>{v.context.view_scope='server';v.mail_integration={phase:'active',
    native_dnsbl_observations:[{zone:'zen.spamhaus.org',label:'Spamhaus ZEN',state:'blocked',observed:1,help_url:'https://www.spamhaus.org/returnc/pub/'},
      {zone:'pbl.spamhaus.org',label:'Spamhaus PBL',state:'unknown',observed:null,help_url:'https://www.spamhaus.org/returnc/pub/'}],
    native_dnsbl_observations_error:'<b>Diagnostic storage unavailable</b>'};}});
  try{
    const panel=f.document.getElementById('cs-mail-advanced'),text=panel.textContent;
    assert.match(text,/Provider access blocked/);assert.match(text,/No native observation recorded/);
    assert.match(text,/not enable\/disable settings/);assert.match(text,/unknown, not disabled/);
    assert.match(text,/1970-01-01 00:00:01/);assert.match(text,/separate from SpamAssassin/);
    assert.match(text,/Managed local recipients follow their selected/);assert.doesNotMatch(text,/Native rejections take precedence/);
    assert.equal(panel.querySelector('.alert-danger').textContent,'<b>Diagnostic storage unavailable</b>');
    assert.equal(panel.querySelector('.alert-danger b'),null);
  }finally{f.close();}
});

for(const [name,state,label,actions] of [
  ['connected',{phase:'active',connected:true,hook_enabled:true},'Enabled',['refresh','disable']],
  ['disabled',{phase:'disabled',connected:false},'Disabled',['enable']],
  ['unconfigured',{phase:'unconfigured'},'Disabled',['enable']],
  ['stale connection',{phase:'active',connected:false,hook_enabled:true},'Needs attention',['refresh','disable']],
  ['missing hook',{phase:'active',connected:true,hook_enabled:false},'Needs attention',['refresh','disable']],
  ['pending transition',{phase:'active',transition:'prepared',connected:true,hook_enabled:true},'Transition pending',['recover']],
  ['unavailable state',{phase:'needs-review',error:'<b>State unavailable</b>'},'Needs attention',['recover']],
])test('mail integration shows '+name+' state with only relevant actions',async()=>{
  const f=fixture({hash:'#settings/mail-settings',change:v=>{v.mail_integration={...state,native_dnsbl_observations:[{zone:'zen.spamhaus.org',label:'Spamhaus ZEN',state:'unknown',observed:null,help_url:'https://example.test/help'}]};}});
  try{
    const panel=f.document.getElementById('cs-mail-integration'),controls=f.document.getElementById('cs-mail-integration-controls');
    assert.equal(f.document.getElementById('cs-mail-integration-state').textContent,'Mail integration: '+label);
    assert.match(panel.querySelector('summary').textContent,new RegExp(label));
    assert.deepEqual([...panel.querySelectorAll('[data-action]')].map(b=>b.dataset.action),actions.map(a=>'mail-integration-'+a));
    assert.equal(controls.querySelector('button'),panel.querySelector('button'));
    assert.ok(controls.compareDocumentPosition(panel.querySelector('.scroll'))&f.w.Node.DOCUMENT_POSITION_FOLLOWING);
    assert.match(panel.textContent,/No native observation recorded/);
    if(state.error){assert.match(panel.textContent,/<b>State unavailable<\/b>/);assert.equal(panel.querySelector('.alert-danger b'),null);}
    await settle();assert.equal(f.requests.some(r=>r.action.startsWith('mail-integration-')),false);
  }finally{await f.close();}
});
function data(admin=true){
  const permissions=Object.fromEntries(['scan','schedule','quarantine','restore','repair','cleanup','exceptions','automatic'].map(key=>[key,true]));
  return {context:{owner:'alice',admin},accounts:[{owner:'alice'}],
    sites:[{domain:'site.test',root:'/home/alice/web/site.test/public_html',suspended:false,
      policy:{watch:false,frequency:'never',time:'03:00',timezone:'UTC',weekday:0,monthday:1},
      remediation:{site:{mode:'inherit'},effective:{mode:'report'}}}],
    summary:{open_findings:0,active_scans:0,quarantined:0},findings:[],jobs:[],repairs:[],quarantine:[],history:[],wordpress:[],exceptions:[],notifications:[],remediation_history:[],
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
  const requests=[],timers=new Map(),errors=[];let timerId=0,statusIndex=0;
  function initialize(w){
  w.addEventListener('error',event=>errors.push(event.error));
  if(options.saved)w.sessionStorage.setItem('clamshield-tab',options.saved);
  w.setTimeout=(callback,delay)=>{timers.set(++timerId,{callback,delay});return timerId;};w.clearTimeout=id=>timers.delete(id);
  w.fetch=async(url,request)=>{const body=Object.fromEntries(request.body);requests.push(body);if(body.action==='rules-status'){const value=options.ruleSnapshots?.[Math.min(statusIndex++,options.ruleSnapshots.length-1)]??{pending:false,latest:null,active:values.rules};return {ok:true,json:async()=>({ok:true,...value})};}if(options.api)return options.api(body);return options.response||{ok:false,json:async()=>({ok:false,error:'Fixture API unavailable'})};};
  }
  const dom=new JSDOM(rendered.stdout,{url:'https://panel.test/plugins/clamshield/'+(options.hash||''),runScripts:options.parser?'dangerously':'outside-only',beforeParse:initialize});
  const w=dom.window;
  if(!options.parser)for(const script of w.document.querySelectorAll('script:not([type="application/json"])'))w.eval(script.textContent);
  return {w,requests,timers,errors,tick:async()=>{const entry=timers.entries().next().value;assert.ok(entry);timers.delete(entry[0]);await entry[1].callback();await new Promise(resolve=>setImmediate(resolve));},document:w.document,close:async()=>{await new Promise(resolve=>setImmediate(resolve));w.close();},click:selector=>w.document.querySelector(selector).click(),
    visible:()=>[...new Set([...w.document.querySelectorAll('[data-page]')].filter(section=>!section.hidden).map(section=>section.dataset.page))]};
}
const labels=['Dashboard','Email Shield','On-Demand Actions','Scheduled Scanner','Review','Updates','Settings'];

test('scan schedules have no post-update rescan checkbox or policy field',async()=>{
  const f=fixture({hash:'#scheduled'});
  try{assert.equal(f.document.querySelector('[name=rescan_updates]'),null);
    assert.equal(f.document.querySelector('[data-action=automatic-rechecks-resume]'),null);
    const form=f.document.querySelector('form.cs-policy');form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(value=>value.action==='policy-defaults-save');assert.ok(request);
    assert.equal(Object.hasOwn(JSON.parse(request.policy),'rescan_updates'),false);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('scripts initialize during normal document parsing and SpamAssassin controls remain connected',async()=>{
  const f=fixture({parser:true,hash:'#settings/spamassassin'});
  try{await settle();assert.deepEqual(f.errors,[]);assert.deepEqual(f.visible(),['spamassassin']);
    f.click('#cs-sa-catalog');await settle();assert.equal(f.requests.filter(r=>r.action==='spamassassin-catalog').length,1);
  }finally{await f.close();}
});

test('configuration, update operations and all-account email records stay in their own views',async()=>{
  const f=fixture({hash:'#updates/rules',change:v=>{v.context.view_scope='server';}});
  try{await settle();
    for(const [id,page] of [['cs-yara-scanning','yara-settings'],['cs-providers','provider-settings'],['cs-mail-server-form','mail-settings'],['cs-mail-messages','email-review'],['cs-sa-tasks','history'],['cs-notification-preferences','notifications'],['cs-notification-list','notices']])
      assert.equal(f.document.getElementById(id).closest('[data-page]').dataset.page,page,id);
    for(const node of f.document.querySelectorAll('[data-page]'))assert.equal(node.hidden,node.dataset.page!=='rules');
    assert.equal(f.document.querySelector('[data-action=rules-build],[data-action=rules-activate]'),null);
    assert.deepEqual([...f.document.getElementById('cs-yara-hosting').querySelectorAll('input')].map(input=>input.name),['web_hosting','web_automatic']);
    const form=f.document.getElementById('cs-forge-install');assert.equal(form.elements.profile.type,'hidden');
    assert.equal(f.document.querySelector('#cs-yara-schedule select[name=profile]').closest('[data-page]').dataset.page,'yara-settings');
  }finally{await f.close();}
});
test('Support Us retains the supplied links and full source notices never appear in operational or technical views',async()=>{
  const full='FULL_UPSTREAM_LICENSE_MARKER '.repeat(100);
  const f=fixture({hash:'#settings/support',change:v=>{
    v.rule_manager.sources=[{id:'web_hosting',name:'Web fixture',kind:'web-hosting',enabled:true,review_only:true,version:'fixture',source_url:'https://github.com/example/rules',license_url:'https://github.com/example/rules/LICENSE',license:full}];
    v.notifications=[{id:'notice',event:'maintenance.completed',owner:'alice',created:1,read_at:null,subject:'fixture',detail:{license:full,licenses:[full]}}];
  }});
  try{assert.doesNotMatch(f.document.body.textContent,/FULL_UPSTREAM_LICENSE_MARKER/);
    const support=f.document.querySelector('[data-page=support]');
    for(const code of ['LDBFB3RRB3E9J','G5RNTC3UF58VU','4NP9RNUYRFRFA'])assert.ok(support.querySelector('a[href="https://www.paypal.com/ncp/payment/'+code+'"]'));
    assert.ok(support.querySelector('a[href="https://sanesecurity.com/donate/"]'));
    for(const link of support.querySelectorAll('a')){assert.equal(link.target,'_blank');assert.match(link.rel,/noopener/);}
  }finally{await f.close();}
});

test('configured remote source updates live in Updates while source choices remain in Settings',async()=>{
  const f=fixture({hash:'#updates/rules',change:v=>v.rule_manager.sources=[{id:'extra',name:'Additional source',kind:'remote',enabled:true,version:'fixture'}]});
  try{const update=f.document.querySelector('[data-action=rules-source-fetch]');
    assert.equal(update.closest('[data-page]').dataset.page,'rules');assert.equal(update.dataset.source_id,'extra');assert.equal(update.dataset.apply,'true');
    assert.equal(f.document.querySelector('[data-action=rules-source-toggle]').closest('[data-page]').dataset.page,'yara-settings');
  }finally{await f.close();}
});
test('YARA scanning settings send real booleans/numbers once and follow maintenance without a page reload',async()=>{
  let resolveSave;
  const f=fixture({hash:'#settings/yara-settings',api:async body=>{
    if(body.action==='yara-settings-save')return new Promise(resolve=>{resolveSave=()=>resolve({ok:true,json:async()=>({ok:true,queued:true})});});
    if(body.action==='yara-settings-status')return {ok:true,json:async()=>({ok:true,pending:false,task:null})};
    return {ok:false,json:async()=>({ok:false,error:'Unused fixture operation'})};
  }});
  try{await settle();const form=f.document.getElementById('cs-yara-scanning');form.elements.enabled.checked=false;form.elements.timeout_seconds.value='12';form.elements.max_file_mib.value='8';
    for(let i=0;i<50;i++)form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    const sent=f.requests.filter(r=>r.action==='yara-settings-save');assert.equal(sent.length,1);assert.deepEqual(JSON.parse(sent[0].policy),{enabled:false,timeout_seconds:12,max_file_mib:8});
    assert.equal(form.querySelector('button').disabled,true);resolveSave();await settle();assert.equal(form.querySelector('button').disabled,false);
    assert.deepEqual(f.visible(),['yara-settings']);
  }finally{await f.close();}
});

test('Trial scans and its permission/category are removed while ordinary YARA controls remain available',async()=>{
  const f=fixture({hash:'#updates/rules',change:v=>{v.rule_trials=[{job_id:'retired-comparison-id',generation:'old-generation'}];}});
  try{await settle();assert.equal(f.document.querySelector('[data-action="rules-trial"]'),null);
    assert.equal(f.document.querySelector('[data-capability="rule_trials"]'),null);
    assert.doesNotMatch(f.document.body.textContent,/Trial scans|Run comparison trial|retired-comparison-id/);
    assert.ok(f.document.getElementById('cs-forge-install'));assert.equal(f.document.querySelector('[data-action="rules-activate"]'),null);
    assert.equal(f.document.querySelector('[name="category"][value="trials"]'),null);
  }finally{await f.close();}
});

test('provider schedule exposes per-provider intervals, minimums and timing with clean database labels',async()=>{
  const f=fixture({hash:'#updates/providers',change:v=>{
    v.providers.automatic=true;v.providers.official={enabled:true,interval_minutes:180};v.providers.securiteinfo.interval_minutes=120;
    v.providers.sanesecurity.interval_minutes=60;v.providers.catalog.securiteinfo=[{name:'securiteinfo.ign2',description:'Provider false-positive exceptions',paid:false}];
    v.providers.catalog.sanesecurity=[{name:'phish.ndb',description:'Phishing and malware',risk:'low'}];
    v.providers.schedule={securiteinfo:{minimum_minutes:60,next_allowed:4071000000,retry_after:4071000000}};
  }});
  try{const form=f.document.getElementById('cs-provider-update-settings');
    assert.equal(form.closest('[data-page]').dataset.page,'providers');
    for(const [provider,value] of [['official',180],['securiteinfo',120],['sanesecurity',60]]){
      const input=form.elements[provider+'_interval_minutes'];assert.equal(Number(input.value),value);assert.equal(input.min,'60');assert.equal(input.step,'1');
      input.value='59';assert.equal(input.checkValidity(),false);input.value=String(value);assert.equal(input.checkValidity(),true);
    }
    const schedule=f.document.getElementById('cs-provider-schedule');assert.match(schedule.textContent,/Last attempt.*Last success.*Next permitted update/);
    assert.match(schedule.textContent,/Freshclam provider cooldown/);assert.match(schedule.textContent,/2099-/);
    const settings=f.document.getElementById('cs-providers');
    assert.match(settings.textContent,/securiteinfo.ign2 - Provider false-positive exceptions/);
    assert.match(settings.textContent,/phish.ndb - Phishing and malware/);
    assert.doesNotMatch(form.textContent,/\u03b2\u20ac|\u0392\u00b7|\ufffd/);
  }finally{await f.close();}
});

test('update schedule saves only timing fields while provider settings retain database and credential ownership',async()=>{
  const f=fixture({hash:'#settings/provider-settings',api:async()=>({ok:false,json:async()=>({ok:false,error:'Fixture: no update performed'})})});
  try{const form=f.document.getElementById('cs-provider-update-settings');form.elements.official_interval_minutes.value='180';form.elements.securiteinfo_interval_minutes.value='120';form.elements.sanesecurity_interval_minutes.value='90';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(r=>r.action==='providers-save');assert.ok(request);const policy=JSON.parse(request.providers);
    assert.equal(policy.official.interval_minutes,180);assert.equal(policy.securiteinfo.interval_minutes,120);assert.equal(policy.sanesecurity.interval_minutes,90);
    assert.equal(typeof policy.automatic,'boolean');
    for(const provider of ['official','securiteinfo','sanesecurity'])assert.deepEqual(Object.keys(policy[provider]),['interval_minutes']);
    assert.match(f.document.getElementById('cs-provider-update-save-status').textContent,/no update performed/);
  }finally{await f.close();}
});
test('provider state, automatic updates and all timing controls live only in Updates, with per-provider actions',async()=>{
  const f=fixture({hash:'#updates/providers',change:v=>{
    v.providers.sanesecurity.enabled=true;
    v.providers.status.activation={state:'active',last_success:5};
    v.providers.status.securiteinfo={state:'downloaded',error:'<img src=x> fixture failure',last_success:3};
    v.providers.schedule={securiteinfo:{minimum_minutes:60,next_allowed:4071000000,retry_after:4071000000}};
  }});
  try{
    const updates=f.document.querySelector('[data-page=providers]'),settings=f.document.querySelector('[data-page=provider-settings]');
    assert.ok(updates.querySelector('[name=automatic]'));assert.equal(settings.querySelector('[name=automatic],[name$="_interval_minutes"]'),null);
    assert.match(updates.textContent,/Database activation: active.*Last success/);assert.match(updates.textContent,/Required · updated with Ubuntu freshclam/);
    assert.doesNotMatch(settings.textContent,/Required · updated with Ubuntu freshclam|Last success|Provider guidance|Database activation/);
    const rows=updates.querySelectorAll('#cs-provider-schedule tr[data-provider]');assert.equal(rows.length,3);
    assert.match(updates.textContent,/Official ClamAV/);assert.match(updates.textContent,/SecuriteInfo/);assert.match(updates.textContent,/SaneSecurity/);
    assert.equal(updates.querySelector('[data-provider=securiteinfo] button').disabled,true);
    assert.equal(updates.querySelector('[data-provider=sanesecurity] button').disabled,false);
    assert.equal(updates.querySelector('img'),null);assert.match(updates.textContent,/<img src=x> fixture failure/);
    updates.querySelector('[data-provider=sanesecurity] button').click();await settle();
    const request=f.requests.find(r=>r.action==='signatures-update');assert.equal(request.provider,'sanesecurity');
    assert.ok(settings.querySelector('[name=si_key]'));assert.ok(settings.querySelector('[name=si_enabled]'));
  }finally{await f.close();}
});
test('saving an update schedule keeps settings drafts, updates saved timing and shows a local receipt',async()=>{
  let finish;const f=fixture({hash:'#updates/providers',api:()=>new Promise(resolve=>finish=resolve)});
  try{
    const settings=f.document.getElementById('cs-providers'),form=f.document.getElementById('cs-provider-update-settings');
    settings.elements.si_key.value='unsaved-credential';form.elements.official_interval_minutes.value='180';form.elements.automatic.checked=true;
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(form.querySelector('[type=submit]').textContent,'Saving…');assert.equal(settings.elements.si_key.disabled,false);
    finish({ok:true,json:async()=>({ok:true,providers:{automatic:true,official:{enabled:true},status:{official:{state:'downloaded'}},schedule:{official:{next_allowed:4071000000}}}})});await settle();
    assert.equal(f.document.getElementById('cs-provider-update-save-status').textContent,'Update schedule saved.');
    assert.equal(settings.elements.si_key.value,'unsaved-credential');assert.equal(form.querySelector('[type=submit]').disabled,false);
    const row=f.document.querySelector('#cs-provider-schedule [data-provider=official]');
    assert.match(row.querySelector('[data-provider-next]').textContent,/2099-/);assert.equal(row.querySelector('button').disabled,true);
    assert.equal(row.querySelector('[data-provider-automatic-off]').hidden,true);
    settings.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    const saved=JSON.parse(f.requests.filter(r=>r.action==='providers-save').at(-1).providers);
    assert.equal(saved.automatic,undefined);assert.equal(saved.official,undefined);assert.equal(saved.securiteinfo.interval_minutes,undefined);
    finish({ok:true,json:async()=>({ok:true})});await settle();
  }finally{await f.close();}
});
test('provider Save shows nearby pending and saved states, prevents duplicates and links to the actual update action',async()=>{
  let finish;const f=fixture({hash:'#settings/provider-settings',api:()=>new Promise(resolve=>finish=resolve)});
  try{
    const form=f.document.getElementById('cs-providers'),button=form.querySelector('[type="submit"]'),status=f.document.getElementById('cs-provider-save-status');
    form.elements.si_key.value='a'.repeat(128);
    const submit=()=>form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    submit();assert.equal(button.textContent,'Saving…');assert.equal(button.disabled,true);
    assert.equal(form.getAttribute('aria-busy'),'true');assert.match(status.textContent,/Saving provider settings/);
    submit();assert.equal(f.requests.filter(r=>r.action==='providers-save').length,1);
    finish({ok:true,json:async()=>({ok:true,providers:{securiteinfo:{has_key:true}}})});await settle();
    assert.equal(button.disabled,false);assert.equal(button.textContent,'Save provider settings');
    assert.equal(form.getAttribute('aria-busy'),'false');assert.match(status.textContent,/Provider settings saved/);
    assert.equal(status.className,'');assert.equal(form.elements.si_key.value,'');assert.match(form.elements.si_key.placeholder,/Saved/);
    assert.equal(f.document.getElementById('cs-provider-activate-link').hidden,false);
    assert.deepEqual(f.visible(),['provider-settings']);
    f.click('#cs-provider-activate-link');assert.deepEqual(f.visible(),['providers']);
    assert.equal(f.document.activeElement.id,'cs-signature-update');assert.equal(f.requests.length,1);
  }finally{await f.close();}
});
test('provider Save failures remain beside the button as escaped text and allow retry without losing the draft',async()=>{
  let attempt=0;const f=fixture({hash:'#settings/provider-settings',api:async()=>++attempt===1?
    {ok:false,json:async()=>({ok:false,error:'<img src=x onerror=bad()> Invalid account key'})}:
    {ok:true,json:async()=>({ok:true})}});
  try{
    const form=f.document.getElementById('cs-providers'),button=form.querySelector('[type="submit"]'),status=f.document.getElementById('cs-provider-save-status');
    form.elements.si_key.value='draft-key';form.elements.si_plan.value='professional';
    const submit=()=>form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    submit();await settle();assert.match(status.textContent,/Could not confirm.*Invalid account key/);
    assert.equal(status.querySelector('img'),null);assert.equal(button.disabled,false);assert.equal(status.className,'error');
    assert.equal(form.elements.si_key.value,'draft-key');assert.equal(form.elements.si_plan.value,'professional');
    assert.equal(f.document.getElementById('cs-provider-activate-link').hidden,true);
    submit();await settle();assert.match(status.textContent,/Provider settings saved/);assert.equal(status.className,'');
    form.elements.si_plan.value='gold';form.elements.si_plan.dispatchEvent(new f.w.Event('input',{bubbles:true}));
    assert.equal(status.textContent,'Unsaved changes.');assert.equal(f.document.getElementById('cs-provider-activate-link').hidden,true);
  }finally{await f.close();}
});
test('provider Save timeout releases the form without claiming the server failed to save',async()=>{
  const f=fixture({hash:'#settings/provider-settings'});
  try{
    f.w.fetch=(_url,request)=>new Promise((_resolve,reject)=>request.signal.addEventListener('abort',()=>reject(new Error('Aborted'))));
    const form=f.document.getElementById('cs-providers');form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.ok([...f.timers.values()].some(v=>v.delay===30000));await f.tick();
    assert.match(f.document.getElementById('cs-provider-save-status').textContent,/confirmation timed out.*check whether the settings were saved/);
    assert.equal(form.querySelector('[type="submit"]').disabled,false);assert.equal(form.getAttribute('aria-busy'),'false');
  }finally{await f.close();}
});
test('native resources show measured current and peak RAM separately from limits with one shared engine',async()=>{
  const limits={cpu_percent:100,memory_mib:2048,io_weight:100};
  const f=fixture({hash:'#settings/resources',change:v=>{
    const service={active:false,memory_current:0,memory_bytes:2147483648,cpu_percent:100,io_weight:100};
    v.resources={policy:{website_clamav:limits,mail_clamav:limits,website_worker:limits},
      services:{website_clamav:{...service,title:'Website ClamAV'},mail_clamav:{...service,title:'Email ClamAV'},website_worker:{...service,title:'Website worker'}},
      memory:{MemTotal:4294967296,MemAvailable:2147483648},recovery_pending:false,website_policy:{enabled:true},
      native_clamav:{active:true,memory_current:1073741824,memory_peak:1610612736,memory_bytes:null,rss_bytes:1006632960,pss_bytes:996147200}};
  }});
  try{
    const view=f.document.querySelector('[data-page="resources"]');assert.match(view.textContent,/One shared native engine/);
    assert.match(view.textContent,/Service RAM now/);assert.match(view.textContent,/1024 MiB/);
    assert.match(view.textContent,/Service peak since start/);assert.match(view.textContent,/1536 MiB/);
    assert.match(view.textContent,/Configured service memory limit/);assert.match(view.textContent,/Unlimited/);
    assert.equal(view.querySelectorAll('input[type="number"][name^="website_clamav."]').length,0);
    assert.equal(view.querySelectorAll('input[type="number"][name^="mail_clamav."]').length,0);
    assert.equal(view.querySelectorAll('input[type="hidden"][name^="mail_clamav."]').length,3);
    assert.match(view.querySelector('[data-action="website-engine-stop"]').textContent,/Disable website ClamAV scanning/);
    assert.match(view.textContent,/leaves the native daemon running for email/);
  }finally{await f.close();}
});

test('DNS observations stay unknown without evidence and excluding one zone preserves other checks until explicit apply',async()=>{
  const f=fixture({hash:'#settings/spamassassin',change:v=>{
    v.spamassassin.policy.blocked_zones=['existing.test'];
    v.spamassassin.dns_observations=[
      {label:'Validity Certified',zone:'sa-trusted.bondedsender.org',state:'blocked',observation:{observed:1},action:'Review provider access',help_url:'https://example.test/help'},
      {label:'Validity Safe',zone:'sa-accredit.habeas.com',state:'failed',observation:{observed:3},action:'Review resolver access',help_url:'https://example.test/help'},
      {label:'URIBL',zone:'multi.uribl.com',state:'unknown',observation:null,help_url:'https://example.test/help'},
      {label:'DNSWL',zone:'list.dnswl.org',state:'response-observed',observation:{observed:2},help_url:'https://example.test/help'}];
  }});
  try{
    const section=f.document.querySelector('[data-page="spamassassin"]');
    assert.match(section.textContent,/Unknown — no response recorded/);assert.match(section.textContent,/not live availability tests/);
    assert.match(section.textContent,/DNS query failed/);assert.match(section.textContent,/Review resolver access/);assert.match(section.textContent,/DNS response observed/);assert.match(section.textContent,/Query blocked by provider/);
    const form=f.document.getElementById('cs-spamassassin'),button=section.querySelector('[data-dns-exclude]');
    assert.equal(button.className,'button');button.click();button.click();assert.equal(f.requests.length,0);
    assert.equal(form.elements.blocked_zones.value,'existing.test\nsa-trusted.bondedsender.org');
    assert.equal(form.elements.rbl_enabled.checked,true);assert.equal(form.elements.uribl_enabled.checked,false);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(row=>row.action==='spamassassin-save'),policy=JSON.parse(request.policy);
    assert.deepEqual(policy.blocked_zones,['existing.test','sa-trusted.bondedsender.org']);assert.equal(policy.rbl_enabled,true);assert.equal(policy.uribl_enabled,false);
  }finally{await f.close();}
});

test('server-wide database controls are shared and preserve saved choices until explicit save',async()=>{
  const f=fixture({hash:'#settings/provider-settings',change:v=>{
    v.providers.securiteinfo.plan='professional';v.providers.securiteinfo.databases=['securiteinfo.ign2','securiteinfo.pdb'];
    v.providers.securiteinfo.website_databases=['securiteinfo.ign2'];v.providers.securiteinfo.mail_databases=['securiteinfo.ign2','securiteinfo.pdb'];
    v.providers.selection_conflicts={securiteinfo:['securiteinfo.pdb']};
    v.providers.catalog.securiteinfo=[{name:'securiteinfo.ign2',description:'Exceptions',scope:'server'},
      {name:'securiteinfo.pdb',description:'Phishing',scope:'server'},
      {name:'javascript.ndb',description:'JavaScript',scope:'profile'}];
  }});
  try{
    const form=f.document.getElementById('cs-providers');assert.equal(f.requests.length,0);
    assert.match(form.textContent,/Existing server-wide selections differ/);
    assert.equal(form.querySelectorAll('input[value="securiteinfo.pdb"]').length,1);
    assert.equal(form.querySelector('input[name="si_shared_databases"][value="securiteinfo.pdb"]').checked,true);
    assert.equal(form.querySelectorAll('input[value="javascript.ndb"]').length,2);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const saved=JSON.parse(f.requests.find(r=>r.action==='providers-save').providers).securiteinfo;
    assert.deepEqual(saved.shared_databases,['securiteinfo.ign2','securiteinfo.pdb']);
    assert.deepEqual(saved.website_databases,[]);assert.deepEqual(saved.mail_databases,[]);
  }finally{await f.close();}
});

test('recommended provider defaults are an explicit unsaved draft and preserve installed custom choices',async()=>{
  const pua='securiteinfo-pua-app-and-vulnerabilities.ndb';
  const f=fixture({hash:'#settings/provider-settings',change:v=>{
    v.providers.securiteinfo.plan='professional';v.providers.securiteinfo.databases=['spam_marketing.ndb',pua];
    v.providers.catalog.securiteinfo=[{name:'javascript.ndb',description:'Malicious JavaScript',paid:true,risk:'not-rated'},
      {name:'spam_marketing.ndb',description:'Marketing spam',paid:true,risk:'not-rated'},
      {name:pua,description:'Potentially unwanted applications',paid:true,risk:'not-rated'}];
    v.providers.sanesecurity.databases=['high.ndb'];
    v.providers.catalog.sanesecurity=[{name:'low.ndb',description:'Malware',risk:'low',risk_url:'https://sanesecurity.com/usage/signatures/'},
      {name:'high.ndb',description:'High risk',risk:'high'}];
    v.providers.recommended={professional:{securiteinfo:{website_databases:['javascript.ndb'],mail_databases:['javascript.ndb','spam_marketing.ndb']},
      sanesecurity:{website_databases:['low.ndb'],mail_databases:['low.ndb']}}};
  }});
  try{
    const form=f.document.getElementById('cs-providers'),input=(prefix,profile,name)=>form.querySelector(`input[name="${prefix}_${profile}_databases"][value="${name}"]`);
    assert.equal(input('si','website',pua).checked,true);assert.equal(input('sane','mail','high.ndb').checked,true);
    assert.match(form.textContent,/False-positive risk/);assert.match(form.textContent,/Not rated/);assert.match(form.textContent,/High/);
    const interval=f.document.getElementById('cs-provider-update-settings').elements.securiteinfo_interval_minutes;interval.value='180';const enabled=form.elements.si_enabled.checked;
    f.click('#cs-provider-recommended');assert.equal(f.requests.length,0);
    assert.equal(input('si','website','spam_marketing.ndb').checked,false);assert.equal(input('si','mail','spam_marketing.ndb').checked,true);
    assert.equal(input('si','website',pua).checked,false);assert.equal(input('sane','mail','high.ndb').checked,false);
    assert.equal(form.elements.si_enabled.checked,enabled);assert.equal(interval.value,'180');
    assert.match(f.document.getElementById('cs-provider-recommended-status').textContent,/Review and save/);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(r=>r.action==='providers-save'),settings=JSON.parse(request.providers);
    assert.deepEqual(settings.securiteinfo.website_databases,['javascript.ndb']);
    assert.deepEqual(settings.securiteinfo.mail_databases,['javascript.ndb','spam_marketing.ndb']);
  }finally{await f.close();}
});
const notificationKinds={detections:'Website malware detections',integrity:'WordPress integrity differences',scan_problems:'Failed, incomplete or interrupted scans',health:'Engine and scanning-data health',maintenance:'Updates and maintenance',mail:'Email protection alerts',actions:'Quarantine, cleaning and repairs',other:'Other notifications'};
const notificationSettings=(extra={})=>({account:'alice',server:false,categories:notificationKinds,settings:{bell:false,categories:Object.keys(notificationKinds),bell_categories:Object.keys(notificationKinds),revision:'preferences-one',last_sent:null,error:null,...extra}});
const notice=(event,id='notice-one',extra={})=>({id,event,owner:'alice',subject:'site.test',created:1,read_at:null,detail:{counters:{scanned:20,infected:1,errors:0}},...extra});
const reviewResponse=(body,extra={})=>({ok:true,json:async()=>({ok:true,list:body.list,html:'<tr><td>Current page</td></tr>',total:560,offset:Number(body.offset||0),limit:Number(body.limit||50),next_offset:50,options:{status:['open'],type:['clamav'],provider:['official']},accounts:['alice','bob'],can_clear:true,...extra})});

test('Review filters query the complete server list and paginate beyond the old preview limit',async()=>{
  const f=fixture({hash:'#review/findings',change:v=>{v.context.view_scope='server';},api:async body=>reviewResponse(body,{next_offset:550})});
  try{await settle();const form=f.document.querySelector('[data-review-list=findings]'),bar=f.document.querySelector('[data-review-pager=findings]');
    assert.match(bar.textContent,/Showing 1–50 of 560/);bar.querySelector('[data-review-command=next]').click();await settle();
    assert.equal(f.requests.filter(r=>r.action==='review-list').at(-1).offset,'550');assert.match(bar.textContent,/Showing 551–560 of 560/);
    form.elements.search.value='site.test';form.elements.account.value='bob';form.elements.type.value='clamav';form.elements.provider.value='official';form.elements.from.value='2026-11-01';form.elements.to.value='2026-11-20';form.elements.rows.value='25';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const sent=f.requests.filter(r=>r.action==='review-list').at(-1);assert.equal(sent.scope,'server');assert.equal(sent.token,'fixture-token');assert.equal(sent.offset,'0');assert.equal(sent.limit,'25');
    assert.deepEqual(JSON.parse(sent.filters),{search:'site.test',account:'bob',status:'',type:'clamav',provider:'official',from:'2026-11-01',to:'2026-11-20',order:'newest'});
    assert.equal(form.elements.account.options[1].textContent,'alice');assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Review ignores stale responses, serializes refreshes and retains rows on escaped failures',async()=>{
  const pending=[];
  const f=fixture({hash:'#review/history',api:body=>body.list==='history'?new Promise(resolve=>pending.push({body,resolve})):reviewResponse(body)});
  try{await settle();const form=f.document.querySelector('[data-review-list=history]'),rows=f.document.getElementById('cs-review-history-rows');
    form.elements.search.value='latest';form.dispatchEvent(new f.w.Event('change',{bubbles:true}));assert.equal(pending.length,1);
    pending[0].resolve(reviewResponse(pending[0].body,{html:'<tr><td>STALE RESPONSE</td></tr>'}));await settle();
    assert.doesNotMatch(rows.textContent,/STALE/);assert.equal(pending.length,2);assert.equal(JSON.parse(pending[1].body.filters).search,'latest');
    pending[1].resolve(reviewResponse(pending[1].body,{html:'<tr><td>Latest rows</td></tr>'}));await settle();assert.equal(rows.textContent,'Latest rows');
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));pending[2].resolve({ok:false,json:async()=>({ok:false,error:'<b>Query unavailable</b>'})});await settle();
    assert.equal(rows.textContent,'Latest rows');assert.match(form.nextElementSibling.nextElementSibling.textContent,/Query unavailable.*last loaded rows are kept/);assert.equal(form.nextElementSibling.nextElementSibling.querySelector('b'),null);
    assert.equal(form.querySelector('[type=submit]').disabled,false);
  }finally{await f.close();}
});

test('newly paged findings retain owner-bound actions and administrator capability restrictions',async()=>{
  const html='<tr data-owner="bob"><td><button class="button" data-action="quarantine" data-finding_id="next-page-finding">Quarantine</button><button class="button" data-action="exception-add" data-finding_id="next-page-finding">Trust</button></td></tr>';
  const f=fixture({hash:'#review/findings',change:v=>{v.context.view_scope='server';v.website_permissions.effective.exceptions=false;},api:async body=>body.action==='review-list'?reviewResponse(body,{html}):{ok:false,json:async()=>({ok:false,error:'Fixture action stopped'})}});
  try{await settle();const rows=f.document.getElementById('cs-review-findings-rows');
    assert.equal(rows.querySelector('[data-action=exception-add]').disabled,true);rows.querySelector('[data-action=quarantine]').click();await settle();
    const request=f.requests.find(r=>r.action==='quarantine');assert.equal(request.owner,'bob');assert.equal(request.finding_id,'next-page-finding');assert.equal(request.token,'fixture-token');
    assert.match(f.document.getElementById('cs-message').textContent,/Fixture action stopped/);assert.equal(rows.querySelector('[data-action=quarantine]').disabled,false);
  }finally{await f.close();}
});

test('retained findings from removed sources are explicitly historical',async()=>{
  const f=fixture({change:v=>{v.findings=[{id:'old-source-finding',owner:'alice',domain:'site.test',path:'inert.php',engine:'yara',provider:'php-hosting',signature:'php_hosting:NonPrintableChars',status:'open',detail:{source_removed:true,review_only:true},fingerprint:{},site_availability:{available:true}}];}});
  try{assert.match(f.document.getElementById('cs-review-findings-rows').textContent,/Historical finding from a removed rule source.*no longer used by current scans/);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('uploads cleanup suggestions explain policy and route to WordPress instead of backup repair',async()=>{
  const make=(engine,id)=>({id,owner:'alice',domain:'site.test',path:id+'.jpg',engine,provider:'local-policy',signature:engine==='recovery-policy'?'WordPress.Uploads.Policy':'Fixture.Detection',status:'open',detail:{},fingerprint:{},site_availability:{available:true}});
  const f=fixture({change:v=>{v.findings=[make('recovery-policy','old-policy'),make('clamav','actual-detection')];}});
  try{const rows=f.document.querySelectorAll('#cs-review-findings-rows tr'),policy=rows[0],actual=rows[1];
    assert.match(policy.textContent,/Uploads cleanup suggestion.*not a malware detection/);
    assert.equal(policy.querySelector('[data-action=repair-backup-preview]'),null);
    assert.equal(policy.querySelector('[data-action=quarantine]'),null);
    assert.ok(actual.querySelector('[data-action=repair-backup-preview]'));
    policy.querySelector('[data-tab=wordpress-recovery]').click();assert.deepEqual(f.visible(),['wordpress-recovery']);
    assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Delete all history requires a scoped count confirmation and guards repeated confirmation clicks',async()=>{
  let finish;
  const f=fixture({hash:'#review/history',change:v=>{v.context.view_scope='server';},api:async body=>{
    if(body.action==='review-bulk-preview')return {ok:true,json:async()=>({ok:true,token:'bound-proof',count:734,scope:'server'})};
    if(body.action==='review-bulk-clear')return new Promise(resolve=>{finish=()=>resolve({ok:true,json:async()=>({ok:true,changed:734})});});
    return reviewResponse(body);
  }});
  try{await settle();f.click('[data-review-pager=history] [data-review-command=delete-all]');await settle();
    const confirmation=f.document.querySelector('[data-review-confirmation=history]');assert.equal(confirmation.hidden,false);assert.match(confirmation.textContent,/734 history events.*all current server accounts.*hidden by filters/);
    assert.equal(f.requests.filter(r=>r.action==='review-bulk-clear').length,0);confirmation.querySelector('button').click();confirmation.querySelector('button').click();
    const sent=f.requests.filter(r=>r.action==='review-bulk-clear');assert.equal(sent.length,1);assert.equal(sent[0].confirmation,'bound-proof');assert.equal(sent[0].scope,'server');assert.equal(sent[0].list,'history');
    finish();await settle();assert.equal(confirmation.hidden,true);assert.equal(f.requests.filter(r=>r.action==='review-list').at(-1).offset,'0');
  }finally{await f.close();}
});

test('bulk notification read and dynamically loaded individual Mark read both use AJAX',async()=>{
  let finish;
  const html='<tr data-owner="bob" data-notification="paged-notice" data-event="scan.malware_found" data-read="false"><td>Finding</td><td><button type="button" class="button cs-notification-read">Mark read</button><p class="cs-notification-read-status"></p></td></tr>';
  const f=fixture({hash:'#review/notices',change:v=>{v.context.view_scope='server';},api:async body=>{
    if(body.action==='notification-settings-get')return {ok:true,json:async()=>({ok:true,...notificationSettings()})};
    if(body.action==='review-read-all')return new Promise(resolve=>{finish=()=>resolve({ok:true,json:async()=>({ok:true,changed:734})});});
    if(body.action==='notification-read')return {ok:true,json:async()=>({ok:true,read:true})};
    return reviewResponse(body,{html});
  }});
  try{await settle();f.click('[data-review-pager=notices] [data-review-command=read-all]');f.click('[data-review-pager=notices] [data-review-command=read-all]');
    const sent=f.requests.filter(r=>r.action==='review-read-all');assert.equal(sent.length,1);assert.equal(sent[0].scope,'server');finish();await settle();
    f.click('#cs-notification-list .cs-notification-read');await settle();assert.equal(f.requests.find(r=>r.action==='notification-read').owner,'bob');
    assert.deepEqual(f.visible(),['notices']);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Global Email uses one paged message list with account and decision filters',async()=>{
  const f=fixture({hash:'#review/email-review',change:v=>{v.context.view_scope='server';},api:async body=>body.action==='review-list'?reviewResponse(body,{html:'<tr><td>fixture account</td></tr>'}):{ok:false,json:async()=>({ok:false,error:'Fixture summary unavailable'})}});
  try{await settle();
    assert.deepEqual([...f.document.querySelectorAll('[data-review-list]')].map(form=>form.dataset.reviewList).sort(),['activity','automatic','email-messages','exceptions','findings','history','notices','quarantine','repairs']);
    for(const kind of ['email-messages'])assert.ok(f.requests.find(r=>r.action==='review-list'&&r.list===kind&&r.scope==='server'));
    const before=f.requests.filter(r=>r.action==='review-list').length;f.click('#cs-email-messages-refresh');await settle();assert.equal(f.requests.filter(r=>r.action==='review-list').length,before+1);
    assert.equal(f.document.getElementById('cs-mail-server-accounts'),null);assert.equal(f.document.getElementById('cs-mail-server-decisions'),null);
    const form=f.document.querySelector('[data-review-list=email-messages]');for(const field of ['account','search','status','type','provider','from','to','rows'])assert.ok(form.elements.namedItem(field));
    assert.equal(f.document.querySelector('[data-review-pager=quarantine] [data-review-command=delete-all]').textContent,'Delete quarantine files');
    assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('navigation controls in paged automatic actions still open their Review destination',async()=>{
  const f=fixture({hash:'#review/activity',api:async body=>reviewResponse(body,{html:'<tr><td><button class="button" data-tab="repairs">Review repair</button></td></tr>'})});
  try{await settle();f.click('#cs-review-automatic-rows [data-tab=repairs]');await settle();assert.deepEqual(f.visible(),['repairs']);assert.equal(f.w.location.hash,'#review/repairs');assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('left row checkboxes select only eligible page records and Clear selected sends their exact IDs',async()=>{
  const f=fixture({hash:'#review/findings',api:async body=>body.action==='review-bulk-preview'?{ok:true,json:async()=>({ok:true,token:'selected-proof',count:2,scope:'account'})}:body.action==='review-bulk-clear'?{ok:true,json:async()=>({ok:true,changed:2})}:reviewResponse(body,{html:'<tr><td>One</td></tr><tr><td>Two</td></tr><tr><td>Protected</td></tr>',selection:[{id:'one',allowed:true},{id:'two',allowed:true},{id:'protected',allowed:false}]})});
  try{await settle();const bar=f.document.querySelector('[data-review-pager=findings]'),rows=f.document.querySelectorAll('#cs-review-findings-rows tr');
    assert.equal(bar.querySelector('[data-review-command=delete-all]').textContent,'Clear all findings');assert.ok(rows[0].firstElementChild.querySelector('input[type=checkbox]'));assert.equal(rows[2].querySelector('input').disabled,true);
    bar.querySelector('[aria-label="Select this page"]').click();assert.match(bar.textContent,/2 selected/);bar.querySelector('[data-review-command=clear-selected]').click();await settle();
    const sent=f.requests.find(r=>r.action==='review-bulk-preview');assert.deepEqual(JSON.parse(sent.selected),['one','two']);assert.equal(f.requests.some(r=>r.action==='review-bulk-clear'),false);
    const confirmation=f.document.querySelector('[data-review-confirmation=findings]');assert.match(confirmation.textContent,/selected 2 finding records/);assert.match(confirmation.textContent,/Website files.*unchanged/);confirmation.querySelector('button').click();await settle();
    assert.equal(f.requests.find(r=>r.action==='review-bulk-clear').confirmation,'selected-proof');assert.match(bar.textContent,/0 selected/);assert.equal(bar.querySelector('[data-review-command=clear-selected]').disabled,true);
  }finally{await f.close();}
});

test('quarantine deletion follows bounded batches and reports retained errors as plain text',async()=>{
  let step=0;
  const f=fixture({hash:'#review/quarantine',api:async body=>body.action==='review-bulk-preview'?{ok:true,json:async()=>({ok:true,token:'delete-proof',count:7,retained:1,scope:'account'})}:body.action==='review-bulk-clear'?{ok:true,json:async()=>({ok:true,changed:++step===1?5:6,pending:step===1,failed:step===1?0:1,failures:[{error:'<b>Changed content retained</b>'}]})}:reviewResponse(body)});
  try{await settle();f.click('[data-review-pager=quarantine] [data-review-command=delete-all]');await settle();const confirmation=f.document.querySelector('[data-review-confirmation=quarantine]');assert.match(confirmation.textContent,/Permanently deletes.*Restore will no longer/);assert.match(confirmation.textContent,/1 active or protected/);
    confirmation.querySelector('button').click();confirmation.querySelector('button').click();await settle();assert.equal(step,2);assert.equal(f.requests.filter(r=>r.action==='review-bulk-clear').length,2);
    const status=f.document.querySelector('[data-review-pager=quarantine]').nextElementSibling;assert.match(status.textContent,/6 processed; 1 retained.*Changed content retained/);assert.equal(status.querySelector('b'),null);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('account email bulk controls retain the original preview and delivery row actions',async()=>{
  const f=fixture({hash:'#review/email-review',api:async body=>body.action==='review-list'?reviewResponse(body):{ok:false,json:async()=>({ok:false,error:'Unused fixture API'})}});
  try{await settle();const body=f.document.getElementById('cs-mail-history');body.innerHTML='<tr data-review-id="decision-one" data-review-allowed="true"><td>Original mail details</td><td><button>Existing review action</button></td></tr>';
    f.document.dispatchEvent(new f.w.CustomEvent('clamshield-mail-rows',{detail:body}));assert.equal(body.querySelector('button').textContent,'Existing review action');assert.equal(body.querySelector('input[type=checkbox]').value,'decision-one');assert.equal(body.closest('table').querySelector('th').textContent,'Select');
    const bar=f.document.querySelector('[data-review-pager=email-decisions]');bar.querySelector('[aria-label="Select this page"]').click();assert.match(bar.textContent,/1 selected/);assert.equal(bar.querySelector('[data-review-command=clear-selected]').disabled,false);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Global Deliver anyway queues once for the recorded account and original recipient without leaving Global',async()=>{
  let finish;
  const html='<tr data-owner="bob"><td><form class="cs-review-email-deliver" data-delivery="stored-recipient"><input name="note" required><button type="submit">Deliver anyway</button><p class="cs-review-email-status"></p></form></td></tr>';
  const f=fixture({hash:'#review/email-review',change:v=>{v.context.view_scope='server';},api:async body=>body.action==='mail-release'?new Promise(resolve=>{finish=()=>resolve({ok:true,json:async()=>({ok:true,queued:true})});}):body.action==='review-list'?reviewResponse(body,{html:body.list==='email-messages'?html:'<tr><td>Decision</td></tr>'}):{ok:false,json:async()=>({ok:false,error:'Unused fixture API'})}});
  try{await settle();const form=f.document.querySelector('.cs-review-email-deliver');form.elements.note.value='Reviewed sender and attachment';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    const sent=f.requests.filter(r=>r.action==='mail-release');assert.equal(sent.length,1);assert.equal(sent[0].owner,'bob');assert.equal(sent[0].delivery_id,'stored-recipient');assert.equal(sent[0].note,'Reviewed sender and attachment');assert.equal(sent[0].recipient,undefined);
    finish();await settle();assert.deepEqual(f.visible(),['email-review']);assert.match(f.document.querySelector('[data-review-pager=email-messages]').nextElementSibling.textContent,/queued.*Delivery is not confirmed/);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Email clear list and physical quarantine deletion use distinct proofs and selected IDs',async()=>{
  const selected=[{id:'stored:private',allowed:true,delivery_id:'private',can_delete:true},{id:'decision:done',allowed:true,delivery_id:null,can_delete:false},{id:'stored:uncertain',allowed:true,delivery_id:'uncertain',can_delete:false}];
  const f=fixture({hash:'#review/email-review',change:v=>{v.context.view_scope='server';},api:async body=>body.action==='review-bulk-preview'?{ok:true,json:async()=>({ok:true,token:'email-proof',count:1,retained:2,scope:'server'})}:body.action==='review-bulk-clear'?{ok:true,json:async()=>({ok:true,changed:1})}:reviewResponse(body,{html:'<tr><td>Quarantined</td></tr><tr><td>Completed</td></tr><tr><td>Unconfirmed</td></tr>',selection:selected})});
  try{await settle();const bar=f.document.querySelector('[data-review-pager=email-messages]');
    assert.equal(f.requests.some(row=>row.action==='mail-server-get'||row.action==='mail-server-activity'),false);
    assert.equal(bar.querySelector('[data-review-command=delete-all]').textContent,'Clear list');
    assert.equal(bar.querySelector('[data-review-command=purge-all]').textContent,'Delete quarantined email');
    bar.querySelector('[aria-label="Select this page"]').click();bar.querySelector('[data-review-command=clear-selected]').click();await settle();
    let sent=f.requests.filter(row=>row.action==='review-bulk-preview').at(-1);assert.equal(sent.list,'email-messages');assert.deepEqual(JSON.parse(sent.selected),selected.map(row=>row.id));
    const confirmation=f.document.querySelector('[data-review-confirmation=email-messages]');assert.match(confirmation.textContent,/recovery evidence.*retained/);confirmation.querySelectorAll('button')[1].click();
    bar.querySelector('[data-review-command=purge-selected]').click();await settle();sent=f.requests.filter(row=>row.action==='review-bulk-preview').at(-1);assert.equal(sent.list,'email-stored');assert.deepEqual(JSON.parse(sent.selected),['private']);
    assert.match(confirmation.textContent,/Permanently deletes.*quarantined email/);confirmation.querySelector('button').click();await settle();
    sent=f.requests.find(row=>row.action==='review-bulk-clear');assert.equal(sent.list,'email-stored');assert.equal(sent.confirmation,'email-proof');assert.equal(f.requests.at(-1).list,'email-messages');assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('notification preferences save selected types and Bell without reload while filters retain access to recorded events',async()=>{
  const f=fixture({hash:'#settings/notifications',change:v=>v.notifications=[notice('scan.malware_found'),notice('scan.partial','notice-two'),notice('wordpress.integrity_issues','notice-three')],api:async body=>({ok:true,json:async()=>({ok:true,...notificationSettings(body.action==='notification-settings-save'?JSON.parse(body.policy):{})})})});
  try{await settle();const form=f.document.getElementById('cs-notification-preferences');assert.equal(form.elements.bell.checked,false);
    assert.match(form.textContent,/ClamShield notifications/);assert.match(form.textContent,/HestiaCP notifications/);assert.doesNotMatch(form.textContent,/Also notify me on Bell/);
    for(const input of form.querySelectorAll('[name=category]'))input.checked=input.value==='detections';
    for(const input of form.querySelectorAll('[name=bell_category]'))input.checked=input.value==='health';form.elements.bell.checked=true;
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const saved=f.requests.find(body=>body.action==='notification-settings-save');assert.deepEqual(JSON.parse(saved.policy),{bell:true,categories:['detections'],bell_categories:['health']});assert.equal(saved.revision,'preferences-one');
    const rows=[...f.document.querySelectorAll('#cs-notification-list tr')];assert.deepEqual(rows.map(r=>r.hidden),[false,true,true]);
    assert.match(f.document.getElementById('cs-notification-preference-status').textContent,/saved/);
    const type=f.document.getElementById('cs-notification-type');type.value='integrity';type.dispatchEvent(new f.w.Event('change'));assert.deepEqual(rows.map(r=>r.hidden),[true,true,false]);
    type.value='all';type.dispatchEvent(new f.w.Event('change'));assert.equal(rows.filter(r=>!r.hidden).length,3);
    assert.equal(f.document.querySelector('[data-main-tab=settings]').getAttribute('aria-current'),'page');
  }finally{await f.close();}
});

test('notification settings link to the Review list without moving its clear controls',async()=>{
  const f=fixture({hash:'#settings/notifications',api:async body=>body.action==='review-list'?reviewResponse(body,{html:'',total:0}):{ok:true,json:async()=>({ok:true,...notificationSettings()})}});
  try{await settle();const settings=f.document.getElementById('cs-notification-settings');
    const link=settings.querySelector('[data-tab=notices]');assert.equal(link.textContent,'View notifications');
    assert.equal(settings.querySelector('[data-review-command=delete-all]'),null);
    link.click();await settle();assert.equal(f.w.location.hash,'#review/notices');assert.deepEqual(f.visible(),['notices']);
    assert.equal(f.document.querySelector('[data-review-pager=notices] [data-review-command=delete-all]').textContent,'Clear all notifications');
    assert.ok(f.document.querySelector('[data-review-pager=notices] [data-review-command=read-all]'));assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('native Bell delivery errors appear as plain text in Review without automatic delivery requests',async()=>{
  const error='<b>v-add-user-notification exited with code 7</b>. No automatic retry.';
  const f=fixture({hash:'#review/notices',api:async body=>body.action==='review-list'?reviewResponse(body,{bell_delivery_error:error,html:'',total:0}):{ok:true,json:async()=>({ok:true,...notificationSettings()})}});
  try{await settle();const status=f.document.querySelector('[data-review-pager=notices]').nextElementSibling;
    assert.match(status.textContent,/exited with code 7.*No automatic retry/);assert.equal(status.querySelector('b'),null);
    assert.ok(f.requests.every(body=>['review-list','notification-settings-get'].includes(body.action)));assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Clear all notifications ignores list filters and confirms the scoped count',async()=>{
  const f=fixture({hash:'#review/notices',api:async body=>body.action==='notification-settings-get'?{ok:true,json:async()=>({ok:true,...notificationSettings()})}:body.action==='review-bulk-preview'?{ok:true,json:async()=>({ok:true,token:'notices-proof',count:734,scope:'account'})}:body.action==='review-bulk-clear'?{ok:true,json:async()=>({ok:true,changed:734,bell_pending:3})}:reviewResponse(body,{html:'',total:0})});
  try{await settle();const status=f.document.getElementById('cs-notification-state');status.value='unread';status.dispatchEvent(new f.w.Event('change'));await settle();
    f.click('[data-review-pager=notices] [data-review-command=delete-all]');await settle();
    const preview=f.requests.find(row=>row.action==='review-bulk-preview');assert.equal(preview.list,'notices');assert.equal(preview.filters,undefined);assert.equal(preview.selected,undefined);
    const confirmation=f.document.querySelector('[data-review-confirmation=notices]');assert.match(confirmation.textContent,/734 ClamShield notifications.*hidden by filters/);
    assert.equal(f.requests.some(row=>row.action==='review-bulk-clear'),false);confirmation.querySelector('button').click();await settle();
    assert.equal(f.requests.find(row=>row.action==='review-bulk-clear').confirmation,'notices-proof');assert.equal(confirmation.hidden,true);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('native Bell cleanup errors are visible as text in Review without retrying deletion',async()=>{
  const error='<b>Native deletion failed</b>. No automatic retry.';
  const f=fixture({hash:'#review/notices',api:async body=>body.action==='review-list'?reviewResponse(body,{bell_cleanup_error:error,total:0,html:''}):{ok:true,json:async()=>({ok:true,...notificationSettings()})}});
  try{await settle();const status=f.document.querySelector('[data-review-pager=notices]').nextElementSibling;
    assert.match(status.textContent,/Native deletion failed.*No automatic retry/);assert.equal(status.querySelector('b'),null);
    const before=f.requests.filter(body=>body.action==='review-bulk-clear').length;
    f.document.querySelector('[data-review-list=notices]').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(f.requests.filter(body=>body.action==='review-bulk-clear').length,before);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('AJAX Mark read queues once, uses each Global row owner and immediately updates unread filters',async()=>{
  let finish;
  const f=fixture({hash:'#settings/notifications',change:v=>{v.context.view_scope='server';v.notifications=[notice('scan.malware_found','bob-notice',{owner:'bob'}),notice('health.problem','server-notice',{owner:'@admin'})];},api:body=>body.action==='notification-read'?new Promise(resolve=>{finish=()=>resolve({ok:true,json:async()=>({ok:true,read:true})});}):{ok:true,json:async()=>({ok:true,...notificationSettings()})}});
  try{await settle();const state=f.document.getElementById('cs-notification-state');state.value='unread';state.dispatchEvent(new f.w.Event('change'));
    const row=f.document.querySelector('#cs-notification-list tr'),button=row.querySelector('.cs-notification-read');assert.equal(button.hasAttribute('data-action'),false);
    button.click();button.click();assert.equal(button.disabled,true);assert.equal(button.textContent,'Marking read…');assert.equal(f.requests.filter(b=>b.action==='notification-read').length,1);
    assert.deepEqual(f.requests.at(-1),{token:'fixture-token',owner:'bob',action:'notification-read',notification_id:'bob-notice'});
    finish();await settle();assert.equal(row.dataset.read,'true');assert.equal(row.hidden,true);assert.equal(row.querySelector('.cs-notification-read'),null);
    f.document.querySelectorAll('#cs-notification-list tr')[1].querySelector('button').click();assert.equal(f.requests.at(-1).owner,'alice');finish();await settle();
    assert.equal(f.document.getElementById('cs-notification-empty').hidden,false);assert.match(f.document.getElementById('cs-notification-count').textContent,/0 shown/);
  }finally{await f.close();}
});

test('notification read failures remain escaped, visible and retryable without marking the row read',async()=>{
  let failed=true;
  const f=fixture({hash:'#settings/notifications',change:v=>v.notifications=[notice('scan.malware_found')],api:async body=>body.action==='notification-read'?{ok:!failed,json:async()=>failed?{ok:false,error:'<b>Request unavailable</b>'}:{ok:true,read:true}}:{ok:true,json:async()=>({ok:true,...notificationSettings()})}});
  try{await settle();const row=f.document.querySelector('#cs-notification-list tr');row.querySelector('button').click();await settle();
    assert.equal(row.dataset.read,'false');assert.equal(row.querySelector('button').disabled,false);assert.match(row.querySelector('.cs-notification-read-status').textContent,/Request unavailable/);assert.equal(row.querySelector('.cs-notification-read-status b'),null);
    failed=false;row.querySelector('button').click();await settle();assert.equal(row.dataset.read,'true');
  }finally{await f.close();}
});

test('personal notification preferences explain administrator scope and failed saves preserve the draft',async()=>{
  const f=fixture({hash:'#settings/notifications',change:v=>{v.context.owner='bob';},api:async body=>body.action==='notification-settings-save'?{ok:false,json:async()=>({ok:false,error:'Preferences changed; refresh and retry'})}:{ok:true,json:async()=>({ok:true,...notificationSettings(),account:'admin',server:true})}});
  try{await settle();assert.match(f.document.getElementById('cs-notification-scope').textContent,/Personal preferences for admin.*all server accounts/);
    const form=f.document.getElementById('cs-notification-preferences');form.elements.bell.checked=true;form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(form.elements.bell.checked,true);assert.equal(f.document.getElementById('cs-notification-choices').disabled,false);assert.match(f.document.getElementById('cs-notification-preference-status').textContent,/Preferences changed/);
  }finally{await f.close();}
});

test('notification preference loading failures allow AJAX reading and can be retried explicitly',async()=>{
  let failed=true;
  const f=fixture({hash:'#settings/notifications',change:v=>v.notifications=[notice('scan.malware_found')],api:async body=>body.action==='notification-settings-get'&&failed?{ok:false,json:async()=>({ok:false,error:'Settings unavailable'})}:{ok:true,json:async()=>body.action==='notification-read'?{ok:true,read:true}:{ok:true,...notificationSettings()}}});
  try{await settle();assert.equal(f.document.getElementById('cs-notification-choices').disabled,true);f.document.querySelector('.cs-notification-read').click();await settle();assert.equal(f.document.querySelector('#cs-notification-list tr').dataset.read,'true');
    failed=false;f.click('#cs-notification-refresh');await settle();assert.equal(f.document.getElementById('cs-notification-choices').disabled,false);
  }finally{await f.close();}
});
const auditEvent=(action,detail={},extra={})=>({created:1,actor:'admin',owner:'alice',identity:'current',action,subject:'a'.repeat(32),detail,...extra});

test('fallback history and notifications show actual observation dates and the relevant settings link',async()=>{
  const detail={message:'Native delivery fallback was recorded. The check was incomplete.',first_observed:1,last_observed:2,observed_fallbacks:3};
  const f=fixture({hash:'#review/notices',change:v=>{
    v.context.view_scope='server';
    v.notifications=[notice('mail.native_fallback','fallback-notice',{owner:'@admin',subject:'mail-integration',detail})];
    v.history=[auditEvent('mail.native_fallback',detail,{owner:'@admin',subject:'mail-integration'})];
  }});
  try{
    const notices=f.document.getElementById('cs-notification-list').textContent;
    assert.match(notices,/Incomplete email check: native delivery fallback/);
    assert.match(notices,/First recorded fallback: 1970-01-01 00:00:01 UTC/);
    assert.match(notices,/Last recorded fallback: 1970-01-01 00:00:02 UTC/);
    assert.match(notices,/Recorded fallback events: 3/);
    assert.ok(f.document.querySelector('#cs-notification-list a[href="#settings/mail-settings"]'));
    const history=f.document.querySelector('#cs-history-events .cs-history-summary').textContent;
    assert.match(history,/First observation \(UTC\): 1970-01-01 00:00:01/);
    assert.match(history,/Last observation \(UTC\): 1970-01-01 00:00:02/);
  }finally{await f.close();}
});

test('history shows readable operations, website scope and counters with references closed by default',async()=>{
  const f=fixture({hash:'#history',change:values=>{values.context.view_scope='server';values.history=[
    auditEvent('scan.queued',{domain:'site.test',target:'',replaces:'b'.repeat(32)}),
    auditEvent('maintenance.completed',{action:'signatures-update',error:null}),
    auditEvent('scan.partial',{counters:{scanned:1450,errors:2,infected:0}}),
  ];}});
  try{const rows=[...f.document.querySelectorAll('#cs-history-events tbody tr')];
    assert.equal(rows[0].children[2].textContent,'Scan queued');
    assert.match(rows[0].querySelector('.cs-history-summary').textContent,/Website: site.testScope: Whole websiteFull replacement scan queued/);
    assert.match(rows[1].querySelector('.cs-history-summary').textContent,/Operation: Update antivirus signatures/);
    assert.equal(rows[2].children[2].textContent,'Scan incomplete');assert.match(rows[2].querySelector('.cs-history-summary').textContent,/Files checked: 1450Errors: 2/);
    for(const row of rows){assert.equal(row.querySelector('details').open,false);assert.doesNotMatch(row.querySelector('.cs-history-summary').textContent,/[a-f0-9]{32}|\{"/);}
    rows[0].querySelector('details').open=true;assert.match(rows[0].querySelector('pre').textContent,new RegExp('b'.repeat(32)));
  }finally{await f.close();}
});

test('history explains interrupted updates and retains escaped original evidence without showing opaque IDs in summaries',async()=>{
  const original='Interrupted for update; replacement '+ 'b'.repeat(32)+' <img src=x onerror=alert(1)>';
  const f=fixture({hash:'#history',change:values=>values.history=[
    auditEvent('installation.scan_interrupted',{domain:'site.test',job_id:'a'.repeat(32),replacement_job:'b'.repeat(32),error:original,counters:{scanned:17,unverified:2}}),
    auditEvent('repair.failed',{path:'<script>alert(1)</script>.php',error:'Cannot read reference '+'c'.repeat(64)}),
    auditEvent('custom.new_event',{enabled:false,policy:{spam_threshold:7},revision:'d'.repeat(64)}),
    auditEvent('mail.policy_saved',{overrides:{spam_threshold:6}},{subject:'site.test/inbox'}),
  ]});
  try{const rows=[...f.document.querySelectorAll('#cs-history-events tbody tr')];
    assert.match(rows[0].querySelector('.cs-history-summary').textContent,/coverage is incomplete.*new full scan was queued automatically/);
    assert.match(rows[0].querySelector('pre').textContent,/onerror=alert/);assert.equal(rows[0].querySelector('img'),null);
    assert.equal(rows[1].querySelector('script'),null);assert.match(rows[1].querySelector('.cs-history-summary').textContent,/File: <script>/);
    assert.doesNotMatch(rows[1].querySelector('.cs-history-summary').textContent,/c{64}/);
    assert.equal(rows[2].children[2].textContent,'Custom new event');assert.match(rows[2].querySelector('.cs-history-summary').textContent,/Enabled: NoPolicy \/ Spam threshold: 7/);
    assert.doesNotMatch(rows[2].querySelector('.cs-history-summary').textContent,/Revision|d{64}/);
    assert.match(rows[3].querySelector('.cs-history-summary').textContent,/Applies to: site.test\/inbox.*Spam threshold: 6/);
  }finally{await f.close();}
});

test('history resolves retained scan context only within the same account generation',async()=>{
  const f=fixture({hash:'#history',change:values=>{values.context.view_scope='server';values.jobs=[
    {...integrityJob('completed'),id:'a'.repeat(32),owner:'alice',identity:'current',domain:'right.test',target:'blog'},
    {...integrityJob('completed'),id:'a'.repeat(32),owner:'bob',identity:'current',domain:'foreign.test'},
    {...integrityJob('completed'),id:'a'.repeat(32),owner:'alice',identity:'old',domain:'old.test'},
  ];values.history=[auditEvent('scan.completed',{counters:{scanned:20}}),auditEvent('scan.completed',{}, {identity:'recreated'})];}});
  try{const summary=f.document.querySelector('#cs-history-events .cs-history-summary').textContent;
    assert.match(summary,/Website: right.testScope: blog/);assert.doesNotMatch(summary,/foreign.test|old.test/);
    assert.doesNotMatch(f.document.querySelectorAll('#cs-history-events .cs-history-summary')[1].textContent,/right.test|foreign.test|old.test/);
  }finally{await f.close();}
});
const queuedScans=async body=>({ok:true,json:async()=>body.action==='scan-targets'?{ok:true,sites:[{domain:'bob.test',suspended:false},{domain:'suspended.test',suspended:true}]}:{ok:true,jobs:['scan-one','scan-two']}});

test('Global admin view defaults the scan target and progress to the entire server',async()=>{
  const f=fixture({hash:'#scan',change:values=>{values.context.view_scope='server';values.sites[0].owner='bob';values.accounts.push({owner:'bob'});},api:queuedScans});
  try{const form=f.document.getElementById('cs-scan-target');
    assert.equal(f.document.getElementById('cs-owner').value,'');assert.equal(form.elements.owner.value,'');
    assert.equal(form.elements.domain.disabled,true);assert.equal(f.document.getElementById('cs-scan-start').disabled,false);
    assert.match(form.elements.domain.textContent,/All websites on this server/);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.deepEqual(f.requests.at(-1),{token:'fixture-token',owner:'alice',action:'scan',scope:'server'});
    const progress=new URL(f.document.getElementById('cs-scan-target-progress').href);
    assert.equal(progress.searchParams.get('scope'),'server');assert.equal(progress.searchParams.has('owner'),false);
    form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();
    assert.equal(form.elements.domain.disabled,false);
    form.elements.owner.value='';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();
    assert.equal(form.elements.domain.disabled,true);assert.equal(f.document.getElementById('cs-scan-start').disabled,false);
  }finally{await f.close();}
});

const mailDefaults={malware_action:'reject',phishing_action:'quarantine',spam_action:'junk',spam_high_action:'reject',block_action:'quarantine',spam_threshold:5,spam_high_threshold:15,signature_spam_score:5,allow_senders:[],block_senders:[]};
const mailPermissions={manage_policy:false,manage_exceptions:false,release:false,delete:false};
test('Global email settings load independently from paged Email review',async()=>{
  const f=fixture({hash:'#settings/mail-settings',change:values=>{values.context.view_scope='server';values.accounts.push({owner:'bob'});},api:async body=>({ok:true,json:async()=>({ok:true,defaults:mailDefaults,permissions:mailPermissions,revision:'server-revision'})})});
  try{await settle();
    assert.ok(f.requests.some(row=>row.action==='mail-server-get'));assert.equal(f.requests.some(row=>row.action==='mail-server-activity'||row.action==='review-list'),false);
    assert.equal(f.requests.some(row=>row.action==='mail-dashboard'),false);
    assert.equal(f.document.getElementById('cs-mail-domain'),null);
    const form=f.document.getElementById('cs-mail-server-form');assert.equal(form.elements.namedItem('enabled'),null);
    assert.equal(form.elements.manage_policy.checked,false);form.elements.spam_threshold.value='7';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const saved=f.requests.find(row=>row.action==='mail-server-save');assert.equal(saved.revision,'server-revision');
    assert.equal(JSON.parse(saved.policy).defaults.spam_threshold,7);assert.deepEqual(JSON.parse(saved.policy).permissions,mailPermissions);
    assert.equal(f.requests.some(row=>row.action==='mail-policy-save'),false);
  }finally{await f.close();}
});

test('Global row actions and site schedules send the actual record owner',async()=>{
  const f=fixture({change:values=>{values.context.view_scope='server';values.sites[0].owner='bob';values.exceptions=[{id:'exception-bob',owner:'bob',domain:'bob.test',path:'inert.php',kind:'file',sha256:'a'.repeat(64),enabled:true}];},api:async()=>({ok:false,json:async()=>({ok:false,error:'Inert fixture: no mutation performed'})})});
  try{f.click('[data-action=exception-remove]');await settle();assert.equal(f.requests.at(-1).owner,'bob');
    const site=f.document.querySelector('.cs-policy[data-domain]');site.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(f.requests.at(-1).owner,'bob');assert.equal(f.requests.at(-1).action,'policy-save');
    const defaults=f.document.querySelector('.cs-policy[data-save-action]');
    defaults.elements.watch.click();await settle();assert.equal(f.requests.filter(row=>row.action==='policy-defaults-save').length,0);
    defaults.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(f.requests.at(-1).scope,'server');assert.equal(f.requests.at(-1).action,'policy-defaults-save');
    assert.equal(f.document.getElementById('cs-scans').dataset.viewScope,'server');
    assert.equal(f.document.getElementById('cs-history-retention'),null);
  }finally{await f.close();}
});

test('account email editor saves only selected overrides and preserves inherited permissions',async()=>{
  const value={defaults:mailDefaults,permissions:mailPermissions,overrides:{},permissions_inherited:true,revision:'account-revision'};
  const f=fixture({hash:'#settings/mail-settings',api:async body=>({ok:true,json:async()=>({ok:true,...value})})});
  try{await settle();const form=f.document.getElementById('cs-mail-server-form');
    assert.equal(form.elements.spam_threshold.disabled,true);assert.equal(form.elements.manage_policy.disabled,true);
    const toggle=form.querySelector('[data-mail-default-override=spam_threshold]');toggle.click();assert.equal(form.elements.spam_threshold.disabled,false);
    form.elements.spam_threshold.value='8';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const saved=f.requests.find(row=>row.action==='mail-account-save');assert.equal(saved.owner,'alice');assert.equal(saved.revision,'account-revision');
    assert.deepEqual(JSON.parse(saved.policy),{defaults:{spam_threshold:8},permissions:null});
    assert.equal(f.requests.some(row=>row.action.startsWith('mail-server-')),false);
  }finally{await f.close();}
});
test('scan dropdown chooses account and website without scanning until Scan is pressed',async()=>{
  const f=fixture({hash:'#scan',change:values=>values.accounts.push({owner:'bob'}),api:queuedScans});
  try{const form=f.document.getElementById('cs-scan-target');
    assert.equal(form.elements.domain.value,'');assert.equal(form.elements.path.disabled,true);assert.equal(f.requests.length,0);
    form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new f.w.Event('change'));await settle();
    assert.deepEqual(f.requests,[{token:'fixture-token',owner:'bob',action:'scan-targets'}]);
    assert.equal(form.elements.domain.options[1].value,'bob.test');assert.equal(form.elements.domain.options[2].disabled,true);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.deepEqual(f.requests.at(-1),{token:'fixture-token',owner:'bob',action:'scan',scope:'account'});
    const link=new URL(f.document.getElementById('cs-scan-target-progress').href);assert.equal(link.searchParams.get('owner'),'bob');assert.equal(link.hash,'#scan/jobs');
    form.elements.domain.value='bob.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));
    assert.equal(f.document.getElementById('cs-scan-path-options').hidden,false);assert.equal(form.elements.path.disabled,false);
    form.elements.path.value='wp-content/uploads';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.deepEqual(f.requests.at(-1),{token:'fixture-token',owner:'bob',action:'scan',scope:'site',domain:'bob.test',path:'wp-content/uploads'});
    form.elements.domain.value='';form.elements.domain.dispatchEvent(new f.w.Event('change'));assert.equal(form.elements.path.value,'');assert.equal(form.elements.path.disabled,true);
  }finally{await f.close();}
});
test('Scan all queues server scope without a selected site or leftover path',async()=>{
  const f=fixture({hash:'#scan',api:queuedScans});
  try{const form=f.document.getElementById('cs-scan-target');form.elements.domain.value='site.test';form.elements.domain.dispatchEvent(new f.w.Event('change'));form.elements.path.value='uploads';
    f.click('#cs-scan-all');await settle();assert.deepEqual(f.requests.at(-1),{token:'fixture-token',owner:'alice',action:'scan',scope:'server'});
    assert.equal(new URL(f.document.getElementById('cs-scan-target-progress').href).searchParams.get('scan_scope'),'server');
  }finally{await f.close();}
});
test('tenant scan permission and failed account discovery cannot enable scanning',async()=>{
  const tenant=fixture({admin:false,hash:'#scan',change:values=>values.website_permissions.effective.scan=false,api:queuedScans});
  try{assert.equal(tenant.document.getElementById('cs-scan-all'),null);assert.equal(tenant.document.querySelector('#cs-scan-target select[name=owner]').disabled,true);
    tenant.document.getElementById('cs-scan-target').dispatchEvent(new tenant.w.Event('submit',{bubbles:true,cancelable:true}));await settle();assert.equal(tenant.requests.length,0);
  }finally{await tenant.close();}
  const failed=fixture({hash:'#scan',change:values=>values.accounts.push({owner:'bob'})});
  try{const form=failed.document.getElementById('cs-scan-target');form.elements.owner.value='bob';form.elements.owner.dispatchEvent(new failed.w.Event('change'));await settle();
    assert.equal(failed.document.getElementById('cs-scan-start').disabled,true);assert.equal(form.elements.domain.disabled,true);assert.equal(form.elements.domain.options.length,1);
    assert.match(failed.document.getElementById('cs-scan-target-status').textContent,/Fixture API unavailable/);
  }finally{await failed.close();}
});
test('full panel opens Dashboard and keeps the seven native menu links while navigating every view',async()=>{
  const f=fixture();try{
    assert.deepEqual(f.visible(),['dashboard']);const menu=f.document.getElementById('cs-main-navigation');
    assert.deepEqual([...menu.children].map(link=>link.textContent),labels);
    for(const link of menu.children){link.click();assert.equal(f.visible().length,1);assert.equal(menu.hidden,false);assert.equal(link.getAttribute('aria-current'),'page');
      for(const sub of f.document.querySelectorAll('[data-subnav]:not([hidden]) [data-tab]')){sub.click();assert.deepEqual(f.visible(),[sub.dataset.tab]);}}
    assert.equal(f.document.querySelector('[data-page=scheduled] .cs-policy[data-domain]').dataset.domain,'site.test');
    assert.equal(f.document.querySelector('[data-page=sites] .cs-policy'),null);
    assert.equal(f.document.querySelectorAll('[id]').length,new Set([...f.document.querySelectorAll('[id]')].map(node=>node.id)).size);
  }finally{await f.close();}
});
test('Scheduled Scanner shows a closed paused site with an authorized explicit Resume control',async()=>{
  const f=fixture({hash:'#scheduled',change:v=>{v.context.view_scope='server';v.sites[0].owner='bob';v.sites[0].initial_monitoring_paused=true;}});
  try{const button=f.document.querySelector('[data-action=initial-monitoring-resume]'),section=button.closest('details');
    assert.equal(section.open,false);assert.match(section.querySelector('summary').textContent,/Initial monitoring paused/);
    assert.equal(button.dataset.capability,'schedule');assert.equal(button.textContent,'Resume initial monitoring');
    button.click();button.click();await settle();const request=f.requests.find(r=>r.action==='initial-monitoring-resume');
    assert.equal(request.owner,'bob');assert.equal(request.domain,'site.test');assert.equal(request.token,'fixture-token');
    assert.equal(f.requests.filter(r=>r.action==='initial-monitoring-resume').length,1);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('Manage links select Settings, while records and retention each load in their own view',async()=>{
 const f=fixture();try{
  f.click('#cs-dashboard [data-tab=provider-settings]');assert.deepEqual(f.visible(),['provider-settings']);
  f.click('[data-main-tab=settings]');f.click('[data-subnav=settings] [data-tab=mail-settings]');
  f.click('[data-subnav=settings] [data-tab=retention]');await settle();
  assert.ok(f.requests.some(request=>request.action==='mail-dashboard'));assert.ok(f.requests.some(request=>request.action==='history-retention-get'));
  f.click('[data-subnav=review] [data-tab=history]');assert.equal(f.w.sessionStorage.getItem('clamshield-tab'),'history');
 }finally{await f.close();}
});
test('direct links, old saved leaf tabs and unavailable administrator views have deterministic fallbacks',async()=>{
  for(const [options,page] of [[{hash:'#settings/provider-settings'},'provider-settings'],[{saved:'jobs'},'jobs'],[{saved:'retired-view'},'dashboard'],[{admin:false,hash:'#settings/resources'},'mail-settings']]){
    const f=fixture(options);try{assert.deepEqual(f.visible(),[page]);}finally{await f.close();}
  }
});

test('Review groups existing review tools and remembers the selected child while both navigation levels stay active',async()=>{
  const f=fixture();try{
    f.click('[data-main-tab=review]');assert.deepEqual(f.visible(),['findings']);
    const review=f.document.querySelector('[data-subnav=review]');
    assert.deepEqual([...review.children].map(link=>link.textContent),['Results','Repairs and cleaning','Exceptions','Quarantine','Email','History','Notifications']);
    for(const page of ['findings','repairs','exceptions','quarantine','history']){
      f.click('[data-subnav=review] [data-tab='+page+']');assert.deepEqual(f.visible(),[page]);
      assert.equal(f.document.querySelector('[data-main-tab=review]').getAttribute('aria-current'),'page');
      assert.equal(review.querySelector('[data-tab='+page+']').getAttribute('aria-current'),'page');
    }
    f.click('[data-main-tab=dashboard]');f.click('[data-main-tab=review]');assert.deepEqual(f.visible(),['history']);
    f.click('[data-main-tab=dashboard]');f.click('#cs-dashboard [data-tab=findings]');assert.deepEqual(f.visible(),['findings']);assert.equal(f.w.location.hash,'#review');
    f.click('[data-main-tab=dashboard]');f.click('#cs-dashboard [data-tab=quarantine]');assert.deepEqual(f.visible(),['quarantine']);assert.equal(f.w.location.hash,'#review/quarantine');
  }finally{await f.close();}
});

test('Review retains old bookmarks and saved selections after consolidating the menu',async()=>{
  for(const [options,page,hash] of [
    [{hash:'#results'},'findings','#review'],[{hash:'#results/repairs'},'repairs','#review/repairs'],
    [{hash:'#exceptions'},'exceptions','#review/exceptions'],[{hash:'#quarantine'},'quarantine','#review/quarantine'],
    [{hash:'#history'},'history','#review/history'],[{hash:'#history/retired'},'history','#review/history'],
    [{hash:'#review/history'},'history','#review/history'],[{saved:'repairs'},'repairs',''],
    [{admin:false,saved:'exceptions'},'exceptions',''],
  ]){
    const f=fixture(options);try{assert.deepEqual(f.visible(),[page]);assert.equal(f.w.location.hash,hash);assert.equal(f.document.querySelector('[data-main-tab=review]').getAttribute('aria-current'),'page');}finally{await f.close();}
  }
  const unknown=fixture({hash:'#__proto__'});try{assert.deepEqual(unknown.visible(),['dashboard']);}finally{await unknown.close();}
});

test('History contains events, maintenance and automatic actions with one refresh and no separate Activity tab',async()=>{
  const f=fixture({hash:'#review/history',api:async body=>reviewResponse(body)});
  try{await settle();assert.equal(f.document.querySelector('[data-tab=activity],[data-page=activity]'),null);
    for(const id of ['cs-review-history-rows','cs-review-activity-rows','cs-review-automatic-rows'])assert.equal(f.document.getElementById(id).closest('[data-page]').dataset.page,'history');
    for(const kind of ['history','activity','automatic'])assert.ok(f.requests.some(r=>r.action==='review-list'&&r.list===kind));
    const before=f.requests.filter(r=>r.action==='review-list').length;f.click('#cs-history-lists-refresh');await settle();assert.equal(f.requests.filter(r=>r.action==='review-list').length,before+3);
    assert.equal(f.document.getElementById('cs-history-refresh').closest('[data-page]').dataset.page,'retention');
    f.click('[data-main-tab=dashboard]');f.click('#cs-dashboard a[data-focus-id=cs-sa-tasks]');await settle();assert.deepEqual(f.visible(),['history']);assert.equal(f.w.location.hash,'#review/history');assert.equal(f.document.activeElement.id,'cs-sa-tasks');assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('former Activity bookmarks and saved selections open History and maintenance links use its canonical route',async()=>{
  for(const options of [{hash:'#activity'},{hash:'#review/activity'},{hash:'#settings/activity'},{saved:'activity'}]){
    const f=fixture(options);try{await settle();assert.deepEqual(f.visible(),['history']);assert.equal(f.document.querySelector('[data-subnav=review] [data-tab=history]').getAttribute('aria-current'),'page');if(options.hash)assert.equal(f.w.location.hash,'#review/history');
      assert.equal(f.document.querySelector('a[href="#review/activity"]'),null);
    }finally{await f.close();}
  }
});

test('tenant History keeps account events and automatic action history without privileged maintenance queries',async()=>{
  const f=fixture({admin:false,hash:'#review/history',api:async body=>reviewResponse(body)});
  try{await settle();assert.deepEqual(f.visible(),['history']);assert.equal(f.document.getElementById('cs-review-activity-rows'),null);assert.ok(f.document.getElementById('cs-review-automatic-rows'));
    f.click('#cs-history-lists-refresh');await settle();assert.equal(f.requests.some(r=>r.action==='review-list'&&r.list==='activity'),false);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});
test('tenant retains all seven sections without privileged forms or navigation targets',async()=>{
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
const settle=()=>new Promise(resolve=>setImmediate(resolve));
test('Email Shield offers protection while configuration and records live in their own sections',async()=>{
  const f=fixture({hash:'#email'});
  try{await settle();assert.equal(f.document.getElementById('cs-mail-protection-toggle').closest('[data-page]').dataset.page,'mail');
    for(const selector of ['[data-action="mail-adapter-build"]','[data-action="mail-integration-enable"]','#cs-mail-policy'])assert.equal(f.document.querySelector(selector).closest('[data-page]').dataset.page,'mail-settings');
    assert.equal(f.document.getElementById('cs-mail-history-form').closest('[data-page]').dataset.page,'email-review');
    assert.equal(f.document.getElementById('cs-mail-quarantine-form').closest('[data-page]').dataset.page,'quarantine');
    const manage=[...f.document.querySelectorAll('a')].find(link=>link.textContent==='Manage quarantined email');
    assert.equal(manage.getAttribute('href'),'#review/email-review');manage.click();assert.deepEqual(f.visible(),['email-review']);assert.equal(f.w.location.hash,'#review/email-review');
    f.click('[data-tab=mail-settings]');assert.deepEqual(f.visible(),['mail-settings']);
  }finally{await f.close();}
});
const inactive={configured:false}, installed={configured:true,profile:'extended',enabled:5089,version:'fixture-new',generation:'generation-installed',created:1};
test('YARA schedule saves numeric intervals and automatic toggle with native controls and without reloading',async()=>{
  const schedule={automatic:true,interval_minutes:1440,last_attempt:1,last_success:2,next_allowed:0};
  const f=fixture({hash:'#updates/rules',change:v=>{v.rule_manager.updates=schedule;},api:async body=>({ok:true,json:async()=>({ok:true,schedule:{...schedule,...JSON.parse(body.policy)}})})});
  try{await settle();const form=f.document.getElementById('cs-yara-schedule'),input=form.elements.interval_minutes;
    assert.equal(input.value,'1440');assert.equal(input.min,'60');input.value='59';assert.equal(input.checkValidity(),false);
    input.value='60.5';assert.equal(input.checkValidity(),false);input.value='2880';assert.equal(input.checkValidity(),true);
    form.elements.automatic.checked=false;form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const requests=f.requests.filter(r=>r.action==='rules-schedule-save');assert.equal(requests.length,1);
    assert.deepEqual(JSON.parse(requests[0].policy),{automatic:false,interval_minutes:2880,profile:'core'});
    assert.equal(f.document.getElementById('cs-yara-schedule-status').textContent,'Update preferences saved.');
    assert.match(f.document.getElementById('cs-yara-timing').textContent,/Automatic checks are off/);
    assert.match(f.document.getElementById('cs-yara-update-schedule').textContent,/Minimum interval: 60 minutes/);
    assert.match(f.document.getElementById('cs-yara-last_success').textContent,/1970-/);
    assert.equal(f.document.querySelector('[data-tab=rules]').getAttribute('aria-current'),'page');
  }finally{await f.close();}
});
test('YARA timing resumes a shared cooldown across profile changes and keeps failed schedule saves visible',async()=>{
  const schedule={automatic:true,interval_minutes:1440,last_attempt:1,last_success:2,next_allowed:4071000000,retry_after:4071000000};
  const f=fixture({hash:'#updates/rules',change:v=>{v.rule_manager.updates=schedule;},ruleSnapshots:[{pending:false,latest:null,active:installed,schedule}],api:async()=>({ok:false,json:async()=>({ok:false,error:'<b>Schedule unavailable</b>'})})});
  try{await settle();const form=f.document.getElementById('cs-forge-install');assert.equal(form.querySelector('button').disabled,true);
    form.elements.profile.value='full';for(let i=0;i<50;i++)form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(f.requests.filter(r=>r.action==='rules-install').length,0);assert.match(f.document.getElementById('cs-yara-timing').textContent,/GitHub cooldown/);
    assert.match(f.document.getElementById('cs-yara-next_allowed').textContent,/2099-/);
    f.document.getElementById('cs-yara-schedule').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const status=f.document.getElementById('cs-yara-schedule-status');assert.match(status.textContent,/Schedule unavailable/);assert.equal(status.querySelector('b'),null);
    assert.equal(form.querySelector('button').disabled,true);f.click('[data-main-tab=dashboard]');assert.equal(f.timers.size,0);
  }finally{await f.close();}
});
function installSnapshot(status,phase,active=inactive){return {pending:['queued','running'].includes(status),active,latest:{status,phase,profile:'extended',generation:installed.generation,activated:status==='completed'}};}
test('one Install click downloads, checks and activates with automatic progress and no advanced controls',async()=>{
  const f=fixture({hash:'#updates',change:values=>{values.rules=inactive;values.engines.yara.rules_available=false;},
    response:{ok:true,json:async()=>({ok:true,queued:true,task_id:'task-fixture'})},
    ruleSnapshots:[{pending:false,latest:null,active:inactive},installSnapshot('queued'),installSnapshot('running','downloading'),installSnapshot('running','checking'),installSnapshot('running','activating'),installSnapshot('completed',null,installed)]});
  try{await settle();const form=f.document.getElementById('cs-forge-install'),button=form.querySelector('button');
    assert.equal(button.textContent,'Install rules');assert.equal(f.document.getElementById('cs-rules-advanced').open,false);
    assert.equal(f.document.querySelector('[data-page=rules] [data-action=rules-activate]'),null);
    form.elements.profile.value='extended';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.deepEqual(f.requests.filter(request=>request.action!=='rules-status'),[{token:'fixture-token',owner:'alice',action:'rules-install',profile:'extended'}]);
    for(const label of ['Downloading rules','Checking rules','Activating rules']){await f.tick();assert.match(f.document.getElementById('cs-forge-status').textContent,new RegExp(label));assert.equal(button.disabled,true);}
    await f.tick();assert.equal(f.document.getElementById('cs-forge-status').textContent,'Rules installed and active.');
    assert.equal(button.textContent,'Update rules');assert.equal(button.disabled,false);assert.equal(f.timers.size,0);
    assert.match(f.document.getElementById('cs-rules-active').textContent,/5089 rules/);assert.match(f.document.getElementById('cs-dashboard-yara-status').textContent,/5089 rules/);
    assert.equal(f.document.getElementById('cs-yara-warning').hidden,true);
  }finally{await f.close();}
});
test('reopening a pending install resumes polling and a failure preserves active rules with retry',async()=>{
  const f=fixture({hash:'#updates',ruleSnapshots:[installSnapshot('running','checking',installed),{pending:false,active:installed,latest:{status:'failed',error:'<b>Rule validation failed</b>'}}]});
  try{await settle();const form=f.document.getElementById('cs-forge-install');assert.equal(form.querySelector('button').disabled,true);
    await f.tick();const status=f.document.getElementById('cs-forge-status');assert.match(status.textContent,/Rule validation failed/);
    assert.equal(status.querySelector('b'),null);assert.match(status.textContent,/Current active rules are shown above/);
    assert.match(f.document.getElementById('cs-rules-active').textContent,/5089 rules/);assert.equal(form.querySelector('button').disabled,false);
  }finally{await f.close();}
});
test('old staged rules and failed build history do not force manual activation in the normal view',async()=>{
  const f=fixture({hash:'#updates',change:values=>{values.rules=inactive;values.maintenance.push({action:'rules-build',status:'failed',created:1,error:'Outdated revision',result:null});}});
  try{await settle();assert.equal(f.document.querySelector('#cs-forge-install button').textContent,'Install rules');
    assert.equal(f.document.getElementById('cs-rules-advanced').open,false);assert.equal(f.document.querySelector('[data-action=rules-activate]'),null);
    assert.equal(f.document.querySelector('[data-page=rules] ol'),null);
  }finally{await f.close();}
});
test('failed queue requests stay escaped and retryable without reporting success',async()=>{
  const f=fixture({hash:'#updates',response:{ok:false,json:async()=>({ok:false,error:'<b>Provider unavailable</b>'})}});
  try{await settle();const form=f.document.getElementById('cs-forge-install');form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const status=f.document.getElementById('cs-forge-status');assert.equal(status.textContent,'Could not start installation: <b>Provider unavailable</b>');
    assert.equal(status.querySelector('b'),null);assert.equal(form.querySelector('button').disabled,false);
  }finally{await f.close();}
});
test('hidden rule views stop polling and resume after navigation',async()=>{
  const f=fixture({hash:'#updates',ruleSnapshots:[installSnapshot('running','checking')]});
  try{await settle();assert.equal(f.timers.size,1);f.click('[data-main-tab=dashboard]');assert.equal(f.timers.size,0);
    const count=f.requests.length;await settle();assert.equal(f.requests.length,count);
    f.click('[data-main-tab=updates]');await settle();assert.ok(f.requests.length>count);assert.equal(f.timers.size,1);
  }finally{await f.close();}
});

const integrityJob=(status,extra={})=>({id:'integrity-one',owner:'alice',domain:'site.test',root:'/home/alice/web/site.test/public_html',target:'',source:'wordpress-integrity',created:1,started:null,finished:null,heartbeat:null,cancel_requested:false,status,counters:{seen:0,scanned:0,installations:0},error:null,report_ready:false,discovery_complete:false,...extra});

test('WordPress has one unified tab and former integrity links open that workflow',async()=>{
  const f=fixture({hash:'#scan/wordpress'});try{
    assert.deepEqual(f.visible(),['wordpress-recovery']);assert.equal(f.document.getElementById('cs-integrity'),null);
    assert.equal(f.document.querySelector('[data-tab=wordpress]'),null);assert.equal(f.document.querySelector('[data-tab=wordpress-recovery]').textContent,'WordPress');
    assert.equal(f.document.querySelectorAll('#cs-wp-recovery').length,1);assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});

test('dashboard shows unavailable website ClamAV with an admin Enable control and preserves engine/provider rows',async()=>{
  const f=fixture({change:v=>{v.engines.clamav={available:false,error:'Internal socket details'};}});
  const tenant=fixture({admin:false,change:v=>{v.engines.clamav={available:false};}});
  const healthy=fixture();
  try{
    const dashboard=f.document.getElementById('cs-dashboard');assert.match(dashboard.textContent,/ClamAV version.*ClamAV is unavailable/s);
    assert.equal(f.document.getElementById('cs-dashboard-clamav-enable').hidden,false);assert.equal(f.document.getElementById('cs-dashboard-clamav-enable').textContent,'Enable');
    assert.doesNotMatch(dashboard.textContent,/Internal socket details/);
    for(const title of ['ClamAV signatures','YARA engine','YARA scanning','YARA rules','SecuriteInfo','SaneSecurity'])assert.ok([...dashboard.querySelectorAll('dt')].some(node=>node.textContent===title));
    assert.equal(tenant.document.getElementById('cs-dashboard-clamav-enable'),null);
    assert.equal(healthy.document.getElementById('cs-dashboard-clamav-enable').hidden,true);
  }finally{await f.close();await tenant.close();await healthy.close();}
});

test('dashboard Enable queues one global startup and follows verification without reload or repeated clicks',async()=>{
  let resolveStart,index=0;
  const f=fixture({change:v=>{v.engines.clamav={available:false};v.context.view_scope='server';},api:async body=>{
    if(body.action==='website-engine-start')return new Promise(resolve=>{resolveStart=()=>resolve({ok:true,json:async()=>({ok:true,queued:true,task_id:'private-task'})});});
    if(body.action==='website-engine-status')return {ok:true,json:async()=>index++===0?({ok:true,pending:true,latest:{action:'website-engine-start',status:'running'},engine:{available:false}}):({ok:true,pending:false,latest:{action:'website-engine-start',status:'completed'},engine:{available:true,version:'ClamAV verified fixture'}})};
    return {ok:false,json:async()=>({ok:false,error:'Unused operation'})};
  }});
  try{const button=f.document.getElementById('cs-dashboard-clamav-enable');for(let i=0;i<50;i++)button.click();
    assert.equal(f.requests.filter(r=>r.action==='website-engine-start').length,1);assert.equal(button.disabled,true);
    assert.equal(f.requests[0].token,'fixture-token');assert.equal(f.requests[0].owner,'alice');
    resolveStart();await settle();assert.match(f.document.getElementById('cs-dashboard-clamav-status').textContent,/Starting.*checking signatures/);
    assert.equal(button.disabled,true);await f.tick();assert.equal(button.hidden,true);assert.equal(f.timers.size,0);
    assert.equal(f.document.getElementById('cs-dashboard-clamav-version').textContent,'ClamAV verified fixture');assert.deepEqual(f.visible(),['dashboard']);
  }finally{await f.close();}
});

test('dashboard startup failures remain readable plain text and allow retry',async()=>{
  const f=fixture({change:v=>{v.engines.clamav={available:false};},api:async body=>({ok:true,json:async()=>body.action==='website-engine-start'?({ok:true,queued:true}):({ok:true,pending:false,latest:{status:'failed',error:'<b>Signatures not ready</b>'},engine:{available:false}})})});
  try{f.click('#cs-dashboard-clamav-enable');await settle();const output=f.document.getElementById('cs-dashboard-clamav-status');
    assert.match(output.textContent,/Could not complete.*<b>Signatures not ready<\/b>/);assert.equal(output.children.length,0);
    assert.equal(f.document.getElementById('cs-dashboard-clamav-enable').disabled,false);assert.equal(f.timers.size,0);
  }finally{await f.close();}
});

test('dashboard pending startup checks pause outside Dashboard and resume when opened',async()=>{
  const f=fixture({hash:'#updates/rules',change:v=>{v.engines.clamav={available:false};v.maintenance=[{action:'website-engine-start',status:'running',created:1,result:null,error:null}];},api:async()=>({ok:true,json:async()=>({ok:true,pending:true,latest:{action:'website-engine-start',status:'running'},engine:{available:false}})})});
  try{await settle();assert.equal(f.requests.some(r=>r.action==='website-engine-status'),false);
    f.click('[data-main-tab=dashboard]');await settle();assert.equal(f.requests.filter(r=>r.action==='website-engine-status').length,1);assert.equal(f.timers.size,1);
    f.click('[data-main-tab=settings]');assert.equal(f.timers.size,0);
  }finally{await f.close();}
});


test('fresh readiness check runs once, shows the required destinations and keeps unrelated tabs closed',async()=>{
  let resolveCheck;
  const f=fixture({change:v=>v.website_readiness={state:'unknown',message:'Website readiness needs a fresh check.',checked:1},api:async body=>{
    assert.equal(body.action,'website-readiness-check');return new Promise(resolve=>{resolveCheck=()=>resolve({ok:true,json:async()=>({ok:true,coverage:{state:'incomplete',message:'Signatures and rules need attention.',checked:100},busy:false,engine:{available:true,version:'ClamAV fixture'},actions:['signatures','rules']})});});
  }});
  try{const button=f.document.getElementById('cs-readiness-check');for(let i=0;i<50;i++)button.click();assert.equal(f.requests.length,1);assert.equal(button.disabled,true);
    assert.deepEqual(f.requests[0],{token:'fixture-token',owner:'alice',action:'website-readiness-check'});
    resolveCheck();await settle();assert.equal(button.disabled,false);assert.match(f.document.getElementById('cs-readiness-message').textContent,/need attention/);
    assert.match(f.document.getElementById('cs-readiness-time').textContent,/1970-01-01 00:01:40 UTC/);
    assert.deepEqual([...f.document.querySelectorAll('[data-readiness-action]')].filter(link=>!link.hidden).map(link=>link.dataset.readinessAction),['signatures','rules']);
    f.click('[data-readiness-action=rules]');assert.deepEqual(f.visible(),['rules']);
  }finally{await f.close();}
});

test('unavailable ClamAV readiness action opens and focuses the real Enable button',async()=>{
  const f=fixture({change:v=>{v.engines.clamav={available:false};v.website_readiness={state:'incomplete',message:'Needs attention.',checked:1};v.readiness_actions=['enable'];}});
  try{const link=f.document.querySelector('[data-readiness-action=enable]');assert.equal(link.hidden,false);link.click();
    assert.deepEqual(f.visible(),['dashboard']);assert.equal(f.document.activeElement.id,'cs-dashboard-clamav-enable');assert.equal(f.requests.some(r=>r.action==='website-engine-start'),false);
    assert.equal(f.document.querySelector('[data-readiness-action=signatures]').hidden,true);
  }finally{await f.close();}
});

test('busy readiness check routes to work in progress without claiming a fresh verification',async()=>{
  const f=fixture({api:async()=>({ok:true,json:async()=>({ok:true,coverage:{state:'unknown',message:'Needs a fresh check.',checked:1},busy:true,engine:{available:true,version:'ClamAV fixture'},actions:['progress','activity']})})});
  try{f.click('#cs-readiness-check');await settle();assert.match(f.document.getElementById('cs-readiness-message').textContent,/waits for an active scan or update/);
    assert.match(f.document.getElementById('cs-readiness-time').textContent,/00:00:01/);f.click('[data-readiness-action=progress]');assert.deepEqual(f.visible(),['jobs']);
  }finally{await f.close();}
});

test('readiness failures remain plain text and retryable while tenant views have no server check',async()=>{
  const f=fixture({api:async()=>({ok:false,json:async()=>({ok:false,error:'<b>Check failed</b>'})})}),tenant=fixture({admin:false});
  try{f.click('#cs-readiness-check');await settle();const output=f.document.getElementById('cs-readiness-message');assert.match(output.textContent,/<b>Check failed/);assert.equal(output.children.length,0);assert.equal(f.document.getElementById('cs-readiness-check').disabled,false);
    assert.equal(tenant.document.getElementById('cs-readiness-check'),null);
  }finally{await f.close();await tenant.close();}
});


test('website startup distinguishes queued work, scan wait, service start and signature verification',async()=>{
  let index=0;
  const stages=[
    {pending:true,latest:{status:'queued'},blocking_action:'signatures-update',engine:{available:false}},
    {pending:true,latest:{status:'running',phase:'waiting-scan'},engine:{available:false}},
    {pending:true,latest:{status:'running',phase:'starting'},engine:{available:false}},
    {pending:true,latest:{status:'running',phase:'verifying'},engine:{available:true,version:'ClamAV fixture'}},
    {pending:false,latest:{status:'completed'},engine:{available:true,version:'ClamAV fixture'}}];
  const f=fixture({change:v=>{v.engines.clamav={available:false};},api:async body=>({ok:true,json:async()=>body.action==='website-engine-start'?({ok:true,queued:true}):({ok:true,...stages[Math.min(index++,stages.length-1)]})})});
  try{f.click('#cs-dashboard-clamav-enable');await settle();const button=f.document.getElementById('cs-dashboard-clamav-enable'),output=f.document.getElementById('cs-dashboard-clamav-status');
    assert.equal(button.textContent,'Queued…');assert.match(output.textContent,/waiting for the current signature update/);assert.doesNotMatch(output.textContent,/Starting/);
    await f.tick();assert.equal(button.textContent,'Waiting for scan…');assert.match(output.textContent,/current file to finish/);
    await f.tick();assert.equal(button.textContent,'Starting…');assert.equal(output.textContent,'Starting website ClamAV…');
    await f.tick();assert.equal(button.textContent,'Checking…');assert.match(output.textContent,/Checking loaded/);
    await f.tick();assert.equal(button.hidden,true);assert.equal(f.timers.size,0);
  }finally{await f.close();}
});


test('native DNSBL status distinguishes protected lists from manual review without exposing query keys',async()=>{
  const safe=fixture({change:v=>{v.mail_integration={phase:'active',native_dnsbl:{state:'active',protected_entries:1,review_required:false}};}});
  const review=fixture({change:v=>{v.mail_integration={phase:'active',native_dnsbl:{state:'review',review_required:true}};}});
  const tenant=fixture({admin:false,change:v=>{v.mail_integration={phase:'active',native_dnsbl:{state:'review',review_required:true}};}});
  try{
    assert.match(safe.document.body.textContent,/Spamhaus error replies excluded for 1 native DNSBL list/);
    assert.match(review.document.body.textContent,/Native DNSBL error-reply filters need review/);
    assert.match(review.document.body.textContent,/No automatic retry will be attempted/);
    assert.doesNotMatch(tenant.document.body.textContent,/Native DNSBL error-reply filters need review/);
    assert.equal(safe.requests.length,0);assert.equal(review.requests.length,0);
  }finally{await safe.close();await review.close();await tenant.close();}
});


function memoryView(v,measurement){
  const limits={cpu_percent:100,memory_mib:2048,io_weight:100},service={active:false,memory_current:0,memory_bytes:2147483648,cpu_percent:100,io_weight:100};
  v.resources={policy:Object.fromEntries(['website_worker','website_clamav','mail_broker','mail_clamav','mail_spamassassin'].map(k=>[k,limits])),
    services:Object.fromEntries(['website_worker','website_clamav','mail_broker','mail_clamav','mail_spamassassin'].map(k=>[k,{...service,title:k}])),
    memory:{MemTotal:4294967296,MemAvailable:2147483648},recovery_pending:false,website_policy:{enabled:true},
    native_clamav:{active:true,memory_current:1258291200,memory_peak:2415919104,memory_bytes:null,rss_bytes:1101004800,pss_bytes:1090519040},signature_memory:measurement};
}
function measuredMemory(stale=false){return {available:true,running:false,report:{measured:1000,engine:'ClamAV fixture',stale,repeats:3,
  baseline:{median_bytes:967.75*1048576},all:{median_bytes:1031.5*1048576},providers:[{label:'SecuriteInfo',delta_bytes:63.75*1048576}]}};}

test('signature memory is an explicit bounded action with deduplicated clicks and a distinct measured-load table',async()=>{
  let pending=false;
  const f=fixture({parser:true,hash:'#settings/resources',change:v=>memoryView(v,measuredMemory()),api:async body=>{
    if(body.action==='signature-memory-measure'){pending=true;return {ok:true,json:async()=>({ok:true,queued:true})};}
    return {ok:true,json:async()=>({ok:true,measurement:measuredMemory(),pending,latest:pending?{status:'running',result:{phase:'measuring'}}:{status:'completed'}})};
  }});
  try{
    await settle();assert.deepEqual(f.errors,[]);assert.equal(f.requests.filter(r=>r.action==='signature-memory-measure').length,0);
    const table=f.document.getElementById('cs-memory-values');assert.match(table.textContent,/967.8 MiB/);assert.match(table.textContent,/1031.5 MiB/);assert.match(table.textContent,/\+63.8 MiB/);
    assert.match(table.textContent,/not the native daemon/);assert.doesNotMatch(table.textContent,/2415919104/);
    f.click('#cs-memory-measure');f.click('#cs-memory-measure');await settle();assert.equal(f.requests.filter(r=>r.action==='signature-memory-measure').length,1);
    assert.equal(f.document.getElementById('cs-memory-measure').disabled,true);assert.match(f.document.getElementById('cs-memory-status').textContent,/queued/);
    pending=false;await f.tick();assert.equal(f.document.getElementById('cs-memory-measure').disabled,false);assert.equal(f.timers.size,0);
  }finally{await f.close();}
});

test('unconfirmed signature measurement never retries its write and requires a status read before another action',async()=>{
  let finished=false,requested=false;
  const f=fixture({hash:'#settings/resources',change:v=>memoryView(v,{available:true,running:false,report:null}),api:async body=>{
    if(body.action==='signature-memory-measure'){requested=true;throw new Error('Connection lost');}
    return {ok:true,json:async()=>({ok:true,measurement:{available:true,running:false,report:null},pending:requested&&!finished,latest:finished?{status:'failed',error:'<b>Memory limit reached</b>'}:requested?{status:'queued'}:null})};
  }});
  try{
    await settle();f.click('#cs-memory-measure');await settle();assert.equal(f.document.getElementById('cs-memory-measure').disabled,true);
    assert.match(f.document.getElementById('cs-memory-status').textContent,/Refresh status before/);
    f.click('#cs-memory-measure');assert.equal(f.requests.filter(r=>r.action==='signature-memory-measure').length,1);
    finished=true;f.click('#cs-memory-refresh');await settle();const output=f.document.getElementById('cs-memory-status');
    assert.match(output.textContent,/<b>Memory limit reached/);assert.equal(output.children.length,0);assert.equal(f.document.getElementById('cs-memory-measure').disabled,false);
  }finally{await f.close();}
});

test('old signature memory is labelled stale and hidden views do not poll or expose controls to tenants',async()=>{
  const f=fixture({change:v=>memoryView(v,measuredMemory(true))}),tenant=fixture({admin:false,change:v=>memoryView(v,measuredMemory())});
  try{
    assert.match(f.document.getElementById('cs-memory-values').textContent,/different signature data or engine/);
    assert.equal(f.requests.filter(r=>r.action.startsWith('signature-memory-')).length,0);assert.equal(tenant.document.getElementById('cs-signature-memory'),null);
    assert.match(f.document.querySelector('a[data-focus-id="cs-signature-memory"]').textContent,/memory costs/);
  }finally{await f.close();await tenant.close();}
});
