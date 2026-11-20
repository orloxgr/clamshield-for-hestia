const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path'),{spawnSync}=require('node:child_process');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../..');
function data(admin=true){
  const permissions=Object.fromEntries(['scan','schedule','quarantine','restore','repair','cleanup','exceptions','automatic'].map(key=>[key,true]));
  return {context:{owner:'alice',admin},accounts:[{owner:'alice'}],
    sites:[{domain:'site.test',root:'/home/alice/web/site.test/public_html',suspended:false,
      policy:{watch:false,frequency:'never',time:'03:00',timezone:'UTC',weekday:0,monthday:1,rescan_updates:true},
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
  const dom=new JSDOM(rendered.stdout,{url:'https://panel.test/plugins/clamshield/'+(options.hash||''),runScripts:'outside-only'});
  const w=dom.window,requests=[],timers=new Map();let timerId=0,statusIndex=0;if(options.saved)w.sessionStorage.setItem('clamshield-tab',options.saved);
  w.setTimeout=(callback,delay)=>{timers.set(++timerId,{callback,delay});return timerId;};w.clearTimeout=id=>timers.delete(id);
  w.fetch=async(url,request)=>{const body=Object.fromEntries(request.body);requests.push(body);if(body.action==='rules-status'){const value=options.ruleSnapshots?.[Math.min(statusIndex++,options.ruleSnapshots.length-1)]??{pending:false,latest:null,active:values.rules};return {ok:true,json:async()=>({ok:true,...value})};}if(options.api)return options.api(body);return options.response||{ok:false,json:async()=>({ok:false,error:'Fixture API unavailable'})};};
  for(const script of w.document.querySelectorAll('script:not([type="application/json"])'))w.eval(script.textContent);
  return {w,requests,timers,tick:async()=>{const entry=timers.entries().next().value;assert.ok(entry);timers.delete(entry[0]);await entry[1].callback();await new Promise(resolve=>setImmediate(resolve));},document:w.document,close:async()=>{await new Promise(resolve=>setImmediate(resolve));w.close();},click:selector=>w.document.querySelector(selector).click(),
    visible:()=>[...w.document.querySelectorAll('[data-page]')].filter(section=>!section.hidden).map(section=>section.dataset.page)};
}
const labels=['Dashboard','Email Shield','On-demand Scan','Scheduled Scanner','Review','Updates','Settings'];

test('Trial scans and its permission/category are removed while ordinary YARA controls remain available',async()=>{
  const f=fixture({hash:'#updates/rules',change:v=>{v.rule_trials=[{job_id:'retired-comparison-id',generation:'old-generation'}];}});
  try{await settle();assert.equal(f.document.querySelector('[data-action="rules-trial"]'),null);
    assert.equal(f.document.querySelector('[data-capability="rule_trials"]'),null);
    assert.doesNotMatch(f.document.body.textContent,/Trial scans|Run comparison trial|retired-comparison-id/);
    assert.ok(f.document.getElementById('cs-forge-install'));assert.ok(f.document.querySelector('[data-action="rules-activate"]'));
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
  try{const form=f.document.getElementById('cs-providers');
    for(const [provider,value] of [['official',180],['securiteinfo',120],['sanesecurity',60]]){
      const input=form.elements[provider+'_interval_minutes'];assert.equal(Number(input.value),value);assert.equal(input.min,'60');assert.equal(input.step,'1');
      input.value='59';assert.equal(input.checkValidity(),false);input.value=String(value);assert.equal(input.checkValidity(),true);
    }
    const schedule=f.document.getElementById('cs-provider-schedule');assert.match(schedule.textContent,/Last attempt.*Last success.*Next permitted update/);
    assert.match(schedule.textContent,/Freshclam provider cooldown/);assert.match(schedule.textContent,/2099-/);
    assert.match(form.textContent,/securiteinfo.ign2 - Provider false-positive exceptions/);
    assert.match(form.textContent,/phish.ndb - Phishing and malware/);
    assert.doesNotMatch(form.textContent,/\u03b2\u20ac|\u0392\u00b7|\ufffd/);
  }finally{await f.close();}
});

test('provider interval fields are sent as numbers while masked credentials and database selections retain their behavior',async()=>{
  const f=fixture({hash:'#updates/providers',api:async()=>({ok:false,json:async()=>({ok:false,error:'Fixture: no update performed'})})});
  try{const form=f.document.getElementById('cs-providers');form.elements.official_interval_minutes.value='180';form.elements.securiteinfo_interval_minutes.value='120';form.elements.sanesecurity_interval_minutes.value='90';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const request=f.requests.find(r=>r.action==='providers-save');assert.ok(request);const policy=JSON.parse(request.providers);
    assert.equal(policy.official.interval_minutes,180);assert.equal(policy.securiteinfo.interval_minutes,120);assert.equal(policy.sanesecurity.interval_minutes,90);
    assert.equal(policy.securiteinfo.key,'');assert.equal(typeof policy.automatic,'boolean');assert.ok(Array.isArray(policy.securiteinfo.databases));
    assert.match(f.document.getElementById('cs-message').textContent,/no update performed/);
  }finally{await f.close();}
});
const notificationKinds={detections:'Website malware detections',integrity:'WordPress integrity differences',scan_problems:'Failed, incomplete or interrupted scans',health:'Engine and scanning-data health',maintenance:'Updates and maintenance',mail:'Email protection alerts',actions:'Quarantine, cleaning and repairs',other:'Other notifications'};
const notificationSettings=(extra={})=>({account:'alice',server:false,categories:notificationKinds,settings:{bell:false,categories:Object.keys(notificationKinds),revision:'preferences-one',last_sent:null,error:null,...extra}});
const notice=(event,id='notice-one',extra={})=>({id,event,owner:'alice',subject:'site.test',created:1,read_at:null,detail:{counters:{scanned:20,infected:1,errors:0}},...extra});

test('notification preferences save selected types and Bell without reload while filters retain access to recorded events',async()=>{
  const f=fixture({hash:'#settings/notifications',change:v=>v.notifications=[notice('scan.malware_found'),notice('scan.partial','notice-two'),notice('wordpress.integrity_issues','notice-three')],api:async body=>({ok:true,json:async()=>({ok:true,...notificationSettings(body.action==='notification-settings-save'?JSON.parse(body.policy):{})})})});
  try{await settle();const form=f.document.getElementById('cs-notification-preferences');assert.equal(form.elements.bell.checked,false);
    for(const input of form.querySelectorAll('[name=category]'))input.checked=input.value==='detections';form.elements.bell.checked=true;
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    const saved=f.requests.find(body=>body.action==='notification-settings-save');assert.deepEqual(JSON.parse(saved.policy),{bell:true,categories:['detections']});assert.equal(saved.revision,'preferences-one');
    const rows=[...f.document.querySelectorAll('#cs-notification-list tr')];assert.deepEqual(rows.map(r=>r.hidden),[false,true,true]);
    assert.match(f.document.getElementById('cs-notification-preference-status').textContent,/saved/);
    const type=f.document.getElementById('cs-notification-type');type.value='integrity';type.dispatchEvent(new f.w.Event('change'));assert.deepEqual(rows.map(r=>r.hidden),[true,true,false]);
    type.value='all';type.dispatchEvent(new f.w.Event('change'));assert.equal(rows.filter(r=>!r.hidden).length,3);
    assert.equal(f.document.querySelector('[data-main-tab=settings]').getAttribute('aria-current'),'page');
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
test('Global Email Shield loads server settings and all-account activity without reading admin mail domains',async()=>{
  const f=fixture({hash:'#email',change:values=>{values.context.view_scope='server';values.accounts.push({owner:'bob'});},api:async body=>({ok:true,json:async()=>({ok:true,...(body.action==='mail-server-activity'?{totals:{domains:2,quarantine:1,decisions:4},accounts:[{owner:'bob',domains:2,quarantine:1,decisions:4}],quarantine:[{owner:'bob',recipient:'inbox@bob.test',created:1,status:'quarantined'}],decisions:[]}:{defaults:mailDefaults,permissions:mailPermissions,revision:'server-revision'})})})});
  try{await settle();
    assert.ok(f.requests.some(row=>row.action==='mail-server-get'));assert.ok(f.requests.some(row=>row.action==='mail-server-activity'));
    assert.equal(f.requests.some(row=>row.action==='mail-dashboard'),false);
    assert.equal(f.document.getElementById('cs-mail-domain'),null);
    assert.match(f.document.getElementById('cs-mail-server-totals').textContent,/2 mail domains/);
    const link=new URL(f.document.querySelector('#cs-mail-server-accounts a').href);assert.equal(link.searchParams.get('owner'),'bob');assert.equal(link.searchParams.has('scope'),false);
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
  const f=fixture({hash:'#email',api:async body=>({ok:true,json:async()=>({ok:true,...value})})});
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
test('Manage links select the right group, preserve leaf refresh state and load lazy email/history views',async()=>{
  const f=fixture();try{
    f.click('#cs-dashboard [data-tab=rules]');assert.deepEqual(f.visible(),['rules']);assert.equal(f.w.location.hash,'#updates');
    f.click('[data-main-tab=dashboard]');f.click('#cs-dashboard [data-focus-provider=securiteinfo]');
    assert.deepEqual(f.visible(),['providers']);assert.equal(f.document.activeElement.id,'cs-provider-securiteinfo');
    f.click('[data-main-tab=email]');f.click('[data-main-tab=review]');f.click('[data-subnav=review] [data-tab=history]');
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

test('Review groups existing review tools and remembers the selected child while both navigation levels stay active',async()=>{
  const f=fixture();try{
    f.click('[data-main-tab=review]');assert.deepEqual(f.visible(),['findings']);
    const review=f.document.querySelector('[data-subnav=review]');
    assert.deepEqual([...review.children].map(link=>link.textContent),['Results','Repairs and cleaning','Exceptions','Quarantine','History']);
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
test('email normal view keeps technical controls closed and management links open the right section',async()=>{
  const f=fixture({hash:'#email'});
  try{await settle();const advanced=f.document.getElementById('cs-mail-advanced');
    assert.equal(advanced.open,false);
    assert.equal(f.document.getElementById('cs-mail-protection-toggle').closest('details'),null);
    for(const selector of ['[data-action="mail-adapter-build"]','[data-action="mail-integration-enable"]','#cs-mail-policy','#cs-mail-history-form','#cs-mail-quarantine-form'])assert.ok(f.document.querySelector(selector).closest('#cs-mail-advanced'));
    f.click('[data-focus-id="cs-mail-domain"]');assert.equal(advanced.open,true);assert.deepEqual(f.visible(),['mail']);
    advanced.open=false;f.click('[data-focus-id="cs-mail-quarantine-form"]');assert.equal(advanced.open,true);
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
    assert.deepEqual(JSON.parse(requests[0].policy),{automatic:false,interval_minutes:2880});
    assert.equal(f.document.getElementById('cs-yara-schedule-status').textContent,'Update schedule saved.');
    assert.match(f.document.getElementById('cs-yara-timing').textContent,/Automatic checks are off/);
    assert.match(f.document.getElementById('cs-yara-update-schedule').textContent,/publishes weekly.*default check is every 24 hours/s);
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
    for(const control of f.document.querySelectorAll('[data-page=rules] button:not([type=submit])'))assert.ok(control.closest('#cs-rules-advanced'));
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
    assert.equal(f.document.getElementById('cs-rules-advanced').open,false);assert.ok(f.document.querySelector('[data-action=rules-activate]').closest('#cs-rules-advanced'));
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

test('integrity table explains the optional folder and one click follows queued/running/completed work',async()=>{
  let completeQueue,statusIndex=0;
  const snapshots=[integrityJob('running',{counters:{seen:100,scanned:20,installations:1}}),integrityJob('completed',{finished:2,report_ready:true,discovery_complete:true,counters:{seen:120,scanned:40,installations:1,modified:1}})];
  const f=fixture({hash:'#scan/wordpress',api:body=>{
    if(body.action==='wordpress-scan')return new Promise(resolve=>{completeQueue=()=>resolve({ok:true,json:async()=>({ok:true,jobs:['integrity-one'],job:integrityJob('queued')})});});
    if(body.action==='wordpress-status')return {ok:true,json:async()=>({ok:true,job:snapshots[Math.min(statusIndex++,1)]})};
    return {ok:true,json:async()=>({ok:true,job:snapshots[1],files:[{path:'<img src=x onerror=alert(1)>.php',status:'modified',detail:{message:'Review this difference',component:{kind:'core',version:'fixture'}}}],next_offset:null})};
  }});
  try{const row=f.document.querySelector('.cs-integrity-row'),form=row.querySelector('form'),button=row.querySelector('.cs-integrity-start');
    assert.equal(row.querySelector('details').open,false);assert.match(row.textContent,/Leave empty to search the whole website/);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(button.disabled,true);assert.equal(button.textContent,'Starting check…');assert.match(row.querySelector('.cs-integrity-status').textContent,/Submitting/);
    for(let i=0;i<50;i++)form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.requests.length,1);assert.deepEqual(f.requests[0],{token:'fixture-token',owner:'alice',action:'wordpress-scan',domain:'site.test',path:''});
    completeQueue();await settle();assert.equal(button.textContent,'Queued…');assert.match(row.querySelector('.cs-integrity-status').textContent,/Waiting for the scanner/);
    await f.tick();assert.equal(button.textContent,'Checking…');assert.match(row.querySelector('.cs-integrity-counts').textContent,/20 files checked/);
    await f.tick();assert.equal(button.disabled,false);assert.equal(button.textContent,'Check again');assert.match(row.querySelector('.cs-integrity-status').textContent,/differences need review/);
    assert.equal(row.querySelector('.cs-integrity-show-report').hidden,false);assert.equal(f.timers.size,0);
    row.querySelector('.cs-integrity-show-report').click();await settle();
    const report=f.document.querySelector('.cs-integrity-report-row');assert.equal(report.hidden,false);assert.match(report.textContent,/Review this difference/);assert.equal(report.querySelector('img'),null);
    assert.equal(f.requests.filter(body=>body.action==='wordpress-scan').length,1);
  }finally{await f.close();}
});

test('integrity Global actions bind the selected website owner and explicit folder',async()=>{
  const f=fixture({hash:'#scan/wordpress',change:values=>{values.context.view_scope='server';values.sites[0].owner='bob';},api:async()=>({ok:true,json:async()=>({ok:true,job:integrityJob('queued',{owner:'bob',target:'blog'})})})});
  try{const row=f.document.querySelector('.cs-integrity-row');row.querySelector('details').open=true;row.querySelector('input[name=path]').value='blog';row.querySelector('form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.deepEqual(f.requests[0],{token:'fixture-token',owner:'bob',action:'wordpress-scan',domain:'site.test',path:'blog'});
    assert.match(row.querySelector('.cs-integrity-counts').textContent,/Folder: blog/);assert.equal(row.querySelector('.cs-integrity-start').disabled,true);
  }finally{await f.close();}
});

test('integrity queue failures stay visible and retryable even after a previous completed check',async()=>{
  const f=fixture({hash:'#scan/wordpress',change:values=>values.jobs=[integrityJob('completed',{discovery_complete:true})],api:async()=>({ok:false,json:async()=>({ok:false,error:'<b>Scanner unavailable</b>'})})});
  try{const row=f.document.querySelector('.cs-integrity-row');row.querySelector('form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();
    assert.equal(row.querySelector('.cs-integrity-start').disabled,false);assert.equal(row.querySelector('.cs-integrity-error').textContent,'<b>Scanner unavailable</b>');assert.equal(row.querySelector('.cs-integrity-error b'),null);
    assert.match(row.querySelector('.cs-integrity-status').textContent,/could not be completed/);
  }finally{await f.close();}
});

test('reopening integrity resumes an existing job and hidden pages stop polling',async()=>{
  const f=fixture({hash:'#scan/wordpress',change:values=>values.jobs=[integrityJob('running')],api:async()=>({ok:true,json:async()=>({ok:true,job:integrityJob('running',{counters:{seen:50,scanned:0,installations:0}})})})});
  try{await settle();assert.equal(f.requests[0].action,'wordpress-status');assert.equal(f.requests.some(body=>body.action==='wordpress-scan'),false);assert.equal(f.timers.size,1);
    f.click('[data-main-tab=dashboard]');assert.equal(f.timers.size,0);const count=f.requests.length;await settle();assert.equal(f.requests.length,count);
    f.click('[data-tab=wordpress]');await settle();assert.equal(f.requests.length,count+1);assert.equal(f.document.querySelector('.cs-integrity-start').disabled,true);
  }finally{await f.close();}
});

test('integrity status errors preserve pending state and an empty partial report never claims success',async()=>{
  let failed=true;
  const f=fixture({hash:'#scan/wordpress',change:values=>values.jobs=[integrityJob('running')],api:async body=>body.action==='wordpress-status'&&failed?{ok:false,json:async()=>({ok:false,error:'Status unavailable'})}:{ok:true,json:async()=>body.action==='wordpress-status'?{ok:true,job:integrityJob('partial',{report_ready:true,counters:{errors:1,installations:0,scanned:0}})}:{ok:true,job:integrityJob('partial'),files:[],next_offset:null}}});
  try{await settle();const row=f.document.querySelector('.cs-integrity-row');assert.match(row.querySelector('.cs-integrity-error').textContent,/last recorded state/);assert.equal(row.querySelector('.cs-integrity-start').disabled,true);
    failed=false;f.click('#cs-integrity-refresh');await settle();assert.match(row.querySelector('.cs-integrity-status').textContent,/Incomplete/);
    row.querySelector('.cs-integrity-show-report').click();await settle();assert.match(f.document.querySelector('.cs-integrity-report-status').textContent,/Coverage is incomplete/);
  }finally{await f.close();}
});

test('revoked scan permission keeps integrity starts disabled while recorded results remain readable',async()=>{
  const f=fixture({hash:'#scan/wordpress',admin:false,change:values=>values.website_permissions.effective.scan=false});
  try{const row=f.document.querySelector('.cs-integrity-row');assert.equal(row.querySelector('.cs-integrity-start').disabled,true);
    row.querySelector('form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await settle();assert.equal(f.requests.length,0);
  }finally{await f.close();}
});
