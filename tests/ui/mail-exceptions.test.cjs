const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {JSDOM} = require('jsdom');

const root = path.resolve(__dirname, '../..');
const php = spawnSync(process.env.CLAMSHIELD_PHP || 'php', ['-r',
  "$data=['context'=>['owner'=>'alice','admin'=>false]];$_SESSION=['token'=>'fixture-token'];" +
  "$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];",
  path.join(root, 'panel/mail.php')], {encoding: 'utf8'});
assert.equal(php.status, 0, php.stderr);
const source = fs.readFileSync(path.join(root, 'panel/mail.js'), 'utf8');
const entry = {id: 'fixture-entry', engine: 'clamav', signature: '<img src=x onerror=alert(1)>',
  sha256: 'a'.repeat(64), expires: 2000000000, reason: '<script>untrusted reason</script>'};
const permissions = {manage_policy: true, manage_exceptions: true, release: true, delete: true};
const base = {enabled: true, malware_action: 'reject', phishing_action: 'quarantine', spam_action: 'junk',
  spam_high_action: 'reject', block_action: 'quarantine', spam_threshold: 5, spam_high_threshold: 15,
  signature_spam_score: 5, allow_senders: [], block_senders: [], exceptions: [entry]};

async function until(predicate) {
  for (let i=0;i<100;i++) { await new Promise(resolve=>setImmediate(resolve)); if (predicate()) return; }
  throw new Error('UI state did not settle');
}

async function fixture(options={}) {
  const dom = new JSDOM(php.stdout, {url: 'https://panel.test/plugins/clamshield/', runScripts: 'outside-only'});
  const w = dom.window, requests = []; let retentionDays = 0;
  const policy = {domain: 'alice.test', mailbox: '', overrides: {exceptions: [entry]}, effective: base,
    revision: 'original-revision', exception_entries: [entry], permissions: {...permissions,...options.permissions},
    native_antivirus: false, native_antispam: false, native_reject_spam: false};
  w.fetch = async (_url, request) => {
    const body = Object.fromEntries(request.body); requests.push(body);
    let result = {};
    if (body.action === 'mail-review') result = {total:(options.reviewItems || []).length,items:options.reviewItems || [],next_offset:null};
    else if (body.action === 'mail-review-recheck') {
      if (options.reviewError) return {ok:false,json:async()=>({ok:false,error:options.reviewError})};
      result = {state: options.reviewState || 'uncertain',stage:body.stage};
    }
    else if (body.action.startsWith('mail-retention-')) {
      if (body.action === 'mail-retention-history') result = {total:(options.retentionActions || []).length,actions:options.retentionActions || [],next_offset:null,can_manage:policy.permissions.delete};
      else if (body.action === 'mail-retention-retry') result = {retry_queued:true};
      else {
        if (body.action === 'mail-retention-save') {
          if (options.retentionConflict) return {ok:false,json:async()=>({ok:false,error:'Quarantine retention changed. Reload it before saving.'})};
          const value=JSON.parse(body.policy);retentionDays=value.days ?? 0;
        }
        result = {domain:'alice.test',mailbox:body.mailbox || '',effective_days:retentionDays,parent_days:0,override_days:retentionDays,
          inherited:false,revision:'retention-revision',can_manage:policy.permissions.delete,
          summary:{due:body.action==='mail-retention-preview'?2:0,held:1,quarantined:3},preview_days:retentionDays};
      }
    }
    else if (body.action === 'mail-dashboard') result = {domains:[{domain:'alice.test', suspended:false,
      mailboxes:[{name:'inbox',address:'inbox@alice.test',suspended:false}]}], permissions:policy.permissions,
      transport_active:true,cleanup_blocked:0};
    else if (body.action === 'mail-policy-get') result = {...policy,mailbox:body.mailbox || '',
      overrides:body.mailbox ? {} : policy.overrides};
    else if (body.action === 'mail-decisions') result = {total:1,decisions:[{created:1,sender:'sender@remote.test',
      recipient:'inbox@alice.test',action:'reject',classification:'malware',sha256:'c'.repeat(64),
      detail:{detections:[{engine:'clamav',signature:'Historical.Rule'}], ...(options.transportNote ? {transport_note:options.transportNote}:{}), ...(options.nativeMime?{native_mime:options.nativeMime}:{}),...(options.nativeDnsbl?{native_dnsbl:options.nativeDnsbl}:{}), ...(options.nativeSpam ? {native_spamassassin:options.nativeSpam}:{}), ...(options.spamassassin ? {spamassassin:options.spamassassin} : {})}}],next_offset:null};
    else if (body.action === 'mail-quarantine') result = {total:1,next_offset:null,permissions:policy.permissions,
      messages:[{id:'delivery-one',created:1,subject:'Fixture',sender:'sender@remote.test',recipient:'inbox@alice.test',
        status:'quarantined',action:'quarantine',source_status:Object.hasOwn(options,'sourceStatus') ? options.sourceStatus : 'accepted'}]};
    else if (body.action === 'mail-preview') result = {preview:{domain:'alice.test',mailbox:'inbox',recipient:'inbox@alice.test',
      sha256:'a'.repeat(64),headers:{Subject:'Fixture'},text:'Plain message',available:true,
      decision:{detections:[{engine:'clamav',signature:'Detected.Fixture'}],...(options.transportNote?{transport_note:options.transportNote}:{}),...(options.nativeMime?{native_mime:options.nativeMime}:{}),...(options.nativeDnsbl?{native_dnsbl:options.nativeDnsbl}:{}),...(options.nativeSpam?{native_spamassassin:options.nativeSpam}:{}),...(options.spamassassin?{spamassassin:options.spamassassin}:{})}}};
    else if (body.action.startsWith('mail-exception') || body.action === 'mail-policy-save' || body.action === 'mail-policy-reset') {
      if (options.conflict) return {ok:false,json:async()=>({ok:false,error:'Email policy changed. Reload it.'})};
      result = policy;
    }
    return {ok:true,json:async()=>({ok:true,...structuredClone(result)})};
  };
  w.sessionStorage.setItem('clamshield-tab','mail-settings'); w.eval(source);
  await until(()=>!w.document.getElementById('cs-mail-policy').hidden && requests.some(r=>r.action==='mail-quarantine'));
  return {dom,w,requests,byId:id=>w.document.getElementById('cs-mail-'+id),close:()=>w.close()};
}

test('Review mailbox selectors stay synchronized with policy scope without leaving Review',async()=>{
  const f=await fixture();
  try{
    const domain=f.w.document.querySelector('.cs-mail-domain-mirror'),box=f.w.document.querySelector('.cs-mail-box-mirror');
    assert.equal(domain.value,'alice.test');assert.equal(box.options.length,2);
    box.value='inbox';box.dispatchEvent(new f.w.Event('change'));
    await until(()=>f.byId('exception-status').textContent.includes('inbox@alice.test'));
    assert.equal(f.byId('box').value,'inbox');assert.equal(f.requests.filter(r=>r.action==='mail-policy-get').at(-1).mailbox,'inbox');
    f.byId('box').value='';f.byId('box').dispatchEvent(new f.w.Event('change'));
    assert.equal(box.value,'');
  }finally{f.close();}
});

test('exceptions are visible as escaped text and policy permission does not grant exception editing', async()=>{
  const f=await fixture({permissions:{manage_exceptions:false}});
  try {
    assert.match(f.byId('exception-list').textContent,/untrusted reason/);
    assert.equal(f.byId('exception-list').querySelector('script,img'),null);
    assert.equal(f.byId('exception-form').querySelector('button').disabled,true);
    assert.equal(f.byId('policy').querySelector('button').disabled,false);
  } finally {f.close();}
});

test('exception-only tenant can submit exact scope, UTC expiry and revision', async()=>{
  const f=await fixture({permissions:{manage_policy:false}});
  try {
    assert.equal(f.byId('policy').querySelector('button').disabled,true);
    const form=f.byId('exception-form');
    for(const [name,value] of Object.entries({engine:'yara',signature:'Reviewed.Rule',sha256:'b'.repeat(64),
      expires:'2030-05-01T12:30',reason:'Reviewed fixture'})) form.elements.namedItem(name).value=value;
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(r=>r.action==='mail-exception-add'));
    const request=f.requests.find(r=>r.action==='mail-exception-add');
    assert.equal(request.owner,'alice'); assert.equal(request.domain,'alice.test'); assert.equal(request.mailbox,'');
    assert.equal(request.revision,'original-revision'); assert.equal(request.token,'fixture-token');
    assert.deepEqual(JSON.parse(request.policy),{engine:'yara',signature:'Reviewed.Rule',sha256:'b'.repeat(64),
      expires:Date.parse('2030-05-01T12:30Z')/1000,reason:'Reviewed fixture'});
  } finally {f.close();}
});

test('stale policy failure stays visible and policy edits send their revision',async()=>{
  const f=await fixture({conflict:true});
  try {
    f.byId('policy').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.byId('status').textContent.includes('policy changed'));
    assert.equal(f.requests.find(r=>r.action==='mail-policy-save').revision,'original-revision');
  } finally {f.close();}
});

test('inherited exception removal sends only the selected mailbox scope and entry identity',async()=>{
  const f=await fixture();
  try {
    f.byId('box').value='inbox'; f.byId('box').dispatchEvent(new f.w.Event('change'));
    await until(()=>f.byId('exception-status').textContent.includes('inherits domain exceptions'));
    f.byId('exception-list').querySelector('button').click();
    await until(()=>f.requests.some(r=>r.action==='mail-exception-remove'));
    const request=f.requests.find(r=>r.action==='mail-exception-remove');
    assert.equal(request.mailbox,'inbox');assert.equal(request.exception_id,'fixture-entry');
  } finally {f.close();}
});

test('quarantine false-positive form uses verified preview selection without supplied hash or destination',async()=>{
  const f=await fixture();
  try {
    f.byId('quarantine').querySelector('button').click();
    await until(()=>f.byId('quarantine').textContent.includes('Save exception for identical content'));
    const submit=[...f.byId('quarantine').querySelectorAll('button')].find(b=>b.textContent==='Save exception for identical content');
    const form=submit.closest('form');form.querySelector('input[type=datetime-local]').value='2030-05-01T12:30';
    form.querySelector('input[aria-label="False-positive reason"]').value='Reviewed original';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(r=>r.action==='mail-quarantine-exception'));
    const request=f.requests.find(r=>r.action==='mail-quarantine-exception'), value=JSON.parse(request.policy);
    assert.equal(request.delivery_id,'delivery-one');assert.equal(value.signature,'Detected.Fixture');
    assert.equal(Object.hasOwn(value,'sha256'),false);assert.equal(Object.hasOwn(request,'mailbox'),false);
    assert.equal(f.requests.some(r=>r.action==='mail-release'),false);
  } finally {f.close();}
});

test('source uncertainty hides false-positive mutation after preview',async()=>{
  const f=await fixture({sourceStatus:'uncertain'});
  try {
    f.byId('quarantine').querySelector('button').click();
    await until(()=>f.byId('quarantine').textContent.includes('Plain message'));
    assert.equal(f.byId('quarantine').textContent.includes('Save exception for identical content'),false);
  } finally {f.close();}
});

test('all unconfirmed source states hide release and deletion while legacy and accepted custody remain manageable',async()=>{
  for(const sourceStatus of ['armed','response_sent','uncertain','proven','rejected','future-state','accepted',null]) {
    const f=await fixture({sourceStatus});
    try {
      await until(()=>f.byId('quarantine').textContent.includes('Preview plain text'));
      const confirmed=sourceStatus===null || sourceStatus==='accepted';
      assert.equal(f.byId('quarantine').textContent.includes('Deliver anyway'),confirmed,sourceStatus);
      assert.equal(f.byId('quarantine').textContent.includes('Delete quarantined email'),confirmed,sourceStatus);
    } finally {f.close();}
  }
});

test('Deliver anyway uses the original quarantine recipient binding and requires a recorded reason',async()=>{
  const f=await fixture();
  try{await until(()=>f.byId('quarantine').textContent.includes('Deliver anyway'));
    const button=[...f.byId('quarantine').querySelectorAll('button')].find(b=>b.textContent==='Deliver anyway'),form=button.closest('form'),reason=form.querySelector('input');
    assert.equal(reason.required,true);reason.value='Reviewed false positive';form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(r=>r.action==='mail-release'));
    assert.deepEqual(f.requests.find(r=>r.action==='mail-release'),{token:'fixture-token',owner:'alice',action:'mail-release',delivery_id:'delivery-one',note:'Reviewed false positive'});
  }finally{f.close();}
});

test('retention applies only a previewed period with its scoped server revision',async()=>{
  const f=await fixture();
  try {
    await until(()=>!f.byId('retention-panel').hidden);
    const form=f.byId('retention-form'),input=form.elements.namedItem('days');
    input.value='3';input.dispatchEvent(new f.w.Event('input',{bubbles:true}));
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.requests.some(r=>r.action==='mail-retention-save'),false);
    f.byId('retention-preview').click();
    await until(()=>!form.querySelector('button[type=submit]').disabled);
    assert.match(f.byId('retention-status').textContent,/2 copies past/);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(r=>r.action==='mail-retention-save'));
    const request=f.requests.find(r=>r.action==='mail-retention-save');
    assert.equal(request.revision,'retention-revision');assert.equal(request.domain,'alice.test');
    assert.equal(request.mailbox,'');assert.deepEqual(JSON.parse(request.policy),{days:3});
  } finally {f.close();}
});

test('retention permission is independent and a stale save requires another preview',async()=>{
  const restricted=await fixture({permissions:{delete:false,manage_policy:true}});
  try {
    await until(()=>!restricted.byId('retention-panel').hidden);
    assert.equal(restricted.byId('retention-form').elements.namedItem('days').disabled,true);
    assert.equal(restricted.byId('retention-preview').disabled,true);
  } finally {restricted.close();}
  const f=await fixture({retentionConflict:true});
  try {
    await until(()=>!f.byId('retention-panel').hidden);
    const form=f.byId('retention-form');form.elements.namedItem('days').value='1';f.byId('retention-preview').click();
    await until(()=>!form.querySelector('button[type=submit]').disabled);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.byId('retention-status').textContent.includes('Preview again'));
    assert.equal(form.querySelector('button[type=submit]').disabled,true);
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.requests.filter(r=>r.action==='mail-retention-save').length,1);
  } finally {f.close();}
});

test('expiry errors render as text and retry supplies only the retained-copy identity',async()=>{
  const f=await fixture({retentionActions:[{recipient_id:'held-copy',recipient:'inbox@alice.test',status:'blocked',custody_status:'quarantined',
    error:'<img src=x onerror=alert(1)>',updated:1,deadline:2}]});
  try {
    await until(()=>f.byId('expiry-history').textContent.includes('Needs review'));
    assert.equal(f.byId('expiry-history').querySelector('img,script'),null);
    const button=f.byId('expiry-history').querySelector('button');assert.equal(button.className,'button');button.click();
    await until(()=>f.requests.some(r=>r.action==='mail-retention-retry'));
    const request=f.requests.find(r=>r.action==='mail-retention-retry');
    assert.equal(request.delivery_id,'held-copy');assert.equal(Object.hasOwn(request,'path'),false);
    assert.equal(Object.hasOwn(request,'policy'),false);
  } finally {f.close();}
});

test('decision history exposes exact content identity for reviewing rejected-message exceptions',async()=>{
  const f=await fixture();
  try {
    await until(()=>f.byId('history').textContent.includes('Historical.Rule'));
    assert.match(f.byId('history').textContent,new RegExp('Content SHA-256: '+'c'.repeat(64)));
    assert.match(f.byId('history').textContent,/reject/);
  } finally {f.close();}
});

test('mixed recipient transport explanation is visible as text in history and retained preview',async()=>{
  const f=await fixture({transportNote:'SMTP retained copy <img src=x onerror=alert(1)>'});
  try{
    await until(()=>f.byId('history').textContent.includes('SMTP retained copy'));
    assert.equal(f.byId('history').querySelector('img,script'),null);
    const preview=Array.from(f.byId('quarantine').querySelectorAll('button')).find(b=>b.textContent==='Preview plain text');preview.click();
    await until(()=>f.byId('quarantine').textContent.includes('SMTP retained copy'));
    assert.equal(f.byId('quarantine').querySelector('img,script'),null);
  } finally {f.close();}
});

test('recorded DNS access failures are separate from score contributions in both history and stored preview',async()=>{
  const f=await fixture({spamassassin:{score:2.395,required_score:5,symbols:[],rules:[],
    dns_observations:[{zone:'sa-trusted.bondedsender.org',state:'blocked'},{zone:'sa-accredit.habeas.com',state:'failed'}]}});
  try{
    await until(()=>f.byId('history').textContent.includes('Query blocked by provider'));
    assert.match(f.byId('history').textContent,/0 points/);assert.match(f.byId('history').textContent,/2.395 \/ 5/);
    f.byId('quarantine').querySelector('button').click();await until(()=>f.byId('quarantine').textContent.includes('Query blocked by provider'));
    assert.match(f.byId('quarantine').textContent,/2.395 \/ 5/);assert.match(f.byId('quarantine').textContent,/0 points/);assert.match(f.byId('quarantine').textContent,/DNS query failed — 0 points/);
  }finally{f.close();}
});

test('native recovery controls recheck original proof without accepting a resend or destination',async()=>{
  const f=await fixture({permissions:{release:false,delete:false,manage_policy:false},reviewItems:[
    {delivery_id:'review-copy',recipient:'inbox@alice.test',stage:'delivery',status:'uncertain',updated:1,error:'Native proof unavailable'}]});
  try {
    await until(()=>f.byId('review-list').querySelector('button'));
    const button=f.byId('review-list').querySelector('button');assert.equal(button.className,'button');
    button.click();await until(()=>f.byId('review-result').textContent.includes('no message was resent'));
    const request=f.requests.find(r=>r.action==='mail-review-recheck');
    assert.deepEqual(Object.keys(request).sort(),['action','delivery_id','owner','stage','token']);
    assert.equal(request.delivery_id,'review-copy');assert.equal(request.stage,'delivery');
    assert.match(f.byId('review-result').textContent,/uncertain/);
    assert.equal(f.requests.some(r=>r.action==='mail-release'),false);
  } finally {f.close();}
});

test('blocked cleanup errors stay escaped and failed rechecks remain visible and retryable',async()=>{
  const f=await fixture({reviewError:'Mail recovery is active',reviewItems:[
    {delivery_id:'cleanup-copy',recipient:'<img src=x onerror=alert(1)>',stage:'source_cleanup',status:'blocked',updated:1,error:'<script>changed</script>'}]});
  try {
    await until(()=>f.byId('review-list').querySelector('button'));
    assert.equal(f.byId('review-list').querySelector('script,img'),null);
    f.byId('review-list').querySelector('button').click();
    await until(()=>f.byId('review-result').textContent.includes('recovery is active'));
    assert.equal(f.byId('review-list').querySelector('button').disabled,false);
    assert.equal(f.requests.find(r=>r.action==='mail-review-recheck').stage,'source_cleanup');
  } finally {f.close();}
});

test('email history displays recorded contribution precision and treats descriptions as text',async()=>{
  const f=await fixture({spamassassin:{score:2.395,required_score:5,symbols:['TRANSACTIONAL'],revision:'a'.repeat(64),
    engine_version:'4.0.2',rules_version:'123456',rules:[{name:'TRANSACTIONAL',score:2.503,description:'From / Reply-To differ <img src=x onerror=alert(1)>'},
      {name:'AUTHENTICATION',score:-.108,description:'Authentication signals'}]}});
  try {
    await until(()=>f.byId('history').textContent.includes('TRANSACTIONAL: +2.503'));
    assert.match(f.byId('history').textContent,/AUTHENTICATION: -0\.108/);
    assert.match(f.byId('history').textContent,/Engine \/ rules: 4\.0\.2 \/ 123456/);
    assert.equal(f.byId('history').querySelector('img,script'),null);
  } finally {f.close();}
});

test('native prefilter score stays separate from ClamShield contributions in history and stored preview',async()=>{
  const f=await fixture({nativeSpam:{score:1000.8,source:'native-exim-acl'},spamassassin:{score:2.395,required_score:5,symbols:[],rules:[]}});
  try{
    await until(()=>f.byId('history').textContent.includes('Native SpamAssassin before ClamShield: 1000.8'));
    assert.match(f.byId('history').textContent,/SpamAssassin: 2\.395 \/ 5/);
    f.byId('quarantine').querySelector('button').click();
    await until(()=>f.byId('quarantine').textContent.includes('Native SpamAssassin before ClamShield: 1000.8'));
    assert.match(f.byId('quarantine').textContent,/SpamAssassin: 2\.395 \/ 5/);
  }finally{f.close();}
});

test('authenticated native DNSBL explanation remains separate from SA points in history and preview',async()=>{
  const f=await fixture({nativeDnsbl:{zone:'zen.spamhaus.org',access:'dqs',state:'listed',return_codes:['127.0.0.2'],listing_codes:['127.0.0.2'],error_codes:[],score_contribution:0},
    spamassassin:{score:1.25,required_score:5,symbols:[],rules:[]}});
  try{
    await until(()=>f.byId('history').textContent.includes('Native DNSBL: zen.spamhaus.org (DQS)'));
    assert.match(f.byId('history').textContent,/selected spam policy applies/);
    assert.match(f.byId('history').textContent,/Native DNSBL score contribution: 0/);
    assert.match(f.byId('history').textContent,/SpamAssassin: 1\.25 \/ 5/);
    f.byId('quarantine').querySelector('button').click();
    await until(()=>f.byId('quarantine').textContent.includes('Return codes: 127.0.0.2'));
  }finally{f.close();}
});

test('native DNSBL operational error renders as plain diagnostic text without a listing verdict',async()=>{
  const f=await fixture({nativeDnsbl:{zone:'<img src=x onerror=alert(1)>',state:'blocked',return_codes:['127.255.255.251'],error_codes:['127.255.255.251']}});
  try{
    await until(()=>f.byId('history').textContent.includes('Provider access/configuration error'));
    assert.match(f.byId('history').textContent,/Operational error codes: 127\.255\.255\.251/);
    assert.doesNotMatch(f.byId('history').textContent,/selected spam policy applies/);
    assert.equal(f.byId('history').querySelector('img,script'),null);
  }finally{f.close();}
});

test('native DNS lookup failure explains incomplete checking without a listing verdict or extra SA points',async()=>{
  const f=await fixture({nativeDnsbl:{zone:'zen.spamhaus.org',access:'public',state:'failed',return_codes:[],error_codes:[],score_contribution:0},
    spamassassin:{score:1.25,required_score:5,symbols:[],rules:[]}});
  try{
    await until(()=>f.byId('history').textContent.includes('DNS lookup failed; check incomplete'));
    assert.match(f.byId('history').textContent,/Native DNSBL score contribution: 0/);
    assert.match(f.byId('history').textContent,/SpamAssassin: 1\.25 \/ 5/);
    assert.doesNotMatch(f.byId('history').textContent,/selected spam policy applies/);
  }finally{f.close();}
});

test('recovery search is account scoped and unknown stages offer no action',async()=>{
  const f=await fixture({reviewItems:[{delivery_id:'future-copy',recipient:'inbox@alice.test',stage:'future-stage',status:'unknown',updated:1}]});
  try {
    await until(()=>f.byId('review-list').textContent.includes('Unknown recovery stage'));
    assert.equal(f.byId('review-list').querySelector('button'),null);
    const form=f.byId('review-search');form.elements.namedItem('search').value='inbox@alice.test';
    form.dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>f.requests.some(r=>r.action==='mail-review'&&r.search==='inbox@alice.test'));
    const request=f.requests.find(r=>r.action==='mail-review'&&r.search==='inbox@alice.test');
    assert.equal(request.owner,'alice');assert.equal(request.offset,'0');
  } finally {f.close();}
});


test('native extension observation explains its separate policy in history and preview',async()=>{
  const f=await fixture({nativeMime:{source:'native-exim-acl',policy:'blocked-extension',matched:true,score_contribution:0}});
  try{
    await until(()=>f.byId('history').textContent.includes('Native attachment policy: blocked extension observed'));
    assert.match(f.byId('history').textContent,/Malware verdict comes from the selected scanner/);
    assert.match(f.byId('history').textContent,/Score contribution: 0/);
    f.byId('quarantine').querySelector('button').click();
    await until(()=>f.byId('quarantine').textContent.includes('Native attachment policy: blocked extension observed'));
  }finally{f.close();}
});
