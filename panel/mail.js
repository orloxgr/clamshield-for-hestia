/* Managed by clamshield */
(() => {
  'use strict';
  function nativeControl(tag, type = 'text') {
    const node = document.createElement(tag);
    if (tag === 'input') node.type = type;
    if (tag === 'button') node.className = 'button';
    else if (tag === 'select') node.className = 'form-select';
    else if (tag !== 'input' || !['checkbox', 'radio', 'hidden'].includes(type)) node.className = 'form-control';
    return node;
  }
  const root = document.getElementById('cs-mail');
  if(!root||root.dataset.global==='true')return;
  const byId = id => document.getElementById('cs-mail-' + id);
  const status = byId('status'), domain = byId('domain'), mailbox = byId('box');
  let domains = [], current = null, permissions = {}, loaded = false, busy = false;
  let historySearch = '', historyOffset = 0, revision = 0, historyRevision = 0;
  let quarantineSearch = '', quarantineOffset = 0, quarantineRevision = 0;
  let retentionValue = null, retentionLoad = 0, retentionPreview = null, retentionInherit = false;
  let expirySearch = '', expiryOffset = 0, expiryRevision = 0;
  let reviewSearch = '', reviewOffset = 0, reviewRevision = 0;
  const fields = [
    ['malware_action', 'Malware', 'action'], ['phishing_action', 'Phishing', 'action'],
    ['spam_action', 'Spam', 'action'], ['spam_high_action', 'High-score spam', 'action'],
    ['block_action', 'Blocked envelope sender', 'action'],
    ['spam_threshold', 'Spam score threshold', 'number'],
    ['spam_high_threshold', 'High spam score threshold', 'number'],
    ['signature_spam_score', 'Score per spam signature match', 'number'],
    ['allow_senders', 'Spam allowlist: envelope sender or *@domain, one per line', 'list'],
    ['block_senders', 'Blocklist: envelope sender or *@domain, one per line', 'list']
  ];
  const permissionLabels = {manage_policy: 'Edit policies', manage_exceptions: 'Manage exact-content exceptions',
    release: 'Release quarantined email', delete: 'Delete quarantined email'};
  const canEdit = () => root.dataset.admin === 'true' || permissions.manage_policy;
  const canExcept = () => root.dataset.admin === 'true' || permissions.manage_exceptions;
  async function api(action, values = {}) {
    const response = await fetch(location.pathname, {method: 'POST', credentials: 'same-origin',
      body: new URLSearchParams({token: root.dataset.token, owner: root.dataset.owner, action, ...values})});
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || 'Email operation failed');
    return result;
  }
  function option(select, value, label) {
    const item = document.createElement('option'); item.value = value; item.textContent = label; select.append(item);
  }
  function detectionLabel(hit) {
    let text = hit.engine + ': ' + hit.signature;
    if (hit.category) text += ' · ' + hit.category;
    if (hit.attribution) text += ' · ' + hit.attribution;
    const origins = hit.origins?.length ? hit.origins : [hit];
    for (const origin of origins) {
      if (origin.provider) text += '\n' + origin.provider;
      if (origin.source_id) text += ' · ' + origin.source_id;
      if (origin.source_version) text += ' · ' + origin.source_version.slice(0, 12);
    }
    return text;
  }
  function spamAssassinLabel(detail) {
    const native=detail.native_spamassassin;
    const dns=detail.native_dnsbl;
    const dnsLabel=dns?'Native DNSBL: '+dns.zone+(dns.access==='dqs'?' (DQS)':'')+' · '+
      ({listed:'Listing observed; selected spam policy applies',blocked:'Provider access/configuration error',failed:'DNS lookup failed; check incomplete',unsupported:'Unrecognized provider or response',invalid:'Invalid native response'}[dns.state]||'Unknown')+
      '\nNative DNSBL score contribution: 0\n'+
      (dns.return_codes?.length?'Return codes: '+dns.return_codes.join(', ')+'\n':'')+
      (dns.error_codes?.length?'Operational error codes: '+dns.error_codes.join(', ')+'\n':''):'';
    const mimeLabel=detail.native_mime?.matched===true?'Native attachment policy: blocked extension observed. Malware verdict comes from the selected scanner. Score contribution: 0\n':'';
    const earlier=(native?'Native SpamAssassin before ClamShield: '+native.score+'\n':'')+dnsLabel+mimeLabel;
    const sa=detail.spamassassin;if(!sa)return earlier;
    return earlier+'SpamAssassin: '+sa.score+' / '+sa.required_score+'\nRules: '+
      (sa.rules?sa.rules.map(rule=>rule.name+': '+(rule.score>0?'+':'')+rule.score+' · '+rule.description).join('\n'):(sa.symbols||[]).join(', '))+
      '\nEngine / rules: '+(sa.engine_version||'unrecorded')+' / '+(sa.rules_version||'unrecorded')+
      '\nConfiguration: '+(sa.revision||'unrecorded')+'\n'+
      (sa.dns_observations?.length?'DNS checks (no spam points for access failures):\n'+
        sa.dns_observations.map(item=>item.zone+': '+({blocked:'Query blocked by provider — 0 points',failed:'DNS query failed — 0 points','response-observed':'DNS response observed'}[item.state]||'Unknown')).join('\n')+'\n':'');
  }
  function showPolicy(value) {
    current = value; permissions = value.permissions;
    byId('native').textContent = 'Native antivirus: ' + (value.native_antivirus ? 'on' : 'off') +
      ' · Native antispam: ' + (value.native_antispam ? 'on' : 'off') +
      ' · Native spam rejection: ' + (value.native_reject_spam ? 'on' : 'off');
    const form = byId('policy'), list = byId('fields'); list.replaceChildren(); form.hidden = false;
    for (const [key, label, kind] of fields) {
      const row = document.createElement('p'), title = document.createElement('label');
      title.textContent = label + ' '; row.append(title);
      let input;
      if (kind === 'action') {
        input = nativeControl('select');
        for (const [action, text] of [['reject', 'SMTP rejection'], ['quarantine', 'Quarantine'], ['junk', 'Junk'], ['tag', 'Tag and deliver']]) {
          if (key === 'malware_action' && action === 'junk') continue;
          option(input, action, text);
        }
        input.value = value.effective[key];
      } else if (kind === 'list') {
        input = nativeControl('textarea'); input.rows = 4; input.style.width = '95%';
        input.value = value.effective[key].join('\n'); input.maxLength = 161000;
      } else {
        input = nativeControl('input', kind === 'boolean' ? 'checkbox' : 'number');
        if (kind === 'boolean') input.checked = value.effective[key];
        else { input.min = '0'; input.max = '100'; input.step = '0.1'; input.value = value.effective[key]; }
      }
      input.name = key; title.append(input);
      {
        const inherit = document.createElement('label'), toggle = nativeControl('input', 'checkbox');
        toggle.dataset.override = key;
        toggle.checked = Object.hasOwn(value.overrides, key);
        toggle.disabled = !canEdit();
        input.disabled = !canEdit() || !toggle.checked;
        toggle.addEventListener('change', () => { input.disabled = !toggle.checked || !canEdit(); });
        inherit.append(toggle, document.createTextNode(value.mailbox?' Override domain setting':' Override server setting')); row.append(' ', inherit);
      }
      list.append(row);
    }
    const explanation = document.createElement('p');
    explanation.textContent = 'The sender allowlist affects spam scoring. Malware and phishing detections still follow their policies. Domains inherit the server settings; mailboxes inherit their domain. Select an override only for settings you want to change.';
    list.append(explanation);
    byId('exceptions').textContent = value.effective.exceptions.length + ' exact-content false-positive exceptions apply.';
    form.querySelector('button[type="submit"]').disabled = !canEdit(); byId('reset').disabled = !canEdit();
    byId('reset').textContent = value.mailbox ? 'Use domain policy for this mailbox' : 'Reset domain policy';
    renderPermissions(); renderExceptions(value);
  }
  function expiryInput(input) {
    input.value = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 16);
  }
  function renderExceptions(value) {
    const panel = byId('exception-panel'), list = byId('exception-list');
    panel.hidden = false; list.replaceChildren();
    const inherited = !!value.mailbox && !Object.hasOwn(value.overrides, 'exceptions');
    byId('exception-status').textContent = (value.mailbox ? 'Mailbox ' + value.mailbox + '@' + value.domain : 'Domain ' + value.domain) +
      (inherited ? ' inherits domain exceptions. Editing creates a mailbox-specific copy.' : ' uses its own exceptions.') +
      (!canExcept() ? ' Exception changes are disabled by the administrator.' : '');
    for (const entry of value.exception_entries) {
      const card = document.createElement('article'), text = document.createElement('p');
      text.textContent = entry.engine + ': ' + entry.signature + '\nSHA-256: ' + entry.sha256 +
        '\nExpires: ' + new Date(entry.expires * 1000).toISOString() + (entry.expires * 1000 <= Date.now() ? ' (expired)' : '') +
        '\nReason: ' + entry.reason; text.style.whiteSpace = 'pre-wrap'; card.append(text);
      const remove = nativeControl('button'); remove.type = 'button'; remove.disabled = !canExcept();
      remove.textContent = inherited ? 'Exclude this exception from this mailbox' : 'Remove exception';
      remove.addEventListener('click', () => changeException(value, 'mail-exception-remove', {exception_id: entry.id}, remove));
      card.append(remove); list.append(card);
    }
    const form = byId('exception-form');
    form.querySelectorAll('input,select,button').forEach(input => { input.disabled = !canExcept(); });
    expiryInput(form.elements.namedItem('expires'));
    const inherit = byId('exception-inherit');
    inherit.hidden = !value.mailbox || inherited; inherit.disabled = !canExcept();
  }
  async function changeException(target, action, values, control) {
    const selected = revision; control.disabled = true;
    try {
      const result = await api(action, {domain: target.domain, mailbox: target.mailbox, revision: target.revision, ...values});
      if (selected === revision) showPolicy(result);
      status.textContent = 'Email exceptions saved. Existing messages and decision history are unchanged.';
    } catch (error) { status.textContent = error.message; }
    finally { if (control.isConnected) control.disabled = !canExcept(); }
  }
  byId('exception-form').addEventListener('submit', event => {
    event.preventDefault(); if (!current || !canExcept()) return;
    const value = Object.fromEntries(new FormData(event.target));
    value.expires = Date.parse(value.expires + 'Z') / 1000;
    changeException(current, 'mail-exception-add', {policy: JSON.stringify(value)}, event.target.querySelector('button'));
  });
  byId('exception-inherit').addEventListener('click', event => {
    if (current && canExcept()) changeException(current, 'mail-exceptions-inherit', {}, event.target);
  });
  function renderPermissions() {
    const list = byId('permission-fields'); if (!list) return;
    list.replaceChildren();
    for (const [key, label] of Object.entries(permissionLabels)) {
      const p = document.createElement('p'), text = document.createElement('label'), input = nativeControl('input', 'checkbox');
      input.name = key; input.checked = permissions[key];
      text.append(input, document.createTextNode(' ' + label)); p.append(text); list.append(p);
    }
  }
  async function loadPolicy() {
    const selected = ++revision;
    current = null; byId('policy').hidden = true; byId('exception-panel').hidden = true;
    retentionValue = null; retentionPreview = null; byId('retention-panel').hidden = true;
    if (!domain.value) return;
    try {
      const value = await api('mail-policy-get', {domain: domain.value, mailbox: mailbox.value});
      if (selected === revision) { showPolicy(value); loadRetention(selected); }
    } catch (error) { if (selected === revision) status.textContent = error.message; }
  }
  function selectDomain() {
    mailbox.replaceChildren(); option(mailbox, '', 'Domain policy');
    const selected = domains.find(row => row.domain === domain.value);
    for (const item of selected?.mailboxes || []) if (!item.suspended) option(mailbox, item.name, item.address);
    loadPolicy();
  }
  async function history(reset = true) {
    const selected = ++historyRevision;
    const body = byId('history'), more = byId('more');
    if (reset) { historyOffset = 0; body.replaceChildren(); }
    more.disabled = true;
    try {
      const result = await api('mail-decisions', {search: historySearch, offset: String(historyOffset)});
      if (selected !== historyRevision) return;
      byId('history-status').textContent = result.total + ' recorded recipient decisions';
      for (const decision of result.decisions) {
        const row = document.createElement('tr');row.dataset.reviewId=decision.id;row.dataset.reviewAllowed='true';
        const values = [new Date(decision.created * 1000).toISOString(), decision.sender + ' → ' + decision.recipient,
          decision.action + ' · ' + (decision.classification==='incomplete'?'Check incomplete — native delivery':decision.classification),
          (decision.detail.scan_complete===false?'Scanning did not complete. This message was not classified as clean.\n':'') +
          (decision.detail.transport_note?decision.detail.transport_note+'\n':'') + spamAssassinLabel(decision.detail) +
          (decision.detail.spam_score != null ? 'Final policy score: ' + decision.detail.spam_score + '\n' : '') +
          (decision.detail.signature_generation ? 'Signature generation: ' + decision.detail.signature_generation + '\n' : '') +
          (decision.sha256 ? 'Content SHA-256: ' + decision.sha256 + '\n' : '') +
          decision.detail.detections.map(detectionLabel).join('\n')];
        for (const value of values) { const cell = document.createElement('td'); cell.textContent = value; row.append(cell); }
        body.append(row);
      }
      document.dispatchEvent(new CustomEvent('clamshield-mail-rows',{detail:body}));
      historyOffset = result.next_offset ?? 0; more.hidden = result.next_offset === null;
    } catch (error) { if (selected === historyRevision) byId('history-status').textContent = error.message; }
    finally { if (selected === historyRevision) more.disabled = false; }
  }
  async function load() {
    if (busy) return; busy = true; byId('refresh').disabled = true;
    ++revision; current = null; byId('policy').hidden = true; byId('exception-panel').hidden = true;
    status.textContent = 'Loading email domains…';
    try {
      const value = await api('mail-dashboard'); domains = value.domains; permissions = value.permissions;
      domain.replaceChildren();
      for (const row of domains) if (!row.suspended) option(domain, row.domain, row.domain);
      status.textContent = value.transport_active ? 'ClamShield mail filtering is connected.' :
        'ClamShield mail filtering is not connected. Saved ClamShield policies are not enforced yet.';
      byId('cleanup').hidden = !value.cleanup_blocked;
      byId('cleanup').textContent = value.cleanup_blocked ?
        'Private email copy cleanup needs review (' + value.cleanup_blocked + '). Open Mail recovery and private-copy cleanup.' : '';
      if (!domains.length) status.textContent += ' No native mail domains exist for this hosting account.';
      loaded = true; renderPermissions(); selectDomain(); syncMirrors(); await Promise.all([history(), quarantine(), review()]);
    } catch (error) { status.textContent = error.message; }
    finally { busy = false; byId('refresh').disabled = false; }
  }
  byId('policy').addEventListener('submit', async event => {
    event.preventDefault(); if (!current || !canEdit()) return;
    const target = current, selected = revision;
    const value = {};
    for (const [key, , kind] of fields) {
      const override = byId('fields').querySelector('[data-override="' + key + '"]');
      if (override && !override.checked) continue;
      const input = event.target.elements.namedItem(key);
      value[key] = kind === 'boolean' ? input.checked : kind === 'number' ? Number(input.value) :
        kind === 'list' ? input.value.split('\n').map(s => s.trim()).filter(Boolean) : input.value;
    }
    if (Object.hasOwn(target.overrides, 'exceptions')) value.exceptions = target.overrides.exceptions;
    try { const result = await api('mail-policy-save', {domain: target.domain, mailbox: target.mailbox, policy: JSON.stringify(value), revision: target.revision});
      if (selected === revision) showPolicy(result);
      status.textContent = 'Email policy saved. Enforcement requires a connected mail scanner.';
    } catch (error) { status.textContent = error.message; }
  });
  byId('reset').addEventListener('click', async () => {
    if (!current || !canEdit()) return;
    const target = current, selected = revision;
    try { const result = await api('mail-policy-reset', {domain: target.domain, mailbox: target.mailbox, revision: target.revision});
      if (selected === revision) showPolicy(result); }
    catch (error) { status.textContent = error.message; }
  });
  byId('permission-form')?.addEventListener('submit', async event => {
    event.preventDefault(); const value = {};
    for (const key of Object.keys(permissionLabels)) value[key] = event.target.elements.namedItem(key).checked;
    try { const result = await api('mail-permissions-save', {policy: JSON.stringify(value)}); permissions = result.permissions;
      renderPermissions(); status.textContent = 'Hosting user email permissions saved.';
    } catch (error) { status.textContent = error.message; }
  });
  byId('permission-reset')?.addEventListener('click',async()=>{try{const result=await api('mail-permissions-reset');permissions=result.permissions;renderPermissions();await loadPolicy();status.textContent='Account inherits global email permissions.';}catch(error){status.textContent=error.message;}});
  function quarantineException(container, mail, preview) {
    const hits = preview.decision.detections || [];
    if (!hits.length) return;
    const form = document.createElement('form'), description = document.createElement('p');
    description.textContent = 'False positive: create an exception for identical content at ' +
      (preview.mailbox ? preview.mailbox + '@' + preview.domain : 'domain ' + preview.domain) +
      '. The stored message remains quarantined; release is a separate action.';
    const choice = nativeControl('select'); choice.setAttribute('aria-label', 'Detected signature to except');
    hits.forEach((hit, index) => option(choice, String(index), hit.engine + ': ' + hit.signature));
    const expiryLabel = document.createElement('label'), expiry = nativeControl('input');
    expiry.type = 'datetime-local'; expiry.required = true; expiryInput(expiry);
    expiryLabel.append(document.createTextNode(' Expiry (UTC) '), expiry);
    const reason = nativeControl('input'); reason.required = true; reason.maxLength = 1000;
    reason.placeholder = 'False-positive reason'; reason.setAttribute('aria-label', 'False-positive reason');
    const submit = nativeControl('button'); submit.type = 'submit'; submit.textContent = 'Save exception for identical content';
    const result = document.createElement('p'); result.setAttribute('role', 'status');
    form.append(description, choice, expiryLabel, reason, submit, result);
    form.addEventListener('submit', async event => {
      event.preventDefault(); submit.disabled = true;
      const hit = hits[Number(choice.value)];
      try {
        await api('mail-quarantine-exception', {delivery_id: mail.id, policy: JSON.stringify({engine: hit.engine,
          signature: hit.signature, expires: Date.parse(expiry.value + 'Z') / 1000, reason: reason.value})});
        result.textContent = 'Exception saved. This message remains quarantined. Other detections still apply.';
        await loadPolicy();
      } catch (error) { result.textContent = error.message; }
      finally { submit.disabled = false; }
    });
    container.append(form);
  }
  async function quarantine(reset = true) {
    const selected = ++quarantineRevision, body = byId('quarantine'), more = byId('quarantine-more');
    if (reset) { quarantineOffset = 0; body.replaceChildren(); }
    more.disabled = true;
    try {
      const result = await api('mail-quarantine', {search: quarantineSearch, offset: String(quarantineOffset)});
      if (selected !== quarantineRevision) return;
      const quarantinePermissions = result.permissions;
      byId('quarantine-status').textContent = result.total + ' stored recipient records';
      for (const mail of result.messages) {
        const row = document.createElement('tr');
        const sourcePending = mail.source_status != null && mail.source_status !== 'accepted';
        row.dataset.reviewId=mail.id;row.dataset.reviewAllowed=String(!sourcePending&&['quarantined','deleting'].includes(mail.status));
        const handlingStatus = sourcePending ?
          (mail.source_status === 'uncertain' || mail.source_error ? 'Mail handling needs review' : 'Awaiting mail server confirmation') :
          ({native_queued: 'Queued with mail server', delivery_pending: 'Preparing delivery',
            delivery_preparing: 'Preparing delivery', delivery_uncertain: 'Delivery needs review',
            native_failed: 'Delivery needs review'}[mail.status] || mail.status);
        for (const value of [new Date(mail.created * 1000).toISOString(), (mail.subject || '(No subject)') + '\n' +
            mail.sender + ' → ' + mail.recipient, handlingStatus + ' · ' + mail.action +
            (mail.expiry_at ? '\nRetention deadline: ' + new Date(mail.expiry_at * 1000).toISOString() : '') + (mail.error ? '\n' + mail.error : '')]) {
          const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
        }
        const actions = document.createElement('td'), preview = nativeControl('button'), output = document.createElement('pre');
        output.style.whiteSpace = 'pre-wrap'; output.style.maxWidth = '650px'; output.setAttribute('aria-live', 'polite');
        preview.type = 'button'; preview.textContent = 'Preview plain text';
        preview.disabled = !['quarantined', 'release_queued', 'ready', 'delivery_uncertain',
          'delivery_preparing', 'delivery_pending', 'native_queued', 'native_failed'].includes(mail.status);
        preview.addEventListener('click', async () => {
          preview.disabled = true;
          try {
            const result = await api('mail-preview', {delivery_id: mail.id}), data = result.preview;
            output.textContent = Object.entries(data.headers).map(([key, value]) => key + ': ' + value).join('\n') +
              '\nRecipient: ' + data.recipient + '\nSHA-256: ' + data.sha256 + '\n\n' + data.text +
              '\n\n' + (data.decision.transport_note?data.decision.transport_note+'\n':'') + spamAssassinLabel(data.decision) + (data.decision.detections || []).map(detectionLabel).join('\n') +
              (!data.available ? '\n[Plain-text preview unavailable]' : '') + (data.truncated ? '\n[Preview truncated]' : '');
            exceptionEditor.replaceChildren();
            if (mail.status === 'quarantined' && !sourcePending && (root.dataset.admin === 'true' || quarantinePermissions.manage_exceptions)) {
              quarantineException(exceptionEditor, mail, data);
            }
          } catch (error) { output.textContent = error.message; }
          finally { preview.disabled = false; }
        });
        const exceptionEditor = document.createElement('div');
        actions.append(preview, exceptionEditor);
        if (mail.status === 'quarantined' && !sourcePending && (root.dataset.admin === 'true' || result.permissions.release)) {
          const form = document.createElement('form'), note = nativeControl('input'), release = nativeControl('button');
          note.required = true; note.maxLength = 1000; note.placeholder = 'Reason for delivering this email'; note.setAttribute('aria-label', 'Email release reason');
          release.type = 'submit'; release.textContent = 'Deliver anyway'; form.append(note, release);
          form.addEventListener('submit', async event => {
            event.preventDefault(); release.disabled = true;
            try { await api('mail-release', {delivery_id: mail.id, note: note.value}); await quarantine(); }
            catch (error) { output.textContent = error.message; release.disabled = false; }
          });
          actions.append(form);
        }
        if (mail.status === 'quarantined' && !sourcePending && (root.dataset.admin === 'true' || result.permissions.delete)) {
          const remove = nativeControl('button'); remove.type = 'button'; remove.textContent = 'Delete quarantined email';
          remove.addEventListener('click', async () => {
            remove.disabled = true;
            try { await api('mail-delete', {delivery_id: mail.id}); await quarantine(); }
            catch (error) { output.textContent = error.message; remove.disabled = false; }
          });
          actions.append(remove);
        }
        actions.append(output); row.append(actions); body.append(row);
      }
      document.dispatchEvent(new CustomEvent('clamshield-mail-rows',{detail:body}));
      quarantineOffset = result.next_offset ?? 0; more.hidden = result.next_offset === null;
    } catch (error) { if (selected === quarantineRevision) byId('quarantine-status').textContent = error.message; }
    finally { if (selected === quarantineRevision) more.disabled = false; }
  }
  function retentionText(value) {
    const summary = value.summary;
    const scope = value.mailbox ? value.mailbox + '@' + value.domain : value.domain + ' (domain default)';
    return 'Retention for ' + scope + '. ' + (value.inherited ? 'Mailbox inherits domain retention. ' : '') +
      'Current period: ' + (value.effective_days ? value.effective_days + (value.effective_days === 1 ? ' day. ' : ' days. ') : 'keep until manual deletion. ') +
      'Preview: ' + summary.due + ' copies past this period; ' + summary.held + ' awaiting mail server confirmation.';
  }
  async function loadRetention(scopeRevision = revision) {
    const selected = ++retentionLoad;
    retentionValue = null; retentionPreview = null;
    byId('retention-form').querySelector('button[type=submit]').disabled = true;
    byId('retention-form').elements.namedItem('days').disabled = true;
    byId('retention-preview').disabled = true; byId('retention-inherit').disabled = true;
    try {
      const value = await api('mail-retention-get', {domain: domain.value, mailbox: mailbox.value});
      if (selected !== retentionLoad || scopeRevision !== revision) return;
      retentionValue = value; retentionPreview = null; retentionInherit = false;
      const form = byId('retention-form'); form.elements.namedItem('days').value = value.effective_days;
      form.elements.namedItem('days').disabled = !value.can_manage;
      form.querySelector('button[type=submit]').disabled = true;
      form.querySelector('button[type=submit]').textContent = 'Apply retention period';
      byId('retention-preview').disabled = !value.can_manage;
      byId('retention-inherit').hidden = !value.mailbox; byId('retention-inherit').disabled = !value.can_manage;
      byId('retention-status').textContent = retentionText(value) + (!value.can_manage ? ' Deletion permission is required to change retention.' : ' Preview a period before applying it.');
      byId('retention-panel').hidden = false; expiryHistory();
    } catch (error) { if (selected === retentionLoad && scopeRevision === revision) { byId('retention-panel').hidden = false; byId('retention-status').textContent = error.message; } }
  }
  async function previewRetention(inherit = false) {
    if (!retentionValue) return;
    const selected = ++retentionLoad, scopeRevision = revision, form = byId('retention-form');
    const period = inherit ? retentionValue.parent_days : Number(form.elements.namedItem('days').value);
    retentionPreview = null; form.querySelector('button[type=submit]').disabled = true;
    if (!Number.isInteger(period) || period < 0 || period > 3650) { byId('retention-status').textContent = 'Choose an integer period from 0 to 3650 days.'; return; }
    byId('retention-preview').disabled = true;
    try {
      const value = await api('mail-retention-preview', {domain: retentionValue.domain, mailbox: retentionValue.mailbox, policy: JSON.stringify({days: period})});
      if (selected !== retentionLoad || scopeRevision !== revision) return;
      retentionValue = value; retentionPreview = period; retentionInherit = inherit;
      form.elements.namedItem('days').value = period;
      form.querySelector('button[type=submit]').disabled = !value.can_manage;
      form.querySelector('button[type=submit]').textContent = inherit ? 'Use domain retention' : 'Apply retention period';
      byId('retention-status').textContent = retentionText(value) + ' Proposed period: ' + (period ? period + (period === 1 ? ' day.' : ' days.') : 'keep until manual deletion.');
    } catch (error) { if (selected === retentionLoad && scopeRevision === revision) byId('retention-status').textContent = error.message; }
    finally { if (selected === retentionLoad && scopeRevision === revision) byId('retention-preview').disabled = !retentionValue?.can_manage; }
  }
  byId('retention-form').elements.namedItem('days').addEventListener('input', () => {
    ++retentionLoad; retentionPreview = null; retentionInherit = false;
    byId('retention-preview').disabled = !retentionValue?.can_manage;
    byId('retention-form').querySelector('button[type=submit]').disabled = true;
  });
  byId('retention-preview').addEventListener('click', () => previewRetention());
  byId('retention-inherit').addEventListener('click', () => previewRetention(true));
  byId('retention-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!retentionValue || retentionPreview === null) return;
    const scopeRevision = revision, value = retentionValue, button = event.target.querySelector('button[type=submit]');
    button.disabled = true;
    try {
      await api('mail-retention-save', {domain: value.domain, mailbox: value.mailbox, revision: value.revision,
        policy: JSON.stringify(retentionInherit ? {inherit: true} : {days: retentionPreview})});
      if (scopeRevision !== revision) return;
      await loadRetention(scopeRevision); quarantine();
    } catch (error) { if (scopeRevision === revision) { retentionPreview = null; byId('retention-status').textContent = error.message + ' Preview again before applying.'; } }
  });
  async function expiryHistory(reset = true) {
    const selected = ++expiryRevision, more = byId('expiry-more'), body = byId('expiry-history');
    if (reset) { expiryOffset = 0; body.replaceChildren(); }
    more.disabled = true;
    try {
      const value = await api('mail-retention-history', {search: expirySearch, offset: expiryOffset});
      if (selected !== expiryRevision) return;
      byId('expiry-status').textContent = value.total + ' retained expiry records';
      for (const item of value.actions) {
        const row = document.createElement('tr');
        const outcome = item.custody_status === 'deleted' && item.status !== 'expired' ? 'Deleted outside expiry' :
          item.error || item.custody_error ? 'Needs review' : item.status;
        for (const text of [item.recipient, (item.deadline ? new Date(item.deadline * 1000).toISOString() : 'No committed expiry') + '\n' +
          new Date(item.updated * 1000).toISOString(), outcome + (item.error || item.custody_error ? '\n' + (item.error || item.custody_error) : '')]) {
          const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
        }
        const action = document.createElement('td');
        if (value.can_manage && ['blocked', 'deleting'].includes(item.status) && ['quarantined', 'deleting'].includes(item.custody_status)) {
          const retry = nativeControl('button'); retry.type = 'button'; retry.textContent = 'Retry expiry checks';
          retry.addEventListener('click', async () => {
            retry.disabled = true;
            try { await api('mail-retention-retry', {delivery_id: item.recipient_id}); await expiryHistory(); }
            catch (error) { byId('expiry-status').textContent = error.message; retry.disabled = false; }
          }); action.append(retry);
        }
        row.append(action); body.append(row);
      }
      expiryOffset = value.next_offset ?? 0; more.hidden = value.next_offset === null;
    } catch (error) { if (selected === expiryRevision) byId('expiry-status').textContent = error.message; }
    finally { if (selected === expiryRevision) more.disabled = false; }
  }
  const reviewStages = {source: 'Source acceptance', delivery: 'Delivery confirmation',
    source_cleanup: 'Stored source cleanup', delivery_cleanup: 'Private delivery copy cleanup'};
  async function review(reset = true) {
    const selected = ++reviewRevision, body = byId('review-list'), more = byId('review-more');
    if (reset) { reviewOffset = 0; body.replaceChildren(); }
    more.disabled = true; byId('review-refresh').disabled = true;
    try {
      const value = await api('mail-review', {search: reviewSearch, offset: String(reviewOffset)});
      if (selected !== reviewRevision) return;
      byId('review-status').textContent = value.total + ' recovery items for this hosting account';
      if (reset && !reviewSearch && value.total === 0) byId('cleanup').hidden = true;
      for (const item of value.items) {
        const row = document.createElement('tr');
        for (const text of [item.recipient, new Date(item.updated * 1000).toISOString(),
          (reviewStages[item.stage] || 'Unknown recovery stage') + ' · ' + item.status + (item.error ? '\n' + item.error : '')]) {
          const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
        }
        const action = document.createElement('td');
        if (Object.hasOwn(reviewStages, item.stage)) {
          const recheck = nativeControl('button'); recheck.type = 'button';
          recheck.textContent = item.stage.endsWith('_cleanup') ? 'Recheck private-copy cleanup' : 'Recheck mail server proof';
          recheck.addEventListener('click', async () => {
            recheck.disabled = true; byId('review-result').textContent = 'Checking the original evidence…';
            try {
              const result = await api('mail-review-recheck', {delivery_id: item.delivery_id, stage: item.stage});
              byId('review-result').textContent = (reviewStages[item.stage] || 'Recovery') + ' for ' + item.recipient + ': ' + result.state +
                (['uncertain', 'blocked', 'proven', 'native_queued', 'armed', 'response_sent'].includes(result.state) ?
                  '. Original evidence or private storage still needs review. Retained copies remain protected; no message was resent.' : '. Recheck completed; no message was resent.');
              await Promise.all([review(), quarantine()]);
            } catch (error) { byId('review-result').textContent = error.message; recheck.disabled = false; }
          }); action.append(recheck);
        }
        row.append(action); body.append(row);
      }
      reviewOffset = value.next_offset ?? 0; more.hidden = value.next_offset === null;
    } catch (error) { if (selected === reviewRevision) byId('review-status').textContent = error.message; }
    finally { if (selected === reviewRevision) { more.disabled = false; byId('review-refresh').disabled = false; } }
  }
  document.addEventListener('clamshield-mail-refresh',event=>{if(event.detail==='email-stored')quarantine();if(event.detail==='email-decisions')history();});
  function syncMirrors(){for(const [kind,original] of [['domain',domain],['box',mailbox]])for(const select of document.querySelectorAll('.cs-mail-'+kind+'-mirror')){select.replaceChildren(...[...original.options].map(option=>option.cloneNode(true)));select.value=original.value;select.onchange=()=>{original.value=select.value;original.dispatchEvent(new Event('change'));};}}
  byId('review-search').addEventListener('submit', event => { event.preventDefault(); reviewSearch = new FormData(event.target).get('search'); byId('review-result').textContent = ''; review(); });
  byId('review-more').addEventListener('click', () => review(false));
  byId('review-refresh').addEventListener('click', () => { byId('review-result').textContent = ''; review(); });
  byId('expiry-search').addEventListener('submit', event => { event.preventDefault(); expirySearch = new FormData(event.target).get('search'); expiryHistory(); });
  byId('expiry-more').addEventListener('click', () => expiryHistory(false));
  byId('refresh').addEventListener('click', load); domain.addEventListener('change',()=>{selectDomain();syncMirrors();}); mailbox.addEventListener('change',()=>{loadPolicy();syncMirrors();});
  byId('history-form').addEventListener('submit', event => { event.preventDefault(); historySearch = new FormData(event.target).get('search'); history(); });
  byId('more').addEventListener('click', () => history(false));
  byId('quarantine-form').addEventListener('submit', event => { event.preventDefault(); quarantineSearch = new FormData(event.target).get('search'); quarantine(); });
  byId('quarantine-more').addEventListener('click', () => quarantine(false));

  document.addEventListener('clamshield-tab-change', event => { if (['mail-settings','email-review','quarantine','exceptions'].includes(event.detail) && !loaded) load(); });
  if (['mail-settings','email-review','quarantine','exceptions'].includes(sessionStorage.getItem('clamshield-tab'))) queueMicrotask(load);
})();
