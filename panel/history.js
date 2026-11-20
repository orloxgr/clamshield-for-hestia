/* Managed by clamshield */
(() => {
  'use strict';
  const root = document.getElementById('cs-history-retention');
  const form = document.getElementById('cs-history-form'), status = document.getElementById('cs-history-status');
  const output = document.getElementById('cs-history-preview-result'), preview = document.getElementById('cs-history-preview');
  const reset = document.getElementById('cs-history-reset'), refresh = document.getElementById('cs-history-refresh');
  const permission = document.getElementById('cs-history-permission');
  let current = null, checked = null, serial = 0, loaded = false;
  async function api(action, values = {}) {
    const response = await fetch(location.pathname, {method:'POST',credentials:'same-origin',
      body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...values})});
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || 'History operation failed');
    return result;
  }
  const policy = () => Object.fromEntries(['scan_days','mail_days','event_days'].map(key => [key, Number(form.elements.namedItem(key).value)]));
  function invalidate() { checked = null; form.querySelector('button[type=submit]').disabled = true; output.textContent = ''; }
  function show(value) {
    current = value; invalidate();
    for (const key of ['scan_days','mail_days','event_days']) {
      form.elements.namedItem(key).value = value.policy[key]; form.elements.namedItem(key).disabled = !value.can_manage;
    }
    preview.disabled = reset.disabled = !value.can_manage;
    status.textContent = 'History retention for ' + root.dataset.owner + '. ' +
      (value.error || (value.can_manage ? 'Preview a period before applying it.' : 'Retention changes are disabled by the administrator.')) +
      (value.last_run ? ' Last background check: ' + new Date(value.last_run * 1000).toISOString() : '');
    if (permission) { permission.elements.namedItem('allowed').checked = value.user_allowed; permission.querySelector('button').disabled = false; }
  }
  async function load() {
    const selected = ++serial; current = null; invalidate(); refresh.disabled = preview.disabled = reset.disabled = true;
    for (const input of form.querySelectorAll('input')) input.disabled = true;
    if (permission) permission.querySelector('button').disabled = true;
    try { const value = await api('history-retention-get'); if (selected === serial) { show(value); loaded = true; } }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { if (selected === serial) refresh.disabled = false; }
  }
  form.addEventListener('input', () => { ++serial; invalidate(); });
  preview.addEventListener('click', async () => {
    if (!current || !current.can_manage || !form.reportValidity()) return;
    const selected = ++serial, proposed = policy(); invalidate(); preview.disabled = true;
    try {
      const value = await api('history-retention-preview', {policy:JSON.stringify(proposed)});
      if (selected !== serial) return;
      current = value; checked = JSON.stringify(proposed);
      output.textContent = 'Currently eligible scan reports: ' + value.preview.scan_reports + ' (' + value.preview.scan_file_rows + ' file rows). Email decisions: ' +
        value.preview.mail_decisions + '. Events: ' + value.preview.audit_events + '. Read notifications: ' + value.preview.read_notifications +
        '. Required recovery and duplicate-prevention evidence remains retained. This policy also applies to future eligible history.';
      form.querySelector('button[type=submit]').disabled = !value.can_manage;
    } catch (error) { if (selected === serial) { invalidate(); status.textContent = error.message; } }
    finally { preview.disabled = !current?.can_manage; }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!current || !current.can_manage || checked !== JSON.stringify(policy())) return;
    const selected = ++serial, proposed = policy(), revision = current.revision; invalidate(); preview.disabled = reset.disabled = true;
    try { const value = await api('history-retention-save',{policy:JSON.stringify(proposed),revision});
      if (selected === serial) { show(value); status.textContent += ' Saved. Eligible old history will be removed by background recovery.'; } }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { preview.disabled = reset.disabled = !current?.can_manage; }
  });
  reset.addEventListener('click', async () => {
    if (!current || !current.can_manage) return;
    const selected = ++serial, revision = current.revision; invalidate(); reset.disabled = true;
    try { const value = await api('history-retention-reset',{revision}); if (selected === serial) show(value); }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { reset.disabled = !current?.can_manage; }
  });
  permission?.addEventListener('submit', async event => {
    event.preventDefault(); if (!current) return;
    const selected = ++serial, revision = current.revision, allowed = permission.elements.namedItem('allowed').checked; invalidate();
    permission.querySelector('button').disabled = true;
    try { const value = await api('history-retention-permission',{policy:JSON.stringify({allowed}),revision}); if (selected === serial) show(value); }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { permission.querySelector('button').disabled = false; }
  });
  refresh.addEventListener('click', load);
  document.querySelector('[data-tab=history]')?.addEventListener('click', () => { if (!loaded) load(); });
  if (sessionStorage.getItem('clamshield-tab') === 'history') queueMicrotask(load);
})();
