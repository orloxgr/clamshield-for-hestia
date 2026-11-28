/* Managed by clamshield */
(() => {
  'use strict';
  const root = document.getElementById('cs-server-history'); if (!root) return;
  const form = document.getElementById('cs-server-history-form'), status = document.getElementById('cs-server-history-status');
  const output = document.getElementById('cs-server-history-preview-result');
  const preview = document.getElementById('cs-server-history-preview'), reset = document.getElementById('cs-server-history-reset');
  const refresh = document.getElementById('cs-server-history-refresh');
  let current = null, checked = null, serial = 0, loaded = false;
  const policy = () => Object.fromEntries(['event_days','maintenance_days'].map(key => [key, Number(form.elements.namedItem(key).value)]));
  async function api(action, values = {}) {
    const response = await window.ClamShieldApiResponse.fetch(location.pathname, {method:'POST',credentials:'same-origin',
      body:new URLSearchParams({token:root.dataset.token,owner:root.dataset.owner,action,...values})});
    const result = await window.ClamShieldApiResponse.read(response,"Server history operation failed");
    if (!response.ok || !result.ok) throw new Error(result.error || 'Server history operation failed');
    return result;
  }
  function invalidate() { checked = null; form.querySelector('button[type=submit]').disabled = true; output.textContent = ''; }
  function show(value) {
    current = value; invalidate();
    for (const key of ['event_days','maintenance_days']) { form.elements.namedItem(key).value = value.policy[key]; form.elements.namedItem(key).disabled = false; }
    preview.disabled = reset.disabled = false;
    status.textContent = 'Server-wide retention. ' + (value.error || value.blocked || 'Preview the eligible records before applying a period.') +
      (value.last_run ? ' Last background check: ' + new Date(value.last_run * 1000).toISOString() : '');
  }
  async function load() {
    const selected = ++serial; current = null; invalidate(); preview.disabled = reset.disabled = refresh.disabled = true;
    for (const input of form.querySelectorAll('input')) input.disabled = true;
    try { const value = await api('server-history-get'); if (selected === serial) { show(value); loaded = true; } }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { if (selected === serial) refresh.disabled = false; }
  }
  form.addEventListener('input', () => { ++serial; invalidate(); });
  preview.addEventListener('click', async () => {
    if (!current || !form.reportValidity()) return;
    const selected = ++serial, proposed = policy(); invalidate(); preview.disabled = true;
    try { const value = await api('server-history-preview',{policy:JSON.stringify(proposed)});
      if (selected !== serial) return;
      current = value; checked = JSON.stringify(proposed);
      output.textContent = (value.blocked ? value.blocked + '. ' : '') + 'Eligible server events: ' + value.preview.server_events +
        '. Read server notices: ' + value.preview.read_server_notifications + '. Old maintenance details: ' + value.preview.maintenance_details +
        '. Required proofs and latest outcomes remain retained. This period also applies to future eligible history.';
      form.querySelector('button[type=submit]').disabled = false;
    } catch (error) { if (selected === serial) { invalidate(); status.textContent = error.message; } }
    finally { preview.disabled = !current; }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!current || checked !== JSON.stringify(policy())) return;
    const selected = ++serial, revision = current.revision, proposed = policy(); invalidate(); preview.disabled = reset.disabled = true;
    try { const value = await api('server-history-save',{policy:JSON.stringify(proposed),revision});
      if (selected === serial) { show(value); status.textContent += ' Saved for background recovery.'; } }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { preview.disabled = reset.disabled = !current; }
  });
  reset.addEventListener('click', async () => {
    if (!current) return;
    const selected = ++serial, revision = current.revision; invalidate(); reset.disabled = true;
    try { const value = await api('server-history-reset',{revision}); if (selected === serial) show(value); }
    catch (error) { if (selected === serial) status.textContent = error.message; }
    finally { reset.disabled = !current; }
  });
  refresh.addEventListener('click',load);
  document.querySelector('[data-tab=retention]')?.addEventListener('click', () => { if (!loaded) load(); });
  document.addEventListener('clamshield-tab-change', event => { if (event.detail === 'retention' && !loaded) load(); });
  if (sessionStorage.getItem('clamshield-tab') === 'retention') queueMicrotask(load);
})();
