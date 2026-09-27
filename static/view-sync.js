// KeyMelier – sync between computers
//
// Status line on the backup page, setup and status card in the app settings.
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js ($, t, escHtml, call,
// icon, render …) only inside functions, never while loading.

let syncState = null;     // sync_status from the service
let syncForm = { folder: '', error: null, busy: false, confirmOff: false };

// ── Sync between computers ──────────────────────────────────────────────────
// Through a folder the user already syncs; files are encrypted with a
// passphrase kept in the OS credential store (fido2tool_core/sync.py).

async function loadSync() {
  try { syncState = await call('sync_status'); } catch { syncState = null; }
  if (PANEL_VIEWS[mainView]) renderPanel();
}

// One line on the backup page; details and setup live in the app settings.
// "Synced" means: this computer read the folder and wrote its file – not
// that the cloud has already delivered it everywhere.
function syncLineHtml() {
  const st = syncState;
  if (!st) return '';
  const problem = st.active && (st.errors.length || st.notice);
  const text = !st.available ? t('sync.line.unavailable')
    : st.active ? t('sync.line.on', { when: st.last_sync ? relTime(st.last_sync) : '—', n: st.devices.length })
      : t('sync.line.off');
  return `<div class="sync-line${problem ? ' warn' : ''}" role="status">${icon('refresh', 15)}
    <span>${escHtml(text)}${problem ? ` · ${escHtml(t('sync.line.problem'))}` : ''}</span>
    <button type="button" class="btn-link" data-act="open-settings">${escHtml(t('sync.line.settings'))}</button></div>`;
}

function syncErrorText(e) {
  return t(`sync.err.${e.code}`, { file: e.file || '' });
}

function syncCardHtml() {
  const st = syncState;
  if (!st) return '';
  const head = `<h2>${escHtml(t('sync.title'))}</h2><p class="card-text">${escHtml(t('sync.textShort'))}</p>
    <details class="acc-more"><summary>${escHtml(t('sync.how'))}</summary><p class="field-hint">${escHtml(t('sync.text'))}</p>
      <p class="field-hint">${escHtml(t('sync.privacy'))}</p></details>`;
  if (!st.available) {
    return `<section class="card" id="sync-card">${head}<p class="field-hint bk-hint">${escHtml(t('sync.needsHistory'))}</p></section>`;
  }
  if (st.active) {
    const devices = st.devices.length
      ? `<ul class="sync-devices">${st.devices.map(d => `<li><span>${escHtml(d.name || d.device)}</span>
          <span class="muted">${escHtml(t('sync.written', { when: relTime(d.written) }))}</span></li>`).join('')}</ul>`
      : `<p class="field-hint bk-hint">${escHtml(t('sync.noOthers'))}</p>`;
    const off = syncForm.confirmOff ? `<div class="sync-off">
        <label class="check"><input type="checkbox" id="sync-remove-file"><span>${escHtml(t('sync.removeFile'))}</span></label>
        <div class="form-actions">
          <button type="button" class="btn btn-secondary" data-act="sync-off-cancel">${escHtml(t('pk.delete.cancel'))}</button>
          <button type="button" class="btn btn-danger" data-act="sync-off">${escHtml(t('sync.off'))}</button>
        </div></div>` : '';
    return `<section class="card" id="sync-card">${head}
      <p class="sync-state"><b>${escHtml(t('sync.on.state'))}</b> · ${escHtml(t('sync.last'))}: ${escHtml(st.last_sync ? relTime(st.last_sync) : '—')}
        · ${escHtml(t('sync.othersN', { n: st.devices.length }))}</p>
      <p class="field-hint">${escHtml(t('sync.lastHint'))}</p>
      ${st.notice ? `<p class="field-hint bk-hint warn-text">${escHtml(t(`sync.notice.${st.notice.code}`, { file: st.notice.file }))}</p>` : ''}
      ${st.errors.map(e => `<p class="field-hint bk-hint warn-text">${escHtml(syncErrorText(e))}</p>`).join('')}
      <div class="form-actions att-actions">
        <button type="button" class="btn btn-secondary" data-act="sync-now">${escHtml(t('sync.now'))}</button>
        ${syncForm.confirmOff ? '' : `<button type="button" class="btn btn-secondary" data-act="sync-off-ask">${escHtml(t('sync.off'))}</button>`}
      </div>
      ${off}
      <details class="acc-more"><summary>${escHtml(t('sync.details'))}</summary>
        <dl class="kv">
          <dt>${escHtml(t('sync.folder'))}</dt><dd class="mono">${escHtml(st.folder)}</dd>
          <dt>${escHtml(t('sync.thisComputer'))}</dt><dd>${escHtml(st.device_name)}</dd>
        </dl>
        <h3 class="bk-group">${escHtml(t('sync.others'))}</h3>
        ${devices}
      </details>
    </section>`;
  }
  const problem = st.problem ? `<p class="field-hint bk-hint warn-text">${escHtml(t(`sync.err.${st.problem}`, { file: '' }))}</p>` : '';
  const folder = syncForm.folder || st.configured_folder || '';
  return `<section class="card" id="sync-card">${head}${problem}
    <form id="sync-form" class="sync-form" autocomplete="off">
      <div class="sync-folder">
        <button type="button" class="btn btn-secondary" data-act="sync-choose">${escHtml(t('sync.choose'))}</button>
        <span class="mono ${folder ? '' : 'muted'}">${escHtml(folder || t('sync.noFolder'))}</span>
      </div>
      <label class="field"><span>${escHtml(t('sync.passphrase'))}</span>
        <input type="password" id="sync-pass" minlength="${st.min_passphrase}" maxlength="200" required></label>
      <label class="field"><span>${escHtml(t('sync.passphrase2'))}</span>
        <input type="password" id="sync-pass2" maxlength="200" required></label>
      <p class="field-hint">${escHtml(t('sync.passHint', { n: st.min_passphrase }))}</p>
      ${syncForm.error ? `<p class="field-error">${escHtml(syncForm.error)}</p>` : ''}
      <div class="form-actions">
        <button type="submit" class="btn btn-primary" ${folder && !syncForm.busy ? '' : 'disabled'}>${escHtml(t(syncForm.busy ? 'sync.working' : 'sync.on'))}</button>
      </div>
    </form>
  </section>`;
}

async function syncAction(act) {
  if (act === 'sync-choose') {
    const folder = await window.pywebview.api.choose_folder();
    if (folder) { syncForm.folder = folder; syncForm.error = null; renderPanel(); }
    return;
  }
  if (act === 'sync-off-ask' || act === 'sync-off-cancel') {
    syncForm.confirmOff = act === 'sync-off-ask';
    return renderPanel();
  }
  try {
    if (act === 'sync-now') syncState = await call('sync_now');
    if (act === 'sync-off') {
      syncState = await call('sync_disable', { remove_file: !!$('sync-remove-file')?.checked });
      syncForm = { folder: '', error: null, busy: false, confirmOff: false };
      showToast(t('sync.turnedOff'), 'success');
    }
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
  await loadHistory();
  render();
}

async function syncSubmit() {
  const pass = $('sync-pass'), pass2 = $('sync-pass2');
  const folder = syncForm.folder || syncState?.configured_folder;
  if (pass.value !== pass2.value) { syncForm.error = t('sync.mismatch'); return renderPanel(); }
  if (pass.value.length < (syncState?.min_passphrase || 10)) {
    syncForm.error = t('sync.passHint', { n: syncState?.min_passphrase || 10 });
    return renderPanel();
  }
  syncForm.busy = true;
  syncForm.error = null;
  const passphrase = pass.value;
  pass.value = pass2.value = '';
  renderPanel();
  try {
    syncState = await call('sync_enable', { folder, passphrase });
    syncForm = { folder: '', error: null, busy: false, confirmOff: false };
    await loadHistory();
    showToast(t('sync.turnedOn'), 'success');
    render();
  } catch (e) {
    syncForm.busy = false;
    const code = e?.data?.code;
    syncForm.error = code && STRINGS.en[`sync.err.${code}`] ? syncErrorText({ code }) : errorMessage(e);
    renderPanel();
  }
}
