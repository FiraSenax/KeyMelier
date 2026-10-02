'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Unlock (shared by Passkeys and Fingerprints) ────────────────────────────

// Shown while the plug-in attestation test holds the key; the tab reloads by
// itself once the test finishes (see onTokenUpdated).
function waitingHtml() {
  return `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.waitAttestation'))}</div></div>`;
}

function isBusy(e) {
  return e.data?.code === 'busy';
}

function isLocked(e) {
  return e.data?.code === 'locked';
}

let unlockBusy = null;    // null | 'pin' | 'uv' while unlocking
let unlockError = null;   // error message shown in the unlock form

function managementGateHtml(st, unsupportedKey) {
  if (!st) {
    return `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
  }
  if (st.busy) return waitingHtml();
  if (st.error) {
    return `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
  }
  if (!st.supported) {
    return `<div class="callout"><div class="callout-text">${escHtml(t(unsupportedKey))}</div></div>`;
  }
  if (!st.pin_set) {
    return `<div class="callout warn"><div class="callout-title">${escHtml(t('pk.needPin.title'))}</div>
      <div class="callout-text">${escHtml(t('pk.needPin.text'))}</div>
      <button type="button" class="btn-link" data-goto-tab="pin">${escHtml(t('pk.needPin.action'))}</button></div>`;
  }
  if (!st.unlocked) {
    const waitingUv = unlockBusy === 'uv';
    return `
      <form class="card form-card unlock-form" autocomplete="off">
        <h2>${escHtml(t('pk.unlock.title'))}</h2>
        <p class="card-text">${escHtml(t('pk.unlock.text'))}</p>
        ${waitingUv ? `<div class="uv-wait"><span class="uv-icon">${icon('fingerprint', 30)}</span>
            <span>${escHtml(t('pk.unlock.uvWaiting'))}</span></div>` : `
        <label class="field">
          <span>${escHtml(t('pin.form.current'))}</span>
          <input type="password" class="unlock-pin" autocomplete="off" spellcheck="false" ${unlockBusy ? 'disabled' : ''}>
        </label>`}
        ${unlockError ? `<p class="field-error">${escHtml(unlockError)}</p>` : ''}
        ${waitingUv ? '' : `<div class="form-actions">
          ${st.uv_unlock ? `<button type="button" class="btn btn-secondary" data-act="unlock-uv" ${unlockBusy ? 'disabled' : ''}>${icon('fingerprint', 15)} ${escHtml(t('pk.unlock.uv'))}</button>` : ''}
          <button type="submit" class="btn btn-primary" ${unlockBusy ? 'disabled' : ''}>${escHtml(unlockBusy === 'pin' ? t('pk.unlock.working') : t('pk.unlock.pin'))}</button>
        </div>`}
      </form>`;
  }
  return null; // unlocked: caller renders its content
}

function toolbarHtml(summary) {
  return `<div class="pk-toolbar">
      <span class="pk-summary">${escHtml(summary)}</span>
      <button type="button" class="btn btn-secondary" data-act="lock">${icon('lock', 15)} ${escHtml(t('pk.lock'))}</button>
    </div>`;
}

function focusUnlockPin(pane) {
  if (!unlockBusy) document.querySelector(`[data-pane="${pane}"] .unlock-pin`)?.focus();
}

function renderManagement() {
  if (activeTab === 'passkeys') renderPasskeys();
  if (activeTab === 'fingerprints') renderFingerprints();
  if (activeTab === 'settings') renderConfig();
}

function loadManagement(token) {
  if (activeTab === 'passkeys') return loadPasskeys(token);
  if (activeTab === 'fingerprints') return loadFingerprints(token);
  if (activeTab === 'settings') return loadConfig(token);
}

// ── Quick unlock from the sidebar ───────────────────────────────────────────

const unlockedUntil = new Map();   // token id -> ms timestamp (mirrors the server-side TTL)
let quickUnlock = null;            // { id, mode: 'uv' | 'pin' | 'probe', busy, error, run }

// Something a PIN unlock gives access to (passkey list, fingerprints, settings)
function canManage(tok) {
  const o = tok?.options || {};
  return !!(o.credMgmt || o.credentialMgmtPreview || o.bioEnroll || o.userVerificationMgmtPreview || o.authnrCfg);
}

function isUnlocked(id) {
  return (unlockedUntil.get(id) || 0) > Date.now();
}

function markUnlocked(id, ttlSeconds) {
  unlockedUntil.set(id, Date.now() + (ttlSeconds || 300) * 1000);
  setTimeout(() => { if (!isUnlocked(id)) renderSidebar(); }, (ttlSeconds || 300) * 1000 + 200);
  renderSidebar();
}

function openProbe(id) {
  quickUnlock = { id, mode: 'probe', busy: false, error: null };
  renderQuickUnlock();
}

function renderProbeDialog(el, tok) {
  const q = quickUnlock;
  const pct = q.total ? Math.round((q.done || 0) * 100 / q.total) : 0;
  el.innerHTML = `<form class="ql-dialog card" autocomplete="off">
    <h2>${escHtml(t('probe.dialogTitle', { name: displayName(tok) }))}</h2>
    <p class="card-text">${escHtml(t('probe.dialogText'))}</p>
    ${tok.options?.clientPin ? `<label class="field"><span>${escHtml(t('probe.pin'))}</span>
      <input type="password" class="ql-pin" autocomplete="off" spellcheck="false" ${q.busy ? 'disabled' : ''}></label>` : ''}
    <label class="field"><span>${escHtml(t('probe.extra'))}</span>
      <input type="text" class="ql-extra" placeholder="firma.okta.com, adfs.firma.de" spellcheck="false" ${q.busy ? 'disabled' : ''}></label>
    ${q.busy ? `<div class="oath-bar probe-bar"><div style="width:${pct}%"></div></div>
      <p class="field-hint">${escHtml(t('probe.progress', { done: q.done || 0, total: q.total || '…' }))}</p>` : ''}
    ${q.error ? `<p class="field-error">${escHtml(q.error)}</p>` : ''}
    <p class="field-hint">${escHtml(t('probe.note'))}</p>
    <div class="form-actions">
      ${q.busy ? `<button type="button" class="btn btn-secondary" data-ql="stop" ${q.stopping ? 'disabled' : ''}>${escHtml(t('probe.stop'))}</button>`
        : `<button type="button" class="btn btn-secondary" data-ql="cancel">${escHtml(t('pk.delete.cancel'))}</button>`}
      <button type="submit" class="btn btn-primary" ${q.busy ? 'disabled' : ''}>${escHtml(t('probe.start'))}</button>
    </div></form>`;
  el.querySelector('.ql-pin')?.focus();
}

async function probeSubmit() {
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  if (!tok || quickUnlock.busy) return;
  const run = {};
  const root = $('quick-unlock');
  const pin = root.querySelector('.ql-pin')?.value || '';
  const extra = (root.querySelector('.ql-extra')?.value || '').split(/[\s,;]+/).filter(Boolean);
  quickUnlock = { ...quickUnlock, busy: true, error: null, done: 0, total: 0, run };
  renderQuickUnlock();
  try {
    const res = await call('passkeys_probe', { token_id: tok.id, pin: pin || null, extra });
    if (quickUnlock?.run !== run) return;
    const got = await call('read_contents', { token_id: tok.id }).catch(() => ({}));
    if (quickUnlock?.run !== run) return;
    const accounts = res.found.reduce((n, f) => n + f.count, 0);
    const parts = [t('probe.found', { n: accounts, sites: res.found.length }),
      res.complete ? '' : t('probe.sum.stoppedShort'),
      got.oath != null ? t('ql.got.oath', { n: got.oath }) : '', got.openpgp ? t('ql.got.pgp', { n: got.openpgp }) : '',
      got.piv ? t('ql.got.piv', { n: got.piv }) : ''].filter(Boolean);
    showToast(`${displayName(tok)}: ${parts.filter(Boolean).join(', ')}`, res.complete ? 'success' : 'info');
    quickUnlock = null;
    renderQuickUnlock();
    await loadHistory();
    render();
    if (selectedId === tok.id && activeTab === 'passkeys') renderPasskeys();
  } catch (e) {
    if (quickUnlock?.run !== run) return;
    quickUnlock = { ...quickUnlock, busy: false, run: null, error: errorMessage(e) };
    renderQuickUnlock();
  }
}

let dialogOpener = null;   // element to focus again when a dialog closes

function renderQuickUnlock() {
  const el = $('quick-unlock');
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  const wasOpen = !el.classList.contains('hidden');
  el.classList.toggle('hidden', !tok);
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-modal', 'true');
  if (!tok) {
    el.innerHTML = '';
    if (wasOpen && dialogOpener?.isConnected) dialogOpener.focus();
    dialogOpener = null;
    return;
  }
  if (!wasOpen) dialogOpener = document.activeElement;
  if (quickUnlock.mode === 'probe') return renderProbeDialog(el, tok);
  if (quickUnlock.mode === 'uv') return renderUvDialog(el, tok);
  const uv = tok.options?.uv === true;
  el.innerHTML = `<form class="ql-dialog card" autocomplete="off">
    <h2>${escHtml(t('ql.title', { name: displayName(tok) }))}</h2>
    <p class="card-text">${escHtml(t('ql.text'))}</p>
    ${tok.options?.clientPin ? `<label class="field"><span>${escHtml(t('pin.form.current'))}</span>
      <input type="password" class="ql-pin" autocomplete="off" spellcheck="false" ${quickUnlock.busy ? 'disabled' : ''}></label>` : ''}
    ${quickUnlock.error ? `<p class="field-error">${escHtml(quickUnlock.error)}</p>` : ''}
    ${uv ? `<p class="ql-switch"><button type="button" class="btn-link" data-ql="uv" ${quickUnlock.busy ? 'disabled' : ''}>${icon('fingerprint', 15)} ${escHtml(t('ql.uv.useFinger'))}</button></p>` : ''}
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" data-ql="cancel">${escHtml(t('pk.delete.cancel'))}</button>
      ${tok.options?.clientPin ? `<button type="submit" class="btn btn-primary" ${quickUnlock.busy ? 'disabled' : ''}>${quickUnlock.busy ? `<span class="spinner"></span>${escHtml(t('ql.reading'))}` : escHtml(t('ql.do'))}</button>` : ''}
    </div></form>`;
  el.querySelector('.ql-pin')?.focus();
}

// Fingerprint first: the key already waits for a finger when the dialog opens.
// "Enter PIN instead" and "Cancel" stop that wait on the key; a new attempt
// only starts when the user asks for it.
function renderUvDialog(el, tok) {
  const q = quickUnlock;
  el.innerHTML = `<form class="ql-dialog card" autocomplete="off">
    <h2>${escHtml(t('ql.title', { name: displayName(tok) }))}</h2>
    <p class="card-text">${escHtml(t('ql.uv.text'))}</p>
    <div role="status">${q.busy ? `<div class="uv-wait"><span class="uv-icon">${icon('fingerprint', 30)}</span>
      <span>${escHtml(t('pk.unlock.uvWaiting'))}</span></div>` : ''}</div>
    ${q.error ? `<p class="field-error" role="alert">${escHtml(q.error)}</p>` : ''}
    ${tok.options?.clientPin ? `<p class="ql-switch"><button type="button" class="btn-link" data-ql="pin">${escHtml(t('ql.uv.usePin'))}</button></p>` : ''}
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" data-ql="cancel">${escHtml(t('pk.delete.cancel'))}</button>
      ${q.busy ? '' : `<button type="submit" class="btn btn-primary">${icon('fingerprint', 15)} ${escHtml(t('pin.retry'))}</button>`}
    </div></form>`;
  el.querySelector(q.busy ? '[data-ql="pin"]' : 'button[type="submit"]')?.focus();
}

async function quickUnlockUv() {
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  if (!tok || (quickUnlock.mode === 'uv' && quickUnlock.busy)) return;
  const run = {};
  quickUnlock = { ...quickUnlock, mode: 'uv', busy: true, error: null, run };
  renderQuickUnlock();
  try {
    const res = await call('unlock', { token_id: tok.id, method: 'uv' });
    if (quickUnlock?.run !== run) return;   // a closed/replaced dialog no longer owns this result
    markUnlocked(tok.id, res.ttl);
    quickUnlock = null;
    renderQuickUnlock();
    await readContentsNow(tok);
    if (selectedId === tok.id && ['passkeys', 'fingerprints', 'settings'].includes(activeTab)) loadManagement(tok);
  } catch (e) {
    if (quickUnlock?.run !== run) return;   // the user switched to the PIN or closed the dialog
    const code = e.data?.code;
    if ((code === 'unsupported' && e.data.reason === 'uv_unlock') || code === 'uv_blocked') {
      // the key cannot (or may no longer) unlock with a finger: the PIN is the way
      quickUnlock = { ...quickUnlock, mode: 'pin', busy: false, run: null, error: code === 'uv_blocked' ? errorMessage(e) : null };
    } else {
      quickUnlock = { ...quickUnlock, busy: false, run: null, error: errorMessage(e) };
    }
    renderQuickUnlock();
  }
}

// Leave the fingerprint wait (switch to the PIN or close): tell the key to stop waiting.
function stopUnlockWait() {
  if (quickUnlock?.busy) call('unlock_cancel', { token_id: quickUnlock.id }).catch(() => {});
}

function closeQuickUnlock() {
  stopUnlockWait();
  quickUnlock = null;
  renderQuickUnlock();
}

async function quickUnlockSubmit() {
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  if (!tok || quickUnlock.busy) return;
  const run = {};
  const pin = $('quick-unlock').querySelector('.ql-pin')?.value || '';
  if (!pin) { quickUnlock.error = t('pin.v.current'); return renderQuickUnlock(); }
  quickUnlock = { ...quickUnlock, busy: true, error: null, run };
  renderQuickUnlock();
  try {
    const res = await call('unlock', { token_id: tok.id, pin });
    if (quickUnlock?.run !== run) return;
    markUnlocked(tok.id, res.ttl);
    quickUnlock = null;
    renderQuickUnlock();
    await readContentsNow(tok);
    if (selectedId === tok.id && ['passkeys', 'fingerprints', 'settings'].includes(activeTab)) loadManagement(tok);
  } catch (e) {
    if (quickUnlock?.run !== run) {
      // The dialog was closed while the key checked the PIN. A wrong PIN has
      // still used up an attempt there – say so instead of dropping it.
      if (['pin_invalid', 'pin_blocked', 'pin_auth_blocked'].includes(e.data?.code)) {
        showToast(`${displayName(tok)}: ${errorMessage(e)}`, 'error');
      }
      return;
    }
    quickUnlock = { ...quickUnlock, busy: false, run: null, error: errorMessage(e) };
    renderQuickUnlock();
  }
}

async function quickLockToggle(id) {
  if (isUnlocked(id)) {
    await call('lock', { token_id: id }).catch(() => {});
    unlockedUntil.delete(id);
    renderSidebar();
    const tok = tokens.get(id);
    if (tok && selectedId === id) loadManagement(tok);
    return;
  }
  const tok = tokens.get(id);
  quickUnlock = { id, mode: 'pin', busy: false, error: null };
  if (tok?.options?.uv === true) quickUnlockUv(); else renderQuickUnlock();
}

async function unlockKey(method) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const pin = document.querySelector(`[data-pane="${activeTab}"] .unlock-pin`)?.value || '';
  if (method !== 'uv' && !pin) { unlockError = t('pin.v.current'); renderManagement(); return; }
  unlockBusy = method;
  unlockError = null;
  renderManagement();
  try {
    const res = await call('unlock', method === 'uv' ? { token_id: token.id, method: 'uv' } : { token_id: token.id, pin });
    markUnlocked(token.id, res.ttl);
    unlockBusy = null;
    if (selectedId === token.id) await loadManagement(token);
  } catch (e) {
    unlockBusy = null;
    if (selectedId === token.id) { unlockError = errorMessage(e); renderManagement(); }
  }
}

async function lockKey() {
  const token = tokens.get(selectedId);
  if (!token) return;
  await call('lock', { token_id: token.id }).catch(() => {});
  unlockedUntil.delete(token.id);
  renderSidebar();
  loadManagement(token);
}

// An action failed because the unlock expired: show the unlock form again
function handleActionError(e, state) {
  if (e.data?.code === 'locked' && state) {
    state.unlocked = false;
    unlockError = errorMessage(e);
  } else {
    showToast(errorMessage(e), 'error');
  }
  renderManagement();
}


// Bind once from app.init(); all quick-unlock event transitions live here.
function initUnlockDialog() {
  $('quick-unlock').addEventListener('submit', ev => {
    ev.preventDefault();
    if (quickUnlock?.mode === 'probe') probeSubmit();
    else if (quickUnlock?.mode === 'uv') quickUnlockUv();
    else quickUnlockSubmit();
  });
  $('quick-unlock').addEventListener('click', ev => {
    const b = ev.target.closest('[data-ql]');
    // A click beside the dialog closes it, except while a PIN check or a
    // passkey search runs (Escape behaves the same); waiting for a finger can
    // always be left. The Cancel/Stop buttons stay the explicit way out.
    const waitingUv = quickUnlock?.mode === 'uv' && quickUnlock.busy;
    if ((ev.target.id === 'quick-unlock' && (!quickUnlock?.busy || waitingUv)) || b?.dataset.ql === 'cancel') { closeQuickUnlock(); return; }
    if (b?.dataset.ql === 'uv') { quickUnlock = { ...quickUnlock, error: null }; quickUnlockUv(); }
    if (b?.dataset.ql === 'pin' && quickUnlock) {
      stopUnlockWait();
      quickUnlock = { ...quickUnlock, mode: 'pin', busy: false, error: null, run: null };
      renderQuickUnlock();
    }
    if (b?.dataset.ql === 'stop' && quickUnlock) {
      quickUnlock = { ...quickUnlock, stopping: true };
      call('passkeys_probe_cancel', { token_id: quickUnlock.id }).catch(() => {});
      renderQuickUnlock();
    }
  });
  document.addEventListener('keydown', ev => {
    if (ev.key === 'Escape' && quickUnlock && (!quickUnlock.busy || quickUnlock.mode === 'uv')) closeQuickUnlock();
  });
}
