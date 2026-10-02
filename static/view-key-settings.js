'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Applications per USB/NFC (YubiKey, settings tab) ────────────────────────

let ifState = null;

function renderInterfaces() {
  const el = $('if-content');
  if (!el) return;
  const token = currentToken();
  if (!token || token.offline || !cardApps.get(token.id)?.interfaces) { el.innerHTML = ''; return; }
  const st = ifState;
  if (!st || st.error) {
    el.innerHTML = st?.error ? `<div class="callout"><div class="callout-text">${escHtml(st.error)}</div></div>` : '';
    return;
  }
  el.innerHTML = `<section class="card"><h2>${escHtml(t('if.title'))}</h2>
    <p class="card-text">${escHtml(t(st.locked ? 'if.locked' : 'if.text'))}</p>
    ${Object.entries(st.transports).map(([tr, apps]) => `<form class="if-form" data-transport="${tr}">
      <h3 class="if-head">${escHtml(t(`if.${tr}`))}</h3>
      <div class="if-grid">${Object.entries(apps).map(([app, on]) => {
        const locked = st.locked || (tr === 'usb' && app === 'FIDO2');
        return `<label class="check"><input type="checkbox" data-app="${app}" ${on ? 'checked' : ''} ${locked ? 'disabled' : ''}>
          <span>${escHtml(t(`if.app.${app}`))}</span></label>`;
      }).join('')}</div>
      ${st.locked ? '' : `<div class="form-actions att-actions"><button type="submit" class="btn btn-secondary">${escHtml(t('if.apply'))}</button></div>`}
    </form>`).join('')}
    <p class="field-hint">${escHtml(t('if.hint'))}</p>
  </section>`;
}

async function loadInterfaces(token) {
  ifState = null;
  renderInterfaces();
  if (!cardApps.get(token.id)?.interfaces) return;
  try {
    ifState = await call('interfaces', { token_id: token.id });
  } catch (e) {
    ifState = { error: errorMessage(e) };
  }
  if (selectedId === token.id) renderInterfaces();
}

function initInterfacesPane() {
  $('if-content').addEventListener('submit', async ev => {
    ev.preventDefault();
    const f = ev.target;
    const token = tokens.get(selectedId);
    if (!token) return;
    const apps = {};
    f.querySelectorAll('input[data-app]:not(:disabled)').forEach(i => { apps[i.dataset.app] = i.checked; });
    try {
      await call('interfaces_set', { token_id: token.id, transport: f.dataset.transport, apps });
      showToast(t('if.restarting'), 'success');
    } catch (e) {
      showToast(errorMessage(e), 'error');
    }
  });
}

// ── Settings tab / key configuration ────────────────────────────────────────

let cfgState = null;
let cfgBusy = false;

function renderConfig() {
  const el = $('cfg-content');
  if (!el) return;
  const st = cfgState;
  if (st && !st.supported) {
    el.innerHTML = `<div class="callout"><div class="callout-text">${escHtml(t('cfg.unsupported'))}</div></div>`;
    return;
  }
  const gate = managementGateHtml(st, 'cfg.unsupported');
  if (gate !== null) { el.innerHTML = gate; focusUnlockPin('settings'); return; }

  const parts = [toolbarHtml(t('cfg.title'))];
  if (st.can_set_min_pin) {
    parts.push(`<form class="card form-card cfg-minpin-form" autocomplete="off">
      <h2>${escHtml(t('cfg.minPin.title'))}</h2>
      <p class="card-text">${escHtml(t('cfg.minPin.text', { n: st.min_pin_length }))}</p>
      <div class="inline-form">
        <input type="number" class="cfg-minpin" min="${st.min_pin_length + 1}" max="63" value="${Math.max(st.min_pin_length + 1, 6)}">
        <button type="submit" class="btn btn-primary" ${cfgBusy ? 'disabled' : ''}>${escHtml(t('cfg.minPin.do'))}</button>
      </div>
      <p class="field-hint">${escHtml(t('cfg.minPin.warn'))}</p>
    </form>`);
  }
  if (st.always_uv !== null && st.always_uv !== undefined) {
    parts.push(`<section class="card">
      <h2>${escHtml(t('cfg.alwaysUv.title'))}</h2>
      <p class="card-text">${escHtml(t('cfg.alwaysUv.text'))}</p>
      <label class="switch-row">
        <input type="checkbox" class="cfg-alwaysuv" ${st.always_uv ? 'checked' : ''} ${cfgBusy ? 'disabled' : ''}>
        <span>${escHtml(st.always_uv ? t('cfg.alwaysUv.on') : t('cfg.alwaysUv.off'))}</span>
      </label>
    </section>`);
  }
  if (st.can_set_min_pin) {
    parts.push(`<section class="card">
      <h2>${escHtml(t('cfg.force.title'))}</h2>
      <p class="card-text">${escHtml(st.force_pin_change ? t('cfg.force.active') : t('cfg.force.text'))}</p>
      ${st.force_pin_change ? '' : `<div class="form-actions"><button type="button" class="btn btn-secondary" data-act="force-pin" ${cfgBusy ? 'disabled' : ''}>${escHtml(t('cfg.force.do'))}</button></div>`}
    </section>`);
  }
  el.innerHTML = parts.join('');
}

async function loadConfig(token, retried = false) {
  cfgState = null;
  if (!retried) unlockError = null;
  renderConfig();
  try {
    const st = await call('config', { token_id: token.id });
    if (selectedId !== token.id) return;
    cfgState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isLocked(e) && !retried) { unlockError = errorMessage(e); return loadConfig(token, true); }
    cfgState = isBusy(e) ? { busy: true } : { error: errorMessage(e) };
  }
  renderConfig();
}

async function updateConfig(changes, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  cfgBusy = true;
  renderConfig();
  try {
    cfgState = await call('config_update', { token_id: token.id, ...changes });
    showToast(t(doneKey), 'success');
  } catch (e) {
    cfgBusy = false;
    handleActionError(e, cfgState);
    return;
  }
  cfgBusy = false;
  renderConfig();
}

function configAction(act) {
  if (act === 'reload') return loadConfig(tokens.get(selectedId));
  if (act === 'force-pin') return updateConfig({ force_pin_change: true }, 'cfg.saved');
}

// ── Settings tab / factory reset ────────────────────────────────────────────

let resetFlow = null;     // { stage, name, deadline, id, error }
let resetTimer = null;

function renderSettings(token) {
  $('rs-prereg').classList.toggle('hidden', !token.force_pin_change);
  $('rs-vuln').classList.toggle('hidden', !(token.cve_ids || []).length);
}

function renderResetOverlay() {
  const ov = $('reset-overlay');
  const f = resetFlow;
  ov.classList.toggle('hidden', !f);
  clearInterval(resetTimer);
  if (!f) return;

  const primary = $('rs-ov-primary');
  const secondary = $('rs-ov-secondary');
  primary.classList.add('hidden');
  secondary.classList.remove('hidden');
  $('rs-ov-count').textContent = '';
  let iconName = 'key', cls = '';

  if (f.stage === 'armed') {
    $('rs-ov-title').textContent = t('rs.ov.armed.title');
    $('rs-ov-text').textContent = t('rs.ov.armed.text', { name: f.name });
    secondary.textContent = t('pk.delete.cancel');
    const tick = () => {
      const s = Math.max(0, Math.ceil((f.deadline - Date.now()) / 1000));
      $('rs-ov-count').textContent = t('rs.ov.armed.count', { s });
    };
    tick();
    resetTimer = setInterval(tick, 500);
  } else if (f.stage === 'running' || f.stage === 'touch') {
    $('rs-ov-title').textContent = t('rs.ov.touch.title');
    $('rs-ov-text').textContent = t('rs.ov.touch.text');
    secondary.classList.add('hidden');
    cls = 'pulse';
  } else if (f.stage === 'done') {
    iconName = 'shield'; cls = 'ok';
    $('rs-ov-title').textContent = t('rs.ov.done.title');
    $('rs-ov-text').textContent = t('rs.ov.done.text');
    secondary.textContent = t('rs.ov.close');
    primary.textContent = t('pin.form.set');
    primary.classList.remove('hidden');
  } else {
    cls = 'bad';
    $('rs-ov-title').textContent = t('rs.ov.failed.title');
    $('rs-ov-text').textContent = f.error || '';
    secondary.textContent = t('rs.ov.close');
  }
  $('rs-ov-icon').className = `rs-ov-icon ${cls}`;
  $('rs-ov-icon').innerHTML = icon(iconName, 34);
}

async function startReset() {
  const token = tokens.get(selectedId);
  if (!token) return;
  try {
    const res = await call('reset_arm', { token_id: token.id, confirm: true });
    resetFlow = { stage: 'armed', name: displayName(token), deadline: Date.now() + res.window * 1000 };
    $('rs-confirm').checked = false;
    $('rs-start').disabled = true;
    renderResetOverlay();
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

function closeReset(goToPin) {
  if (resetFlow?.stage === 'armed') call('reset_disarm').catch(() => {});
  const id = resetFlow?.id;
  resetFlow = null;
  renderResetOverlay();
  if (goToPin && id && tokens.has(id)) {
    selectToken(id);
    switchTab('pin');
  }
}

function onResetProgress(p) {
  if (!resetFlow) return;
  resetFlow = { ...resetFlow, stage: p.stage, id: p.id };
  renderResetOverlay();
}

function onResetDone(r) {
  if (!resetFlow) return;
  if (r.ok) {
    resetFlow = { ...resetFlow, stage: 'done', id: r.id };
  } else {
    resetFlow = { ...resetFlow, stage: 'failed', error: r.code === 'expired' ? t('rs.ov.expired') : errorMessage({ data: r, message: r.error }) };
  }
  renderResetOverlay();
}

// ── PIN tab ─────────────────────────────────────────────────────────────────

function renderPinStatus(st) {
  const el = $('pin-status');
  const form = $('pin-form');

  if (!st.supported) {
    el.className = 'callout';
    el.innerHTML = `<div class="callout-text">${escHtml(t('pin.unsupported'))}</div>`;
    form.classList.add('hidden');
    return;
  }

  const blocked = st.is_set && st.retries === 0;
  const parts = [];
  if (!st.is_set) {
    el.className = 'callout warn';
    parts.push(`<div class="callout-title">${escHtml(t('pin.notSet.title'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.notSet.text'))}</div>`);
  } else if (blocked) {
    el.className = 'callout crit';
    parts.push(`<div class="callout-title">${escHtml(t('pin.blocked.title'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.blocked.text'))}</div>`);
  } else {
    const low = st.retries != null && st.retries <= 3;
    el.className = `callout ${low || st.force_change ? 'warn' : 'ok'}`;
    parts.push(`<div class="callout-title">${escHtml(t('pin.set.title'))}</div>`);
    if (st.retries != null) {
      parts.push(`<div class="callout-text">${escHtml(st.retries === 1 ? t('pin.retries1') : t('pin.retries', { n: st.retries }))}</div>`);
    }
  }
  if (st.power_cycle_required) parts.push(`<div class="callout-text">${escHtml(t('pin.powerCycle'))}</div>`);
  if (st.force_change) {
    parts.push(`<div class="callout-text">${escHtml(t('pin.forceChange'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.forceChangeHint'))}</div>`);
  }

  const facts = [[t('pin.fact.minLen'), t('pin.fact.minLenValue', { n: st.min_length })]];
  if (st.uv != null) {
    facts.push([t('pin.fact.bio'), st.uv ? t('pin.fact.bioEnrolled') : t('pin.fact.bioNone')]);
    if (st.uv_retries != null) facts.push([t('pin.fact.bioRetries'), String(st.uv_retries)]);
  }
  parts.push(`<dl class="kv">${buildKv(facts)}</dl>`);
  el.innerHTML = parts.join('');

  form.classList.toggle('hidden', blocked);
  $('pin-current-row').classList.toggle('hidden', !st.is_set);
  const label = st.is_set ? t('pin.form.change') : t('pin.form.set');
  $('pin-form-title').textContent = label;
  $('pin-submit').textContent = label;
  $('pin-hint').textContent = t('pin.form.hint', { min: st.min_length });
}

let pinWaiting = false;   // PIN status deferred until the attestation test ends

async function loadPinStatus(token) {
  pinWaiting = false;
  const el = $('pin-status');
  el.className = 'callout';
  el.innerHTML = `<div class="loading"><span class="spinner"></span>${escHtml(t('pin.loading'))}</div>`;
  $('pin-form').classList.add('hidden');
  hidePinError();
  try {
    const st = await call('pin_status', { token_id: token.id });
    if (selectedId !== token.id) return; // selection changed meanwhile
    pinState = st;
    renderPinStatus(st);
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isBusy(e)) {
      pinWaiting = true;
      el.className = 'callout';
      el.innerHTML = `<div class="loading"><span class="spinner"></span>${escHtml(t('mg.waitAttestation'))}</div>`;
      return;
    }
    el.className = 'callout crit';
    el.innerHTML = `<div class="callout-text">${escHtml(errorMessage(e))}</div>
      <button type="button" class="btn-link" id="pin-retry">${escHtml(t('pin.retry'))}</button>`;
    $('pin-retry').onclick = () => loadPinStatus(token);
  }
}

function showPinError(msg) {
  $('pin-error').textContent = msg;
  $('pin-error').classList.remove('hidden');
}

function hidePinError() {
  $('pin-error').classList.add('hidden');
}

function clearPinInputs() {
  for (const id of ['pin-current', 'pin-new', 'pin-confirm']) $(id).value = '';
  $('pin-show').checked = false;
  setPinVisible(false);
}

function setPinVisible(visible) {
  for (const id of ['pin-current', 'pin-new', 'pin-confirm']) $(id).type = visible ? 'text' : 'password';
}

async function submitPinForm(ev) {
  ev.preventDefault();
  hidePinError();
  const token = tokens.get(selectedId);
  if (!token || !pinState) return;

  const current = $('pin-current').value;
  const next = $('pin-new').value;
  const confirm = $('pin-confirm').value;

  if (pinState.is_set && !current) return showPinError(t('pin.v.current'));
  if ([...next].length < pinState.min_length) return showPinError(t('pin.v.tooShort', { n: pinState.min_length }));
  if (new TextEncoder().encode(next).length > 63) return showPinError(t('pin.v.tooLong'));
  if (next !== confirm) return showPinError(t('pin.v.mismatch'));

  const btn = $('pin-submit');
  btn.disabled = true;
  try {
    const body = { new_pin: next };
    if (pinState.is_set) body.current_pin = current;
    const res = await call('pin_update', { token_id: token.id, ...body });
    clearPinInputs();
    showToast(res.result === 'set' ? t('pin.done.set') : t('pin.done.changed'), 'success');
    loadPinStatus(token);
  } catch (e) {
    $('pin-current').value = '';
    showPinError(errorMessage(e));
    if (['pin_invalid', 'pin_blocked', 'pin_auth_blocked'].includes(e.data?.code)) {
      // Refresh the retry counter without wiping the error message
      call('pin_status', { token_id: token.id }).then(st => { pinState = st; renderPinStatus(st); }).catch(() => {});
    }
  } finally {
    btn.disabled = false;
  }
}
