'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Authenticator (OATH) tab ────────────────────────────────────────────────

let oathState = null;     // server response (status + accounts)
let oathForm = null;      // null | 'add' | 'password'
let oathEdit = null;      // account id being renamed
let oathConfirm = null;   // account id awaiting delete confirmation, or 'reset'
let oathBusy = null;      // account id whose touch code is being calculated
let oathTimer = null;
let oathError = null;

function stopOathTimer() {
  clearInterval(oathTimer);
  oathTimer = null;
}

function startOathTimer(token) {
  stopOathTimer();
  oathTimer = setInterval(() => {
    if (activeTab !== 'oath' || selectedId !== token.id) return stopOathTimer();
    const now = Date.now() / 1000;
    let expired = false;
    document.querySelectorAll('#oath-content [data-valid-to]').forEach(el => {
      const to = Number(el.dataset.validTo), period = Number(el.dataset.period) || 30;
      const left = Math.max(0, to - now);
      el.style.width = `${(left / period) * 100}%`;
      if (left <= 0) expired = true;
    });
    if (expired && !oathForm && !oathEdit) loadOath(token, true);
  }, 500);
}

function formatCode(code) {
  if (!code) return '';
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code;
}

function oathAccountHtml(a, st) {
  const label = a.issuer || a.name;
  if (oathEdit === a.id) {
    return `<li class="pk-item"><form class="oath-rename-form pk-rename-form" data-id="${escHtml(a.id)}">
      <input type="text" class="oath-rename-issuer" value="${escHtml(a.issuer)}" placeholder="${escHtml(t('oath.issuer'))}" maxlength="60">
      <input type="text" class="oath-rename-name" value="${escHtml(a.name)}" placeholder="${escHtml(t('oath.account'))}" maxlength="60">
      <div class="pk-rename-actions">
        <button type="button" class="btn btn-secondary" data-act="edit-cancel">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
      </div></form></li>`;
  }
  let codeHtml;
  if (a.code) {
    codeHtml = `<button type="button" class="oath-code" data-act="copy" data-code="${escHtml(a.code)}" title="${escHtml(t('oath.copy'))}">${escHtml(formatCode(a.code))}</button>
      ${a.valid_to ? `<div class="oath-bar"><div data-valid-to="${a.valid_to}" data-period="${a.period || 30}"></div></div>` : ''}`;
  } else if (oathBusy === a.id) {
    codeHtml = `<span class="oath-wait"><span class="spinner"></span>${escHtml(t('oath.touch'))}</span>`;
  } else {
    codeHtml = `<button type="button" class="btn btn-secondary oath-get" data-act="code" data-id="${escHtml(a.id)}">${icon(a.touch ? 'key' : 'lock', 14)} ${escHtml(t(a.touch ? 'oath.touchForCode' : 'oath.generate'))}</button>`;
  }
  const actions = oathConfirm === a.id
    ? `<div class="pk-confirm"><span>${escHtml(t('pk.delete.confirm'))}</span>
        <button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="button" class="btn btn-danger" data-act="delete" data-id="${escHtml(a.id)}">${escHtml(t('pk.delete.do'))}</button></div>`
    : `${st.can_rename ? `<button type="button" class="btn-icon" data-act="edit" data-id="${escHtml(a.id)}" title="${escHtml(t('fp.rename'))}">${icon('pencil', 16)}</button>` : ''}
       <button type="button" class="btn-icon danger" data-act="ask-delete" data-id="${escHtml(a.id)}" title="${escHtml(t('pk.delete.do'))}">${icon('trash', 16)}</button>`;
  return `<li class="pk-item oath-item">
    ${serviceAvatar(a.issuer, label)}
    <div class="pk-user"><div class="pk-user-name">${escHtml(label)}</div>
      ${a.issuer ? `<div class="pk-user-sub">${escHtml(a.name)}</div>` : ''}</div>
    <div class="oath-code-wrap">${codeHtml}</div>
    ${actions}
  </li>`;
}

function renderOath() {
  const el = $('oath-content');
  if (!el) return;
  const st = oathState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
    return;
  }
  if (!st.unlocked) {
    el.innerHTML = `<form class="card form-card oath-unlock-form" autocomplete="off">
      <h2>${escHtml(t('oath.locked.title'))}</h2>
      <p class="card-text">${escHtml(t('oath.locked.text'))}</p>
      <label class="field"><span>${escHtml(t('oath.password'))}</span>
        <input type="password" class="oath-password" autocomplete="off" spellcheck="false"></label>
      ${oathError ? `<p class="field-error">${escHtml(oathError)}</p>` : ''}
      <div class="form-actions"><button type="submit" class="btn btn-primary">${escHtml(t('pk.unlock.pin'))}</button></div>
    </form>`;
    el.querySelector('.oath-password')?.focus();
    return;
  }
  const accounts = st.accounts || [];
  const parts = [`<div class="pk-toolbar"><span class="pk-summary">${escHtml(t('oath.count', { n: accounts.length }))}</span>
    <button type="button" class="btn btn-primary" data-act="show-add">${escHtml(t('oath.add'))}</button></div>`];
  if (oathError) parts.push(`<p class="field-error">${escHtml(oathError)}</p>`);
  if (oathForm === 'add') {
    parts.push(`<form class="card form-card oath-add-form" autocomplete="off">
      <h2>${escHtml(t('oath.add'))}</h2>
      <label class="field"><span>${escHtml(t('oath.uri'))}</span>
        <input type="text" class="oath-uri" placeholder="otpauth://totp/…" spellcheck="false"></label>
      <p class="field-hint">${escHtml(t('oath.orManual'))}</p>
      <div class="oath-grid">
        <label class="field"><span>${escHtml(t('oath.issuer'))}</span><input type="text" class="oath-issuer" maxlength="60"></label>
        <label class="field"><span>${escHtml(t('oath.account'))}</span><input type="text" class="oath-name" maxlength="60"></label>
        <label class="field oath-wide"><span>${escHtml(t('oath.secret'))}</span><input type="text" class="oath-secret" spellcheck="false" autocomplete="off"></label>
        <label class="field"><span>${escHtml(t('oath.type'))}</span><select class="oath-type bk-select"><option>TOTP</option><option>HOTP</option></select></label>
        <label class="field"><span>${escHtml(t('oath.digits'))}</span><select class="oath-digits bk-select"><option>6</option><option>7</option><option>8</option></select></label>
      </div>
      <label class="check"><input type="checkbox" class="oath-touch"><span>${escHtml(t('oath.requireTouch'))}</span></label>
      <div class="form-actions">
        <button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="submit" class="btn btn-primary">${escHtml(t('oath.save'))}</button>
      </div></form>`);
  }
  if (accounts.length) {
    parts.push(`<section class="card"><ul class="pk-list">${accounts.map(a => oathAccountHtml(a, st)).join('')}</ul></section>`);
  } else if (oathForm !== 'add') {
    parts.push(`<div class="callout"><div class="callout-title">${escHtml(t('oath.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('oath.empty.text'))}</div></div>`);
  }
  // Password & reset
  parts.push(oathForm === 'password'
    ? `<form class="card form-card oath-password-form" autocomplete="off">
        <h2>${escHtml(t(st.password ? 'oath.pw.change' : 'oath.pw.set'))}</h2>
        <label class="field"><span>${escHtml(t('oath.pw.new'))}</span><input type="password" class="oath-pw-new" autocomplete="new-password"></label>
        <label class="field"><span>${escHtml(t('pin.form.confirm'))}</span><input type="password" class="oath-pw-confirm" autocomplete="new-password"></label>
        <p class="field-hint">${escHtml(t('oath.pw.hint'))}</p>
        <div class="form-actions">
          ${st.password ? `<button type="button" class="btn btn-secondary" data-act="pw-remove">${escHtml(t('oath.pw.remove'))}</button>` : ''}
          <button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
          <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
        </div></form>`
    : `<section class="card"><h2>${escHtml(t('oath.protect.title'))}</h2>
        <p class="card-text">${escHtml(t(st.password ? 'oath.protect.on' : 'oath.protect.off'))}</p>
        <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="show-password">${escHtml(t(st.password ? 'oath.pw.change' : 'oath.pw.set'))}</button></div>
      </section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('oath.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('oath.reset.text'))}</p>
    <div class="form-actions att-actions">${oathConfirm === 'reset'
      ? `<button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('oath.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="ask-reset">${escHtml(t('oath.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
}

async function loadOath(token, quiet = false) {
  if (!quiet) { oathState = null; oathError = null; renderOath(); }
  try {
    const st = await call('oath', { token_id: token.id });
    if (selectedId !== token.id) return;
    oathState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (e.data?.code === 'oath_locked') oathState = { unlocked: false };
    else oathState = isBusy(e) ? { error: t('err.busy') } : { error: errorMessage(e) };
  }
  renderOath();
  if (oathState?.unlocked) startOathTimer(token);
}

async function oathCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  oathError = null;
  try {
    oathState = await call(method, { token_id: token.id, ...args });
    oathForm = null; oathEdit = null; oathConfirm = null;
    if (doneKey) showToast(t(doneKey), 'success');
  } catch (e) {
    if (e.data?.code === 'oath_locked') oathState = { unlocked: false };
    oathError = errorMessage(e);
  }
  renderOath();
  if (oathState?.unlocked) startOathTimer(token);
}

async function oathAction(act, id, el) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const st = oathState || {};
  if (act === 'reload') return loadOath(token);
  if (act === 'show-add') { oathForm = 'add'; oathError = null; return renderOath(); }
  if (act === 'show-password') { oathForm = 'password'; oathError = null; return renderOath(); }
  if (act === 'hide-form') { oathForm = null; return renderOath(); }
  if (act === 'edit') { oathEdit = id; oathConfirm = null; return renderOath(); }
  if (act === 'edit-cancel') { oathEdit = null; return renderOath(); }
  if (act === 'ask-delete') { oathConfirm = id; oathEdit = null; return renderOath(); }
  if (act === 'ask-reset') { oathConfirm = 'reset'; return renderOath(); }
  if (act === 'cancel') { oathConfirm = null; return renderOath(); }
  if (act === 'copy') {
    const ok = await window.pywebview?.api?.copy_text(el.dataset.code);
    return showToast(t(ok ? 'oath.copied' : 'oath.copyFailed'), ok ? 'success' : 'error');
  }
  if (act === 'code') {
    oathBusy = id; renderOath();
    try {
      const acc = await call('oath_code', { token_id: token.id, account_id: id });
      const list = st.accounts || [];
      const i = list.findIndex(a => a.id === id);
      if (i >= 0) list[i] = { ...list[i], code: acc.code, valid_to: acc.valid_to };
    } catch (e) { showToast(errorMessage(e), 'error'); }
    oathBusy = null; renderOath();
    return;
  }
  if (act === 'delete') {
    const acc = (st.accounts || []).find(a => a.id === id);
    return oathCall('oath_delete', { account_id: id, label: acc ? [acc.issuer, acc.name].filter(Boolean).join(': ') : '' }, 'oath.deleted');
  }
  if (act === 'reset') return oathCall('oath_reset', { confirm: true }, 'oath.resetDone');
  if (act === 'pw-remove') return oathCall('oath_password', { password: null }, 'oath.pw.removed');
}

function initOathPane() {
  const el = $('oath-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (b) oathAction(b.dataset.act, b.dataset.id, b);
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    if (f.classList.contains('oath-unlock-form')) {
      const token = tokens.get(selectedId);
      return call('oath_unlock', { token_id: token.id, password: f.querySelector('.oath-password').value })
        .then(st => { oathState = st; oathError = null; renderOath(); startOathTimer(token); })
        .catch(e => { oathError = errorMessage(e); renderOath(); });
    }
    if (f.classList.contains('oath-add-form')) {
      const uri = f.querySelector('.oath-uri').value.trim();
      return oathCall('oath_add', uri ? { uri, touch: f.querySelector('.oath-touch').checked } : {
        issuer: f.querySelector('.oath-issuer').value, name: f.querySelector('.oath-name').value,
        secret: f.querySelector('.oath-secret').value.replace(/\s+/g, ''),
        oath_type: f.querySelector('.oath-type').value, digits: Number(f.querySelector('.oath-digits').value),
        touch: f.querySelector('.oath-touch').checked,
      }, 'oath.added');
    }
    if (f.classList.contains('oath-rename-form')) {
      return oathCall('oath_rename', { account_id: f.dataset.id, issuer: f.querySelector('.oath-rename-issuer').value,
        name: f.querySelector('.oath-rename-name').value }, 'oath.renamed');
    }
    if (f.classList.contains('oath-password-form')) {
      const a = f.querySelector('.oath-pw-new').value, b = f.querySelector('.oath-pw-confirm').value;
      if (!a) { oathError = t('oath.pw.empty'); return renderOath(); }
      if (a !== b) { oathError = t('pin.v.mismatch'); return renderOath(); }
      return oathCall('oath_password', { password: a }, 'oath.pw.saved');
    }
  });
}
