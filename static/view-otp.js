'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── OTP tab (YubiKey slots) ─────────────────────────────────────────────────

let otpState = null;
let otpForm = null;        // 'static:<n>' | 'hmac:<n>' | 'delete:<n>'
let otpError = null;
let otpSecret = null;      // challenge-response secret to show once

function renderOtp() {
  const el = $('otp-content');
  if (!el) return;
  const st = otpState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout ${st.code === 'otp_permission' ? 'warn' : 'crit'}">
      <div class="callout-title">${escHtml(t(st.code === 'otp_permission' ? 'otp.perm.title' : 'otp.error'))}</div>
      <div class="callout-text">${escHtml(st.code === 'otp_permission' ? t('otp.perm.text') : st.error)}</div>
      <div class="form-actions att-actions">
        ${st.code === 'otp_permission' ? `<button type="button" class="btn btn-secondary" data-act="privacy">${escHtml(t('otp.perm.open'))}</button>` : ''}
        <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div></div>`;
    return;
  }
  const access = `<details class="otp-access"><summary>${escHtml(t('otp.access'))}</summary>${fieldHtml('otp-acc', t('otp.accessCode'), 'password', '', 'placeholder="000000000000"')}</details>`;
  const parts = [];
  if (otpSecret) {
    parts.push(`<div class="callout warn"><div class="callout-title">${escHtml(t('otp.secret.title'))}</div>
      <div class="callout-text">${escHtml(t('otp.secret.text'))}</div>
      <div class="pgp-fp">${escHtml(otpSecret.match(/.{1,4}/g).join(' '))}</div>
      <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="copy-secret">${escHtml(t('otp.secret.copy'))}</button>
        <button type="button" class="btn btn-primary" data-act="secret-done">${escHtml(t('otp.secret.done'))}</button></div></div>`);
  }
  const [kind, n] = (otpForm || '').split(':');
  const used = st.slots.some(s => String(s.slot) === n && s.configured);
  const replace = used ? (n === '1' ? `<p class="field-hint">${escHtml(t('otp.delete.text1'))}</p>` : '') + replaceCheck() : '';
  if (kind === 'static') parts.push(formCardHtml(otpForm, t('otp.static.title', { slot: t(`otp.slot${n}`) }), t('otp.static.text'),
    fieldHtml('otp-pw', t('otp.static.password'), 'password', '', 'maxlength="38"') + replace + access, otpError));
  if (kind === 'hmac') parts.push(formCardHtml(otpForm, t('otp.hmac.title', { slot: t(`otp.slot${n}`) }), t('otp.hmac.text'),
    fieldHtml('otp-secret', t('otp.hmac.secret'), 'text', '', `placeholder="${escHtml(t('otp.hmac.random'))}"`) +
    `<label class="check"><input type="checkbox" class="otp-touch" checked><span>${escHtml(t('oath.requireTouch'))}</span></label>` + replace + access, otpError));
  if (kind === 'delete') parts.push(formCardHtml(otpForm, t('otp.delete.title', { slot: t(`otp.slot${n}`) }),
    t(n === '1' ? 'otp.delete.text1' : 'otp.delete.text'), access, otpError, 'pk.delete.do'));
  if (!otpForm && otpError) parts.push(`<p class="field-error">${escHtml(otpError)}</p>`);
  parts.push(`<section class="card"><h2>${escHtml(t('otp.slots'))}</h2><p class="card-text">${escHtml(t('otp.intro'))}</p>
    <ul class="pgp-keys">${st.slots.map(s => `<li class="pgp-key${s.configured ? '' : ' empty'}">
      <div class="pgp-key-head"><span class="pgp-slot">${escHtml(t(`otp.slot${s.slot}`))}</span>
        ${s.configured ? `<span class="pill on">${escHtml(t('otp.configured'))}</span>${s.touch === false ? `<span class="muted">${escHtml(t('otp.noTouch'))}</span>` : ''}`
          : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}</div>
      <div class="piv-actions">
        <button type="button" class="btn-link" data-act="form" data-form="static:${s.slot}">${escHtml(t('otp.static.short'))}</button>
        <button type="button" class="btn-link" data-act="form" data-form="hmac:${s.slot}">${escHtml(t('otp.hmac.short'))}</button>
        ${s.configured ? `<button type="button" class="btn-link danger-link" data-act="form" data-form="delete:${s.slot}">${escHtml(t('pk.delete.do'))}</button>` : ''}
      </div></li>`).join('')}</ul>
    <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="swap">${escHtml(t('otp.swap'))}</button></div>
    <p class="field-hint">${escHtml(t('otp.hint'))}</p></section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.app-form input')?.focus();
}

async function loadOtp(token) {
  otpState = null; otpError = null; otpForm = null;
  renderOtp();
  try {
    const st = await call('otp', { token_id: token.id });
    if (selectedId !== token.id) return;
    otpState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    otpState = { error: isBusy(e) ? t('err.busy') : errorMessage(e), code: e.data?.code };
  }
  renderOtp();
}

async function otpCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  otpError = null;
  try {
    const st = await call(method, { token_id: token.id, ...args });
    if (st.secret) otpSecret = st.secret;
    otpState = st; otpForm = null;
    showToast(t(doneKey), 'success');
  } catch (e) {
    otpError = errorMessage(e);
  }
  renderOtp();
}

function initOtpPane() {
  const el = $('otp-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadOtp(token);
    if (act === 'privacy') return call('open_privacy_settings', {}).catch(() => {});
    if (act === 'form') { otpForm = b.dataset.form; otpError = null; return renderOtp(); }
    if (act === 'hide-form') { otpForm = null; otpError = null; return renderOtp(); }
    if (act === 'swap') return otpCall('otp_swap', {}, 'otp.swapped');
    if (act === 'copy-secret') return copyText(otpSecret);
    if (act === 'secret-done') { otpSecret = null; return renderOtp(); }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const [kind, n] = (f.dataset.form || '').split(':');
    const access_code = val('otp-acc').trim() || null;
    const replace = !!f.querySelector('.app-replace')?.checked;
    const slot = Number(n);
    if (kind === 'static') return otpCall('otp_static', { slot, password: val('otp-pw'), access_code, replace }, 'otp.programmed');
    if (kind === 'hmac') return otpCall('otp_hmac', { slot, secret: val('otp-secret').trim() || null, touch: f.querySelector('.otp-touch').checked, access_code, replace }, 'otp.programmed');
    if (kind === 'delete') return otpCall('otp_delete', { slot, access_code }, 'otp.deleted');
  });
}
