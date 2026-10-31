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
  if (!st) return el.replaceChildren(loadingNode());
  if (st.error) {
    const permission = st.code === 'otp_permission';
    el.replaceChildren(uiElement('div', {class: `callout ${permission ? 'warn' : 'crit'}`},
      uiElement('div', {class: 'callout-title'}, t(permission ? 'otp.perm.title' : 'otp.error')),
      uiElement('div', {class: 'callout-text'}, permission ? t('otp.perm.text') : st.error),
      uiElement('div', {class: 'form-actions att-actions'},
        permission ? actionButton('privacy', t('otp.perm.open')) : null,
        actionButton('reload', t('pin.retry'), 'btn-link'))));
    return;
  }
  const access = uiElement('details', {class: 'otp-access'}, uiElement('summary', {}, t('otp.access')),
    fieldNode('otp-acc', t('otp.accessCode'), 'password', '', {placeholder: '000000000000'}));
  const parts = [];
  if (otpSecret) {
    parts.push(uiElement('div', {class: 'callout warn'}, uiElement('div', {class: 'callout-title'}, t('otp.secret.title')),
      uiElement('div', {class: 'callout-text'}, t('otp.secret.text')),
      uiElement('div', {class: 'pgp-fp'}, (otpSecret.match(/.{1,4}/g) || []).join(' ')),
      uiElement('div', {class: 'form-actions att-actions'}, actionButton('copy-secret', t('otp.secret.copy')),
        actionButton('secret-done', t('otp.secret.done'), 'btn btn-primary'))));
  }
  const [kind, n] = (otpForm || '').split(':');
  const used = st.slots.some(s => String(s.slot) === n && s.configured);
  const replace = used ? [n === '1' ? uiElement('p', {class: 'field-hint'}, t('otp.delete.text1')) : null, replaceCheck()] : null;
  if (kind === 'static') parts.push(formCardNode(otpForm, t('otp.static.title', {slot: t(`otp.slot${n}`)}), t('otp.static.text'), [
    fieldNode('otp-pw', t('otp.static.password'), 'password', '', {maxlength: 38}), replace, access], otpError));
  if (kind === 'hmac') parts.push(formCardNode(otpForm, t('otp.hmac.title', {slot: t(`otp.slot${n}`)}), t('otp.hmac.text'), [
    fieldNode('otp-secret', t('otp.hmac.secret'), 'text', '', {placeholder: t('otp.hmac.random')}),
    checkFieldNode('otp-touch', t('oath.requireTouch'), true), replace, access], otpError));
  if (kind === 'delete') parts.push(formCardNode(otpForm, t('otp.delete.title', {slot: t(`otp.slot${n}`)}),
    t(n === '1' ? 'otp.delete.text1' : 'otp.delete.text'), access, otpError, 'pk.delete.do'));
  if (!otpForm && otpError) parts.push(uiElement('p', {class: 'field-error'}, otpError));
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('otp.slots')),
    uiElement('p', {class: 'card-text'}, t('otp.intro')),
    uiElement('ul', {class: 'pgp-keys'}, st.slots.map(s => uiElement('li', {class: `pgp-key${s.configured ? '' : ' empty'}`},
      uiElement('div', {class: 'pgp-key-head'}, uiElement('span', {class: 'pgp-slot'}, t(`otp.slot${s.slot}`)),
        s.configured ? [uiElement('span', {class: 'pill on'}, t('otp.configured')),
          s.touch === false ? uiElement('span', {class: 'muted'}, t('otp.noTouch')) : null]
          : uiElement('span', {class: 'muted'}, t('pgp.empty'))),
      uiElement('div', {class: 'piv-actions'},
        actionButton('form', t('otp.static.short'), 'btn-link', {'data-form': `static:${s.slot}`}),
        actionButton('form', t('otp.hmac.short'), 'btn-link', {'data-form': `hmac:${s.slot}`}),
        s.configured ? actionButton('form', t('pk.delete.do'), 'btn-link danger-link', {'data-form': `delete:${s.slot}`}) : null)))),
    uiElement('div', {class: 'form-actions att-actions'}, actionButton('swap', t('otp.swap'))),
    uiElement('p', {class: 'field-hint'}, t('otp.hint'))));
  el.replaceChildren(...parts);
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
    if (act === 'copy-secret') return copyText(otpSecret, 'oath.copied', true);
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
