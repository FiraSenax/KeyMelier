'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── OpenPGP tab ─────────────────────────────────────────────────────────────

let pgpState = null;
let pgpForm = null;       // null | 'pin' | 'admin' | 'unblock' | 'holder' | 'sigpin' | 'touch:<slot>'
let pgpConfirmReset = false;
let pgpError = null;
let pgpResult = null;     // freshly generated public key + revocation certificate
let gpgAvailable = null;

function pgpField(cls, label, type = 'password', value = '', extra = '') {
  return `<label class="field"><span>${escHtml(label)}</span>
    <input type="${type}" class="${cls}" value="${escHtml(value)}" autocomplete="off" spellcheck="false" ${extra}></label>`;
}

function pgpFormHtml(st) {
  const cancel = `<button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>`;
  const err = pgpError ? `<p class="field-error">${escHtml(pgpError)}</p>` : '';
  const admin = pgpField('pgp-admin', t('pgp.adminPin'));
  const wrap = (title, text, fields) => `<form class="card form-card pgp-form" data-form="${escHtml(pgpForm)}" autocomplete="off">
      <h2>${escHtml(title)}</h2>${text ? `<p class="card-text">${escHtml(text)}</p>` : ''}${fields}${err}
      <div class="form-actions">${cancel}<button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button></div></form>`;
  if (pgpForm === 'pin') return wrap(t('pgp.pin.change'), t('pgp.pin.hint'),
    pgpField('pgp-current', t('pgp.pin.current')) + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'admin') return wrap(t('pgp.admin.change'), t('pgp.admin.hint'),
    pgpField('pgp-current', t('pgp.admin.current')) + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'unblock') return wrap(t('pgp.unblock'), t('pgp.unblock.text'),
    admin + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'holder') return wrap(t('pgp.holder.edit'), t('pgp.holder.text'),
    pgpField('pgp-name', t('pgp.name'), 'text', st.name, 'maxlength="39"') +
    pgpField('pgp-url', t('pgp.url'), 'url', st.url, 'maxlength="254" placeholder="https://…"') + admin);
  if (pgpForm === 'sigpin') return wrap(t('pgp.sigpin.title'), t('pgp.sigpin.text'),
    `<label class="check"><input type="checkbox" class="pgp-sigpin" ${st.pin.sign_every_time ? 'checked' : ''}><span>${escHtml(t('pgp.sigpin.every'))}</span></label>` + admin);
  if (pgpForm === 'generate') {
    const replacing = st.keys.some(k => k.present);
    const algos = st.algorithms || ['rsa2048'];
    return `<form class="card form-card pgp-form" data-form="generate" autocomplete="off">
      <h2>${escHtml(t('pgp.gen.title'))}</h2>
      <p class="card-text">${escHtml(t('pgp.gen.text'))}</p>
      ${replacing ? `<div class="callout crit"><div class="callout-text">${escHtml(t('pgp.gen.replace'))}</div></div>` : ''}
      ${['on', 'fixed', 'cached', 'cached_fixed'].includes(st.keys.find(k => k.slot === 'sig')?.touch)
        ? `<div class="callout warn"><div class="callout-text">${escHtml(t('pgp.gen.touchHint'))}</div></div>` : ''}
      <div class="oath-grid">
        ${pgpField('pgp-gname', t('pgp.gen.name'), 'text', st.name || '', 'maxlength="100"')}
        ${pgpField('pgp-gemail', t('pgp.gen.email'), 'email', '', 'maxlength="120"')}
        <label class="field"><span>${escHtml(t('pgp.gen.algorithm'))}</span><select class="pgp-galgo bk-select">
          ${algos.map(a => `<option value="${a}">${escHtml(t(`pgp.gen.algo.${a}`))}</option>`).join('')}</select></label>
        <label class="field"><span>${escHtml(t('pgp.gen.validity'))}</span><select class="pgp-gexpire bk-select">
          ${[[730, 'pgp.gen.years2'], [365, 'pgp.gen.years1'], [1825, 'pgp.gen.years5'], [0, 'pgp.gen.never']].map(([d, k]) => `<option value="${d}">${escHtml(t(k))}</option>`).join('')}</select></label>
      </div>
      ${pgpField('pgp-guser', t('pgp.userPin'))}${pgpField('pgp-admin', t('pgp.adminPin'))}
      ${replacing ? `<label class="check"><input type="checkbox" class="pgp-gconfirm"><span>${escHtml(t('pgp.gen.confirm'))}</span></label>` : ''}
      ${err}
      <div class="form-actions">${cancel}<button type="submit" class="btn btn-primary">${escHtml(t('pgp.gen.do'))}</button></div></form>`;
  }
  if (pgpForm?.startsWith('touch:')) {
    const slot = pgpForm.slice(6);
    const cur = st.keys.find(k => k.slot === slot)?.touch;
    return wrap(t('pgp.touch.title', { slot: t(`pgp.slot.${slot}`) }), t('pgp.touch.text'),
      `<label class="field"><span>${escHtml(t('pgp.touch'))}</span><select class="pgp-touch bk-select">
        ${['off', 'on', 'cached'].map(p => `<option value="${p}" ${p === cur ? 'selected' : ''}>${escHtml(t(`pgp.touch.${p}`))}</option>`).join('')}
      </select></label>` + admin);
  }
  return '';
}

function renderPgp() {
  const el = $('pgp-content');
  if (!el) return;
  const st = pgpState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
    return;
  }
  const parts = [];
  if (pgpResult) parts.push(pgpResultHtml(pgpResult));
  if (pgpForm) parts.push(pgpFormHtml(st));
  else if (pgpError) parts.push(`<p class="field-error">${escHtml(pgpError)}</p>`);
  const anyKey = st.keys.some(k => k.present);
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.keys'))}</h2>
    ${anyKey ? '' : `<p class="card-text">${escHtml(t('pgp.noKeys'))}</p>`}
    <ul class="pgp-keys">${st.keys.map(k => `<li class="pgp-key${k.present ? '' : ' empty'}">
      <div class="pgp-key-head"><span class="pgp-slot">${escHtml(t(`pgp.slot.${k.slot}`))}</span>
        ${k.present ? `<span class="pill">${escHtml(k.algorithm || '?')}</span>` : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}
        ${st.can_touch && k.touch ? `<button type="button" class="btn-link pgp-touch-btn" data-act="touch" data-slot="${k.slot}">${icon('key', 12)} ${escHtml(t(`pgp.touch.${k.touch}`) || k.touch)}</button>` : ''}
      </div>
      ${k.present ? `<div class="pgp-fp">${escHtml(k.fingerprint)}</div>
        <div class="muted pgp-meta">${escHtml([k.created ? t('pgp.created', { date: new Date(k.created).toLocaleDateString(LANG) }) : '',
          k.origin ? t(`pgp.origin.${k.origin}`) : ''].filter(Boolean).join(' · '))}</div>` : ''}
    </li>`).join('')}</ul>
    <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="form" data-form="generate">${escHtml(t('pgp.gen.title'))}</button></div>
    <p class="field-hint">${escHtml(t('pgp.gpgHint'))}</p>
  </section>`);
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.card'))}</h2>
    <dl class="kv">${buildKv([
      [t('pgp.name'), st.name || '–'],
      [t('pgp.url'), st.url || '–'],
      [t('pgp.serial'), st.serial || '–'],
      [t('pgp.spec'), st.spec],
      [t('pgp.counter'), st.signature_counter == null ? '–' : String(st.signature_counter)],
      [t('pgp.sigpin.title'), t(st.pin.sign_every_time ? 'pgp.sigpin.always' : 'pgp.sigpin.once')],
    ])}</dl>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="holder">${escHtml(t('pgp.holder.edit'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="sigpin">${escHtml(t('pgp.sigpin.title'))}</button>
    </div></section>`);
  const tries = (n, max = 3) => `<span class="${n === 0 ? 'bad-text' : n < max ? 'warn-text' : ''}">${escHtml(t('pgp.tries', { n }))}</span>`;
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.pins'))}</h2>
    <dl class="kv"><dt>${escHtml(t('pgp.userPin'))}</dt><dd>${tries(st.pin.user)}</dd>
      <dt>${escHtml(t('pgp.adminPin'))}</dt><dd>${tries(st.pin.admin)}</dd></dl>
    ${st.pin.user === 0 ? `<p class="card-text">${escHtml(t('pgp.userBlocked'))}</p>` : ''}
    ${st.pin.admin === 0 ? `<p class="card-text">${escHtml(t('pgp.adminBlocked'))}</p>` : ''}
    <p class="field-hint">${escHtml(t('pgp.defaults'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="pin">${escHtml(t('pgp.pin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="admin">${escHtml(t('pgp.admin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="unblock">${escHtml(t('pgp.unblock'))}</button>
    </div></section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('pgp.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('pgp.reset.text'))}</p>
    <div class="form-actions att-actions">${pgpConfirmReset
      ? `<button type="button" class="btn btn-secondary" data-act="reset-cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('pgp.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="reset-ask">${escHtml(t('pgp.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.pgp-form input')?.focus();
}

function pgpResultHtml(r) {
  return `<section class="card pgp-result">
    <h2>${escHtml(t('pgp.res.title'))}</h2>
    <p class="card-text">${escHtml(r.user_id)}</p>
    <div class="pgp-fp">${escHtml(r.fingerprint)}</div>
    <div class="callout warn"><div class="callout-title">${escHtml(t('pgp.res.revTitle'))}</div>
      <div class="callout-text">${escHtml(t('pgp.res.revText'))}</div>
      <div class="form-actions att-actions"><button type="button" class="btn btn-primary" data-act="save-rev">${escHtml(t('pgp.res.saveRev'))}</button></div></div>
    <p class="card-text">${escHtml(t('pgp.res.pubText'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="save-pub">${escHtml(t('pgp.res.savePub'))}</button>
      <button type="button" class="btn btn-secondary" data-act="copy-pub">${escHtml(t('pgp.res.copyPub'))}</button>
      ${gpgAvailable ? `<button type="button" class="btn btn-secondary" data-act="gpg-import">${escHtml(t('pgp.res.gpgImport'))}</button>` : ''}
      <button type="button" class="btn-link" data-act="result-done">${escHtml(t('otp.secret.done'))}</button>
    </div>
    <p class="field-hint">${escHtml(t(gpgAvailable ? 'pgp.res.hintGpg' : 'pgp.res.hintNoGpg'))}</p>
  </section>`;
}

async function loadPgp(token) {
  pgpState = null; pgpError = null; pgpForm = null; pgpConfirmReset = false;
  renderPgp();
  try {
    const st = await call('openpgp', { token_id: token.id });
    if (selectedId !== token.id) return;
    pgpState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    pgpState = { error: isBusy(e) ? t('err.busy') : errorMessage(e) };
  }
  renderPgp();
}

async function pgpCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  pgpError = null;
  try {
    pgpState = await call(method, { token_id: token.id, ...args });
    pgpForm = null; pgpConfirmReset = false;
    showToast(t(doneKey), 'success');
  } catch (e) {
    pgpError = e.data?.retries != null && e.data.code?.endsWith('_invalid')
      ? t('pgp.wrongPin', { n: e.data.retries }) : errorMessage(e);
    // Retry counters changed: refresh them without losing the open form
    try { const st = await call('openpgp', { token_id: token.id }); pgpState = st; } catch { /* keep old */ }
  }
  renderPgp();
}

async function pgpGenerate(f) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
  const confirm = f.querySelector('.pgp-gconfirm');
  if (confirm && !confirm.checked) { pgpError = t('pgp.gen.confirmNeeded'); return renderPgp(); }
  pgpError = null;
  const btn = f.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>${escHtml(t(val('pgp-galgo').startsWith('rsa') ? 'pgp.gen.workingRsa' : 'piv.working'))}`;
  try {
    const res = await call('openpgp_generate', { token_id: token.id, algorithm: val('pgp-galgo'), name: val('pgp-gname'),
      email: val('pgp-gemail'), expire_days: Number(val('pgp-gexpire')), admin_pin: val('pgp-admin'), user_pin: val('pgp-guser'),
      replace: !!confirm?.checked });
    pgpState = res.state;
    pgpResult = res;
    pgpForm = null;
    if (gpgAvailable === null) gpgAvailable = await window.pywebview.api.gpg_available().catch(() => false);
    showToast(t('pgp.res.title'), 'success');
  } catch (e) {
    pgpError = wrongSecretMessage(e);
    try { pgpState = await call('openpgp', { token_id: token.id }); } catch { /* keep */ }
  }
  renderPgp();
}

function initPgpPane() {
  const el = $('pgp-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadPgp(token);
    if (act === 'form') { pgpForm = b.dataset.form; pgpError = null; return renderPgp(); }
    if (act === 'touch') { pgpForm = `touch:${b.dataset.slot}`; pgpError = null; return renderPgp(); }
    if (act === 'hide-form') { pgpForm = null; pgpError = null; return renderPgp(); }
    if (act === 'reset-ask') { pgpConfirmReset = true; return renderPgp(); }
    if (act === 'reset-cancel') { pgpConfirmReset = false; return renderPgp(); }
    if (act === 'reset') return pgpCall('openpgp_reset', { confirm: true }, 'pgp.reset.done');
    if (act === 'save-pub' || act === 'save-rev') {
      const rev = act === 'save-rev';
      const name = `${pgpResult.filename}${rev ? '-revocation' : ''}.asc`;
      window.pywebview.api.save_text(name, rev ? pgpResult.revocation : pgpResult.public_key, rev)
        .then(path => { if (path) showToast(t('pgp.res.saved', { path }), 'success'); });
      return;
    }
    if (act === 'copy-pub') return copyText(pgpResult.public_key);
    if (act === 'gpg-import') {
      b.disabled = true;
      window.pywebview.api.gpg_import(pgpResult.public_key).then(res => {
        b.disabled = false;
        showToast(t(res?.ok ? 'pgp.res.gpgDone' : 'pgp.res.gpgFailed'), res?.ok ? 'success' : 'error');
      });
      return;
    }
    if (act === 'result-done') { pgpResult = null; return renderPgp(); }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const form = f.dataset.form;
    if (['pin', 'admin', 'unblock'].includes(form) && val('pgp-new') !== val('pgp-confirm')) {
      pgpError = t('pin.v.mismatch'); return renderPgp();
    }
    if (form === 'pin' || form === 'admin') {
      return pgpCall('openpgp_change_pin', { which: form === 'admin' ? 'admin' : 'user', current: val('pgp-current'), new: val('pgp-new') }, 'pgp.saved');
    }
    if (form === 'unblock') return pgpCall('openpgp_unblock_pin', { admin_pin: val('pgp-admin'), new_pin: val('pgp-new') }, 'pgp.saved');
    if (form === 'holder') return pgpCall('openpgp_cardholder', { name: val('pgp-name'), url: val('pgp-url'), admin_pin: val('pgp-admin') }, 'pgp.saved');
    if (form === 'sigpin') return pgpCall('openpgp_signature_pin', { every_time: f.querySelector('.pgp-sigpin').checked, admin_pin: val('pgp-admin') }, 'pgp.saved');
    if (form === 'generate') return pgpGenerate(f);
    if (form?.startsWith('touch:')) {
      return pgpCall('openpgp_touch', { slot: form.slice(6), policy: val('pgp-touch'), admin_pin: val('pgp-admin') }, 'pgp.saved');
    }
  });
}
