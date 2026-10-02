'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── PIV tab ─────────────────────────────────────────────────────────────────

let pivState = null;
let pivForm = null;        // 'pin' | 'puk' | 'unblock' | 'protect' | 'gen:<slot>' | 'import:<slot>' | 'delete:<slot>'
let pivError = null;
let pivConfirmReset = false;

function pivNeedsMgmtKey(st) {
  return st.management_key.protected === false && st.management_key.default === false;
}

function pivAuthFields(st, withPin = true) {
  return (withPin || st.management_key.protected ? fieldHtml('piv-pin', t('piv.pin')) : '') +
    (pivNeedsMgmtKey(st) ? fieldHtml('piv-mgmt', t('piv.mgmt.key'), 'password', '', 'placeholder="010203…"') : '');
}

function pivFormHtml(st) {
  const [kind, slot] = (pivForm || '').split(':');
  if (kind === 'pin') return formCardHtml(pivForm, t('piv.pin.change'), t('piv.pin.hint'),
    fieldHtml('piv-current', t('pgp.pin.current')) + fieldHtml('piv-new', t('pin.form.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'puk') return formCardHtml(pivForm, t('piv.puk.change'), t('piv.puk.hint'),
    fieldHtml('piv-current', t('piv.puk.current')) + fieldHtml('piv-new', t('piv.puk.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'unblock') return formCardHtml(pivForm, t('pgp.unblock'), t('piv.unblock.text'),
    fieldHtml('piv-puk', t('piv.puk')) + fieldHtml('piv-new', t('pin.form.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'protect') return formCardHtml(pivForm, t('piv.mgmt.protect'), t('piv.mgmt.protectText'), pivAuthFields(st), pivError);
  if (kind === 'gen') return formCardHtml(pivForm, t('piv.gen.title', { slot: slotName(slot) }), t('piv.gen.text'),
    fieldHtml('piv-subject', t('piv.gen.subject'), 'text', '', 'placeholder="Erika Mustermann"') +
    `<div class="oath-grid">
      <label class="field"><span>${escHtml(t('piv.gen.type'))}</span><select class="piv-type bk-select">${st.key_types.map(k => `<option>${k}</option>`).join('')}</select></label>
      <label class="field"><span>${escHtml(t('piv.gen.days'))}</span><input type="number" class="piv-days" value="365" min="1" max="3650"></label>
      <label class="field"><span>${escHtml(t('piv.gen.pinPolicy'))}</span><select class="piv-pinpol bk-select">
        ${['default', 'once', 'always', 'never'].map(p => `<option value="${p}">${escHtml(t(`piv.policy.${p}`))}</option>`).join('')}</select></label>
      <label class="field"><span>${escHtml(t('piv.gen.touchPolicy'))}</span><select class="piv-touchpol bk-select">
        ${['default', 'never', 'always', 'cached'].map(p => `<option value="${p}">${escHtml(t(`piv.touch.${p}`))}</option>`).join('')}</select></label>
    </div>` + (pivSlotUsed(st, slot) ? replaceCheck() : '') + pivAuthFields(st), pivError, 'piv.gen.do');
  if (kind === 'import') return formCardHtml(pivForm, t('piv.import.title', { slot: slotName(slot) }), t('piv.import.text'),
    `<label class="field"><span>PEM</span><textarea class="piv-pem" rows="6" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>` +
    pivAuthFields(st, false), pivError, 'piv.import.do');
  if (kind === 'delete') return formCardHtml(pivForm, t('piv.delete.title', { slot: slotName(slot) }), t('piv.delete.text'),
    (st.can_delete_key ? `<label class="check"><input type="checkbox" class="piv-delkey"><span>${escHtml(t('piv.delete.key'))}</span></label>` : '') +
    pivAuthFields(st, false), pivError, 'pk.delete.do');
  return '';
}

function pivSlotUsed(st, slot) {
  return st.slots.some(s => s.slot === slot && (s.cert || s.key));
}

function replaceCheck() {
  return `<label class="check"><input type="checkbox" class="app-replace"><span>${escHtml(t('confirm.replace'))}</span></label>`;
}

function slotName(slot) {
  const key = `piv.slot.${slot}`;
  const name = STRINGS[LANG][key] || STRINGS.en[key];
  return name ? `${name} (${slot.toUpperCase()})` : t('piv.slot.retired', { slot: slot.toUpperCase() });
}

function renderPiv() {
  const el = $('piv-content');
  if (!el) return;
  const st = pivState;
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
  if (pivForm) parts.push(pivFormHtml(st));
  else if (pivError) parts.push(`<p class="field-error">${escHtml(pivError)}</p>`);
  const warn = [];
  if (st.pin.default) warn.push(t('piv.warn.pin'));
  if (st.pin.puk_default) warn.push(t('piv.warn.puk'));
  if (st.management_key.default) warn.push(t('piv.warn.mgmt'));
  if (warn.length) parts.push(`<div class="callout warn"><div class="callout-title">${escHtml(t('piv.warn.title'))}</div>
    <ul class="callout-list">${warn.map(w => `<li>${escHtml(w)}</li>`).join('')}</ul></div>`);
  parts.push(`<section class="card"><h2>${escHtml(t('piv.slots'))}</h2>
    <ul class="pgp-keys">${st.slots.map(s => {
      const c = s.cert;
      const k = s.key;
      const status = c ? (c.expired ? `<span class="pill bad">${escHtml(t('piv.expired'))}</span>` : c.expires_soon ? `<span class="pill warn">${escHtml(t('piv.expiresSoon'))}</span>` : '') : '';
      return `<li class="pgp-key${c || k ? '' : ' empty'}">
        <div class="pgp-key-head"><span class="pgp-slot">${escHtml(slotName(s.slot))}</span>
          ${c?.unreadable ? `<span class="pill warn">${escHtml(t('piv.unreadable'))}</span>` : c ? `<span class="pill">${escHtml(c.algorithm)}</span>` : k ? `<span class="pill">${escHtml(k.type)}</span>` : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}
          ${status}</div>
        ${c?.unreadable ? `<div class="muted pgp-meta">${escHtml(t('piv.unreadableHint'))}</div>` : ''}
        ${c && !c.unreadable ? `<div class="piv-subject">${escHtml(c.subject)}</div>
          <div class="muted pgp-meta">${escHtml([c.self_signed ? t('piv.selfSigned') : t('piv.issuer', { name: c.issuer }),
            t('piv.validUntil', { date: new Date(c.not_after).toLocaleDateString(LANG) })].join(' · '))}</div>` : ''}
        ${k ? `<div class="muted pgp-meta">${escHtml([t(k.generated ? 'pgp.origin.generated' : 'pgp.origin.imported'),
            `${t('piv.gen.pinPolicy')}: ${t(`piv.policy.${k.pin_policy}`) || k.pin_policy}`,
            `${t('piv.gen.touchPolicy')}: ${t(`piv.touch.${k.touch_policy}`) || k.touch_policy}`].join(' · '))}</div>` : ''}
        <div class="piv-actions">
          <button type="button" class="btn-link" data-act="form" data-form="gen:${s.slot}">${escHtml(t('piv.gen.short'))}</button>
          <button type="button" class="btn-link" data-act="form" data-form="import:${s.slot}">${escHtml(t('piv.import.short'))}</button>
          ${c && !c.unreadable ? `<button type="button" class="btn-link" data-act="export" data-slot="${s.slot}">${escHtml(t('piv.export'))}</button>` : ''}
          ${c || k ? `<button type="button" class="btn-link danger-link" data-act="form" data-form="delete:${s.slot}">${escHtml(t('pk.delete.do'))}</button>` : ''}
        </div>
      </li>`;
    }).join('')}</ul>
    <p class="field-hint">${escHtml(t('piv.hint'))}</p></section>`);
  const tries = n => n == null ? '–' : `<span class="${n === 0 ? 'bad-text' : n < 3 ? 'warn-text' : ''}">${escHtml(t('pgp.tries', { n }))}</span>`;
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.pins'))}</h2>
    <dl class="kv"><dt>${escHtml(t('piv.pin'))}</dt><dd>${tries(st.pin.attempts)}</dd>
      ${st.pin.puk_attempts != null ? `<dt>${escHtml(t('piv.puk'))}</dt><dd>${tries(st.pin.puk_attempts)}</dd>` : ''}</dl>
    <p class="field-hint">${escHtml(t('piv.defaults'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="pin">${escHtml(t('piv.pin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="puk">${escHtml(t('piv.puk.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="unblock">${escHtml(t('pgp.unblock'))}</button>
    </div></section>`);
  const m = st.management_key;
  parts.push(`<section class="card"><h2>${escHtml(t('piv.mgmt.title'))}</h2>
    <p class="card-text">${escHtml(t(m.protected ? 'piv.mgmt.protected' : m.default ? 'piv.mgmt.default' : m.default === false ? 'piv.mgmt.custom' : 'piv.mgmt.unknown'))}</p>
    ${m.protected ? '' : `<div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="form" data-form="protect">${escHtml(t('piv.mgmt.protect'))}</button></div>`}
  </section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('piv.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('piv.reset.text'))}</p>
    <div class="form-actions att-actions">${pivConfirmReset
      ? `<button type="button" class="btn btn-secondary" data-act="reset-cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('piv.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="reset-ask">${escHtml(t('piv.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.app-form input, .app-form textarea')?.focus();
}

async function loadPiv(token) {
  pivState = null; pivError = null; pivForm = null; pivConfirmReset = false;
  renderPiv();
  try {
    const st = await call('piv', { token_id: token.id });
    if (selectedId !== token.id) return;
    pivState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    pivState = { error: isBusy(e) ? t('err.busy') : errorMessage(e) };
  }
  renderPiv();
}

async function pivCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  pivError = null;
  const busy = $('piv-content').querySelector('.app-form button[type=submit]');
  if (busy) { busy.disabled = true; busy.innerHTML = `<span class="spinner"></span>${escHtml(t('piv.working'))}`; }
  try {
    pivState = await call(method, { token_id: token.id, ...args });
    pivForm = null; pivConfirmReset = false;
    showToast(t(doneKey), 'success');
  } catch (e) {
    pivError = wrongSecretMessage(e);
    try { pivState = await call('piv', { token_id: token.id }); } catch { /* keep old */ }
  }
  renderPiv();
}

function initPivPane() {
  const el = $('piv-content');
  el.addEventListener('click', async ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadPiv(token);
    if (act === 'form') { pivForm = b.dataset.form; pivError = null; return renderPiv(); }
    if (act === 'hide-form') { pivForm = null; pivError = null; return renderPiv(); }
    if (act === 'reset-ask') { pivConfirmReset = true; return renderPiv(); }
    if (act === 'reset-cancel') { pivConfirmReset = false; return renderPiv(); }
    if (act === 'reset') return pivCall('piv_reset', { confirm: true }, 'piv.reset.done');
    if (act === 'export' && token) {
      try { const res = await call('piv_export', { token_id: token.id, slot: b.dataset.slot }); copyText(res.pem); }
      catch (e) { showToast(errorMessage(e), 'error'); }
    }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const [kind, slot] = (f.dataset.form || '').split(':');
    const auth = { pin: val('piv-pin') || null, management_key: val('piv-mgmt') || null };
    if (['pin', 'puk', 'unblock'].includes(kind) && val('piv-new') !== val('piv-confirm')) {
      pivError = t('pin.v.mismatch'); return renderPiv();
    }
    if (kind === 'pin' || kind === 'puk') return pivCall('piv_change_pin', { which: kind, current: val('piv-current'), new: val('piv-new') }, 'pgp.saved');
    if (kind === 'unblock') return pivCall('piv_unblock_pin', { puk: val('piv-puk'), new_pin: val('piv-new') }, 'pgp.saved');
    if (kind === 'protect') return pivCall('piv_protect_management_key', { pin: val('piv-pin'), management_key: auth.management_key }, 'pgp.saved');
    if (kind === 'gen') {
      return pivCall('piv_generate', { slot, key_type: val('piv-type'), subject: val('piv-subject'), days: Number(val('piv-days')) || 365,
        pin: val('piv-pin'), management_key: auth.management_key, pin_policy: val('piv-pinpol'), touch_policy: val('piv-touchpol'),
        replace: !!f.querySelector('.app-replace')?.checked }, 'piv.gen.done');
    }
    if (kind === 'import') return pivCall('piv_import', { slot, pem: val('piv-pem'), ...auth }, 'piv.import.done');
    if (kind === 'delete') return pivCall('piv_delete', { slot, key: !!f.querySelector('.piv-delkey')?.checked, confirm: true, ...auth }, 'piv.deleted');
  });
}
