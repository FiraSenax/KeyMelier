'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── OpenPGP tab ─────────────────────────────────────────────────────────────

let pgpState = null;
let pgpForm = null;       // null | 'pin' | 'admin' | 'unblock' | 'holder' | 'sigpin' | 'touch:<slot>'
let pgpConfirmReset = false;
let pgpError = null;
let pgpResult = null;     // freshly generated public key + revocation certificate
let gpgAvailable = null;

function pgpFormNode(st) {
  const admin = fieldNode('pgp-admin', t('pgp.adminPin'));
  const wrap = (title, text, fields, submitKey = 'fp.save') =>
    formCardNode(pgpForm, title, text, fields, pgpError, submitKey, 'pgp-form');
  const confirm = () => fieldNode('pgp-confirm', t('pin.form.confirm'));
  if (pgpForm === 'pin') return wrap(t('pgp.pin.change'), t('pgp.pin.hint'), [
    fieldNode('pgp-current', t('pgp.pin.current')), fieldNode('pgp-new', t('pin.form.new')), confirm()]);
  if (pgpForm === 'admin') return wrap(t('pgp.admin.change'), t('pgp.admin.hint'), [
    fieldNode('pgp-current', t('pgp.admin.current')), fieldNode('pgp-new', t('pin.form.new')), confirm()]);
  if (pgpForm === 'unblock') return wrap(t('pgp.unblock'), t('pgp.unblock.text'), [
    admin, fieldNode('pgp-new', t('pin.form.new')), confirm()]);
  if (pgpForm === 'holder') return wrap(t('pgp.holder.edit'), t('pgp.holder.text'), [
    fieldNode('pgp-name', t('pgp.name'), 'text', st.name, {maxlength: 39}),
    fieldNode('pgp-url', t('pgp.url'), 'url', st.url, {maxlength: 254, placeholder: 'https://…'}), admin]);
  if (pgpForm === 'sigpin') return wrap(t('pgp.sigpin.title'), t('pgp.sigpin.text'), [
    checkFieldNode('pgp-sigpin', t('pgp.sigpin.every'), !!st.pin.sign_every_time), admin]);
  if (pgpForm === 'generate') {
    const replacing = st.keys.some(k => k.present);
    const algos = st.algorithms || ['rsa2048'];
    return wrap(t('pgp.gen.title'), t('pgp.gen.text'), [
      replacing ? uiElement('div', {class: 'callout crit'}, uiElement('div', {class: 'callout-text'}, t('pgp.gen.replace'))) : null,
      ['on', 'fixed', 'cached', 'cached_fixed'].includes(st.keys.find(k => k.slot === 'sig')?.touch)
        ? uiElement('div', {class: 'callout warn'}, uiElement('div', {class: 'callout-text'}, t('pgp.gen.touchHint'))) : null,
      uiElement('div', {class: 'oath-grid'},
        fieldNode('pgp-gname', t('pgp.gen.name'), 'text', st.name || '', {maxlength: 100}),
        fieldNode('pgp-gemail', t('pgp.gen.email'), 'email', '', {maxlength: 120}),
        selectFieldNode('pgp-galgo bk-select', t('pgp.gen.algorithm'), algos.map(a => [a, t(`pgp.gen.algo.${a}`)])),
        selectFieldNode('pgp-gexpire bk-select', t('pgp.gen.validity'),
          [[730, 'pgp.gen.years2'], [365, 'pgp.gen.years1'], [1825, 'pgp.gen.years5'], [0, 'pgp.gen.never']].map(([d, k]) => [d, t(k)]))),
      fieldNode('pgp-guser', t('pgp.userPin')), admin,
      replacing ? checkFieldNode('pgp-gconfirm', t('pgp.gen.confirm')) : null], 'pgp.gen.do');
  }
  if (pgpForm?.startsWith('touch:')) {
    const slot = pgpForm.slice(6);
    const cur = st.keys.find(k => k.slot === slot)?.touch;
    return wrap(t('pgp.touch.title', {slot: t(`pgp.slot.${slot}`)}), t('pgp.touch.text'), [
      selectFieldNode('pgp-touch bk-select', t('pgp.touch'),
        ['off', 'on', 'cached'].map(p => [p, t(`pgp.touch.${p}`), p === cur])), admin]);
  }
  return null;
}

function renderPgp() {
  const el = $('pgp-content');
  if (!el) return;
  const st = pgpState;
  if (!st) return el.replaceChildren(loadingNode());
  if (st.error) return el.replaceChildren(retryErrorNode(st.error));
  const parts = [];
  if (pgpResult) parts.push(pgpResultNode(pgpResult));
  if (pgpForm) parts.push(pgpFormNode(st));
  else if (pgpError) parts.push(uiElement('p', {class: 'field-error'}, pgpError));
  const anyKey = st.keys.some(k => k.present);
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('pgp.keys')),
    anyKey ? null : uiElement('p', {class: 'card-text'}, t('pgp.noKeys')),
    uiElement('ul', {class: 'pgp-keys'}, st.keys.map(k =>
      uiElement('li', {class: `pgp-key${k.present ? '' : ' empty'}`},
        uiElement('div', {class: 'pgp-key-head'}, uiElement('span', {class: 'pgp-slot'}, t(`pgp.slot.${k.slot}`)),
          k.present ? uiElement('span', {class: 'pill'}, k.algorithm || '?') : uiElement('span', {class: 'muted'}, t('pgp.empty')),
          st.can_touch && k.touch ? uiElement('button', {type: 'button', class: 'btn-link pgp-touch-btn', 'data-act': 'touch', 'data-slot': k.slot},
            iconNode('key', 12), ' ', t(`pgp.touch.${k.touch}`) || k.touch) : null),
        k.present ? [uiElement('div', {class: 'pgp-fp'}, k.fingerprint),
          uiElement('div', {class: 'muted pgp-meta'}, [k.created ? t('pgp.created', {date: new Date(k.created).toLocaleDateString(LANG)}) : '',
            k.origin ? t(`pgp.origin.${k.origin}`) : ''].filter(Boolean).join(' · '))] : null))),
    uiElement('div', {class: 'form-actions att-actions'}, actionButton('form', t('pgp.gen.title'), undefined, {'data-form': 'generate'})),
    uiElement('p', {class: 'field-hint'}, t('pgp.gpgHint'))));
  const facts = [
    [t('pgp.name'), st.name || '–'], [t('pgp.url'), st.url || '–'], [t('pgp.serial'), st.serial || '–'],
    [t('pgp.spec'), st.spec], [t('pgp.counter'), st.signature_counter == null ? '–' : String(st.signature_counter)],
    [t('pgp.sigpin.title'), t(st.pin.sign_every_time ? 'pgp.sigpin.always' : 'pgp.sigpin.once')],
  ];
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('pgp.card')),
    uiElement('dl', {class: 'kv'}, facts.map(([k, v]) => [uiElement('dt', {}, k), uiElement('dd', {}, v ?? '—')])),
    uiElement('div', {class: 'form-actions att-actions'},
      actionButton('form', t('pgp.holder.edit'), undefined, {'data-form': 'holder'}),
      actionButton('form', t('pgp.sigpin.title'), undefined, {'data-form': 'sigpin'}))));
  const tries = (n, max = 3) => uiElement('span', {class: n === 0 ? 'bad-text' : n < max ? 'warn-text' : ''}, t('pgp.tries', {n}));
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('pgp.pins')),
    uiElement('dl', {class: 'kv'}, uiElement('dt', {}, t('pgp.userPin')), uiElement('dd', {}, tries(st.pin.user)),
      uiElement('dt', {}, t('pgp.adminPin')), uiElement('dd', {}, tries(st.pin.admin))),
    st.pin.user === 0 ? uiElement('p', {class: 'card-text'}, t('pgp.userBlocked')) : null,
    st.pin.admin === 0 ? uiElement('p', {class: 'card-text'}, t('pgp.adminBlocked')) : null,
    uiElement('p', {class: 'field-hint'}, t('pgp.defaults')),
    uiElement('div', {class: 'form-actions att-actions'},
      actionButton('form', t('pgp.pin.change'), undefined, {'data-form': 'pin'}),
      actionButton('form', t('pgp.admin.change'), undefined, {'data-form': 'admin'}),
      actionButton('form', t('pgp.unblock'), undefined, {'data-form': 'unblock'}))));
  parts.push(uiElement('section', {class: 'card danger-card'}, uiElement('h2', {}, t('pgp.reset.title')),
    uiElement('p', {class: 'card-text'}, t('pgp.reset.text')),
    uiElement('div', {class: 'form-actions att-actions'}, pgpConfirmReset
      ? [actionButton('reset-cancel', t('pk.delete.cancel')), actionButton('reset', t('pgp.reset.do'), 'btn btn-danger')]
      : actionButton('reset-ask', t('pgp.reset.do')))));
  el.replaceChildren(...parts.filter(Boolean));
  el.querySelector('.pgp-form input')?.focus();
}

function pgpResultNode(r) {
  return uiElement('section', {class: 'card pgp-result'}, uiElement('h2', {}, t('pgp.res.title')),
    uiElement('p', {class: 'card-text'}, r.user_id), uiElement('div', {class: 'pgp-fp'}, r.fingerprint),
    uiElement('div', {class: 'callout warn'}, uiElement('div', {class: 'callout-title'}, t('pgp.res.revTitle')),
      uiElement('div', {class: 'callout-text'}, t('pgp.res.revText')),
      uiElement('div', {class: 'form-actions att-actions'}, actionButton('save-rev', t('pgp.res.saveRev'), 'btn btn-primary'))),
    uiElement('p', {class: 'card-text'}, t('pgp.res.pubText')),
    uiElement('div', {class: 'form-actions att-actions'},
      actionButton('save-pub', t('pgp.res.savePub')), actionButton('copy-pub', t('pgp.res.copyPub')),
      gpgAvailable ? actionButton('gpg-import', t('pgp.res.gpgImport')) : null,
      actionButton('result-done', t('otp.secret.done'), 'btn-link')),
    uiElement('p', {class: 'field-hint'}, t(gpgAvailable ? 'pgp.res.hintGpg' : 'pgp.res.hintNoGpg')));
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
  btn.replaceChildren(uiElement('span', {class: 'spinner'}), t(val('pgp-galgo').startsWith('rsa') ? 'pgp.gen.workingRsa' : 'piv.working'));
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
