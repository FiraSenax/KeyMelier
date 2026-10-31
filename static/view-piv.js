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
  return [withPin || st.management_key.protected ? fieldNode('piv-pin', t('piv.pin')) : null,
    pivNeedsMgmtKey(st) ? fieldNode('piv-mgmt', t('piv.mgmt.key'), 'password', '', {placeholder: '010203…'}) : null];
}

function pivFormNode(st) {
  const [kind, slot] = (pivForm || '').split(':');
  const confirm = () => fieldNode('piv-confirm', t('pin.form.confirm'));
  if (kind === 'pin') return formCardNode(pivForm, t('piv.pin.change'), t('piv.pin.hint'), [
    fieldNode('piv-current', t('pgp.pin.current')), fieldNode('piv-new', t('pin.form.new')), confirm()], pivError);
  if (kind === 'puk') return formCardNode(pivForm, t('piv.puk.change'), t('piv.puk.hint'), [
    fieldNode('piv-current', t('piv.puk.current')), fieldNode('piv-new', t('piv.puk.new')), confirm()], pivError);
  if (kind === 'unblock') return formCardNode(pivForm, t('pgp.unblock'), t('piv.unblock.text'), [
    fieldNode('piv-puk', t('piv.puk')), fieldNode('piv-new', t('pin.form.new')), confirm()], pivError);
  if (kind === 'protect') return formCardNode(pivForm, t('piv.mgmt.protect'), t('piv.mgmt.protectText'), pivAuthFields(st), pivError);
  if (kind === 'gen') return formCardNode(pivForm, t('piv.gen.title', {slot: slotName(slot)}), t('piv.gen.text'), [
    fieldNode('piv-subject', t('piv.gen.subject'), 'text', '', {placeholder: 'Erika Mustermann'}),
    uiElement('div', {class: 'oath-grid'},
      selectFieldNode('piv-type bk-select', t('piv.gen.type'), st.key_types.map(k => [k, k])),
      fieldNode('piv-days', t('piv.gen.days'), 'number', '365', {min: 1, max: 3650}),
      selectFieldNode('piv-pinpol bk-select', t('piv.gen.pinPolicy'),
        ['default', 'once', 'always', 'never'].map(p => [p, t(`piv.policy.${p}`)])),
      selectFieldNode('piv-touchpol bk-select', t('piv.gen.touchPolicy'),
        ['default', 'never', 'always', 'cached'].map(p => [p, t(`piv.touch.${p}`)]))),
    pivSlotUsed(st, slot) ? replaceCheck() : null, pivAuthFields(st)], pivError, 'piv.gen.do');
  if (kind === 'import') return formCardNode(pivForm, t('piv.import.title', {slot: slotName(slot)}), t('piv.import.text'), [
    uiElement('label', {class: 'field'}, uiElement('span', {}, 'PEM'),
      uiElement('textarea', {class: 'piv-pem', rows: 6, spellcheck: 'false', placeholder: '-----BEGIN CERTIFICATE-----'})),
    pivAuthFields(st, false)], pivError, 'piv.import.do');
  if (kind === 'delete') return formCardNode(pivForm, t('piv.delete.title', {slot: slotName(slot)}), t('piv.delete.text'), [
    st.can_delete_key ? checkFieldNode('piv-delkey', t('piv.delete.key')) : null,
    pivAuthFields(st, false)], pivError, 'pk.delete.do');
  return null;
}

function pivSlotUsed(st, slot) {
  return st.slots.some(s => s.slot === slot && (s.cert || s.key));
}

function replaceCheck() {
  return checkFieldNode('app-replace', t('confirm.replace'));
}

function slotName(slot) {
  const key = `piv.slot.${slot}`;
  const name = STRINGS[LANG][key] || STRINGS.en[key];
  return name ? `${name} (${slot.toUpperCase()})` : t('piv.slot.retired', {slot: slot.toUpperCase()});
}

function renderPiv() {
  const el = $('piv-content');
  if (!el) return;
  const st = pivState;
  if (!st) return el.replaceChildren(loadingNode());
  if (st.error) return el.replaceChildren(retryErrorNode(st.error));
  const parts = [];
  if (pivForm) parts.push(pivFormNode(st));
  else if (pivError) parts.push(uiElement('p', {class: 'field-error'}, pivError));
  const warn = [];
  if (st.pin.default) warn.push(t('piv.warn.pin'));
  if (st.pin.puk_default) warn.push(t('piv.warn.puk'));
  if (st.management_key.default) warn.push(t('piv.warn.mgmt'));
  if (warn.length) parts.push(uiElement('div', {class: 'callout warn'},
    uiElement('div', {class: 'callout-title'}, t('piv.warn.title')),
    uiElement('ul', {class: 'callout-list'}, warn.map(w => uiElement('li', {}, w)))));
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('piv.slots')),
    uiElement('ul', {class: 'pgp-keys'}, st.slots.map(s => {
      const c = s.cert, k = s.key;
      return uiElement('li', {class: `pgp-key${c || k ? '' : ' empty'}`},
        uiElement('div', {class: 'pgp-key-head'}, uiElement('span', {class: 'pgp-slot'}, slotName(s.slot)),
          c?.unreadable ? uiElement('span', {class: 'pill warn'}, t('piv.unreadable'))
            : c || k ? uiElement('span', {class: 'pill'}, c ? c.algorithm : k.type)
              : uiElement('span', {class: 'muted'}, t('pgp.empty')),
          c?.expired ? uiElement('span', {class: 'pill bad'}, t('piv.expired'))
            : c?.expires_soon ? uiElement('span', {class: 'pill warn'}, t('piv.expiresSoon')) : null),
        c?.unreadable ? uiElement('div', {class: 'muted pgp-meta'}, t('piv.unreadableHint')) : null,
        c && !c.unreadable ? [uiElement('div', {class: 'piv-subject'}, c.subject),
          uiElement('div', {class: 'muted pgp-meta'}, [c.self_signed ? t('piv.selfSigned') : t('piv.issuer', {name: c.issuer}),
            t('piv.validUntil', {date: new Date(c.not_after).toLocaleDateString(LANG)})].join(' · '))] : null,
        k ? uiElement('div', {class: 'muted pgp-meta'}, [t(k.generated ? 'pgp.origin.generated' : 'pgp.origin.imported'),
          `${t('piv.gen.pinPolicy')}: ${t(`piv.policy.${k.pin_policy}`) || k.pin_policy}`,
          `${t('piv.gen.touchPolicy')}: ${t(`piv.touch.${k.touch_policy}`) || k.touch_policy}`].join(' · ')) : null,
        uiElement('div', {class: 'piv-actions'},
          actionButton('form', t('piv.gen.short'), 'btn-link', {'data-form': `gen:${s.slot}`}),
          actionButton('form', t('piv.import.short'), 'btn-link', {'data-form': `import:${s.slot}`}),
          c && !c.unreadable ? actionButton('export', t('piv.export'), 'btn-link', {'data-slot': s.slot}) : null,
          c || k ? actionButton('form', t('pk.delete.do'), 'btn-link danger-link', {'data-form': `delete:${s.slot}`}) : null));
    })), uiElement('p', {class: 'field-hint'}, t('piv.hint'))));
  const tries = n => n == null ? '–' : uiElement('span', {class: n === 0 ? 'bad-text' : n < 3 ? 'warn-text' : ''}, t('pgp.tries', {n}));
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('pgp.pins')),
    uiElement('dl', {class: 'kv'}, uiElement('dt', {}, t('piv.pin')), uiElement('dd', {}, tries(st.pin.attempts)),
      st.pin.puk_attempts != null ? [uiElement('dt', {}, t('piv.puk')), uiElement('dd', {}, tries(st.pin.puk_attempts))] : null),
    uiElement('p', {class: 'field-hint'}, t('piv.defaults')),
    uiElement('div', {class: 'form-actions att-actions'},
      actionButton('form', t('piv.pin.change'), undefined, {'data-form': 'pin'}),
      actionButton('form', t('piv.puk.change'), undefined, {'data-form': 'puk'}),
      actionButton('form', t('pgp.unblock'), undefined, {'data-form': 'unblock'}))));
  const m = st.management_key;
  parts.push(uiElement('section', {class: 'card'}, uiElement('h2', {}, t('piv.mgmt.title')),
    uiElement('p', {class: 'card-text'}, t(m.protected ? 'piv.mgmt.protected' : m.default ? 'piv.mgmt.default' : m.default === false ? 'piv.mgmt.custom' : 'piv.mgmt.unknown')),
    m.protected ? null : uiElement('div', {class: 'form-actions att-actions'},
      actionButton('form', t('piv.mgmt.protect'), undefined, {'data-form': 'protect'}))));
  parts.push(uiElement('section', {class: 'card danger-card'}, uiElement('h2', {}, t('piv.reset.title')),
    uiElement('p', {class: 'card-text'}, t('piv.reset.text')),
    uiElement('div', {class: 'form-actions att-actions'}, pivConfirmReset
      ? [actionButton('reset-cancel', t('pk.delete.cancel')), actionButton('reset', t('piv.reset.do'), 'btn btn-danger')]
      : actionButton('reset-ask', t('piv.reset.do')))));
  el.replaceChildren(...parts.filter(Boolean));
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
  if (busy) { busy.disabled = true; busy.replaceChildren(uiElement('span', {class: 'spinner'}), t('piv.working')); }
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
