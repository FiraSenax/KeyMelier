'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Shared form helpers (PIV, OTP) ──────────────────────────────────────────

function fieldNode(cls, label, type = 'password', value = '', extra = {}) {
  return uiElement('label', {class: 'field'}, uiElement('span', {}, label),
    uiElement('input', {type, class: cls, value: value ?? '', autocomplete: 'off', spellcheck: 'false', ...extra}));
}

function selectFieldNode(cls, label, options) {
  return uiElement('label', {class: 'field'}, uiElement('span', {}, label),
    uiElement('select', {class: cls}, options.map(([value, text, selected]) =>
      uiElement('option', {value, selected: !!selected}, text))));
}

function checkFieldNode(cls, text, checked = false) {
  return uiElement('label', {class: 'check'},
    uiElement('input', {type: 'checkbox', class: cls, checked}), uiElement('span', {}, text));
}

function actionButton(act, text, cls = 'btn btn-secondary', attrs = {}) {
  return uiElement('button', {type: 'button', class: cls, 'data-act': act, ...attrs}, text);
}

function formCardNode(id, title, text, fields, error, submitKey = 'fp.save', cls = 'app-form') {
  return uiElement('form', {class: `card form-card ${cls}`, 'data-form': id, autocomplete: 'off'},
    uiElement('h2', {}, title), text ? uiElement('p', {class: 'card-text'}, text) : null, fields,
    error ? uiElement('p', {class: 'field-error'}, error) : null,
    uiElement('div', {class: 'form-actions'}, actionButton('hide-form', t('pk.delete.cancel')),
      uiElement('button', {type: 'submit', class: 'btn btn-primary'}, t(submitKey))));
}

function loadingNode() {
  return uiElement('div', {class: 'callout'}, uiElement('div', {class: 'loading'},
    uiElement('span', {class: 'spinner'}), t('mg.loading')));
}

function retryErrorNode(message) {
  return uiElement('div', {class: 'callout crit'}, uiElement('div', {class: 'callout-text'}, message),
    actionButton('reload', t('pin.retry'), 'btn-link'));
}

function wrongSecretMessage(e) {
  const code = e.data?.code || '';
  if (e.data?.retries != null && code.endsWith('_invalid')) return t('pgp.wrongPin', { n: e.data.retries });
  return errorMessage(e);
}

async function copyText(text, successKey = 'oath.copied', sensitive = false) {
  let ok = false;
  try { ok = await window.pywebview?.api?.copy_text(text, sensitive); } catch { /* report clipboard failure below */ }
  showToast(t(ok ? (sensitive ? 'oath.copiedSensitive' : successKey) : 'oath.copyFailed'), ok ? 'success' : 'error');
}

// Text/data builders. No caller-provided markup is accepted by uiElement.
function uiElement(tag, attrs = {}, ...children) {
  if (!/^(span|div|button|input|form|section|ul|li|details|summary|dl|dt|dd|code|p|label|select|option|textarea|h2)$/.test(tag)) throw new Error('Unsafe element');
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (!/^(class|type|title|role|tabindex|value|placeholder|maxlength|autocomplete|spellcheck|disabled|hidden|open|checked|selected|rows|min|max|data-[a-z-]+|aria-[a-z-]+)$/.test(key)) throw new Error('Unsafe attribute');
    if (value === false || value == null) continue;
    el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child != null) el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function iconNode(name, size = 18) {
  if (!Object.hasOwn(ICONS, name) || !Number.isFinite(size)) throw new Error('Unknown icon');
  const template = document.createElement('template');
  template.innerHTML = icon(name, size); // Reviewed sink: bundled SVG paths and numeric size only.
  return template.content;
}

function keyAvatarNode(token, size) {
  if (!Number.isFinite(size)) throw new Error('Invalid icon size');
  const template = document.createElement('template');
  template.innerHTML = keyArt(token, size); // Reviewed sink: local SVG geometry; no interpolated device strings.
  const node = uiElement('span', {class: 'key-art-wrap'}, template.content);
  if (typeof token.mds_icon === 'string' && /^data:image\/(png|jpeg|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(token.mds_icon)) {
    const img = document.createElement('img');
    img.className = 'vendor-badge'; img.alt = ''; img.src = token.mds_icon;
    node.append(img);
  }
  return node;
}

function serviceAvatarNode(...names) {
  for (const name of names) {
    const ic = SERVICE_ICONS[serviceKey(name)];
    if (!ic) continue;
    const img = document.createElement('img'); img.src = ic.src; img.alt = ''; img.setAttribute('aria-hidden', 'true');
    return uiElement('button', {type: 'button', class: 'pk-avatar svc-logo', 'data-brand-url': ic.url,
      title: ic.title + ' · ' + ic.url, 'aria-label': ic.title + ' · ' + ic.url}, img);
  }
  const first = String(names.find(n => n && !String(n).includes('.')) || serviceKey(names.find(Boolean)) || '?');
  return uiElement('span', {class: 'pk-avatar'}, (first[0] || '?').toUpperCase());
}
