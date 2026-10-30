'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Shared form helpers (PIV, OTP) ──────────────────────────────────────────

function fieldHtml(cls, label, type = 'password', value = '', extra = '') {
  return `<label class="field"><span>${escHtml(label)}</span>
    <input type="${type}" class="${cls}" value="${escHtml(value)}" autocomplete="off" spellcheck="false" ${extra}></label>`;
}

function formCardHtml(id, title, text, fields, error, submitKey = 'fp.save') {
  return `<form class="card form-card app-form" data-form="${escHtml(id)}" autocomplete="off">
    <h2>${escHtml(title)}</h2>${text ? `<p class="card-text">${escHtml(text)}</p>` : ''}${fields}
    ${error ? `<p class="field-error">${escHtml(error)}</p>` : ''}
    <div class="form-actions"><button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
      <button type="submit" class="btn btn-primary">${escHtml(t(submitKey))}</button></div></form>`;
}

function wrongSecretMessage(e) {
  const code = e.data?.code || '';
  if (e.data?.retries != null && code.endsWith('_invalid')) return t('pgp.wrongPin', { n: e.data.retries });
  return errorMessage(e);
}

async function copyText(text, successKey = 'oath.copied') {
  let ok = false;
  try { ok = await window.pywebview?.api?.copy_text(text); } catch { /* report clipboard failure below */ }
  showToast(t(ok ? successKey : 'oath.copyFailed'), ok ? 'success' : 'error');
}

// Text/data builders. No caller-provided markup is accepted by uiElement.
function uiElement(tag, attrs = {}, ...children) {
  if (!/^(span|div|button|input|form|section|ul|li|details|summary|dl|dt|dd|code|p)$/.test(tag)) throw new Error('Unsafe element');
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (!/^(class|type|title|role|tabindex|value|placeholder|maxlength|autocomplete|spellcheck|disabled|hidden|open|data-[a-z-]+|aria-[a-z-]+)$/.test(key)) throw new Error('Unsafe attribute');
    if (value === false || value == null) continue;
    el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) {
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
