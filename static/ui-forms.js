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

async function copyText(text) {
  const ok = await window.pywebview?.api?.copy_text(text);
  showToast(t(ok ? 'oath.copied' : 'oath.copyFailed'), ok ? 'success' : 'error');
}
