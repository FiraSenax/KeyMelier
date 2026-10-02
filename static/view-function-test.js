'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
// ── Function test ───────────────────────────────────────────────────────────

let ftRun = null;
let ftState = null;       // { needsPin, running, touch, result }

function renderFunctionTest() {
  const el = $('ft-card');
  const token = currentToken();
  if (!el || !token || token.offline) { if (el) el.innerHTML = ''; el?.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  const st = ftState || {};
  const r = st.result;
  let body = '';
  if (st.running) {
    body = `<div class="uv-wait"><span class="uv-icon">${icon('key', 26)}</span>
      <span>${escHtml(t(st.needsPin ? 'ft.touchUv' : 'ft.touch'))}</span></div>`;
  } else if (r) {
    const names = { register: 'ft.step.register', sign_in: 'ft.step.signIn', signature: 'ft.step.signature' };
    body = `<div class="att-summary ${r.ok ? 'pass' : 'fail'}">${escHtml(r.ok ? t('ft.ok', { s: r.seconds }) : (r.error ? errorMessage({ data: r, message: r.error }) : t('ft.failed')))}</div>
      <div class="att-checks">${(r.steps || []).map(s => `<div class="att-check ${s.ok ? 'pass' : 'fail'}">
        <span class="att-check-icon">${s.ok ? '✓' : '✕'}</span><div><div class="att-check-name">${escHtml(t(names[s.step] || s.step))}</div></div></div>`).join('')}
        ${r.ok ? `<div class="att-check pass"><span class="att-check-icon">${r.user_verified ? '✓' : '○'}</span><div><div class="att-check-name">${escHtml(t(r.user_verified ? 'ft.uv' : 'ft.noUv'))}</div></div></div>` : ''}
      </div>`;
  }
  el.innerHTML = `<h2>${escHtml(t('ft.title'))}</h2>
    <p class="card-text">${escHtml(t('ft.text'))}</p>
    ${body}
    ${st.running ? '' : `<form class="ft-form" autocomplete="off">
      ${st.needsPin ? `<label class="field"><span>${escHtml(t('pin.form.current'))}</span>
        <input type="password" class="ft-pin" autocomplete="off" spellcheck="false"></label>` : ''}
      <div class="form-actions att-actions"><button type="submit" class="btn btn-secondary">${escHtml(t(r ? 'ft.again' : 'ft.start'))}</button></div>
    </form>`}`;
}

async function loadFunctionTest(token) {
  ftRun = null;
  ftState = { needsPin: false };
  renderFunctionTest();
  try {
    const info = await call('function_test_info', { token_id: token.id });
    if (selectedId === token.id) { ftState = { ...ftState, needsPin: !!info.needs_pin }; renderFunctionTest(); }
  } catch { /* busy during attestation – button still works */ }
}

async function runFunctionTest(pin) {
  const token = tokens.get(selectedId);
  if (!token || ftState?.running) return;
  const run = ftRun = {};
  ftState = { ...ftState, running: true, result: null };
  renderFunctionTest();
  try {
    const result = await call('function_test', { token_id: token.id, pin: pin || null });
    if (ftRun !== run || selectedId !== token.id) return;
    ftState = { ...ftState, running: false, result, needsPin: ftState.needsPin || result.code === 'pin_required' };
  } catch (e) {
    if (ftRun !== run || selectedId !== token.id) return;
    ftState = { ...ftState, running: false, result: { ok: false, error: e.message, code: e.data?.code, steps: [] } };
  }
  if (selectedId === token.id) renderFunctionTest();
}
