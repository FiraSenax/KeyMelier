// KeyMelier – introduction on first start
//
// Four short steps: what KeyMelier does, what it stores (with the choice to
// store nothing), what the platform warnings mean (admin rights on Windows,
// unsigned / not notarized builds – from the real build state), and how to
// start. Skippable (Escape), reopenable from About. Nothing is changed on
// any key; the storage choice only changes the app settings.
//
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js only inside functions.

let onboarding = null;   // { step, store: 'all' | 'nothing' } while open

const ONBOARDING_STEPS = 4;

function maybeStartOnboarding() {
  if (!appSettings.onboarding_done && !appSettings.stateless) openOnboarding();
}

function openOnboarding() {
  onboarding = { step: 1, store: appSettings.history_enabled === false ? 'nothing' : 'all', opener: document.activeElement };
  renderOnboarding();
}

async function closeOnboarding() {
  const opener = onboarding?.opener;
  onboarding = null;
  renderOnboarding();
  appSettings = await call('set_settings', { values: { onboarding_done: true } }).catch(() => appSettings);
  if (opener?.isConnected) opener.focus();
}

// "Store nothing": no history and no remembered contents (settings stay so the
// choice is kept; the --stateless start option leaves no trace at all)
async function applyStorageChoice(store) {
  const off = store === 'nothing';
  appSettings = await call('set_settings', { values: { history_enabled: !off, remember_sites: !off } }).catch(() => appSettings);
  if (off) await loadHistory();
  render();
}

function onboardingPlatformHtml() {
  const b = appSettings.build || {};
  const parts = [];
  if (appSettings.platform === 'win32') {
    parts.push(`<h3>${escHtml(t('ob.admin.title'))}</h3><p>${escHtml(t('ob.admin.text'))}</p>`);
    parts.push(b.signed ? `<p>${escHtml(t('ob.win.signed'))}</p>`
      : `<h3>${escHtml(t('ob.win.unsigned.title'))}</h3><p>${escHtml(t('ob.win.unsigned.text'))}</p>`);
  } else if (appSettings.platform === 'darwin') {
    parts.push(b.notarized ? `<p>${escHtml(t('ob.mac.notarized'))}</p>`
      : `<h3>${escHtml(t('ob.mac.unsigned.title'))}</h3><p>${escHtml(t('ob.mac.unsigned.text'))}</p>`);
  } else {
    parts.push(`<p>${escHtml(t('ob.other.text'))}</p>`);
  }
  if (!(b.signed || b.notarized)) {
    parts.push(`<p class="field-hint">${escHtml(t('ob.verify'))}
      <button type="button" class="btn-link" data-url="https://github.com/FiraSenax/KeyMelier/releases/latest">${escHtml(t('ob.releases'))}</button></p>`);
  }
  return parts.join('');
}

function renderOnboarding() {
  const el = $('onboarding');
  el.classList.toggle('hidden', !onboarding);
  if (!onboarding) { el.innerHTML = ''; return; }
  const s = onboarding.step;
  const body = {
    1: `<h2 id="ob-title">${escHtml(t('ob.welcome.title'))}</h2>
        <ul class="ob-list"><li>${escHtml(t('ob.welcome.check'))}</li><li>${escHtml(t('ob.welcome.manage'))}</li>
        <li>${escHtml(t('ob.welcome.accounts'))}</li></ul>
        <p class="field-hint">${escHtml(t('ob.welcome.local'))}</p>`,
    2: `<h2 id="ob-title">${escHtml(t('ob.store.title'))}</h2>
        <fieldset class="ob-choice"><legend class="sr-only">${escHtml(t('ob.store.title'))}</legend>
          <label class="ob-option"><input type="radio" name="ob-store" value="all" ${onboarding.store === 'all' ? 'checked' : ''}>
            <span><b>${escHtml(t('ob.store.all'))}</b><span class="field-hint">${escHtml(t('ob.store.allText'))}</span></span></label>
          <label class="ob-option"><input type="radio" name="ob-store" value="nothing" ${onboarding.store === 'nothing' ? 'checked' : ''}>
            <span><b>${escHtml(t('ob.store.nothing'))}</b><span class="field-hint">${escHtml(t('ob.store.nothingText'))}</span></span></label>
        </fieldset>
        <p class="field-hint">${escHtml(t('ob.store.stateless')).replace('--stateless', '<code class="nowrap">--stateless</code>')}</p>`,
    3: `<h2 id="ob-title">${escHtml(t('ob.platform.title'))}</h2>${onboardingPlatformHtml()}`,
    4: `<h2 id="ob-title">${escHtml(t('ob.start.title'))}</h2>
        <ol class="ob-list"><li>${escHtml(t('ob.start.plug'))}</li><li>${escHtml(t('ob.start.read'))}</li>
        <li>${escHtml(t('ob.start.backup'))}</li></ol>
        <p class="field-hint">${escHtml(t('ob.start.again'))}</p>`,
  }[s];
  el.innerHTML = `<div class="ql-dialog card ob-dialog">
    <p class="ob-progress" aria-live="polite">${escHtml(t('ob.progress', { n: s, total: ONBOARDING_STEPS }))}</p>
    <div class="ob-body">${body}</div>
    <div class="form-actions ob-actions">
      <button type="button" class="btn-link" data-ob="skip">${escHtml(t('ob.skip'))}</button>
      ${s > 1 ? `<button type="button" class="btn btn-secondary" data-ob="back">${escHtml(t('rp.prev'))}</button>` : ''}
      <button type="button" class="btn btn-primary" data-ob="${s < ONBOARDING_STEPS ? 'next' : 'done'}">${escHtml(t(s < ONBOARDING_STEPS ? 'rp.next' : 'ob.done'))}</button>
    </div>
  </div>`;
  el.querySelector('[data-ob="next"], [data-ob="done"]').focus();
}

async function onboardingAction(act) {
  if (!onboarding) return;
  if (act === 'skip' || act === 'done') return closeOnboarding();
  if (act === 'back') onboarding.step = Math.max(1, onboarding.step - 1);
  if (act === 'next') {
    if (onboarding.step === 2) await applyStorageChoice(onboarding.store);
    onboarding.step = Math.min(ONBOARDING_STEPS, onboarding.step + 1);
  }
  renderOnboarding();
}

function initOnboarding() {
  const el = $('onboarding');
  trapFocus(el);
  el.addEventListener('click', ev => {
    const link = ev.target.closest('[data-url]');
    if (link) return window.pywebview?.api?.open_url(link.dataset.url);
    const b = ev.target.closest('[data-ob]');
    if (b) onboardingAction(b.dataset.ob);
  });
  el.addEventListener('change', ev => {
    if (ev.target.name === 'ob-store' && onboarding) onboarding.store = ev.target.value;
  });
  el.addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { ev.preventDefault(); onboardingAction('skip'); }
  });
}
