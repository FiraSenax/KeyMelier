// KeyMelier – menus and dialogs
//
// Keyboard handling for the tab bar's Advanced menu and the actions menu
// (arrows, Home/End, Escape with focus return) and the About dialog.
// Classic script loaded before app.js (see keymelier_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js ($, t, escHtml, call,
// icon, render …) only inside functions, never while loading.

// Modal dialogs: Tab and Shift+Tab stay inside the dialog
function trapFocus(dialog) {
  dialog.addEventListener('keydown', ev => {
    if (ev.key !== 'Tab') return;
    const f = [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]')];
    if (!f.length) return;
    const i = f.indexOf(document.activeElement);
    if (ev.shiftKey && i <= 0) { ev.preventDefault(); f[f.length - 1].focus(); }
    else if (!ev.shiftKey && i === f.length - 1) { ev.preventDefault(); f[0].focus(); }
  });
}

// "Advanced" menu of the tab bar: shown when it has an item for this key;
// names the active area when one of its items is open
function syncTabMore() {
  const items = [...document.querySelectorAll('#tab-more-menu .tab')];
  $('tab-more').classList.toggle('hidden', !items.some(b => !b.classList.contains('hidden')));
  const active = items.find(b => b.dataset.tab === activeTab);
  $('tab-more-btn').classList.toggle('active', !!active);
  $('tab-more-current').textContent = active ? ` · ${t(`tab.${activeTab}`)}` : '';
}

function setTabMenu(open, focusFirst = false) {
  const menu = $('tab-more-menu');
  menu.classList.toggle('hidden', !open);
  $('tab-more-btn').setAttribute('aria-expanded', String(open));
  if (open) {
    // fixed to the window, under its button (the tab bar scrolls sideways and would clip it)
    const btn = $('tab-more-btn').getBoundingClientRect();
    const width = menu.offsetWidth;
    menu.style.top = `${Math.round(btn.bottom + 6)}px`;
    menu.style.left = `${Math.round(Math.max(8, Math.min(btn.left, innerWidth - width - 8)))}px`;
    const items = [...menu.querySelectorAll('.tab:not(.hidden)')];
    (focusFirst ? items[0] : items.find(b => b.dataset.tab === activeTab) || items[0])?.focus();
  }
}

function tabMenuKey(ev) {
  const items = [...$('tab-more-menu').querySelectorAll('.tab:not(.hidden)')];
  const i = items.indexOf(document.activeElement);
  const go = n => { ev.preventDefault(); items[(n + items.length) % items.length]?.focus(); };
  if (ev.key === 'ArrowDown') go(i + 1);
  else if (ev.key === 'ArrowUp') go(i - 1);
  else if (ev.key === 'Home') go(0);
  else if (ev.key === 'End') go(items.length - 1);
  else if (ev.key === 'Escape') { ev.preventDefault(); setTabMenu(false); $('tab-more-btn').focus(); }
  else if (ev.key === 'Tab') setTabMenu(false);
}

// A button that opens a menu: arrows, Home/End move, Esc closes and returns focus
function closeMenu(menuId) {
  const menu = $(menuId);
  if (!menu || menu.classList.contains('hidden')) return;
  menu.classList.add('hidden');
  document.querySelector(`[aria-controls="${menuId}"]`)?.setAttribute('aria-expanded', 'false');
}

function setupMenu(btnId, menuId) {
  const btn = $(btnId), menu = $(menuId);
  const items = () => [...menu.querySelectorAll('[role="menuitem"]:not(.hidden):not(:disabled)')];
  const open = first => {
    menu.classList.remove('hidden');
    btn.setAttribute('aria-expanded', 'true');
    (first ? items()[0] : items()[0])?.focus();
  };
  btn.addEventListener('click', () => (menu.classList.contains('hidden') ? open(true) : closeMenu(menuId)));
  btn.addEventListener('keydown', ev => { if (ev.key === 'ArrowDown') { ev.preventDefault(); open(true); } });
  menu.addEventListener('keydown', ev => {
    const list = items();
    const i = list.indexOf(document.activeElement);
    const go = n => { ev.preventDefault(); list[(n + list.length) % list.length]?.focus(); };
    if (ev.key === 'ArrowDown') go(i + 1);
    else if (ev.key === 'ArrowUp') go(i - 1);
    else if (ev.key === 'Home') go(0);
    else if (ev.key === 'End') go(list.length - 1);
    else if (ev.key === 'Escape') { ev.preventDefault(); closeMenu(menuId); btn.focus(); }
    else if (ev.key === 'Tab') closeMenu(menuId);
  });
  document.addEventListener('click', ev => { if (!ev.target.closest(`#${btnId}`) && !ev.target.closest(`#${menuId}`)) closeMenu(menuId); });
}

// "About KeyMelier" inside the app (Windows has no app menu; also from the sidebar on macOS)
const ABOUT_LINKS = [['about.site', 'https://firasenax.github.io/KeyMelier/'],
  ['about.source', 'https://github.com/FiraSenax/KeyMelier'],
  ['about.issues', 'https://github.com/FiraSenax/KeyMelier/issues']];

// "Build 4216033" – the source commit the app was built from (data/build.json);
// "modified" when the tree had uncommitted changes, "unknown" without one
function buildLabel(build) {
  const commit = typeof build?.commit === 'string' && /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(build.commit) ? build.commit : null;
  if (!commit) return t('about.buildUnknown');
  return t(build.modified === false ? 'about.build' : 'about.buildModified', { commit: commit.slice(0, 7) });
}

function openAbout(open = true) {
  diagText = null;
  licenseDocuments = null;
  licenseRequest++;
  const el = $('about-dialog');
  el.removeAttribute('aria-busy');
  el.classList.toggle('hidden', !open);
  if (!open) { el.innerHTML = ''; $('about-open').focus(); return; }
  const v = dataStatus?.app?.current;
  el.innerHTML = `<div class="ql-dialog card about-dialog">
    <img src="${escHtml(document.querySelector('.brand img')?.src || '')}" width="64" height="64" alt="">
    <h2 id="about-title">KeyMelier</h2>
    ${v ? `<p class="muted">${escHtml(t('upd.version', { v }))}</p>` : ''}
    <p class="muted about-build" id="about-build">${escHtml(buildLabel(appSettings.build))}</p>
    <p class="about-lead">${escHtml(t('app.tagline'))}</p>
    <p class="card-text">${escHtml(t('about.what'))}</p>
    <p class="field-hint">${escHtml(t('about.privacy'))}</p>
    <p class="field-hint">${escHtml(t('mds.termsNotice'))}
      <button type="button" class="btn-link" data-url="https://fidoalliance.org/metadata-usage-terms-for-relying-parties-or-service-providers-2/">${escHtml(t('mds.terms'))}</button></p>
    <p class="about-links">${ABOUT_LINKS.map(([k, url]) => `<button type="button" class="btn-link" data-url="${escHtml(url)}">${escHtml(t(k))}</button>`).join(' · ')}</p>
    <div class="form-actions about-actions">
      <button type="button" class="btn btn-secondary" data-about="licenses">${escHtml(t('about.licenses'))}</button>
      <button type="button" class="btn btn-secondary" data-about="updates">${escHtml(t('upd.check'))}</button>
      <button type="button" class="btn btn-secondary" data-about="intro">${escHtml(t('ob.open'))}</button>
      <button type="button" class="btn btn-secondary" data-about="diag">${escHtml(t('diag.open'))}</button>
      <button type="button" class="btn btn-primary" data-about="close">${escHtml(t('about.close'))}</button>
    </div>
    <p class="field-hint">© 2026 Sven Frank · MIT License</p>
  </div>`;
  el.querySelector('[data-about="close"]').focus();
}

window.__kmAbout = () => openAbout();

// Original texts stay plain text, including any HTML-looking upstream notice.
// The backend supplies fixed local files; the reader never fetches a URL.
let licenseDocuments = null;
let licenseRequest = 0;
let licenseMatch = -1;

async function openLicenses() {
  const el = $('about-dialog');
  openAbout();
  const request = ++licenseRequest;
  el.setAttribute('aria-busy', 'true');
  let result;
  try { result = await window.pywebview.api.get_licenses(); }
  catch { result = null; }
  if (request !== licenseRequest) return;
  el.removeAttribute('aria-busy');
  if (!result?.documents?.length) { showToast(t('licenses.error'), 'error'); return; }
  licenseDocuments = result.documents;
  el.innerHTML = `<div class="ql-dialog card licenses-dialog">
    <h2 id="about-title">${escHtml(t('about.licenses'))}</h2>
    <p class="field-hint">${escHtml(t(result.bundled ? 'licenses.scope' : 'licenses.source'))}</p>
    <label for="license-document" class="sr-only">${escHtml(t('licenses.document'))}</label>
    <select id="license-document">${licenseDocuments.map((doc, i) => `<option value="${i}">${escHtml(t('licenses.' + doc.id))}</option>`).join('')}</select>
    <div class="license-search">
      <label for="license-search" class="sr-only">${escHtml(t('licenses.search'))}</label>
      <input id="license-search" type="search" placeholder="${escHtml(t('licenses.search'))}">
      <button type="button" class="btn btn-secondary" data-about="license-find">${escHtml(t('licenses.next'))}</button>
    </div>
    <p id="license-result" class="field-hint" role="status" aria-live="polite"></p>
    <textarea id="license-text" class="license-text" readonly wrap="off" spellcheck="false" aria-label="${escHtml(t('about.licenses'))}"></textarea>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" data-about="license-back">${escHtml(t('licenses.back'))}</button>
      <button type="button" class="btn btn-secondary" data-about="license-save">${escHtml(t('licenses.save'))}</button>
      <button type="button" class="btn btn-primary" data-about="close">${escHtml(t('about.close'))}</button>
    </div>
  </div>`;
  $('license-document').addEventListener('change', showLicenseDocument);
  $('license-search').addEventListener('input', () => { licenseMatch = -1; $('license-result').textContent = ''; });
  $('license-search').addEventListener('keydown', ev => {
    if (ev.key === 'Enter') { ev.preventDefault(); findLicenseText(); }
  });
  showLicenseDocument();
  $('license-search').focus();
}

function showLicenseDocument() {
  const doc = licenseDocuments?.[Number($('license-document')?.value)];
  if (!doc) return;
  $('license-text').value = doc.text;
  $('license-text').scrollTop = 0;
  licenseMatch = -1;
  $('license-result').textContent = '';
}

function findLicenseText() {
  const query = $('license-search').value;
  const area = $('license-text');
  if (!query) { $('license-search').focus(); return; }
  // RegExp provides offsets into the original text, including case mappings
  // whose lower-case form has a different length (e.g. capital dotted I).
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = [...area.value.matchAll(new RegExp(escaped, 'gi'))];
  licenseMatch = matches.length ? (licenseMatch + 1) % matches.length : -1;
  $('license-result').textContent = matches.length
    ? t('licenses.matches', { n: licenseMatch + 1, total: matches.length }) : t('licenses.none');
  if (licenseMatch < 0) return;
  const match = matches[licenseMatch];
  area.focus();
  area.setSelectionRange(match.index, match.index + match[0].length);
  const line = area.value.slice(0, match.index).split('\n').length - 1;
  area.scrollTop = Math.max(0, line * parseFloat(getComputedStyle(area).lineHeight) - area.clientHeight / 3);
}

async function saveLicenseDocument() {
  const doc = licenseDocuments?.[Number($('license-document')?.value)];
  if (!doc) return;
  try { await window.pywebview.api.save_license(doc.id); }
  catch { showToast(t('licenses.error'), 'error'); }
}

// Diagnostic report: built by the backend from a fixed list of fields (no
// names, serials, paths, URLs or messages – keymelier_core/diagnostics.py).
// The user reads exactly the text that would be saved; nothing is saved
// without clicking Save, nothing is sent anywhere.
let diagText = null;

async function openDiagnostics() {
  const el = $('about-dialog');
  let report;
  try {
    report = await call('diagnostics');
  } catch (e) {
    showToast(errorMessage(e), 'error');
    return;
  }
  if (el.classList.contains('hidden')) return;   // About was closed while the report was built
  diagText = JSON.stringify(report, null, 2) + '\n';
  el.innerHTML = `<div class="ql-dialog card diag-dialog">
    <h2 id="about-title">${escHtml(t('diag.title'))}</h2>
    <p class="card-text">${escHtml(t('diag.text'))}</p>
    <pre class="diag-preview" id="diag-preview" tabindex="0" aria-label="${escHtml(t('diag.title'))}">${escHtml(diagText)}</pre>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" data-about="diag-cancel">${escHtml(t('diag.cancel'))}</button>
      <button type="button" class="btn btn-primary" data-about="diag-save">${escHtml(t('diag.save'))}</button>
    </div>
  </div>`;
  el.querySelector('[data-about="diag-save"]').focus();
}

async function saveDiagnostics() {
  const text = diagText;
  if (!text) return;
  const date = new Date().toISOString().slice(0, 10);
  let path;
  try {
    path = await window.pywebview?.api?.save_text(`keymelier-diagnostics-${date}.json`, text, true);
  } catch (e) {
    showToast(errorMessage(e), 'error');   // e.g. a read-only folder; the preview stays
    return;
  }
  if (!path) return;   // cancelled in the file dialog: nothing written, preview stays
  showToast(t('diag.saved'), 'info');
  openAbout(false);
}
