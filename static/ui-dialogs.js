// KeyMelier – menus and dialogs
//
// Keyboard handling for the tab bar's Advanced menu and the actions menu
// (arrows, Home/End, Escape with focus return) and the About dialog.
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js ($, t, escHtml, call,
// icon, render …) only inside functions, never while loading.

// Modal dialogs: Tab and Shift+Tab stay inside the dialog
function trapFocus(dialog) {
  dialog.addEventListener('keydown', ev => {
    if (ev.key !== 'Tab') return;
    const f = [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]')];
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

function openAbout(open = true) {
  const el = $('about-dialog');
  el.classList.toggle('hidden', !open);
  if (!open) { el.innerHTML = ''; $('about-open').focus(); return; }
  const v = dataStatus?.app?.current;
  el.innerHTML = `<div class="ql-dialog card about-dialog">
    <img src="${escHtml(document.querySelector('.brand img')?.src || '')}" width="64" height="64" alt="">
    <h2 id="about-title">KeyMelier</h2>
    ${v ? `<p class="muted">${escHtml(t('upd.version', { v }))}</p>` : ''}
    <p class="about-lead">${escHtml(t('app.tagline'))}</p>
    <p class="card-text">${escHtml(t('about.what'))}</p>
    <p class="field-hint">${escHtml(t('about.privacy'))}</p>
    <p class="about-links">${ABOUT_LINKS.map(([k, url]) => `<button type="button" class="btn-link" data-url="${escHtml(url)}">${escHtml(t(k))}</button>`).join(' · ')}</p>
    <div class="form-actions about-actions">
      <button type="button" class="btn btn-secondary" data-about="licenses">${escHtml(t('about.licenses'))}</button>
      <button type="button" class="btn btn-secondary" data-about="updates">${escHtml(t('upd.check'))}</button>
      <button type="button" class="btn btn-secondary" data-about="intro">${escHtml(t('ob.open'))}</button>
      <button type="button" class="btn btn-primary" data-about="close">${escHtml(t('about.close'))}</button>
    </div>
    <p class="field-hint">© 2026 Sven Frank · MIT License</p>
  </div>`;
  el.querySelector('[data-about="close"]').focus();
}
