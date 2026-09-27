// UI tests on the demo page (the real app page with the demo bridge – no
// Python backend, no real keys) in headless Chrome, driven through the
// DevTools protocol with real keyboard and mouse input.
//
//   node tests/ui/ui_test.cjs            (CHROME=/path/to/chrome to choose a browser)
//
// Fails (exit 1) on any failed check, uncaught page error, console error or
// timeout; then writes a screenshot and the browser log to
// build/ui-test-artifacts/ (UI_ARTIFACTS to change).

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { launch, sleep, killAll } = require('./cdp.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const ARTIFACTS = process.env.UI_ARTIFACTS || path.join(ROOT, 'build', 'ui-test-artifacts');
const TIMEOUT_MS = Number(process.env.UI_TIMEOUT_MS || 180000);
const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

const KEYS = {
  Enter: { code: 'Enter', keyCode: 13, text: '\r' },
  ' ': { code: 'Space', keyCode: 32, text: ' ' },
  Tab: { code: 'Tab', keyCode: 9 },
  Escape: { code: 'Escape', keyCode: 27 },
  ArrowDown: { code: 'ArrowDown', keyCode: 40 },
  ArrowUp: { code: 'ArrowUp', keyCode: 38 },
  Home: { code: 'Home', keyCode: 36 },
  End: { code: 'End', keyCode: 35 },
  Backspace: { code: 'Backspace', keyCode: 8 },
};

async function main() {
  const page = execFileSync(PYTHON, [path.join(ROOT, 'tools', 'demo_page.py')], { encoding: 'utf8' }).trim();
  const browser = await launch({ width: 1280, height: 800 });
  const { send, on } = browser;
  const log = [];
  const pageErrors = [];
  on('Runtime.consoleAPICalled', p => {
    const text = p.args.map(a => a.value ?? a.description ?? '').join(' ');
    log.push(`[console.${p.type}] ${text}`);
    if (p.type === 'error' || p.type === 'assert') pageErrors.push(text);
  });
  on('Runtime.exceptionThrown', p => {
    const text = p.exceptionDetails.exception?.description || p.exceptionDetails.text;
    log.push(`[exception] ${text}`);
    pageErrors.push(text);
  });
  on('Log.entryAdded', p => log.push(`[${p.entry.level}] ${p.entry.text}`));
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: `${pathToFileURL(page).href}#none` });

  // ── helpers ──
  const js = async expression => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  };
  const until = async (expression, what, ms = 5000) => {
    for (let t = 0; t < ms; t += 50) { if (await js(expression)) return; await sleep(50); }
    throw new Error(`timed out waiting for ${what}`);
  };
  const press = async (key, { shift = false } = {}) => {
    const k = KEYS[key];
    const base = { key, code: k.code, windowsVirtualKeyCode: k.keyCode, nativeVirtualKeyCode: k.keyCode, modifiers: shift ? 8 : 0 };
    await send('Input.dispatchKeyEvent', { type: k.text ? 'keyDown' : 'rawKeyDown', ...base, ...(k.text ? { text: k.text, unmodifiedText: k.text } : {}) });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
    await sleep(40);
  };
  const type = async text => { await send('Input.insertText', { text }); await sleep(60); };
  const click = async selector => {
    const r = await js(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null;
      el.scrollIntoView({ block: 'center' }); const b = el.getBoundingClientRect(); return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; })()`);
    if (!r) throw new Error(`nothing to click: ${selector}`);
    for (const t of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type: t, x: r.x, y: r.y, button: 'left', clickCount: 1 });
    await sleep(60);
  };
  const focus = selector => js(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el?.focus(); return !!el; })()`);
  const active = () => js(`(() => { const a = document.activeElement; return a ? (a.id || a.dataset.accFilter !== undefined && 'filter:' + a.dataset.accFilter || a.dataset.act || a.dataset.tab || a.dataset.rpStep && 'step:' + a.dataset.rpStep || a.dataset.next && 'next' || a.dataset.unlock && 'unlock:' + a.dataset.unlock || a.dataset.about || a.dataset.ql || a.className || a.tagName) : null; })()`);
  const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

  const results = [];
  const test = async (name, fn) => {
    try { await fn(); results.push({ name, ok: true }); } catch (e) { results.push({ name, ok: false, error: e.message }); }
  };

  await until('typeof tokens !== "undefined" && tokens.size > 0 && historyKeys.size > 0', 'the app to load its demo data', 15000);
  await js('selectToken("demo-yk5")');   // a defined start: first key selected (no demo scene runs with #none)

  // ── 1. Navigation ──
  await test('backup page: coverage, lost key and replacement visible at 1280x800 without scrolling', async () => {
    await click('#nav-backup');
    await until('mainView === "backup" && document.querySelectorAll("#backup-content .bk-card").length === 3', 'backup page');
    const bottoms = await js('[...document.querySelectorAll("#backup-content .bk-card")].map(c => c.getBoundingClientRect().bottom)');
    assert(bottoms.every(b => b <= 800), `cards end at ${bottoms.map(Math.round)}`);
    assert(await js('!!document.querySelector("#backup-content .sync-line [data-act=open-settings]")'), 'sync status line with settings link');
  });
  await test('keyboard: Tab moves through the sidebar, Enter opens a view', async () => {
    await focus('#nav-backup');
    await press('Tab');
    assert(await active() === 'nav-accounts', `focus after Tab: ${await active()}`);
    await press('Tab');
    assert(await active() === 'nav-keys', `focus after 2×Tab: ${await active()}`);
    await press('Tab');
    assert(await active() === 'nav-settings', `focus after 3×Tab: ${await active()}`);
    await press('Enter');
    await until('mainView === "settings"', 'settings view');
    assert(await js('!!$("history-enabled") && !!$("personal-mode") && !!$("bk-remember") && !!$("sync-card")'), 'app settings present');
    await press('Tab', { shift: true });
    assert(await active() === 'nav-keys', `Shift+Tab goes back: ${await active()}`);
  });

  // ── 2. Account filters and search ──
  await test('filters: cards are buttons; Enter filters, Space clears, focus stays', async () => {
    await click('#nav-accounts');
    await until('mainView === "accounts"', 'accounts view');
    const total = await js('document.querySelectorAll("#accounts-content .acc-sub-row").length');
    await focus('#accounts-content [data-acc-filter=""]');
    await press('Tab'); await press('Tab');
    assert(await active() === 'filter:warn', `Tab order of the cards: ${await active()}`);
    await press('Enter');
    await until('accLevel === "warn"', 'warn filter');
    const rows = await js('[...document.querySelectorAll("#accounts-content .acc-sub-row")].map(r => r.className)');
    assert(rows.length > 0 && rows.length < total && rows.every(c => c.includes('acc-warn')), `rows: ${rows}`);
    assert(await js('document.querySelector("[data-acc-filter=warn]").getAttribute("aria-pressed")') === 'true', 'aria-pressed');
    assert(await active() === 'filter:warn', 'focus kept on the card');
    assert(await js('document.querySelector("[data-acc-filter=\\"\\"] b").textContent') === String(total), 'totals unchanged');
    await press(' ');
    await until('accLevel === ""', 'filter cleared by Space');
  });
  await test('search: typing filters together with a category, focus stays; reset; empty state', async () => {
    await click('[data-acc-filter=warn]');
    await click('#acc-search');
    await type('contoso');
    assert(await active() === 'acc-search', `focus while typing: ${await active()}`);
    const txt = await js('document.querySelector(".acc-filter-state").textContent');
    assert(/contoso/.test(txt), `filter state shows the search: ${txt}`);
    const rows = await js('document.querySelectorAll("#accounts-content .acc-sub-row").length');
    assert(rows >= 1, 'matches');
    await type('-nothing-matches');
    await until('!!document.querySelector("#accounts-content .acc-empty [data-acc-reset]")', 'empty state');
    await focus('#accounts-content .acc-empty [data-acc-reset]');
    await press('Enter');
    await until('accLevel === "" && accFilter === ""', 'reset');
    assert(await active() === 'acc-search', 'focus returns to the search');
  });
  await test('risk at a glance: every row has a symbol with text, gaps only on keys in use in risky rows', async () => {
    const rows = await js(`[...document.querySelectorAll('#accounts-content .acc-sub-row')].map(r => ({
      level: [...r.classList].find(c => c.startsWith('acc-') && c !== 'acc-sub-row'),
      badge: r.querySelector('.acc-level .sr-only')?.textContent || '',
      gaps: r.querySelectorAll('td.gap').length }))`);
    assert(rows.length > 0 && rows.every(r => r.badge.length > 0), 'each row names its risk in text');
    assert(rows.filter(r => r.gaps).every(r => r.level === 'acc-crit' || r.level === 'acc-warn'), 'gaps only in risky rows');
    assert(rows.some(r => r.gaps), 'the demo has at least one backup gap');
    const lostGap = await js(`(() => { const lostCol = [...document.querySelectorAll('.acc-table thead th')].findIndex(th => th.classList.contains('lost'));
      return [...document.querySelectorAll('#accounts-content .acc-sub-row')].some(r => r.children[lostCol]?.classList.contains('gap')); })()`);
    assert(!lostGap, 'a lost key is never marked as a place for a backup');
  });
  await test('next step: Enter expands the explanation (aria-expanded), focus stays', async () => {
    await focus('#accounts-content [data-next]');
    await press('Enter');
    await until('document.querySelector("#accounts-content [data-next][aria-expanded=true]") && document.querySelector(".acc-next-row")', 'expanded');
    assert(await active() === 'next', `focus: ${await active()}`);
    assert(await js('getComputedStyle(document.querySelector(".acc-table thead th")).position') === 'sticky', 'sticky header');
    assert(await js('getComputedStyle(document.querySelector(".acc-table th.acc-name")).position') === 'sticky', 'sticky column');
  });

  // ── 3. Menus and dialogs ──
  await test('Advanced menu: arrows, End, Escape returns focus, Enter opens an item', async () => {
    await js('selectToken("demo-yk5"); switchTab("overview")');
    await focus('#tab-more-btn');
    await press('ArrowDown');
    assert(await js('!$("tab-more-menu").classList.contains("hidden")'), 'menu open');
    const first = await active();
    await press('ArrowDown');
    assert(await active() !== first, 'ArrowDown moves');
    await press('End');
    assert(await active() === 'details', `End: ${await active()}`);
    await press('Escape');
    assert(await js('$("tab-more-menu").classList.contains("hidden")') && await active() === 'tab-more-btn', 'Escape closes, focus back');
    await press('ArrowDown'); await press('End');
    await press('Enter');
    await until('activeTab === "details" && $("tab-more-menu").classList.contains("hidden")', 'details tab via keyboard');
  });
  await test('actions menu (⋯): opens by keyboard, Escape returns focus', async () => {
    await js('switchTab("overview")');
    await focus('#key-actions-btn');
    await press('ArrowDown');
    assert(await active() === 'export-btn', `focus: ${await active()}`);
    await press('Escape');
    assert(await js('$("key-actions-menu").classList.contains("hidden")') && await active() === 'key-actions-btn', 'closed, focus back');
  });
  await test('unlock dialog: keyboard opens it, focus stays inside, Escape cancels without an unlock, retry works', async () => {
    await js('window.__demoCalls.length = 0');
    await focus('[data-unlock="demo-yk5"]');
    await press('Enter');
    await until('!$("quick-unlock").classList.contains("hidden")', 'dialog opened by keyboard');
    assert(await js('$("quick-unlock").contains(document.activeElement)'), 'focus inside');
    for (let i = 0; i < 6; i++) await press('Tab');
    assert(await js('$("quick-unlock").contains(document.activeElement)'), 'Tab stays inside the dialog');
    await press('Escape');
    await until('$("quick-unlock").classList.contains("hidden")', 'closed');
    assert(await active() === 'unlock:demo-yk5', `focus returned to the lock: ${await active()}`);
    const DEVICE = '["unlock","read_contents","passkeys","passkeys_probe","oath","openpgp","piv","otp","pin_status"]';
    assert(await js(`!window.__demoCalls.some(c => ${DEVICE}.includes(c))`), `no device call after a cancel: ${await js('window.__demoCalls')}`);
    await press('Enter');                                  // open again, this time cancel with the button
    await until('!!document.querySelector("#quick-unlock [data-ql=cancel]")', 'dialog with cancel button');
    await click('#quick-unlock [data-ql=cancel]');
    await until('$("quick-unlock").classList.contains("hidden")', 'closed by the button');
    assert(await js(`!window.__demoCalls.some(c => ${DEVICE}.includes(c))`), 'no device call after the cancel button');
    await focus('[data-unlock="demo-yk5"]');
    await press('Enter');                                  // try again
    await until('!!document.querySelector("#quick-unlock .ql-pin")', 'dialog again');
    await focus('#quick-unlock .ql-pin');
    await type('123456');
    await press('Enter');
    await until('$("quick-unlock").classList.contains("hidden")', 'unlocked and closed');
    const calls = await js('window.__demoCalls.filter(c => c === "unlock" || c === "read_contents")');
    assert(JSON.stringify(calls) === '["unlock","read_contents"]', `exactly one unlock, then reading: ${calls}`);
  });
  await test('reading: a key pulled out mid-read shows an error with the next step, never success', async () => {
    await js(`(() => { const real = window.pywebview.api.call;
      window.__realCall = real;
      window.pywebview.api.call = async (m, a) => m === 'read_contents'
        ? { ok: true, data: { sites: null, oath: null, openpgp: null, piv: null, failed: ['passkeys'], removed: true } }
        : real(m, a); })()`);
    await js('document.querySelectorAll("#toast-container .toast").forEach(t => t.remove())');
    await js('selectToken("demo-yk5"); switchTab("overview")');
    await click('#read-btn');                               // the key is still unlocked from the test above
    await until('document.querySelector("#toast-container .toast")', 'a message');
    const toast = await js('[...document.querySelectorAll("#toast-container .toast")].map(t => t.className + " | " + t.textContent)');
    assert(toast.length === 1 && toast[0].includes('error') && /removed|abgezogen/.test(toast[0]), `message: ${toast}`);
    assert(await js('!$("read-btn").disabled'), 'button usable again');
    await js('window.pywebview.api.call = window.__realCall');
  });
  await test('passkey search on a FIDO 2.0 key: cancelling the PIN/search dialog calls nothing on the key', async () => {
    // simulate a FIDO 2.0 key (no credential management) with the second demo key
    await js(`(() => { const t = tokens.get("demo-t2"); t.options = { rk: true, up: true, clientPin: true };
      window.__demoCalls.length = 0; selectToken("demo-t2"); switchTab("overview"); })()`);
    assert(await js('!canManage(tokens.get("demo-t2"))'), 'simulated key without credential management');
    await click('#read-btn');
    await until('!$("quick-unlock").classList.contains("hidden")', 'search dialog');
    await press('Escape');
    await until('$("quick-unlock").classList.contains("hidden")', 'closed');
    assert(await js('!window.__demoCalls.includes("passkeys_probe")'), `no search started: ${await js('window.__demoCalls')}`);
  });
  await test('About dialog: Enter opens, Tab stays inside, Escape returns focus', async () => {
    await focus('#about-open');
    await press('Enter');
    await until('!$("about-dialog").classList.contains("hidden")', 'about open');
    assert(await active() === 'close', `initial focus: ${await active()}`);
    for (let i = 0; i < 8; i++) await press('Tab');
    assert(await js('$("about-dialog").contains(document.activeElement)'), 'focus trapped');
    await press('Escape');
    await until('$("about-dialog").classList.contains("hidden")', 'closed');
    assert(await active() === 'about-open', `focus back: ${await active()}`);
  });

  // ── 4. Guided key replacement ──
  await test('replacement: steps by keyboard, open-only by Space, tick vs. technical check, cancel asks first', async () => {
    // set up through the bridge, as the real app would: replacement a1 -> b2 with two ticks
    await js(`(async () => {
      const kid = 'a1a1a1a1a1a1a1a1';
      let sum = await call('history_replace', { kid, new_kid: 'b2b2b2b2b2b2b2b2' });
      for (const item of ['pk:bitwarden.com|erika@example.com', 'pk:github.com|erika'])
        sum = await call('history_replace_done', { kid, item, done: true });
      historyKeys.set(kid, sum);
      showReplaceView(kid); })()`);
    assert(await js('replaceStep') === 2, 'opens at step 2');
    await focus('[data-rp-step="3"]');
    await press('Enter');
    await until('replaceStep === 3 && document.querySelectorAll("#replace-content [data-rp-item]").length > 0', 'step 3');
    const unproven = await js('[...document.querySelectorAll("#replace-content li")].find(li => li.textContent.includes("bitwarden.com"))?.querySelectorAll(".rp-chip.warn").length');
    assert(unproven >= 2, 'ticked but not found stays marked (not found + not verified)');
    const all = await js('document.querySelectorAll("#replace-content li").length');
    await focus('#rp-open-only');
    await press(' ');
    await until(`document.querySelectorAll("#replace-content li").length === ${all - 1}`, 'open only hides the one complete entry');
    await js('window.__demoCalls.length = 0');
    await focus('#replace-content [data-rp-item]:not(:checked)');
    await press(' ');
    await until('window.__demoCalls.includes("history_replace_done")', 'tick saved');
    await focus('[data-rp-step="4"]');
    await press('Enter');
    await until('replaceStep === 4', 'summary');
    await js('showBackupView()');
    await focus('#backup-content [data-act="rp-cancel-ask"]');
    await press('Enter');
    assert(await active() === 'rp-cancel-no', `safe default focused: ${await active()}`);
    await press('Tab');
    assert(await active() === 'rp-cancel-yes', `next: ${await active()}`);
    await press('Enter');
    await until('!historyKeys.get("a1a1a1a1a1a1a1a1").replace', 'progress forgotten');
  });

  // ── 5. Passkeys ──
  await test('passkeys: typing into the search keeps focus and caret; Backspace restores the list', async () => {
    await js('selectToken("demo-yk5"); switchTab("passkeys")');
    await until('!!$("pk-search")', 'passkey list');
    const all = await js('document.querySelectorAll("#pk-content .pk-item").length');
    await click('#pk-search');
    await type('git');
    assert(await active() === 'pk-search' && await js('$("pk-search").selectionStart') === 3, 'focus and caret kept');
    assert(await js('document.querySelectorAll("#pk-content .pk-item").length') < all, 'filtered');
    for (let i = 0; i < 3; i++) await press('Backspace');
    assert(await js('document.querySelectorAll("#pk-content .pk-item").length') === all, 'all again');
  });

  await test('introduction: shown on first start, keyboard steps, storage choice applied, Escape skips, reopen from About', async () => {
    await js(`(() => { window.__demoCalls.length = 0; appSettings.onboarding_done = false; document.activeElement.blur(); maybeStartOnboarding(); })()`);
    await until('!$("onboarding").classList.contains("hidden")', 'introduction open');
    assert(await js('document.activeElement.dataset.ob') === 'next', 'focus on Next');
    await press('Enter');
    await until('onboarding?.step === 2', 'step 2');
    await focus('#onboarding input[value=nothing]');
    await press(' ');
    assert(await js('onboarding.store') === 'nothing', 'choice by keyboard');
    await focus('#onboarding [data-ob=next]');
    await press('Enter');
    await until('onboarding?.step === 3', 'step 3');
    assert(await js('appSettings.history_enabled === false && appSettings.remember_sites === false'), 'storage switched off');
    assert(await js('/notarized|notarisiert/i.test($("onboarding").textContent)'), 'macOS demo build: says it is not notarized');
    await press('Tab', { shift: true }); await press('Tab', { shift: true }); await press('Tab', { shift: true }); await press('Tab', { shift: true });
    assert(await js('$("onboarding").contains(document.activeElement)'), 'focus stays inside');
    await press('Escape');
    await until('$("onboarding").classList.contains("hidden") && appSettings.onboarding_done === true', 'skipped and remembered');
    assert(await js('!window.__demoCalls.some(c => ["unlock","read_contents","passkeys","pin_update"].includes(c))'), 'nothing done on a key');
    await js('call("set_settings", { values: { history_enabled: true, remember_sites: true } }).then(s => { appSettings = s; })');
    await focus('#about-open'); await press('Enter');
    await until('!$("about-dialog").classList.contains("hidden")', 'about');
    await focus('#about-dialog [data-about=intro]'); await press('Enter');
    await until('!$("onboarding").classList.contains("hidden") && onboarding.step === 1', 'introduction reopened');
    await press('Escape');
    await until('$("onboarding").classList.contains("hidden")', 'closed again');
  });
  await test('introduction on Windows explains admin rights and the unsigned build', async () => {
    await js('appSettings.platform = "win32"; appSettings.build = { signed: false }; openOnboarding(); onboarding.step = 3; renderOnboarding();');
    const text = await js('$("onboarding").textContent');
    assert(/administrator/i.test(text) && /SmartScreen/.test(text) && /SHA256SUMS/.test(text), text.slice(0, 200));
    await js('appSettings.build = { signed: true }; renderOnboarding();');
    assert(!(await js('/SmartScreen/.test($("onboarding").textContent)')), 'no unsigned warning for a signed build');
    await press('Escape');
    await js('appSettings.platform = "darwin"; appSettings.build = { signed: false, notarized: false };');
  });
  await test('Linux: introduction explains device access, pcscd and the keyring; empty screen hints at udev', async () => {
    await js('appSettings.platform = "linux"; appSettings.build = { signed: false }; openOnboarding(); onboarding.step = 3; renderOnboarding();');
    const text = await js('$("onboarding").textContent');
    assert(/udev/.test(text) && /pcscd/.test(text) && /Secret Service/.test(text) && /SHA256SUMS/.test(text), text.slice(0, 300));
    assert(!/administrator|SmartScreen|notarized/i.test(text), 'no Windows/macOS notes on Linux');
    await press('Escape');
    await js(`$('empty-linux').classList.toggle('hidden', appSettings.platform !== 'linux')`);
    assert(/udev/.test(await js('$("empty-linux").textContent')), 'hint on the empty screen');
    await js('appSettings.platform = "darwin"; appSettings.build = { signed: false, notarized: false }; $("empty-linux").classList.add("hidden");');
  });
  await test('reopened introduction keeps a mixed storage setting; double click on Next skips no step', async () => {
    await js('appSettings.history_enabled = true; appSettings.remember_sites = false; window.__demoCalls.length = 0; openOnboarding();');
    assert(await js('!document.querySelector("#onboarding input[name=ob-store]:checked")'), 'mixed setting: neither option preselected');
    await click('#onboarding [data-ob=next]');
    await click('#onboarding [data-ob=next]');
    await until('onboarding?.step === 3', 'step 3');
    assert(await js('!window.__demoCalls.includes("set_settings")'), 'nothing changed without a choice');
    await js('onboardingAction("back")');
    await until('onboarding?.step === 2', 'back on step 2');
    await js('document.querySelector("#onboarding input[value=nothing]").click()');
    await js('onboardingAction("next"); onboardingAction("next");');   // double click while saving
    await until('onboarding && !onboarding.busy', 'saved');
    assert(await js('onboarding.step') === 3, 'the platform notes are not skipped');
    assert(await js('appSettings.remember_sites === false && appSettings.history_enabled === false'), 'the chosen setting applied');
    await press('Escape');
    await js('appSettings.history_enabled = true; appSettings.remember_sites = true;');
  });
  await test('PIN on several keys: Stop and Skip wait while a key is being changed', async () => {
    await js('keysPin = { step: "run", selected: ["demo-yk5", "demo-t2"], newPin: "123456", index: 0, results: {}, error: null, busy: true }; showKeysView();');
    await until('!!document.querySelector("#kpin [data-act=kpin-skip]")', 'assistant');
    assert(await js('document.querySelector("#kpin [data-act=kpin-skip]").disabled && document.querySelector("#kpin [data-act=kpin-stop]").disabled'), 'disabled while busy');
    await js('keysAction("kpin-skip"); keysAction("kpin-stop");');
    assert(await js('keysPin.index === 0 && keysPin.step === "run"'), 'ignored while busy');
    await js('keysPin = null; renderPanel();');
  });
  await test('inventory export: JSON and CSV with filters, saved privately', async () => {
    await js('showSettingsView()');
    await until('!!$("inventory-card")', 'export card');
    await click('#inventory-card [data-act=inv-export]');
    await until('window.__lastSave?.name?.endsWith(".json")', 'JSON saved');
    const json = await js('JSON.parse(window.__lastSave.text)');
    assert(json.format === 'keymelier-inventory' && json.keys.length >= 3 && json.accounts.length > 0, 'complete JSON');
    assert(await js('window.__lastSave.priv === true'), 'saved readable only by the user');
    await js('$("inv-format").value = "csv"; $("inv-key").value = "b2b2b2b2b2b2b2b2"; $("inv-level").value = "warn";');
    await click('#inventory-card [data-act=inv-export]');
    await until('window.__lastSave?.name?.endsWith(".csv")', 'CSV saved');
    const csv = await js('window.__lastSave.text');
    assert(csv.startsWith('\ufeff"key"') && csv.split('\r\n').slice(1, -1).every(l => l.startsWith('"Backup key"')), 'only the chosen key');
  });
  await test('what this key can do: every area with a state; a FIDO 2.0 key says passkeys work by search only', async () => {
    await js('selectToken("demo-yk5"); switchTab("overview")');
    await until('!$("caps").classList.contains("hidden")', 'capability card');
    const caps = await js('keyCapabilities(tokens.get("demo-yk5"))');
    assert(caps.length === 8 && caps.find(c => c.area === 'passkeys').state === 'full', JSON.stringify(caps));
    await focus('#caps summary'); await press('Enter');
    assert(await js('$("caps").querySelector("details").open'), 'opens by keyboard');
    assert(await js('$("caps").querySelectorAll(".cap-list li").length') === 8, 'eight areas listed');
    await js(`(() => { const t2 = tokens.get("demo-t2"); t2.options = { rk: true, clientPin: true }; t2.fido2_versions = ["FIDO_2_0"]; })()`);
    assert(await js('keyCapabilities(tokens.get("demo-t2")).find(c => c.area === "passkeys").state') === 'partial', 'FIDO 2.0: partly');
    const msg = await js(`errorMessage(Object.assign(new Error('x'), { data: { code: 'unsupported', reason: 'passkey_rename' } }))`);
    assert(/FIDO 2.1/.test(msg), `specific reason instead of a generic "cannot": ${msg}`);
    const generic = await js(`errorMessage(Object.assign(new Error('x'), { data: { code: 'unsupported' } }))`);
    assert(generic.length > 0, 'still a message without a reason');
  });
  await test('all keys: table, re-check and read all without extra PIN prompts for unlocked keys', async () => {
    await focus('#nav-keys'); await press('Enter');
    await until('mainView === "keys"', 'all keys view');
    assert(await js('document.querySelectorAll("#keys-content .keys-table tbody tr").length') === 3, 'two plugged in + one from history');
    await js('window.__demoCalls.length = 0');
    await click('#keys-content [data-act=keys-recheck]');
    await until('window.__demoCalls.includes("check_updates") && !keysBusy', 're-checked');
    await js('for (const id of ["demo-yk5", "demo-t2"]) { tokens.get(id).options = { ...tokens.get(id).options, credMgmt: true, clientPin: true }; markUnlocked(id, 300); } window.__demoCalls.length = 0;');
    await click('#keys-content [data-act=keys-readall]');
    await until('!keysBusy && window.__demoCalls.filter(c => c === "read_contents").length === 2', 'both read');
    assert(await js('!window.__demoCalls.includes("unlock")'), 'no PIN asked for keys that are unlocked');
  });
  await test('PIN on several keys: each key confirmed, stop at the first error, nothing retried, PIN not kept', async () => {
    await js('window.__demoCalls.length = 0; showKeysView()');
    await click('#kpin [data-act=kpin-start]');
    await focus('#kpin [data-kpin-key="demo-yk5"]'); await press(' ');
    await focus('#kpin [data-kpin-key="demo-t2"]'); await press(' ');
    await focus('#kpin [data-act=kpin-next]'); await press('Enter');
    await until('keysPin.step === "pin"', 'PIN step');
    await focus('#kpin-new'); await type('246810');
    await focus('#kpin-new2'); await type('246811');
    await press('Enter');
    await until('keysPin.error', 'mismatch reported');
    await focus('#kpin-new'); await type('246810');
    await focus('#kpin-new2'); await type('246810');
    await press('Enter');
    await until('keysPin.step === "run" && !!$("kpin-current")', 'first key');
    assert(await js('window.__demoCalls.filter(c => c === "pin_update").length') === 0, 'nothing sent before the explicit click');
    await focus('#kpin-current'); await type('000000');       // wrong current PIN on the first key
    await press('Enter');
    await until('keysPin.step === "done"', 'stopped');
    assert(await js('window.__demoCalls.filter(c => c === "pin_update").length') === 1, 'exactly one attempt, no retry, second key untouched');
    assert(await js('keysPin.results["demo-yk5"] === "error" && !keysPin.results["demo-t2"] && keysPin.newPin === ""'), 'result per key; new PIN cleared');
    assert(await js('/7/.test(keysPin.error)'), 'the error says how many attempts are left');
    await click('#kpin [data-act=kpin-close]');
    await click('#kpin [data-act=kpin-start]');
    await focus('#kpin [data-kpin-key="demo-t2"]'); await press(' ');
    await click('#kpin [data-act=kpin-next]');
    await focus('#kpin-new'); await type('246810'); await focus('#kpin-new2'); await type('246810'); await press('Enter');
    await until('!!$("kpin-current")', 'key step');
    await focus('#kpin-current'); await type('123456'); await press('Enter');
    await until('keysPin.step === "done" && keysPin.results["demo-t2"] === "changed"', 'changed');
    await click('#kpin [data-act=kpin-close]');
  });
  await test('company advisory sources: finding names its source, status listed, nothing to configure', async () => {
    await js(`(() => { const tk = tokens.get("demo-yk5");
      tk.advisories = [{ id: "CVE-2024-45678", severity: "MEDIUM" }, { id: "CORP-1", severity: "HIGH", title: "<b>x</b>", origin: "Contoso <IT>" }];
      selectToken("demo-yk5"); renderSecurity(tk); })()`);
    const origins = await js('[...$("sec-advisories").querySelectorAll(".advisory-origin")].map(e => e.textContent)');
    assert(origins.length === 1 && origins[0].includes('Contoso <IT>'), `only the company finding shows its source: ${origins}`);
    assert(await js('!$("sec-advisories").querySelector("b")'), 'escaped');
    await js('switchTab("security")');
    await js(`dataStatus = { ...(dataStatus || {}), advisories: { source: "bundled", updated: new Date().toISOString(), count: 5,
      policy: [{ name: "Contoso", status: "ok", count: 3 }, { name: "Lab", status: "invalid", count: 0 }] } }; renderDataStatus();`);
    const text = await js('$("data-status").textContent');
    assert(text.includes('Contoso') && text.includes('3') && text.includes('Lab'), text);
    assert(await js('!document.querySelector("input[name*=policy], [data-act*=policy]")'), 'no settings for the sources');
  });
  await test('About names the build commit; the diagnostic report has the same full commit', async () => {
    const full = '4216033e9d042fa2a010ffeb0374756297418b09';
    await js(`appSettings.build = { signed: false, notarized: false, ci: true, commit: '${full}', modified: false }; openAbout();`);
    assert((await js('$("about-build").textContent')).includes('4216033') && !(await js('$("about-build").textContent')).includes(full.slice(7, 14)), 'short commit');
    await click('#about-dialog [data-about=diag]');
    await until('!!$("diag-preview")', 'preview');
    assert(JSON.parse(await js('$("diag-preview").textContent')).app.build.commit === full, 'full commit in the report');
    await js('openAbout(false); appSettings.build = { commit: "' + full + '", modified: true }; openAbout();');
    assert(/modified|verändert/.test(await js('$("about-build").textContent')), 'a locally modified build says so');
    for (const bad of ['null', '"xyz"', '"' + full.toUpperCase() + '"', '"<b>' + full + '</b>"']) {
      await js(`openAbout(false); appSettings.build = { commit: ${bad}, modified: false }; openAbout();`);
      assert(/unknown|unbekannt/.test(await js('$("about-build").textContent')), `invalid commit ${bad} shows unknown`);
    }
    await js('openAbout(false); appSettings.build = { signed: false, notarized: false };');
  });
  await test('diagnostic report: preview first, Back saves nothing, Save writes exactly the preview (privately)', async () => {
    await js('window.__lastSave = null; window.__demoCalls.length = 0; openAbout();');
    await until('!!document.querySelector("#about-dialog [data-about=diag]")', 'about dialog');
    await focus('#about-dialog [data-about=diag]'); await press('Enter');
    await until('!!$("diag-preview")', 'preview');
    const preview = await js('$("diag-preview").textContent');
    const report = JSON.parse(preview);
    assert(report.format === 'keymelier-diagnostics' && Array.isArray(report.recent_errors), preview.slice(0, 120));
    assert(await js('(() => { const r = document.querySelector(".diag-dialog").getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth; })()'), 'dialog fits the window');
    await click('#about-dialog [data-about=diag-cancel]');
    await until('!!document.querySelector("#about-dialog [data-about=diag]")', 'back in About');
    assert(await js('window.__lastSave === null'), 'Back writes nothing');
    await click('#about-dialog [data-about=diag]');
    await until('!!$("diag-preview")', 'preview again');
    const shown = await js('$("diag-preview").textContent');
    await click('#about-dialog [data-about=diag-save]');
    await until('window.__lastSave !== null', 'saved');
    assert(await js('window.__lastSave.text') === shown, 'saved text equals the preview');
    assert(await js('window.__lastSave.priv === true && /^keymelier-diagnostics-\\d{4}-\\d{2}-\\d{2}\\.json$/.test(window.__lastSave.name)'), 'private file, dated name');
    assert(await js('$("about-dialog").classList.contains("hidden")'), 'closes after saving');
    await js('tokens.clear(); render();');
    await js('openAbout(); openDiagnostics();');
    await until('!!$("diag-preview")', 'works without a key');
    await press('Escape');
    await js('location.hash = ""');
  });
  await test('no uncaught errors or console errors on the page', async () => {
    assert(!pageErrors.length, pageErrors.join('\n'));
  });

  const failed = results.filter(r => !r.ok);
  for (const r of results) console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name}${r.ok ? '' : `\n     ${r.error}`}`);
  console.log(`${results.length - failed.length}/${results.length} UI tests passed`);
  if (failed.length) {
    log.unshift(...failed.map(r => `[failed] ${r.name}: ${r.error}`));
    await saveArtifacts(send, log, 'failure');
  }
  await browser.close();
  return failed.length ? 1 : 0;
}

async function saveArtifacts(send, log, label) {
  fs.mkdirSync(ARTIFACTS, { recursive: true });
  try {
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(ARTIFACTS, `${label}.png`), Buffer.from(shot.data, 'base64'));
  } catch (e) { log.push(`[screenshot failed] ${e.message}`); }
  fs.writeFileSync(path.join(ARTIFACTS, 'browser.log'), log.join('\n') || '(no browser console output)');
  console.log(`artifacts: ${ARTIFACTS}`);
}

// a timeout or crash never leaves the browser running (killAll)
const timer = setTimeout(() => { console.error(`UI tests timed out after ${TIMEOUT_MS / 1000}s`); killAll(); process.exit(1); }, TIMEOUT_MS);
main().then(code => { clearTimeout(timer); process.exit(code); }, e => { clearTimeout(timer); console.error(e); killAll(); process.exit(1); });
