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
    assert(await active() === 'nav-settings', `focus after 2×Tab: ${await active()}`);
    await press('Enter');
    await until('mainView === "settings"', 'settings view');
    assert(await js('!!$("history-enabled") && !!$("personal-mode") && !!$("bk-remember") && !!$("sync-card")'), 'app settings present');
    await press('Tab', { shift: true });
    assert(await active() === 'nav-accounts', `Shift+Tab goes back: ${await active()}`);
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
    assert(!(await js('window.__demoCalls.includes("unlock")')), 'no PIN sent after a cancel');
    await press('Enter');                                  // try again
    await until('!!document.querySelector("#quick-unlock .ql-pin")', 'dialog again');
    await focus('#quick-unlock .ql-pin');
    await type('123456');
    await press('Enter');
    await until('$("quick-unlock").classList.contains("hidden")', 'unlocked and closed');
    const calls = await js('window.__demoCalls.filter(c => c === "unlock" || c === "read_contents")');
    assert(JSON.stringify(calls) === '["unlock","read_contents"]', `exactly one unlock, then reading: ${calls}`);
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
    await js(`(() => { const o = historyKeys.get('a1a1a1a1a1a1a1a1');
      o.replace = { new: 'b2b2b2b2b2b2b2b2', since: new Date().toISOString(), done: ['pk:bitwarden.com|erika@example.com', 'pk:github.com|erika'] };
      showReplaceView(o.key_id); })()`);
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
