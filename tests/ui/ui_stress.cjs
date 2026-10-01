// UI under load and in tight layouts: the demo page with #stress (12 keys,
// 300+ accounts, long German and Japanese names – tools/demo_stress.js) in
// headless Chrome, driven with real keyboard and mouse input.
//
//   node tests/ui/ui_stress.cjs          (CHROME=/path/to/chrome to choose a browser)
//
// Checked at 1280×800 and at the app's minimum window size 820×560 (app.py
// min_size), in light and dark mode, in English, German and Japanese:
// search and category filters against the account model, focus and caret
// while results update, sticky header and account column while scrolling,
// no clipped actions and no page-wide horizontal overflow (scrolling inside
// the account matrix is intended), dialogs inside the window, readable text
// in both colour schemes, response times, no page errors.
// On failure: one screenshot per failed scenario and the browser log in
// build/ui-test-artifacts/ (UI_ARTIFACTS to change).

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { launch, sleep, killAll } = require('./cdp.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const ARTIFACTS = process.env.UI_ARTIFACTS || path.join(ROOT, 'build', 'ui-test-artifacts');
const TIMEOUT_MS = Number(process.env.UI_TIMEOUT_MS || 300000);
const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

// Response time of one search/filter update (model + re-render of the whole
// matrix, ~300 rows × 13 columns), median of several runs. Locally this is
// about 15–40 ms; shared CI runners are several times slower and noisy, so
// the limit is generous – it still catches a regression by an order of
// magnitude (e.g. quadratic filtering or re-rendering per row).
const RESPONSE_LIMIT_MS = Number(process.env.UI_RESPONSE_LIMIT_MS || 400);
const SIZES = [{ width: 1280, height: 800 }, { width: 820, height: 560 }];

const KEYS = {
  Enter: { code: 'Enter', keyCode: 13, text: '\r' },
  Escape: { code: 'Escape', keyCode: 27 },
  ArrowLeft: { code: 'ArrowLeft', keyCode: 37 },
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

  // ── helpers ──
  const js = async expression => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  };
  const until = async (expression, what, ms = 8000) => {
    for (let t = 0; t < ms; t += 50) { if (await js(expression)) return; await sleep(50); }
    throw new Error(`timed out waiting for ${what}`);
  };
  const press = async key => {
    const k = KEYS[key];
    const base = { key, code: k.code, windowsVirtualKeyCode: k.keyCode, nativeVirtualKeyCode: k.keyCode };
    await send('Input.dispatchKeyEvent', { type: k.text ? 'keyDown' : 'rawKeyDown', ...base, ...(k.text ? { text: k.text, unmodifiedText: k.text } : {}) });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
    await sleep(30);
  };
  const type = async text => { for (const ch of text) { await send('Input.insertText', { text: ch }); await sleep(15); } };
  const click = async selector => {
    const r = await js(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null;
      el.scrollIntoView({ block: 'center', inline: 'nearest' }); const b = el.getBoundingClientRect(); return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; })()`);
    if (!r) throw new Error(`nothing to click: ${selector}`);
    for (const t of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type: t, x: r.x, y: r.y, button: 'left', clickCount: 1 });
    await sleep(60);
  };
  const setSize = async ({ width, height }) => {
    await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    await sleep(150);
  };
  const setScheme = async scheme => {
    await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
    await sleep(100);
  };
  const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

  const results = [];
  let scenario = '';
  const test = async (name, fn) => {
    scenario = name;
    try { await fn(); results.push({ name, ok: true }); } catch (e) {
      results.push({ name, ok: false, error: e.message });
      await screenshot(send, name, log);
    }
  };

  await setSize(SIZES[0]);
  await send('Page.navigate', { url: `${pathToFileURL(page).href}#stress` });
  await until('typeof historyKeys !== "undefined" && historyKeys.size >= 10 && tokens.size > 0', 'the stress data', 20000);
  await js('selectToken("demo-yk5")');

  // Layout helpers in the page (after it has loaded): page-wide overflow, clipped/covered controls, dialogs
  await js(`window.__layout = {
    overflow() {
      const d = document.documentElement;
      return { scrollWidth: Math.max(d.scrollWidth, document.body.scrollWidth), width: innerWidth };
    },
    // A control is usable when it is inside the window and not cut off by a
    // scrolling or clipping ancestor, after scrolling it into view.
    clipped(selector) {
      const out = [];
      for (const el of document.querySelectorAll(selector)) {
        if (!el.offsetParent && getComputedStyle(el).position !== 'fixed') continue;   // not shown
        el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        const b = el.getBoundingClientRect();
        const name = (el.id || el.dataset.act || el.dataset.accFilter || el.className || el.tagName) + ' "' + el.textContent.trim().slice(0, 30) + '"';
        if (b.width < 4 || b.height < 4) { out.push(name + ' has no size'); continue; }
        if (b.left < -1 || b.top < -1 || b.right > innerWidth + 1 || b.bottom > innerHeight + 1) {
          out.push(name + ' outside the window ' + JSON.stringify([b.left, b.top, b.right, b.bottom].map(Math.round))); continue;
        }
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const s = getComputedStyle(p);
          if (s.overflowX === 'visible' && s.overflowY === 'visible') continue;
          const r = p.getBoundingClientRect();
          if (b.left < r.left - 1 || b.right > r.right + 1 || b.top < r.top - 1 || b.bottom > r.bottom + 1) {
            out.push(name + ' cut off by ' + (p.id || p.className)); break;
          }
        }
        const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
        if (hit && hit !== el && !el.contains(hit)) out.push(name + ' covered by ' + (hit.id || hit.className || hit.tagName));
      }
      return out;
    },
    dialog(selector) {
      const el = document.querySelector(selector);
      if (!el) return 'missing';
      const b = el.getBoundingClientRect();
      if (b.left < -1 || b.top < -1 || b.right > innerWidth + 1 || b.bottom > innerHeight + 1) {
        // taller than the window is only fine if the dialog itself scrolls
        const s = getComputedStyle(el);
        const scrolls = /auto|scroll/.test(s.overflowY) && b.top >= -1 && b.bottom <= innerHeight + 1;
        if (!scrolls) return 'dialog outside the window ' + JSON.stringify([b.left, b.top, b.right, b.bottom].map(Math.round)) + ' in ' + innerWidth + 'x' + innerHeight;
      }
      return '';
    },
    // WCAG contrast of an element's text against what is really behind it: the
    // browser composites the backgrounds of all ancestors on a 1×1 canvas, so
    // any colour syntax (color-mix(), color(srgb …), alpha) is resolved exactly.
    contrast(el) {
      const cv = document.createElement('canvas'); cv.width = cv.height = 1;
      const ctx = cv.getContext('2d', { willReadFrequently: true });
      const chain = []; for (let p = el; p; p = p.parentElement) chain.unshift(p);
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, 1, 1);
      for (const p of chain) { ctx.fillStyle = getComputedStyle(p).backgroundColor; ctx.fillRect(0, 0, 1, 1); }
      const bg = [...ctx.getImageData(0, 0, 1, 1).data].slice(0, 3);
      ctx.fillStyle = getComputedStyle(el).color; ctx.fillRect(0, 0, 1, 1);
      const fg = [...ctx.getImageData(0, 0, 1, 1).data].slice(0, 3);
      const lum = ([r, g, b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const [a, b] = [lum(fg), lum(bg)];
      return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    },
  }`);


  // Rows the model says should be shown vs. rows the matrix shows (by label, in order)
  const expected = (level, query) => `(() => {
    const m = accountModel();
    return filterAccountRows(m, { level: ${JSON.stringify(level)}, query: ${JSON.stringify(query)} })
      .map(r => r.kind === 'unknown' ? unknownAccountLabel(r) : r.account || r.issuer).sort();
  })()`;
  const shownRows = `[...document.querySelectorAll('#accounts-content tr.acc-sub-row .acc-upn')].map(e => e.textContent).sort()`;
  const sameRows = async (level, query, what) => {
    const [want, got] = [await js(expected(level, query)), await js(shownRows)];
    assert(JSON.stringify(want) === JSON.stringify(got), `${what}: model ${want.length} rows, matrix ${got.length} rows`);
    return got.length;
  };
  const clearSearch = async () => {
    await js('accFilter = ""; accLevel = ""; renderAccountsView()');
  };

  await test('stress data: ≥10 keys in all states, ≥200 accounts, several per service, long and Japanese names', async () => {
    const s = await js(`(() => { const m = accountModel(); const rows = overviewRows(m); const per = {};
      rows.forEach(r => { per[r.group] = (per[r.group] || 0) + 1; });
      const info = [...m.keyInfo.values()];
      return { keys: m.keys.length, rows: rows.length, maxPerService: Math.max(...Object.values(per)),
        lost: m.keys.filter(k => k.lost_since).length, plugged: tokens.size, probe: info.filter(i => i.probeIncomplete).length,
        never: info.filter(i => i.coverage === 'none').length, stale: info.filter(i => i.stale).length,
        levels: [...new Set(rows.map(r => r.level))].length,
        longest: Math.max(...rows.map(r => (r.account || '').length), ...m.keys.map(k => (k.label || '').length)),
        japanese: rows.some(r => /[\\u3040-\\u30ff\\u4e00-\\u9fff]/.test(r.account + r.groupLabel)) }; })()`);
    assert(s.keys >= 10 && s.rows >= 200 && s.maxPerService >= 5 && s.lost >= 1 && s.plugged >= 2 && s.probe >= 1
      && s.never >= 1 && s.stale >= 1 && s.levels === 5 && s.longest >= 60 && s.japanese, JSON.stringify(s));
  });

  await test('search: every query shows exactly the rows of the account model; focus and caret stay', async () => {
    await js('showAccountsView()');
    await until('!!document.getElementById("acc-search")', 'account overview');
    await sameRows('', '', 'all rows');
    for (const q of ['github', 'ERIKA@', 'やまだ', 'weiterbildung', 'musterstadt', 'no-such-account-xyz']) {
      await clearSearch();
      await click('#acc-search');
      await type(q);
      assert(await js('document.activeElement?.id === "acc-search"'), `focus left the search box while typing "${q}"`);
      assert(await js(`document.getElementById("acc-search").value === ${JSON.stringify(q)}`), `search box lost input for "${q}"`);
      assert(await js(`document.getElementById("acc-search").selectionStart === ${q.length}`), `caret moved while typing "${q}"`);
      const n = await sameRows('', q, `search "${q}"`);
      if (q === 'no-such-account-xyz') assert(n === 0 && await js('!!document.querySelector(".acc-empty [data-acc-reset]")'), 'empty result offers a reset');
    }
    // editing in the middle of the text keeps the caret where it was
    await clearSearch();
    await click('#acc-search');
    await type('githb');
    await press('ArrowLeft');
    await type('u');
    const st = await js('(() => { const b = document.getElementById("acc-search"); return { v: b.value, pos: b.selectionStart, focus: document.activeElement === b }; })()');
    assert(st.v === 'github' && st.pos === 5 && st.focus, `caret after editing in the middle: ${JSON.stringify(st)}`);
    await sameRows('', 'github', 'search after correction');
    await clearSearch();
  });

  await test('category filters (mouse) alone and with a search match the model', async () => {
    await js('showAccountsView()');
    for (const level of ['crit', 'warn', 'unclear', 'info', 'ok']) {
      await clearSearch();
      await click(`#accounts-content [data-acc-filter="${level}"]`);
      assert(await js(`accLevel === ${JSON.stringify(level)} && document.activeElement?.dataset.accFilter === ${JSON.stringify(level)}`), `filter ${level}: focus stays on the card`);
      await sameRows(level, '', `filter ${level}`);
      await click('#acc-search');
      await type('erika');
      await sameRows(level, 'erika', `filter ${level} + "erika"`);
    }
    await clearSearch();
  });

  await test(`search and filter respond within ${RESPONSE_LIMIT_MS} ms (median of 7)`, async () => {
    await js('showAccountsView()');
    const t = await js(`(() => {
      const median = a => a.sort((x, y) => x - y)[Math.floor(a.length / 2)];
      const box = () => document.getElementById('acc-search');
      const timeSearch = q => { const t0 = performance.now(); box().value = q; box().dispatchEvent(new Event('input', { bubbles: true })); return performance.now() - t0; };
      const search = [], filter = [];
      for (let i = 0; i < 7; i++) { search.push(timeSearch(i % 2 ? 'erika' : 'git')); timeSearch(''); }
      for (let i = 0; i < 7; i++) {
        const t0 = performance.now();
        document.querySelector('#accounts-content [data-acc-filter="warn"]').click();
        filter.push(performance.now() - t0);
        document.querySelector('#accounts-content [data-acc-filter="warn"]').click();
      }
      return { search: median(search), filter: median(filter) };
    })()`);
    console.log(`     response times: search ${t.search.toFixed(1)} ms, filter ${t.filter.toFixed(1)} ms (limit ${RESPONSE_LIMIT_MS} ms)`);
    assert(t.search < RESPONSE_LIMIT_MS && t.filter < RESPONSE_LIMIT_MS, `too slow: ${JSON.stringify(t)}`);
    await clearSearch();
  });

  for (const size of SIZES) {
    const tag = `${size.width}x${size.height}`;
    await test(`${tag}: sidebar scrolls as one (every key row whole), tabs stay on one line, Advanced menu inside the window`, async () => {
      await setSize(size);
      await js('selectToken("demo-yk5"); switchTab("overview")');
      await sleep(150);
      const r = await js(`(() => {
        const scroller = document.querySelector('.sidebar-scroll');
        const nested = [...document.querySelectorAll('.sidebar .key-list')].filter(l => /auto|scroll/.test(getComputedStyle(l).overflowY));
        const cut = [];
        for (const row of document.querySelectorAll('.sidebar .key-list .key-item')) {
          row.scrollIntoView({ block: 'nearest' });
          const b = row.getBoundingClientRect(), s = scroller.getBoundingClientRect();
          if (b.top < s.top - 1 || b.bottom > s.bottom + 1) cut.push(row.textContent.trim().slice(0, 20));
        }
        const bar = document.querySelector('.tabs');
        const tabs = [...bar.querySelectorAll(':scope > .tab:not(.hidden), :scope > .tab-more .tab-more-btn')];
        const rows = new Set(tabs.map(t => Math.round(t.getBoundingClientRect().top)));
        const active = bar.querySelector('.tab.active').getBoundingClientRect(), b = bar.getBoundingClientRect();
        return { nested: nested.length, cut, rows: rows.size, activeVisible: active.left >= b.left - 1 && active.right <= b.right + 1 };
      })()`);
      assert(r.nested === 0, 'no nested scroll boxes in the sidebar');
      assert(r.cut.length === 0, `key rows cut off: ${r.cut}`);
      assert(r.rows === 1, `tabs on ${r.rows} lines`);
      assert(r.activeVisible, 'active tab in view');
      await js('setTabMenu(true)');
      const menu = await js('__layout.dialog("#tab-more-menu")');
      assert(menu === '', `Advanced menu: ${menu}`);
      await js('setTabMenu(false)');
    });

    await test(`${tag}: header row and account column stay in place while the matrix scrolls`, async () => {
      await setSize(size);
      await js('showAccountsView()');
      await clearSearch();
      const r = await js(`(() => {
        const wrap = document.querySelector('.acc-wrap');
        wrap.scrollIntoView({ block: 'start' });
        wrap.scrollTop = wrap.scrollHeight / 2; wrap.scrollLeft = wrap.scrollWidth;   // middle, far right
        const w = wrap.getBoundingClientRect();
        const head = wrap.querySelector('thead th.acc-key:last-child').getBoundingClientRect();
        const corner = wrap.querySelector('thead .acc-corner').getBoundingClientRect();
        // a row visible below the header in the scrolled area – it need not fit
        // completely: with wider fonts (e.g. DejaVu on Linux) long advice texts
        // wrap into rows taller than the visible part of the box
        const rows = [...wrap.querySelectorAll('tr.acc-sub-row')];
        const row = rows.find(tr => { const b = tr.getBoundingClientRect(); return b.bottom > head.bottom + 20 && b.top < w.bottom - 20; });
        if (!row) return { noRow: 'no account row visible below the header: header ' + Math.round(head.height) + 'px of a ' + Math.round(w.height) + 'px box' };
        const name = row.querySelector('th.acc-name').getBoundingClientRect();
        const cell = row.querySelector('td:last-child').getBoundingClientRect();
        return { wTop: w.top, wLeft: w.left, headTop: head.top, cornerLeft: corner.left, nameLeft: name.left,
          headLeft: head.left, headRight: head.right, cellLeft: cell.left, cellRight: cell.right,
          horizontal: wrap.scrollWidth > wrap.clientWidth, name: name.right, scrolledX: wrap.scrollLeft > 0 };
      })()`);
      assert(!r.noRow, r.noRow);
      assert(Math.abs(r.headTop - r.wTop) <= 2, `header row does not stick to the top: ${JSON.stringify(r)}`);
      assert(Math.abs(r.nameLeft - r.wLeft) <= 2 && Math.abs(r.cornerLeft - r.wLeft) <= 2, `account column does not stick to the left: ${JSON.stringify(r)}`);
      assert(Math.abs(r.headLeft - r.cellLeft) <= 1 && Math.abs(r.headRight - r.cellRight) <= 1, `key column header and its cells are not aligned: ${JSON.stringify(r)}`);
      assert(!r.horizontal || r.scrolledX, 'the matrix scrolls horizontally inside its box');
      await js('document.querySelector(".acc-wrap").scrollTo(0, 0)');
    });

    for (const lang of ['en', 'de', 'ja']) {
      await test(`${tag} ${lang}: no page-wide overflow, actions reachable in every view`, async () => {
        await setSize(size);
        await js(`changeLang(${JSON.stringify(lang)}, false)`);
        const views = {
          accounts: 'showAccountsView()', backup: 'showBackupView()', keys: 'showKeysView()', settings: 'showSettingsView()',
          'key (plugged in)': 'selectToken("demo-yk5")', 'key (lost, offline)': 'selectHistory(Object.values(Object.fromEntries(historyKeys)).find(k => k.lost_since).key_id)',
        };
        const problems = [];
        for (const [view, show] of Object.entries(views)) {
          await js(show);
          await sleep(120);
          const o = await js('__layout.overflow()');
          if (o.scrollWidth > o.width + 1) problems.push(`${view}: page is ${o.scrollWidth}px wide in a ${o.width}px window`);
          const clipped = await js(`__layout.clipped('.sidebar .nav-item, .sidebar button[id], .main .btn, .main button.acc-stat, .main [data-act], .main .tab, .main .acc-next-btn, #about-open')`);
          problems.push(...clipped.slice(0, 5).map(c => `${view}: ${c}`));
          await js('window.scrollTo(0, 0); document.querySelectorAll(".main").forEach(e => e.scrollTo?.(0, 0))');
        }
        assert(!problems.length, problems.join('\n     '));
      });
    }
    await js('changeLang("en", false)');

    await test(`${tag}: dialogs fit into the window (about, introduction, unlock, PIN on several keys)`, async () => {
      await setSize(size);
      const problems = [];
      const check = async (name, open, selector, close) => {
        await js(open);
        await sleep(200);
        const p = await js(`__layout.dialog(${JSON.stringify(selector)})`);
        if (p) problems.push(`${name}: ${p}`);
        const clipped = await js(`__layout.clipped(${JSON.stringify(selector + ' button')})`);
        problems.push(...clipped.slice(0, 3).map(c => `${name}: ${c}`));
        await js(close);
        await sleep(100);
      };
      for (const lang of ['en', 'de']) {
        await js(`changeLang(${JSON.stringify(lang)}, false)`);
        await check(`about (${lang})`, 'openAbout()', '#about-dialog .ql-dialog', 'openAbout(false)');
        await check(`introduction (${lang})`, 'openOnboarding()', '#onboarding .ql-dialog', 'onboarding = null; renderOnboarding()');
        await check(`introduction step 3 (${lang})`, 'openOnboarding(); onboarding.step = 3; renderOnboarding()', '#onboarding .ql-dialog', 'onboarding = null; renderOnboarding()');
        await check(`unlock (${lang})`, 'selectToken("demo-yk5"); quickLockToggle("demo-yk5")', '#quick-unlock .ql-dialog',
          'document.querySelector("#quick-unlock [data-ql=cancel], #quick-unlock .btn-secondary")?.click()');
        await check(`PIN on several keys (${lang})`, 'showKeysView(); keysAction("kpin-start")', '#kpin',
          'keysAction("kpin-cancel")');
      }
      await js('changeLang("en", false)');
      assert(!problems.length, problems.join('\n     '));
    });
  }

  for (const scheme of ['light', 'dark']) {
    await test(`${scheme} mode: text readable on its background in the matrix, sidebar and dialogs`, async () => {
      await setSize(SIZES[0]);
      await setScheme(scheme);
      await js('showAccountsView()');
      await sleep(150);
      const c = await js(`(() => {
        const q = s => document.querySelector(s);
        const pairs = { body: q('#accounts-content .acc-filter-state span'), account: q('#accounts-content .acc-upn'),
          header: q('#accounts-content thead th.acc-key'), sidebar: q('.sidebar .nav-item'), group: q('#accounts-content .acc-label') };
        openAbout();
        pairs.dialog = q('#about-dialog .ql-dialog p');
        const out = {};
        for (const [k, el] of Object.entries(pairs)) out[k] = el ? +__layout.contrast(el).toFixed(2) : 'missing';
        openAbout(false);
        out.dark = matchMedia('(prefers-color-scheme: dark)').matches;
        out.bg = getComputedStyle(document.body).backgroundColor;
        return out;
      })()`);
      assert(c.dark === (scheme === 'dark'), `colour scheme not applied: ${JSON.stringify(c)}`);
      assert(!Object.values(c).includes('missing'), `element to check not found: ${JSON.stringify(c)}`);
      const low = Object.entries(c).filter(([k, v]) => typeof v === 'number' && v < 4.5);
      assert(!low.length, `contrast below 4.5:1 – ${JSON.stringify(low)} (${scheme})`);
    });
  }
  await setScheme('light');
  const bgs = await js('getComputedStyle(document.body).backgroundColor');
  await setScheme('dark');
  const bgd = await js('getComputedStyle(document.body).backgroundColor');
  await setScheme('light');
  await test('light and dark mode really differ', async () => assert(bgs !== bgd, `same background ${bgs}`));

  await test('no uncaught errors or console errors on the page', async () => {
    assert(!pageErrors.length, pageErrors.join('\n'));
  });

  const failed = results.filter(r => !r.ok);
  for (const r of results) console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name}${r.ok ? '' : `\n     ${r.error}`}`);
  console.log(`${results.length - failed.length}/${results.length} UI stress tests passed`);
  if (failed.length) {
    log.unshift(...failed.map(r => `[failed] ${r.name}: ${r.error}`));
    fs.mkdirSync(ARTIFACTS, { recursive: true });
    fs.writeFileSync(path.join(ARTIFACTS, 'stress-browser.log'), log.join('\n') || '(no browser console output)');
    console.log(`artifacts: ${ARTIFACTS}`);
  }
  await browser.close();
  return failed.length ? 1 : 0;
}

// One screenshot per failed scenario, named after it
async function screenshot(send, name, log) {
  fs.mkdirSync(ARTIFACTS, { recursive: true });
  const file = `stress-${name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 80)}.png`;
  try {
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(ARTIFACTS, file), Buffer.from(shot.data, 'base64'));
  } catch (e) { log.push(`[screenshot failed] ${name}: ${e.message}`); }
}

const timer = setTimeout(() => { console.error(`UI stress tests timed out after ${TIMEOUT_MS / 1000}s`); killAll(); process.exit(1); }, TIMEOUT_MS);
main().then(code => { clearTimeout(timer); process.exit(code); }, e => { clearTimeout(timer); console.error(e); killAll(); process.exit(1); });
