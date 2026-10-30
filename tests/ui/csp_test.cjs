// The production document with its real CSP; the ordinary demo removes CSP.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {execFileSync} = require('node:child_process');
const {launch, sleep, callPage, killAll} = require('./cdp.cjs');
const root = path.resolve(__dirname, '../..');

async function main() {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'km-csp-'));
  let browser;
  try {
    const html = execFileSync(process.env.PYTHON || 'python3', ['-c',
      'from keymelier_core.page import build_html; print(build_html())'], {cwd: root, encoding: 'utf8', maxBuffer: 8 << 20});
    const file = path.join(folder, 'page.html');
    fs.writeFileSync(file, html);
    browser = await launch();
    await browser.send('Page.enable');
    await browser.send('Runtime.enable');
    await browser.send('Page.navigate', {url: pathToFileURL(file).href});
    let ready = false;
    for (let i = 0; i < 100; i++) {
      ready = await callPage(browser.send, () => typeof renderSidebar === 'function' && typeof uiElement === 'function');
      if (ready) break;
      await sleep(50);
    }
    assert(ready, 'all production script hashes allow the application to load');
    await callPage(browser.send, () => {
      window.__cspProbe = {script: false, handler: false, blocked: []};
      document.addEventListener('securitypolicyviolation', e => window.__cspProbe.blocked.push(e.effectiveDirective));
      const script = document.createElement('script');
      script.textContent = 'window.__cspProbe.script = true';
      document.body.append(script);
      const img = document.createElement('img');
      img.setAttribute('onerror', 'window.__cspProbe.handler = true');
      img.src = 'data:image/png;base64,AA==';
      document.body.append(img);
    });
    await sleep(300);
    const result = await callPage(browser.send, () => window.__cspProbe);
    assert.equal(result.script, false);
    assert.equal(result.handler, false);
    assert(result.blocked.includes('script-src-elem'));
    assert(result.blocked.includes('script-src-attr'));
    const dynamic = await browser.send('Runtime.evaluate', {expression: 'new Function("return 42")()',
      returnByValue: true, allowUnsafeEvalBlockedByCSP: false});
    assert.equal(dynamic.result.value, 42, 'the pinned native bridge still needs string evaluation');
    console.log('Production CSP: scripts load, injected scripts/handlers are blocked, bridge evaluation remains supported');
  } finally {
    if (browser) await browser.close();
    fs.rmSync(folder, {recursive: true, force: true});
  }
}
const timer = setTimeout(() => { killAll(); process.exit(1); }, 30000);
main().then(() => clearTimeout(timer)).catch(error => { clearTimeout(timer); killAll(); console.error(error); process.exitCode = 1; });
