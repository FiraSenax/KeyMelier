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
    const panes = await callPage(browser.send, () => {
      const attack = '\"><img data-injected="yes" src=x onerror="window.__injected=true"><b>device & value</b>';
      const outcomes = [];
      const safe = id => !document.querySelector(`#${id} [data-injected], #${id} script, #${id} b`);
      pivState = {pin: {default: true, puk_default: true, attempts: 3, puk_attempts: 3},
        management_key: {protected: false, default: false}, key_types: [attack], can_delete_key: true,
        slots: [{slot: '9a', cert: {subject: attack, issuer: attack, algorithm: attack, not_after: '2030-01-01'},
          key: {type: attack, generated: true, pin_policy: attack, touch_policy: attack}},
        {slot: attack, key: {type: attack}}]};
      for (const form of [null, 'pin', 'puk', 'unblock', 'protect', 'gen:9a', 'import:9a', 'delete:9a']) {
        pivForm = form; renderPiv();
        outcomes.push(safe('piv-content') && $('piv-content').textContent.includes(attack));
        if (form === 'gen:9a') outcomes.push(document.querySelector('.piv-type').value === attack
          && document.querySelector('.piv-days').value === '365' && !document.querySelector('.app-replace').checked);
        if (form) outcomes.push(document.querySelector('#piv-content form').dataset.form === form);
      }
      outcomes.push([...document.querySelectorAll('#piv-content [data-form]')].some(b => b.dataset.form === `gen:${attack}`));
      pgpState = {name: attack, url: attack, serial: attack, spec: attack, signature_counter: 3,
        pin: {user: 3, admin: 3, sign_every_time: false}, can_touch: true, algorithms: [attack],
        keys: [{slot: 'sig', present: true, algorithm: attack, fingerprint: attack, touch: 'cached'},
          {slot: attack, present: false, touch: attack}]};
      pgpResult = {user_id: attack, fingerprint: attack}; gpgAvailable = true;
      for (const form of [null, 'pin', 'admin', 'unblock', 'holder', 'sigpin', 'generate', 'touch:sig']) {
        pgpForm = form; renderPgp();
        outcomes.push(safe('pgp-content') && $('pgp-content').textContent.includes(attack));
        if (form === 'holder') outcomes.push(document.querySelector('.pgp-name').value === attack
          && document.querySelector('.pgp-url').value === attack);
        if (form === 'sigpin') outcomes.push(!document.querySelector('.pgp-sigpin').checked);
        if (form === 'generate') outcomes.push(document.querySelector('.pgp-galgo').value === attack
          && document.querySelector('.pgp-gexpire').value === '730');
        if (form === 'touch:sig') outcomes.push(document.querySelector('.pgp-touch').value === 'cached');
        if (form) outcomes.push(document.querySelector('#pgp-content form').dataset.form === form);
      }
      outcomes.push([...document.querySelectorAll('#pgp-content [data-slot]')].some(b => b.dataset.slot === attack));
      otpState = {slots: [{slot: 1, configured: true, touch: false}, {slot: 2, configured: false}, {slot: attack, configured: true}]};
      otpSecret = attack; otpError = attack;
      for (const form of [null, 'static:1', 'hmac:1', 'delete:1', 'static:2', 'hmac:2', 'delete:2']) {
        otpForm = form; renderOtp();
        outcomes.push(safe('otp-content'));
        if (form?.startsWith('hmac:')) outcomes.push(document.querySelector('.otp-touch').checked);
        if (form?.endsWith(':2')) outcomes.push(!document.querySelector('#otp-content .app-replace'));
        if (form) outcomes.push(document.querySelector('#otp-content form').dataset.form === form);
      }
      outcomes.push([...document.querySelectorAll('#otp-content [data-form]')].some(b => b.dataset.form === `static:${attack}`));
      for (const [set, render, id] of [
        [value => { pivState = value; }, renderPiv, 'piv-content'],
        [value => { pgpState = value; }, renderPgp, 'pgp-content'],
        [value => { otpState = value; }, renderOtp, 'otp-content'],
      ]) {
        set(null); render(); outcomes.push(!!document.querySelector(`#${id} .spinner`));
        set({error: attack}); render(); outcomes.push(safe(id) && $(id).textContent.includes(attack));
      }
      return outcomes;
    });
    assert(panes.every(Boolean), `PIV/OpenPGP/OTP data stays literal and all forms retain their defaults: ${panes}`);
    console.log(`Production DOM: ${panes.length} checks across PIV, OpenPGP and OTP forms/results`);
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
