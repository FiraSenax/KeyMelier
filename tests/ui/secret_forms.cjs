// Real production forms/CSP, synthetic device replies, including delayed errors.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {execFileSync} = require('node:child_process');
const {launch, sleep, callPage, killAll} = require('./cdp.cjs');
const root = path.resolve(__dirname, '../..');

async function main() {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'km-secret-forms-'));
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
      ready = await callPage(browser.send, () => document.readyState === 'complete' && typeof secretSubmission === 'function');
      if (ready) break;
      await sleep(50);
    }
    assert(ready, 'production scripts loaded');
    const results = await callPage(browser.send, async () => {
      const results = [];
      const check = (name, ok) => results.push({name, ok: !!ok});
      const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
      const token = {id: 'fixture-key', product_name: 'Fixture key', options: {clientPin: true, uv: true},
        attestation: {inconclusive: 'pin_invalid'}, versions: ['FIDO_2_1'], security_status: 'UNKNOWN'};
      tokens.set(token.id, token); selectedId = token.id;
      const calls = [];
      let pending, wanted;
      const states = {
        piv: {pin: {attempts: 3, puk_attempts: 3}, management_key: {default: true}, slots: [], key_types: []},
        openpgp: {pin: {user: 3, admin: 3}, keys: [], algorithms: [], signature_counter: 0},
        oath: {unlocked: true, accounts: [], password: true},
        otp: {slots: [{slot: 1, configured: false}, {slot: 2, configured: false}]},
        pin_status: {is_set: true, min_length: 4, retries: 7},
      };
      call = (method, args = {}) => {
        calls.push({method, args: structuredClone(args)});
        if (method === wanted) return new Promise((resolve, reject) => { pending = {resolve, reject}; });
        return Promise.resolve(states[method] || {});
      };
      const arm = method => { calls.length = 0; wanted = method; pending = null; };
      const fill = (form, fields) => {
        for (const [selector, value] of Object.entries(fields)) {
          const input = form.querySelector(selector);
          input.defaultValue = value; input.value = value;
        }
      };
      const submit = form => form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
      const cleared = form => [...form.querySelectorAll(SECRET_INPUTS)].every(input => input.value === '' && input.defaultValue === '');
      const fail = () => pending.reject(Object.assign(new Error('Synthetic cancellation'), {data: {code: 'cancelled'}}));

      renderSecurity(token);
      let form = document.querySelector('.att-pin-form');
      fill(form, {'.att-pin': 'synthetic-pin'}); arm('attestation_rerun'); submit(form);
      check('attestation PIN cleared before reply', cleared(form));
      check('attestation receives captured PIN once', calls.length === 1 && calls[0].args.pin === 'synthetic-pin');
      check('PIN and UV submit disabled while waiting', form.querySelector('button[type=submit]').disabled && $('att-uv').disabled);
      // A poll may replace the form while its original request is still running.
      renderSecurity(token); form = document.querySelector('.att-pin-form');
      fill(form, {'.att-pin': 'second-pin'}); submit(form);
      check('rerender does not bypass duplicate guard', calls.length === 1);
      fail(); await flush(); submit(form);
      check('error permits a deliberate retry', calls.length === 2 && calls[1].args.pin === 'second-pin');
      pending.resolve({}); await flush();

      const cases = [
        ['OATH unlock', 'oath_unlock', () => { oathState = {unlocked: false}; renderOath(); }, '#oath-content form', {'.oath-password': 'synthetic-password'}, 'password'],
        ['OATH URI', 'oath_add', () => { oathState = states.oath; oathForm = 'add'; renderOath(); }, '.oath-add-form', {'.oath-uri': 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP'}, 'uri'],
        ['OATH password', 'oath_password', () => { oathState = states.oath; oathForm = 'password'; renderOath(); }, '.oath-password-form', {'.oath-pw-new': 'synthetic-password', '.oath-pw-confirm': 'synthetic-password'}, 'password'],
        ['PIV PIN', 'piv_change_pin', () => { pivState = states.piv; pivForm = 'pin'; renderPiv(); }, '#piv-content form', {'.piv-current': 'old-pin', '.piv-new': 'new-pin', '.piv-confirm': 'new-pin'}, 'current'],
        ['OpenPGP PIN', 'openpgp_change_pin', () => { pgpState = states.openpgp; pgpForm = 'pin'; renderPgp(); }, '#pgp-content form', {'.pgp-current': 'old-pin', '.pgp-new': 'new-pin', '.pgp-confirm': 'new-pin'}, 'current'],
        ['OTP HMAC', 'otp_hmac', () => { otpState = states.otp; otpForm = 'hmac:2'; renderOtp(); }, '#otp-content form', {'.otp-secret': '00112233445566778899', '.otp-acc': '001122334455'}, 'secret'],
      ];
      for (const [name, method, renderForm, selector, fields, arg] of cases) {
        renderForm(); form = document.querySelector(selector); fill(form, fields); arm(method);
        submit(form); submit(form);
        check(name + ': captured once', calls.filter(c => c.method === method).length === 1 && !!calls[0].args[arg]);
        check(name + ': fields cleared while pending', cleared(form));
        check(name + ': submit disabled while pending', form.querySelector('button[type=submit]').disabled);
        form.reset(); check(name + ': reset cannot restore secret', cleared(form));
        fail(); await flush();
        check(name + ': operation guard released after error', pendingSecretSubmissions.size === 0);
      }

      // FIDO PIN form also covers its "show PIN" text-input state.
      pinState = states.pin_status; form = $('pin-form'); setPinVisible(true);
      fill(form, {'#pin-current': 'old-pin', '#pin-new': 'new-pin', '#pin-confirm': 'new-pin'});
      arm('pin_update'); submit(form); submit(form);
      check('FIDO PIN captured once and visible fields cleared', calls.length === 1 && cleared(form));
      fail(); await flush();
      check('FIDO PIN retry remains available', !$('pin-submit').disabled && pendingSecretSubmissions.size === 0);

      // Closing a form clears its old DOM nodes too, not just the replacement page.
      oathState = states.oath; oathForm = 'add'; renderOath(); form = document.querySelector('.oath-add-form');
      fill(form, {'.oath-secret': 'synthetic-secret'});
      form.querySelector('[data-act=hide-form]').click();
      check('cancel clears detached secret inputs', cleared(form) && !form.isConnected);

      otpState = states.otp; otpForm = 'hmac:2'; renderOtp(); form = document.querySelector('#otp-content form');
      arm('otp_hmac'); submit(form); selectedId = 'another-key';
      pending.resolve({...states.otp, secret: 'late-generated-secret'}); await flush();
      check('late OTP secret never enters another key view', otpSecret === null);
      selectedId = token.id; otpSecret = 'one-time-secret';
      renderOtp();
      const oldSecret = document.querySelector('#otp-content .pgp-fp');
      resetViewState();
      check('leaving a key clears one-time OTP secret from state and old DOM', otpSecret === null && oldSecret.textContent === '');

      // Synchronous errors must release the form as well; public fields survive.
      form = uiElement('form', {}, fieldNode('private', 'PIN'), fieldNode('public', 'Name', 'text', 'Keep name'),
        uiElement('button', {type: 'submit', disabled: true}, 'Submit'));
      fill(form, {'.private': 'synthetic-secret'});
      try { await secretSubmission('throwing', token.id, form, () => { throw new Error('Synthetic failure'); }); } catch { /* expected */ }
      check('synchronous failure clears secret and preserves existing control state', cleared(form)
        && form.querySelector('button').disabled && !form.querySelector('.private').disabled
        && form.querySelector('.public').value === 'Keep name' && pendingSecretSubmissions.size === 0);

      // Each management pane requests its own permission, even if the user
      // switches tabs while a request is pending. No duplicate PIN/UV call.
      const gate = {supported: true, pin_set: true, uv_unlock: true, unlocked: false};
      states.passkeys = {...gate}; states.fingerprints = {...gate}; states.config = {...gate};
      for (const scope of ['passkeys', 'fingerprints', 'settings']) {
        for (const method of ['pin', 'uv']) {
          selectedId = token.id; activeTab = scope;
          pkState = {...gate}; fpState = {...gate}; cfgState = {...gate};
          unlockBusy = null; renderManagement(); arm('unlock');
          const pane = document.querySelector(`[data-pane="${scope}"]`);
          const input = pane.querySelector('.unlock-pin');
          input.value = 'synthetic-pin'; input.defaultValue = 'synthetic-pin';
          const first = unlockKey(method); unlockKey(method);
          check(`${scope}/${method}: single scoped request`, calls.length === 1 && calls[0].args.scope === scope);
          check(`${scope}/${method}: PIN cleared while pending`, input.value === '' && input.defaultValue === '');
          activeTab = scope === 'settings' ? 'passkeys' : 'settings';
          renderManagement();
          fail(); await first;
          check(`${scope}/${method}: error releases busy state`, unlockBusy === null);
          const activePane = document.querySelector(`[data-pane="${activeTab}"]`);
          const ready = {pin: !!activePane.querySelector('.unlock-pin'),
            disabled: activePane.querySelector('.unlock-form button[type="submit"]')?.disabled,
            waiting: !!activePane.querySelector('.unlock-form .uv-wait'),
            error: activePane.querySelector('.unlock-form .field-error')?.textContent};
          check(`${scope}/${method}: switched pane permits a fresh attempt`,
            ready.pin && ready.disabled === false && !ready.waiting && !ready.error);
        }
      }
      // Exercise the actual tab loader: a read queued behind UV can report
      // busy. Once UV ends, reload the newly requested pane instead of keeping
      // its cached attestation-wait screen, without retrying authentication.
      activeTab = 'settings'; cfgState = {...gate}; renderManagement(); arm('unlock');
      const queuedUnlock = unlockKey('uv');
      const normalCall = call;
      let fingerprintReads = 0;
      call = (method, args) => {
        if (method === 'fingerprints') {
          fingerprintReads++;
          if (fingerprintReads === 1) return Promise.reject(Object.assign(new Error('Busy'), {data: {code: 'busy'}}));
        }
        return normalCall(method, args);
      };
      switchTab('fingerprints'); await flush();
      check('tab read reports busy while UV owns the key', fpState?.busy && fingerprintReads === 1);
      fail(); await queuedUnlock; await flush();
      check('failed UV reloads the busy tab without another authentication attempt', fingerprintReads === 2
        && !fpState?.busy && calls.filter(c => c.method === 'unlock').length === 1
        && !document.querySelector('#fp-content .unlock-form button[type="submit"]').disabled);
      call = normalCall;
      activeTab = 'settings'; cfgState = {...gate}; renderManagement(); arm('unlock');
      const refused = unlockKey('uv');
      pending.reject(Object.assign(new Error('UV not permitted'), {data: {code: 'unsupported', reason: 'uv_unlock'}}));
      await refused;
      check('permission refusal offers PIN without repeating UV', calls.length === 1
        && !document.querySelector('[data-pane="settings"] [data-act="unlock-uv"]')
        && !!document.querySelector('[data-pane="settings"] .unlock-pin'));

      token.options.credMgmt = true;
      token.options.uv = false;
      markUnlocked(token.id, 300, 'settings');
      check('settings unlock is not sufficient to read passkeys', isUnlocked(token.id) && !isUnlocked(token.id, 'read'));
      arm('unlock');
      await readKey(token);
      check('read after settings opens PIN dialog without locking or reading', calls.length === 0
        && quickUnlock?.id === token.id && !!document.querySelector('#quick-unlock .ql-pin'));
      document.querySelector('#quick-unlock .ql-pin').value = 'synthetic-pin';
      const readUnlock = quickUnlockSubmit();
      check('sidebar PIN requests read scope', calls.length === 1 && calls[0].args.scope === 'read');
      fail(); await readUnlock; closeQuickUnlock();
      quickUnlock = {id: token.id, mode: 'uv', busy: false}; arm('unlock');
      const readUv = quickUnlockUv();
      check('sidebar UV requests read scope', calls.length === 1 && calls[0].args.scope === 'read');
      fail(); await readUv; closeQuickUnlock();
      markUnlocked(token.id, 300, 'passkeys');
      check('passkey permission permits read without another PIN', isUnlocked(token.id, 'read'));
      onTokenDisconnected({id: token.id});
      check('disconnect clears scoped UI unlock', !isUnlocked(token.id) && !unlockedScopes.has(token.id));
      stopOathTimer();
      return results;
    });
    assert(results.every(r => r.ok), JSON.stringify(results.filter(r => !r.ok)));
    console.log(`Secret forms: ${results.length} production DOM checks passed`);
  } finally {
    if (browser) await browser.close();
    fs.rmSync(folder, {recursive: true, force: true});
  }
}
const timer = setTimeout(() => { killAll(); process.exit(1); }, 60000);
main().then(() => clearTimeout(timer)).catch(error => { clearTimeout(timer); killAll(); console.error(error); process.exitCode = 1; });
