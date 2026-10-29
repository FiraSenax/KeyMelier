const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('static/app.js', 'utf8');
const fn = source.slice(source.indexOf('function attestationSummary('), source.indexOf('// ── Sidebar'));
const ctx = {t: key => key};
vm.createContext(ctx);
vm.runInContext(fn, ctx);
for (const att of [{}, {passed:true}, {status:'UNVERIFIED', passed:false},
                   {status:'VERIFIED',passed:true,sig_valid:true,chain_valid:null}]) {
  assert.equal(ctx.attestationSummary(att, {}).cls, 'partial');
}
assert.equal(ctx.attestationSummary({status:'VERIFIED',passed:true,sig_valid:true,chain_valid:true,aaguid_match:true},{}).cls,'pass');
assert.equal(ctx.attestationSummary({status:'FAILED',checks:[{passed:false}]},{}).cls,'fail');
console.log('UI security classification tests passed');

vm.runInContext(source.slice(source.indexOf('function eventText('), source.indexOf('// "What was on this key"')), ctx);
assert.equal(ctx.eventText({type:'attestation', passed:true, source:'import'}), 'acc.src.import: ev.attestation.pass');
assert.equal(ctx.eventText({type:'function_test', passed:true, source:'sync'}), 'acc.src.sync: ev.function_test.pass');
assert.equal(ctx.eventText({type:'attestation', passed:true}), 'ev.attestation.pass');
vm.runInContext(source.slice(source.indexOf('function escHtml('), source.indexOf('function showToast(')), ctx);
assert.equal(ctx.escHtml(`'"<&>`), '&#39;&quot;&lt;&amp;&gt;');

// Download completion only exposes an Open button. Starting the installer must
// be a separate user action, even when the signature and checksum are valid.
const calls = [];
const elements = new Map();
const updates = {
  window: {}, console, dataStatus: {app: {newer: true, url: 'release', latest: '9.9.9', asset: {}}},
  call: async name => { calls.push(name); }, t: key => key,
  $: id => {
    if (!elements.has(id)) elements.set(id, {classList: {toggle() {}}});
    return elements.get(id);
  },
};
vm.createContext(updates);
vm.runInContext(source.slice(source.indexOf('let updateFlow = null;'), source.indexOf('function renderDataStatus()')), updates);
vm.runInContext(source.slice(source.indexOf('const EVENT_HANDLERS ='), source.indexOf('// ── Init')), updates);
for (const platform of ['win32', 'darwin', 'linux']) {
  updates.window.__kmEvent('update_ready', {platform});
  assert.deepEqual(calls, []);
  assert.equal(elements.get('update-btn').textContent, 'upd.open');
}
updates.onUpdateButton();
assert.deepEqual(calls, ['update_open']);
console.log('Updates require an explicit Open action');

const notices = [];
updates.showToast = (text, level) => notices.push({text, level});
calls.length = 0;
updates.window.__kmEvent('update_failed', {code: 'update_revocation_state'});
assert.equal(elements.get('update-text').textContent, 'err.update_revocation_state');
assert.equal(elements.get('update-btn').disabled, true);
updates.onUpdateButton();
assert.deepEqual(calls, [], 'unreadable revocation state never opens or downloads an installer');
assert.equal(notices.at(-1).text, 'err.update_revocation_state');
console.log('Unreadable revocation state stays visible and blocks installer actions');
