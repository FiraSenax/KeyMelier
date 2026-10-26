const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('static/app.js', 'utf8');
const toasts = [];
const ctx = {
  window: {}, dataStatus: null,
  t: key => key, showToast: (...args) => toasts.push(args),
  renderDataStatus: () => {},
  call: async () => ({app: {current: '1.8.6', newer: false, managed: true}}),
};
vm.createContext(ctx);
vm.runInContext(source.slice(source.indexOf('let updateChecking ='), source.indexOf('async function checkDataNow()')), ctx);
(async () => {
  await ctx.checkForUpdates();
  assert.equal(toasts.at(-1)[0], 'upd.managed');
  assert(!toasts.some(t => t[0] === 'upd.current'), 'must not claim that the Store was checked');
  console.log('MSIX update UI tests passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
