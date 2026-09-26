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
