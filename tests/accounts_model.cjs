// Regression tests for static/accounts.js – each case is a misclassification
// that must not happen again (node tests/accounts_model.cjs).
const assert = require('node:assert/strict');
const { buildAccountModel, cellState, registrableDomain } = require('../static/accounts.js');

const NOW = Date.parse('2026-09-27T12:00:00Z');
const day = n => new Date(NOW - n * 86400e3).toISOString();
const key = (id, extra = {}) => ({ key_id: id, snapshot: {}, ...extra });
const site = (rp_id, users, extra = {}) => ({ rp_id, name: extra.name || '', count: extra.count || users.length || 1,
  users: users.map(n => ({ name: n, display: '' })), source: extra.source || 'list', checked: day(1) });
const find = (m, pred) => m.rows.find(pred);

// 1. Different accounts of the same service are rated separately
{
  const m = buildAccountModel([
    key('A', { sites: [site('login.microsoft.com', ['alice@contoso.com', 'admin@contoso.com'])], sites_updated: day(1) }),
    key('B', { sites: [site('login.microsoft.com', ['alice@contoso.com'])], sites_updated: day(1) }),
  ], NOW);
  assert.equal(find(m, r => r.account === 'alice@contoso.com').status, 'passkey_multi');
  assert.equal(find(m, r => r.account === 'admin@contoso.com').status, 'passkey_single');
  assert.equal(m.groups.length, 1, 'both accounts are shown under one service');
}

// 2. A nameless passkey on another key is NOT treated as the named account's backup
{
  const m = buildAccountModel([
    key('A', { sites: [site('github.com', ['erika'])], sites_updated: day(1) }),
    key('B', { sites: [site('github.com', [], { count: 1 })], sites_updated: day(1) }),
  ], NOW);
  assert.equal(find(m, r => r.account === 'erika').status, 'passkey_single');
  assert.equal(find(m, r => r.kind === 'unknown').status, 'unclear');
  assert.ok(!m.rows.some(r => r.level === 'ok'), 'nothing may look protected');
}

// 3. Similar names with different rpIds stay different accounts
{
  const m = buildAccountModel([
    key('A', { sites: [site('proton.me', ['erika'], { name: 'Proton' })], sites_updated: day(1) }),
    key('B', { sites: [site('proton.com.evil.io', ['erika'], { name: 'Proton' })], sites_updated: day(1) }),
  ], NOW);
  assert.equal(m.rows.length, 2);
  assert.ok(m.rows.every(r => r.status === 'passkey_single'));
  assert.equal(registrableDomain('login.microsoft.com'), 'microsoft.com');
  assert.equal(registrableDomain('microsoft.com.evil.io'), 'evil.io');
  // same domain, different rpId: separate accounts too
  const n = buildAccountModel([
    key('A', { sites: [site('login.microsoft.com', ['x@y'])], sites_updated: day(1) }),
    key('B', { sites: [site('login.live.com', ['x@y'])], sites_updated: day(1) }),
  ], NOW);
  assert.ok(n.rows.every(r => r.status === 'passkey_single'));
}

// 4. Passkey only on a lost key + codes on active keys is never "well protected"
{
  const entries = [
    key('LOST', { lost_since: day(3), sites: [site('github.com', ['erika'])], sites_updated: day(30) }),
    key('A', { sites: [], sites_updated: day(1), inventory: { oath: { items: [{ issuer: 'GitHub', name: 'erika' }], updated: day(1) } } }),
    key('B', { sites: [], sites_updated: day(1), inventory: { oath: { items: [{ issuer: 'GitHub', name: 'erika' }], updated: day(1) } } }),
  ];
  const m = buildAccountModel(entries, NOW);
  const pk = find(m, r => r.kind === 'passkey');
  assert.equal(pk.status, 'passkey_lost_code');
  assert.notEqual(pk.level, 'ok');
  // with a different account name the code is not linked; the passkey is lost-only
  entries[1].inventory.oath.items[0].name = 'someone-else';
  entries[2].inventory.oath.items[0].name = 'someone-else';
  const m2 = buildAccountModel(entries, NOW);
  assert.equal(find(m2, r => r.kind === 'passkey').status, 'lost_only');
  assert.equal(find(m2, r => r.kind === 'code').status, 'codes_multi');
}

// 5. Passkey on two keys vs passkey plus code vs codes only are distinguished
{
  const oath = name => ({ oath: { items: [{ issuer: 'GitHub', name }], updated: day(1) } });
  const m = buildAccountModel([
    key('A', { sites: [site('github.com', ['erika'])], sites_updated: day(1) }),
    key('B', { sites: [], sites_updated: day(1), inventory: oath('erika') }),
  ], NOW);
  assert.equal(find(m, r => r.kind === 'passkey').status, 'passkey_code');
  const c = buildAccountModel([key('A', { inventory: oath('x') }), key('B', { inventory: oath('x') })], NOW);
  assert.equal(c.rows[0].status, 'codes_multi');
}

// 6. Unknown, incomplete, stale and imported data are never shown as "absent"
{
  const m = buildAccountModel([
    key('A', { sites: [site('github.com', ['erika'])], sites_updated: day(1) }),
    key('NEVER'),                                                             // never read
    key('PROBE', { sites: [], sites_updated: day(1), probe: { complete: false } }),  // interrupted search
    key('OLD', { sites: [], sites_updated: day(200) }),                       // stale
    key('IMP', { snapshot: { imported: true }, sites: [site('x.com', ['q'], { source: 'import' })], sites_updated: day(5) }),
  ], NOW);
  const r = find(m, x => x.account === 'erika');
  assert.equal(cellState(m, r, 'NEVER').unknown, true);
  assert.equal(cellState(m, r, 'PROBE').unknown, true);
  assert.equal(cellState(m, r, 'OLD').unknown, false);     // known absent, but …
  assert.equal(m.keyInfo.get('OLD').stale, true);          // … flagged as stale
  assert.equal(cellState(m, find(m, x => x.account === 'q'), 'IMP').source, 'import');
}

console.log('Account model tests passed');
