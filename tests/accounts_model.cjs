// Regression tests for static/accounts.js – each case is a misclassification
// that must not happen again (node tests/accounts_model.cjs).
const assert = require('node:assert/strict');
const { buildAccountModel, cellState, passkeyAbsence, rowsOfKey, registrableDomain, buildReplacePlan, replacePlanItems } = require('../static/accounts.js');

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

// 7. Key replacement: only exact identities count as "found" on the new key
{
  const oldKey = key('OLD', {
    sites: [site('github.com', ['erika']), site('login.microsoft.com', ['a@c.com', 'b@c.com']), site('webauthn.io', [], { count: 1 })],
    sites_updated: day(1),
    inventory: {
      oath: { items: [{ issuer: 'GitHub', name: 'erika' }, { issuer: 'AWS', name: 'root' }], updated: day(1) },
      openpgp: { items: [{ slot: 'sig', fingerprint: 'AAAA' }, { slot: 'enc', fingerprint: 'BBBB' }], updated: day(1) },
      piv: { items: [{ slot: '9a', label: '9A: CN=erika' }], updated: day(1) },
    },
  });
  const fresh = key('NEW');  // never read
  let m = buildAccountModel([oldKey, fresh], NOW);
  let p = buildReplacePlan(m, 'OLD', 'NEW');
  assert.ok(replacePlanItems(p).every(i => i.check === 'unknown'), 'a new key that was never read proves nothing');
  assert.equal(p.passkeys.length, 4);
  assert.equal(buildReplacePlan(m, 'OLD', 'OLD'), null, 'old and new must differ');

  const read = key('NEW', {
    sites: [site('github.com', ['erika']), site('login.microsoft.com', ['a@c.com']), site('webauthn.io', ['someone'])],
    sites_updated: day(0),
    inventory: {
      oath: { items: [{ issuer: 'GitHub', name: 'erika' }], updated: day(0) },
      openpgp: { items: [{ slot: 'sig', fingerprint: 'aaaa' }], updated: day(0) },
      piv: { items: [{ slot: '9a', label: '9A: CN=erika' }], updated: day(0) },
    },
  });
  m = buildAccountModel([oldKey, read], NOW);
  p = buildReplacePlan(m, 'OLD', 'NEW');
  const by = id => replacePlanItems(p).find(i => i.id === id).check;
  assert.equal(by('pk:github.com|erika'), 'found');
  assert.equal(by('pk:login.microsoft.com|a@c.com'), 'found');
  assert.equal(by('pk:login.microsoft.com|b@c.com'), 'missing', 'another UPN of the same service is not a replacement');
  assert.equal(by('pk?:webauthn.io'), 'similar', 'a nameless passkey only matches the site, never the account');
  assert.equal(by('oath:github|erika'), 'found');
  assert.equal(by('oath:aws|root'), 'missing');
  assert.equal(by('openpgp:aaaa'), 'found');
  assert.equal(by('openpgp:bbbb'), 'missing');
  assert.equal(by('piv:9A: CN=erika'), 'similar', 'same certificate subject is a hint, not the same key');

  // an interrupted search on the new key cannot prove anything is missing
  const partial = { ...read, sites: [], probe: { complete: false } };
  m = buildAccountModel([oldKey, partial], NOW);
  p = buildReplacePlan(m, 'OLD', 'NEW');
  assert.ok(p.passkeys.every(i => i.check === 'unknown'));
}

// 8. Display names never identify an account (review 1.5.0, task 1)
{
  const shown = (rp, display, extra = {}) => ({ rp_id: rp, count: 1, users: [{ name: '', display }], source: 'list', checked: day(1), ...extra });
  // repro: same display name on two keys was rated passkey_multi
  let m = buildAccountModel([
    key('A', { sites: [shown('example.com', 'Administrator')], sites_updated: day(1) }),
    key('B', { sites: [shown('example.com', 'Administrator')], sites_updated: day(1) }),
  ], NOW);
  assert.ok(m.rows.every(r => r.kind === 'unknown' && r.status === 'unclear'), 'equal display names are no identity');
  assert.equal(m.rows.length, 2, 'never merged');
  assert.ok(!m.rows.some(r => r.level === 'ok' || r.level === 'info'));
  assert.deepEqual(m.rows[0].displays, ['Administrator'], 'display name kept for showing only');

  // named account on one key, same text only as display name on the other
  m = buildAccountModel([
    key('A', { sites: [site('example.com', ['erika'])], sites_updated: day(1) }),
    key('B', { sites: [shown('example.com', 'erika')], sites_updated: day(1) }),
  ], NOW);
  assert.equal(find(m, r => r.account === 'erika').status, 'passkey_single');
  assert.equal(find(m, r => r.kind === 'unknown').status, 'unclear');
  assert.equal(cellState(m, find(m, r => r.account === 'erika'), 'B').unknown, true, 'B may or may not hold it');

  // completely nameless entries
  m = buildAccountModel([
    key('A', { sites: [{ rp_id: 'example.com', count: 2, users: [] }], sites_updated: day(1) }),
    key('B', { sites: [{ rp_id: 'example.com', count: 1, users: [{ name: '', display: '' }] }], sites_updated: day(1) }),
  ], NOW);
  assert.ok(m.rows.every(r => r.status === 'unclear'));
  assert.equal(m.rows.find(r => r.holders.has('A')).count, 2);

  // lost-key assistant: a lost key's display-only entry never shows a backup
  m = buildAccountModel([
    key('L', { lost_since: day(1), sites: [shown('example.com', 'Administrator')], sites_updated: day(5) }),
    key('B', { sites: [shown('example.com', 'Administrator')], sites_updated: day(1) }),
  ], NOW);
  const mine = rowsOfKey(m, 'L');
  assert.equal(mine.length, 1);
  assert.equal(mine[0].status, 'unclear_lost');
  assert.deepEqual(mine[0].activeKeys, [], 'no backup via display name');

  // key replacement: display-only on the new key is at most "similar"
  m = buildAccountModel([
    key('OLD', { sites: [shown('example.com', 'Administrator'), site('github.com', ['erika'])], sites_updated: day(1) }),
    key('NEW', { sites: [shown('example.com', 'Administrator'), shown('github.com', 'erika')], sites_updated: day(0) }),
  ], NOW);
  const p = buildReplacePlan(m, 'OLD', 'NEW');
  assert.equal(p.passkeys.find(i => i.id === 'pk?:example.com').check, 'similar');
  assert.equal(p.passkeys.find(i => i.id === 'pk:github.com|erika').check, 'unknown',
    'a display name "erika" on the new key neither proves nor disproves the account');
}

// 9. Search coverage per rpId (review 1.5.0, task 2)
{
  const A = key('A', { sites: [site('example.com', ['erika']), site('shop.com', ['erika'])], sites_updated: day(1) });
  const probed = (probe_rp, extra = {}) => key('B', { sites: [], sites_updated: day(0), sites_probed: Object.keys(probe_rp).length,
    probe: { complete: true, asked: Object.keys(probe_rp).length }, probe_rp, ...extra });
  const at = (m, rp) => cellState(m, find(m, r => r.rpId === rp), 'B');

  // repro: a complete search only for different.com said "not there" for example.com
  let m = buildAccountModel([A, probed({ 'different.com': { status: 'none', checked: day(0) } })], NOW);
  assert.equal(at(m, 'example.com').unknown, true, 'not asked = unknown');
  assert.equal(m.keyInfo.get('B').coverage, 'probe');
  assert.equal(m.keyInfo.get('B').passkeysKnown, false, 'search finished ≠ complete list');

  // explicit "no credentials" proves absence for exactly that rpId
  m = buildAccountModel([A, probed({ 'example.com': { status: 'none', checked: day(0) } })], NOW);
  assert.equal(at(m, 'example.com').unknown, false);
  assert.equal(at(m, 'shop.com').unknown, true);

  // errors, unsupported, PIN required prove nothing
  for (const status of ['error', 'unsupported', 'uv_required']) {
    m = buildAccountModel([A, probed({ 'example.com': { status, checked: day(0) } })], NOW);
    assert.equal(at(m, 'example.com').unknown, true, status);
  }

  // a hit with an incomplete account list does not prove other accounts missing
  const hitB = (partial) => key('B', { sites: [{ rp_id: 'example.com', count: partial ? 3 : 1, users: [{ name: 'other', display: '' }], ...(partial ? { partial: true } : {}) }],
    sites_updated: day(0), sites_probed: 1, probe: { complete: true, asked: 1 },
    probe_rp: { 'example.com': { status: 'found', checked: day(0), ...(partial ? { partial: true } : {}) } } });
  m = buildAccountModel([A, hitB(true)], NOW);
  assert.equal(at(m, 'example.com').unknown, true, 'partial hit');
  m = buildAccountModel([A, hitB(false)], NOW);
  assert.equal(at(m, 'example.com').unknown, false, 'complete, fully named hit: erika is not there');

  // cancelled search: the answers it got still count, the rest stays unknown
  m = buildAccountModel([A, probed({ 'example.com': { status: 'none', checked: day(0) } }, { probe: { complete: false, asked: 1 } })], NOW);
  assert.equal(at(m, 'example.com').unknown, false);
  assert.equal(at(m, 'shop.com').unknown, true);

  // old or imported search data without per-site results: unknown
  m = buildAccountModel([A, key('B', { sites: [], sites_updated: day(0), sites_probed: 70, probe: { complete: true, asked: 70 } })], NOW);
  assert.equal(at(m, 'example.com').unknown, true, 'legacy probe');
  m = buildAccountModel([A, key('B', { sites: [], sites_updated: day(0), sites_probed: 70, snapshot: { imported: true } })], NOW);
  assert.equal(at(m, 'example.com').unknown, true, 'imported probe');

  // a complete list from the key still proves absence
  m = buildAccountModel([A, key('B', { sites: [], sites_updated: day(0) })], NOW);
  assert.equal(at(m, 'example.com').unknown, false);
  assert.equal(passkeyAbsence(m, 'B', 'example.com', 'erika'), 'absent');

  // key replacement uses the same rule: missing only with proof
  m = buildAccountModel([A, probed({ 'example.com': { status: 'none', checked: day(0) } })], NOW);
  const plan = buildReplacePlan(m, 'A', 'B');
  assert.equal(plan.passkeys.find(i => i.rpId === 'example.com').check, 'missing');
  assert.equal(plan.passkeys.find(i => i.rpId === 'shop.com').check, 'unknown');
}

console.log('Account model tests passed');
