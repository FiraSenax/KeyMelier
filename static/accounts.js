/* global module */
// Account model shared by the account overview, the backup view, the
// lost-key assistant and the security check. Pure functions without DOM
// access – tested by tests/accounts_model.cjs.
//
// Rules (a wrong green light is worse than a missing one):
// - An account is identified exactly: passkeys by rpId + account name,
//   authenticator codes by issuer + account name. Display names and similar
//   domains only group rows for display; they never make two entries "the same".
// - Passkeys whose account name is unknown are never assigned to a named
//   account – they stay "unclear" until the key is searched with the PIN.
//   A display name ("Administrator") is shown, but never identifies an account.
// - A passkey and a code are linked only if their account names are equal
//   (case-insensitive); such a link is shown as "by name, not verified".
// - Only keys that are not marked as lost count as protection.
// - "Not there" needs proof for that exact website: a complete list from the
//   key (credential management), or a search answer "no credentials" for that
//   rpId. A search only covers the sites it asked; everything else, errors,
//   unsupported or PIN-required answers and incompletely listed sites stay
//   "unknown".

const MULTI_TLD = new Set(['co.uk', 'com.au', 'co.jp', 'co.nz', 'com.br', 'co.za', 'com.tr', 'co.in', 'com.mx']);
const STALE_DAYS = 90;

function registrableDomain(host) {
  const parts = String(host || '').toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const tail2 = parts.slice(-2).join('.');
  return (MULTI_TLD.has(tail2) ? parts.slice(-3) : parts.slice(-2)).join('.');
}

// "login.microsoft.com" / "Microsoft" / "GitHub" -> "microsoft" / "github"
function serviceKey(value) {
  let v = String(value || '').toLowerCase().trim();
  if (v.includes('.')) v = registrableDomain(v).split('.')[0];
  return v.replace(/[^a-z0-9]/g, '');
}

// The account name the service stored (user.name) – the only identity.
function accountName(u) {
  return String((u && u.name) || '').trim();
}

// Display name – for showing only
function userDisplay(u) {
  return String((u && u.display) || '').trim();
}

// How much a key's passkey data covers: 'full' (complete list from the key),
// 'probe' (only the sites a search asked, see e.probe_rp) or 'none'
function passkeyCoverage(e) {
  if (!e.sites) return e.probe || e.sites_probed != null ? 'probe' : 'none';
  return e.probe || e.sites_probed != null ? 'probe' : 'full';
}

function buildAccountModel(entries, now = Date.now()) {
  const keys = [...entries].sort((a, b) => (a.lost_since ? 1 : 0) - (b.lost_since ? 1 : 0));
  const isActive = keyId => !keys.find(k => k.key_id === keyId)?.lost_since;
  const groups = new Map();
  const rows = new Map();

  const group = (id, label, domain) => {
    if (!groups.has(id)) groups.set(id, { id, label, domain, rows: [] });
    return groups.get(id);
  };
  const row = (id, init) => {
    if (!rows.has(id)) {
      const r = { id, holders: new Map(), links: [], ...init };
      rows.set(id, r);
      group(r.group, r.groupLabel, r.domain).rows.push(r);
    }
    return rows.get(id);
  };
  const hold = (r, keyId, what, n, source, checked) => {
    const h = r.holders.get(keyId) || { passkey: 0, code: 0, source, checked };
    h[what] += n;
    r.holders.set(keyId, h);
  };

  // Per key: what is known, from where, how fresh
  const keyInfo = new Map();
  for (const e of keys) {
    const imported = !!e.snapshot?.imported;
    const coverage = passkeyCoverage(e);
    const sitesSource = coverage === 'none' ? null
      : coverage === 'probe' ? 'probe'
        : e.sites.find(s => s.source)?.source || (imported ? 'import' : 'list');
    const checked = e.sites_updated || null;
    const probeRp = e.probe_rp && typeof e.probe_rp === 'object' ? e.probe_rp : {};
    keyInfo.set(e.key_id, {
      coverage,
      probeRp,
      probedCount: Object.keys(probeRp).length,
      // the complete passkey list of this key is known (not just searched sites)
      passkeysKnown: coverage === 'full',
      codesKnown: !!e.inventory?.oath,
      sitesSource,
      probeIncomplete: e.probe?.complete === false,
      checked,
      codesChecked: e.inventory?.oath?.updated || null,
      stale: !!checked && now - new Date(checked).getTime() > STALE_DAYS * 86400e3,
      imported,
    });
  }

  for (const e of keys) {
    const info = keyInfo.get(e.key_id);
    for (const s of e.sites || []) {
      if (!s || !s.rp_id) continue;
      const domain = registrableDomain(s.rp_id);
      const base = { group: `d:${domain}`, groupLabel: s.name || domain, domain, rpId: s.rp_id };
      const source = s.source || info.sitesSource || 'list';
      const checked = s.checked || e.sites_updated;
      const named = (s.users || []).map(accountName).filter(Boolean);
      for (const name of named) {
        const r = row(`pk|${s.rp_id}|${name.toLowerCase()}`, { ...base, kind: 'passkey', account: name });
        hold(r, e.key_id, 'passkey', 1, source, checked);
      }
      const unnamed = Math.max(0, (s.count || 1) - named.length);
      if (unnamed) {
        // never merged: one row per key and site (display names only shown)
        const displays = [...new Set((s.users || []).filter(u => !accountName(u)).map(userDisplay).filter(Boolean))];
        const r = row(`pk?|${s.rp_id}|${e.key_id}`, { ...base, kind: 'unknown', account: '', count: unnamed, displays });
        hold(r, e.key_id, 'passkey', unnamed, source, checked);
      }
    }
  }
  // Codes after all passkeys, so they can be shown with the passkey's service
  for (const e of keys) {
    const info = keyInfo.get(e.key_id);
    for (const a of e.inventory?.oath?.items || []) {
      const issuer = String(a.issuer || '').trim();
      const name = String(a.name || '').trim();
      const svc = serviceKey(issuer || name);
      // shown with a passkey service whose domain starts with the issuer name ("GitHub" -> github.com)
      const pkGroup = [...groups.values()].find(g => g.domain && g.domain.split('.')[0] === svc);
      const r = row(`code|${issuer.toLowerCase()}|${name.toLowerCase()}`, {
        kind: 'code', account: name, issuer,
        group: pkGroup ? pkGroup.id : `i:${svc}`, groupLabel: pkGroup ? pkGroup.label : (issuer || name),
        domain: pkGroup ? pkGroup.domain : '',
      });
      hold(r, e.key_id, 'code', 1, info.imported ? 'import' : 'list', e.inventory.oath.updated);
    }
  }

  // Link codes to passkeys of the same account name in the same group (by name only)
  for (const g of groups.values()) {
    for (const code of g.rows.filter(r => r.kind === 'code' && r.account)) {
      const pk = g.rows.find(r => r.kind === 'passkey' && r.account.toLowerCase() === code.account.toLowerCase());
      if (pk) { pk.links.push(code); code.linkedTo = pk; }
    }
  }

  const activeWith = (r, what) => [...r.holders].filter(([k, h]) => h[what] > 0 && isActive(k)).map(([k]) => k);
  for (const r of rows.values()) {
    if (r.kind === 'unknown') {
      const [keyId] = [...r.holders.keys()];
      r.status = isActive(keyId) ? 'unclear' : 'unclear_lost';
      r.level = isActive(keyId) ? 'unclear' : 'crit';
      r.activeKeys = isActive(keyId) ? [keyId] : [];
      continue;
    }
    if (r.kind === 'passkey') {
      const pk = activeWith(r, 'passkey');
      const codes = [...new Set(r.links.flatMap(c => activeWith(c, 'code')))].filter(k => !pk.includes(k));
      r.activeKeys = pk;
      r.codeKeys = codes;
      if (pk.length >= 2) [r.status, r.level] = ['passkey_multi', 'ok'];
      else if (pk.length === 1 && codes.length) [r.status, r.level] = ['passkey_code', 'info'];
      else if (pk.length === 1) [r.status, r.level] = ['passkey_single', 'warn'];
      else if (codes.length) [r.status, r.level] = ['passkey_lost_code', 'warn'];
      else [r.status, r.level] = ['lost_only', 'crit'];
      continue;
    }
    // code rows
    const c = activeWith(r, 'code');
    r.activeKeys = c;
    if (r.linkedTo) [r.status, r.level] = ['linked', r.linkedTo.level || 'info'];
    else if (c.length >= 2) [r.status, r.level] = ['codes_multi', 'info'];
    else if (c.length === 1) [r.status, r.level] = ['code_single', 'warn'];
    else [r.status, r.level] = ['lost_only', 'crit'];
  }
  // linked code rows take the level of their passkey row (computed above)
  for (const r of rows.values()) if (r.kind === 'code' && r.linkedTo) r.level = r.linkedTo.level;

  const rank = { crit: 0, warn: 1, unclear: 2, info: 3, ok: 4 };
  const sorted = [...groups.values()].map(g => {
    g.rows.sort((a, b) => rank[a.level] - rank[b.level] || a.account.localeCompare(b.account));
    g.level = g.rows.filter(r => !(r.kind === 'code' && r.linkedTo))
      .reduce((w, r) => (rank[r.level] < rank[w] ? r.level : w), 'ok');
    return g;
  }).sort((a, b) => rank[a.level] - rank[b.level] || a.label.localeCompare(b.label));

  return { keys, groups: sorted, rows: [...rows.values()], keyInfo };
}

// Is there provably NO passkey for rpId (and, if given, this account) on the
// key? 'absent' needs proof for exactly this website; otherwise 'unknown'.
// (Holding it is checked by the caller via the row's holders.)
function passkeyAbsence(model, keyId, rpId, account) {
  const e = model.keys.find(k => k.key_id === keyId);
  const info = model.keyInfo.get(keyId);
  if (!e || !info) return 'unknown';
  const site = (e.sites || []).find(s => s && s.rp_id === rpId);
  const fullyNamed = site && !site.partial && (site.count || 1) <= (site.users || []).map(accountName).filter(Boolean).length;
  if (info.coverage === 'full') {
    if (!site) return 'absent';
    // other accounts of this site are listed by name: this one is not there
    return account && fullyNamed ? 'absent' : 'unknown';
  }
  if (info.coverage === 'probe') {
    const p = info.probeRp[rpId];
    if (!p) return 'unknown';                        // never asked
    if (p.status === 'none') return 'absent';        // the key said "no credentials" for this rpId
    if (p.status === 'found' && account && !p.partial && fullyNamed) return 'absent';
    return 'unknown';                                // error, unsupported, PIN required, partial
  }
  return 'unknown';
}

// What a key shows for a row: 'passkey'/'code'/both, or 'none' (known absent) / 'unknown'
function cellState(model, r, keyId) {
  const h = r.holders.get(keyId);
  const linked = r.kind === 'passkey' ? r.links.map(c => c.holders.get(keyId)).find(Boolean) : null;
  if (h || linked) return { passkey: h?.passkey || 0, code: (h?.code || 0) + (linked?.code || 0), source: (h || linked).source, checked: (h || linked).checked };
  if (r.kind === 'code') return { absent: true, unknown: !model.keyInfo.get(keyId)?.codesKnown };
  const absent = passkeyAbsence(model, keyId, r.rpId, r.kind === 'passkey' ? r.account : '') === 'absent';
  return { absent: true, unknown: !absent };
}

// Rows of one key whose protection depends on it (for the security check and the lost-key assistant)
function rowsOfKey(model, keyId) {
  return model.rows.filter(r => r.holders.has(keyId) && !(r.kind === 'code' && r.linkedTo));
}

// Categories of the account overview (its summary cards) = the rating levels.
// Filtering only selects rows; it never changes a rating.
const ACCOUNT_FILTERS = ['', 'crit', 'warn', 'unclear', 'info', 'ok'];

// Rows shown in the overview (codes linked to a passkey are shown with it)
function overviewRows(model) {
  return model.rows.filter(r => !(r.kind === 'code' && r.linkedTo));
}

// Rows for a category ('' = all) and a search text; a row matches when its
// website, issuer, account, display name, domain or service name contains it.
function filterAccountRows(model, { level = '', query = '' } = {}) {
  const q = String(query || '').toLowerCase().trim();
  const hay = r => [r.rpId, r.issuer, r.account, r.domain, r.groupLabel, ...(r.displays || []),
    ...r.links.flatMap(c => [c.issuer, c.account])].map(v => String(v || '').toLowerCase());
  return overviewRows(model).filter(r => (!level || r.level === level) && (!q || hay(r).some(v => v.includes(q))));
}

// Replacing an old key with a new one: what the old key holds, and what the
// new key technically shows for it. "found" is only claimed when the new key
// was read and holds the same identity (passkey: rpId + account name, code:
// issuer + name, OpenPGP: fingerprint). PIV certificates and OTP slots only
// match by subject/slot – a hint, not proof of the same key ("similar").
// Nothing here is ever "copied": device-bound private keys cannot leave a key.
function buildReplacePlan(model, oldId, newId) {
  const oldKey = model.keys.find(k => k.key_id === oldId);
  const newKey = model.keys.find(k => k.key_id === newId);
  if (!oldKey || !newKey || oldId === newId) return null;
  const newInfo = model.keyInfo.get(newId);
  const verdict = (found, known) => (found ? 'found' : known ? 'missing' : 'unknown');
  const pkVerdict = (found, rpId, account) => (found ? 'found'
    : passkeyAbsence(model, newId, rpId, account) === 'absent' ? 'missing' : 'unknown');

  const passkeys = model.rows
    .filter(r => (r.kind === 'passkey' || r.kind === 'unknown') && r.holders.get(oldId)?.passkey > 0)
    .map(r => {
      if (r.kind === 'unknown') {
        // account unknown: at most "the new key has some passkey for this site"
        const other = model.rows.find(o => o.rpId === r.rpId && o.kind !== 'code' && o.holders.get(newId)?.passkey > 0);
        const h = other?.holders.get(newId);
        return { id: `pk?:${r.rpId}`, kind: 'unknown', rpId: r.rpId, account: '', count: r.count, displays: r.displays,
          group: r.groupLabel, check: other ? 'similar' : pkVerdict(false, r.rpId, ''), source: h?.source, checked: h?.checked };
      }
      const h = r.holders.get(newId);
      return { id: `pk:${r.rpId}|${r.account.toLowerCase()}`, kind: 'passkey', rpId: r.rpId, account: r.account,
        group: r.groupLabel, check: pkVerdict(h?.passkey > 0, r.rpId, r.account), source: h?.source, checked: h?.checked };
    });

  const codes = model.rows
    .filter(r => r.kind === 'code' && r.holders.get(oldId)?.code > 0)
    .map(r => {
      const h = r.holders.get(newId);
      return { id: `oath:${r.issuer.toLowerCase()}|${r.account.toLowerCase()}`, kind: 'code', issuer: r.issuer, account: r.account,
        check: verdict(h?.code > 0, newInfo.codesKnown), source: h?.source, checked: h?.checked };
    });

  const inv = (key, section) => key.inventory?.[section];
  const cardItems = (section, idOf, strict) => {
    const mine = inv(oldKey, section)?.items || [];
    const theirs = inv(newKey, section);
    return mine.map(item => {
      const match = (theirs?.items || []).some(o => idOf(o) === idOf(item));
      return { id: `${section}:${idOf(item)}`, kind: section, item,
        check: match ? (strict ? 'found' : 'similar') : verdict(false, !!theirs), checked: theirs?.updated || null };
    });
  };
  return {
    oldKey, newKey,
    passkeys, codes,
    openpgp: cardItems('openpgp', i => String(i.fingerprint || '').toLowerCase(), true),
    piv: cardItems('piv', i => String(i.label || ''), false),
    otp: cardItems('otp', i => String(i.otp_slot || ''), false),
  };
}

function replacePlanItems(plan) {
  return plan ? [...plan.passkeys, ...plan.codes, ...plan.openpgp, ...plan.piv, ...plan.otp] : [];
}

if (typeof module !== 'undefined') {
  module.exports = { buildAccountModel, cellState, passkeyAbsence, rowsOfKey, overviewRows, filterAccountRows, ACCOUNT_FILTERS, buildReplacePlan, replacePlanItems, registrableDomain, serviceKey, STALE_DAYS };
}
