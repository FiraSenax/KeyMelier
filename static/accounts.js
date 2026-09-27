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
// - A passkey and a code are linked only if their account names are equal
//   (case-insensitive); such a link is shown as "by name, not verified".
// - Only keys that are not marked as lost count as protection.
// - A key that was never read, or whose search was incomplete, is "unknown"
//   for that account – never "not there".

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

function accountName(u) {
  return String((u && (u.name || u.display)) || '').trim();
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
    const sitesSource = !e.sites ? null
      : e.probe || e.sites_probed ? 'probe'
        : e.sites.find(s => s.source)?.source || (imported ? 'import' : 'list');
    const checked = e.sites_updated || null;
    keyInfo.set(e.key_id, {
      // an interrupted search proves nothing about the sites it did not reach
      passkeysKnown: !!e.sites && !(e.probe && e.probe.complete === false),
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
        // never merged: one row per key and site
        const r = row(`pk?|${s.rp_id}|${e.key_id}`, { ...base, kind: 'unknown', account: '', count: unnamed });
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

// What a key shows for a row: 'passkey'/'code'/both, or 'none' (known absent) / 'unknown'
function cellState(model, r, keyId) {
  const h = r.holders.get(keyId);
  const linked = r.kind === 'passkey' ? r.links.map(c => c.holders.get(keyId)).find(Boolean) : null;
  if (h || linked) return { passkey: h?.passkey || 0, code: (h?.code || 0) + (linked?.code || 0), source: (h || linked).source, checked: (h || linked).checked };
  const info = model.keyInfo.get(keyId);
  const known = r.kind === 'code' ? info.codesKnown : info.passkeysKnown;
  return { absent: true, unknown: !known };
}

// Rows of one key whose protection depends on it (for the security check and the lost-key assistant)
function rowsOfKey(model, keyId) {
  return model.rows.filter(r => r.holders.has(keyId) && !(r.kind === 'code' && r.linkedTo));
}

if (typeof module !== 'undefined') {
  module.exports = { buildAccountModel, cellState, rowsOfKey, registrableDomain, serviceKey, STALE_DAYS };
}
