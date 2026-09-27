// KeyMelier – account overview
//
// The account model (static/accounts.js) as a filterable matrix: summary
// cards as filters, search, sticky header, next-step explanations.
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js ($, t, escHtml, call,
// icon, render …) only inside functions, never while loading.

// One model for account overview, backup view, lost-key assistant and the
// security check (static/accounts.js) – so they can never disagree.
function accountModel() {
  return buildAccountModel([...historyKeys.values()]);
}

// "2 accounts without a known name (shown as “Administrator”)" – display names only for reading
function unknownAccountLabel(r) {
  const base = t(r.count === 1 ? 'acc.unknownAccount1' : 'acc.unknownAccounts', { n: r.count });
  return r.displays?.length ? `${base} (${t('acc.shownAs', { name: r.displays.join(', ') })})` : base;
}

// ── Accounts overview (personal mode) ───────────────────────────────────────

function personalMode() {
  return appSettings.personal_mode !== false;
}

// Logo for a service where the brand allows it (static/service-icons.js),
// otherwise the first letter. Bundled – nothing is loaded from the network.
function serviceAvatar(...names) {
  const icons = typeof SERVICE_ICONS === 'object' ? SERVICE_ICONS : {};
  for (const n of names) {
    const ic = icons[serviceKey(n)];
    if (ic) {
      return `<span class="pk-avatar svc-logo" title="${escHtml(ic.title)}"><svg viewBox="0 0 24 24" aria-hidden="true">
        <path fill="#${escHtml(ic.hex)}" d="${escHtml(ic.path)}"/></svg></span>`;
    }
  }
  // Letter: prefer a service name ("Microsoft") over a domain ("login.microsoft.com")
  const first = String(names.find(n => n && !String(n).includes('.')) || serviceKey(names.find(Boolean)) || '?');
  return `<span class="pk-avatar">${escHtml((first[0] || '?').toUpperCase())}</span>`;
}

let accFilter = '';        // search text
let accLevel = '';         // category ('' = all), see ACCOUNT_FILTERS
const accNextOpen = new Set();   // rows whose "next step" is expanded

const STATUS_TEXT = {
  passkey_multi: r => t('acc.st.passkeyMulti', { n: r.activeKeys.length }),
  passkey_code: r => t('acc.st.passkeyCode', { key: keyLabel(historyKeys.get(r.activeKeys[0])) }),
  passkey_single: r => t('acc.st.single', { key: keyLabel(historyKeys.get(r.activeKeys[0])) }),
  passkey_lost_code: r => t('acc.st.passkeyLostCode', { key: r.codeKeys.map(k => keyLabel(historyKeys.get(k))).join(', ') }),
  codes_multi: r => t('acc.st.codesOnly', { n: r.activeKeys.length }),
  code_single: r => t('acc.st.single', { key: keyLabel(historyKeys.get(r.activeKeys[0])) }),
  lost_only: () => t('acc.st.lostOnly'),
  unclear: r => t('acc.st.unclear', { key: keyLabel(historyKeys.get([...r.holders.keys()][0])) }),
  unclear_lost: () => t('acc.st.unclearLost'),
  linked: () => '',
};

// Summary cards: totals per category; as buttons they filter the overview
const ACC_CARDS = [['', 'acc.sum.accounts'], ['crit', 'acc.sum.lost'], ['warn', 'acc.sum.single'],
  ['unclear', 'acc.sum.unclear'], ['info', 'acc.sum.codes'], ['ok', 'acc.sum.ok']];

function accSummaryHtml(rows, clickable = false, active = null) {
  const count = lvl => (lvl ? rows.filter(r => r.level === lvl).length : rows.length);
  return ACC_CARDS.map(([lvl, key]) => {
    const inner = `<b>${count(lvl)}</b><span>${escHtml(t(key))}</span>`;
    if (!clickable) return `<div class="acc-stat ${lvl}">${inner}</div>`;
    const on = active === lvl;
    return `<button type="button" class="acc-stat ${lvl}${on ? ' active' : ''}" data-acc-filter="${lvl}"
      ${active !== null ? `aria-pressed="${on}"` : ''}>${inner}</button>`;
  }).join('');
}

function keyFreshness(info) {
  if (info.coverage === 'none' && !info.codesKnown) return t('acc.fresh.never');
  const src = info.probeIncomplete ? t('acc.src.probeIncomplete')
    : info.coverage === 'probe' ? t('acc.probedN', { n: info.probedCount })
      : info.sitesSource ? t(`acc.src.${info.sitesSource}`) : '';
  const when = info.checked || info.codesChecked;
  return [src, when ? t(info.stale ? 'acc.fresh.stale' : 'acc.fresh.read', { when: relTime(when) }) : ''].filter(Boolean).join(' · ');
}

// What to do next for a problem row – explanation only, nothing is done automatically
const NEXT_STEP = {
  lost_only: () => t('acc.next.lostOnly'),
  passkey_single: () => t('acc.next.passkeySingle'),
  code_single: () => t('acc.next.codeSingle'),
  passkey_lost_code: r => t('acc.next.passkeyLostCode', { key: (r.codeKeys || []).map(k => keyLabel(historyKeys.get(k))).join(', ') }),
  unclear: () => t('acc.next.unclear'),
  unclear_lost: () => t('acc.next.unclearLost'),
};

function renderAccountsView() {
  $('accounts-avatar').innerHTML = icon('passkey', 30);
  const el = $('accounts-content');
  const m = accountModel();
  const all = overviewRows(m);
  if (!all.length) {
    el.innerHTML = `<div class="callout"><div class="callout-title">${escHtml(t('acc.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('acc.empty.text'))}</div></div>`;
    return;
  }
  const shown = new Set(filterAccountRows(m, { level: accLevel, query: accFilter }));
  const cols = m.keys.length + 1;
  const head = m.keys.map(k => {
    const info = m.keyInfo.get(k.key_id);
    const free = k.snapshot?.remaining_disc_creds;
    return `<th class="acc-key${k.lost_since ? ' lost' : ''}" scope="col">${escHtml(keyLabel(k))}
      <span class="acc-sub">${escHtml(serialLabel(k.snapshot))}</span>
      <span class="acc-sub${info.stale || info.probeIncomplete ? ' warn-text' : ''}">${escHtml(k.lost_since ? t('bk.lostBadge') : keyFreshness(info))}</span>
      ${!k.lost_since && free != null ? `<span class="acc-sub">${escHtml(t('acc.free', { n: free }))}</span>` : ''}</th>`;
  }).join('');
  const cells = r => m.keys.map(k => {
    const c = cellState(m, r, k.key_id);
    const lost = k.lost_since ? ' lost' : '';
    if (c.absent) {
      return c.unknown ? `<td class="unknown${lost}" title="${escHtml(t('acc.cell.unknown'))}"><span aria-hidden="true">?</span><span class="sr-only">${escHtml(t('acc.cell.unknown'))}</span></td>`
        : `<td class="no${lost}" title="${escHtml(t('acc.cell.absent'))}"><span aria-hidden="true">–</span><span class="sr-only">${escHtml(t('acc.cell.absent'))}</span></td>`;
    }
    const tags = [c.passkey ? `<span class="pill on">${escHtml(c.passkey > 1 ? `${t('acc.passkey')} ×${c.passkey}` : t('acc.passkey'))}</span>` : '',
      c.code ? `<span class="pill">${escHtml(t('acc.code'))}</span>` : ''].join('');
    const src = t(`acc.src.${c.source || 'list'}`) + (c.checked ? ` · ${relTime(c.checked)}` : '');
    return `<td class="yes${lost}" title="${escHtml(src)}">${tags}${c.source && c.source !== 'list' ? `<span class="acc-src">${escHtml(t(`acc.src.${c.source}`))}</span>` : ''}</td>`;
  }).join('');
  const rowHtml = (r, g) => {
    const label = r.kind === 'unknown' ? unknownAccountLabel(r) : r.account || r.issuer;
    const sub = r.kind === 'code' ? t('acc.kind.code') : r.rpId !== g.domain ? r.rpId : '';
    const link = r.kind === 'passkey' && r.links.length ? `<span class="acc-note">${escHtml(t('acc.linkedByName'))}</span>` : '';
    const next = NEXT_STEP[r.status];
    const open = next && accNextOpen.has(r.id);
    const nextId = `acc-next-${escHtml(r.id).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
    return `<tr class="acc-sub-row acc-${r.level}"><th scope="row" class="acc-name acc-indent">
      <span><span class="acc-upn">${escHtml(label)}</span>${sub ? `<span class="acc-note">${escHtml(sub)}</span>` : ''}
      <span class="acc-note acc-status">${escHtml(STATUS_TEXT[r.status](r))}</span>${link}
      ${next ? `<button type="button" class="btn-link acc-next-btn" data-next="${escHtml(r.id)}" aria-expanded="${!!open}" aria-controls="${nextId}">${escHtml(t('acc.next'))}</button>` : ''}</span></th>${cells(r)}</tr>
      ${open ? `<tr class="acc-next-row" id="${nextId}"><td colspan="${cols}"><div class="acc-next-text">${escHtml(next(r))}</div></td></tr>` : ''}`;
  };
  const body = m.groups.map(g => {
    const rows = g.rows.filter(r => shown.has(r));
    if (!rows.length) return '';
    return `<tr class="acc-group acc-${g.level}"><td class="acc-name" colspan="${cols}"><span class="acc-group-label">${serviceAvatar(g.domain, g.label)}
        <span><span class="acc-label">${escHtml(g.label)}</span>${g.domain && g.domain !== g.label ? `<span class="acc-note">${escHtml(g.domain)}</span>` : ''}</span></span></td></tr>`
      + rows.map(r => rowHtml(r, g)).join('');
  }).join('');
  const activeCard = ACC_CARDS.find(([lvl]) => lvl === accLevel);
  const filtered = accLevel || accFilter.trim();
  const status = filtered
    ? `<div class="acc-filter-state" role="status">
        <span>${escHtml(t('acc.filter.count', { n: shown.size, total: all.length }))}</span>
        ${accLevel ? `<span class="pill on">${escHtml(t(activeCard[1]))}</span>` : ''}
        ${accFilter.trim() ? `<span class="pill">„${escHtml(accFilter.trim())}“</span>` : ''}
        <button type="button" class="btn-link" data-acc-reset>${escHtml(t('acc.filter.reset'))}</button></div>`
    : `<div class="acc-filter-state" role="status"><span>${escHtml(t('acc.filter.all', { n: all.length }))}</span></div>`;
  el.innerHTML = `
    <div class="acc-summary" role="group" aria-label="${escHtml(t('acc.filter.label'))}">${accSummaryHtml(all, true, accLevel)}</div>
    <section class="card">
      <div class="acc-tools">
        <input type="search" id="acc-search" placeholder="${escHtml(t('acc.search'))}" value="${escHtml(accFilter)}" spellcheck="false" aria-label="${escHtml(t('acc.search'))}">
      </div>
      ${status}
      <ul class="acc-legend" aria-label="${escHtml(t('acc.legend.title'))}">
        <li><span class="pill on">${escHtml(t('acc.passkey'))}</span> <span class="pill">${escHtml(t('acc.code'))}</span> ${escHtml(t('acc.legend.yes'))}</li>
        <li><span class="acc-legend-mark">–</span> ${escHtml(t('acc.legend.no'))}</li>
        <li><span class="acc-legend-mark">?</span> ${escHtml(t('acc.legend.unknown'))}</li>
      </ul>
      ${shown.size ? `<div class="bk-table-wrap acc-wrap" tabindex="0" aria-label="${escHtml(t('acc.title'))}"><table class="bk-table acc-table">
        <thead><tr><th scope="col" class="acc-corner">${escHtml(t('acc.service'))}</th>${head}</tr></thead>
        <tbody>${body}</tbody>
      </table></div>` : `<div class="acc-empty"><p>${escHtml(t('acc.filter.empty'))}</p>
        <button type="button" class="btn btn-secondary" data-acc-reset>${escHtml(t('acc.filter.reset'))}</button></div>`}
      <details class="acc-more"><summary>${escHtml(t('acc.limits.title'))}</summary>
        <p class="field-hint bk-hint">${escHtml(t('acc.limits'))}</p>
        <p class="field-hint bk-hint">${escHtml(t('acc.legend.source'))}</p></details>
    </section>`;
}

function showAccountsView() {
  mainView = 'accounts';
  render();
}

function showBackupView() {
  mainView = 'backup';
  render();
  loadSync();
}

function renderTiles(token) {
  const o = token.options || {};
  const tiles = [];
  const notes = [];   // optional hardware or functions the key does not have – one compact line
  const tile = spec => tileHtml({ ...spec, tab: spec.tab && tabAllowed(token, spec.tab) ? spec.tab : null });
  const entry = historyKeys.get(token.history_id);
  const m = accountModel();
  const info = entry && m.keyInfo.get(entry.key_id);

  // Passkeys on the key: what is known (never "0" for "not read")
  const known = info && info.coverage !== 'none';
  const count = (entry?.sites || []).reduce((n, site) => n + (site.count || 1), 0);
  const free = token.remaining_disc_creds != null ? t('tile.passkeys.free', { n: token.remaining_disc_creds }) : '';
  if (!known) {
    tiles.push(tile({ cls: 'neutral', iconName: 'passkey', label: t('tile.passkeys'), primary: true,
      value: t('tile.notRead'), sub: [t(canManage(token) ? 'tile.readHint' : 'tile.searchHint'), free].filter(Boolean).join(' · '), tab: 'passkeys' }));
  } else {
    const how = info.coverage === 'probe' ? t('tile.passkeys.bySearch', { n: info.probedCount }) : t('acc.fresh.read', { when: relTime(info.checked) });
    tiles.push(tile({ cls: 'info', iconName: 'passkey', label: t('tile.passkeys'), primary: true,
      value: t(count === 1 ? 'tile.passkeys.count1' : 'tile.passkeys.count', { n: count }), sub: [how, free].filter(Boolean).join(' · '), tab: 'passkeys' }));
  }

  // Authenticator accounts (only keys with the OATH application)
  const oath = entry?.inventory?.oath;
  if (tabAllowed(token, 'oath') || oath) {
    tiles.push(tile({ cls: oath ? 'info' : 'neutral', iconName: 'key', label: t('tile.oath'), primary: true,
      value: oath ? t(oath.items.length === 1 ? 'tile.oath.count1' : 'tile.oath.count', { n: oath.items.length }) : t('tile.notRead'),
      sub: oath ? t('acc.fresh.read', { when: relTime(oath.updated) }) : t('tile.readHint'), tab: 'oath' }));
  }

  // Open tasks: accounts that depend on this key (personal mode)
  const acc = accountCheck(token);
  if (acc) {
    tiles.push(tileHtml({ cls: acc.n ? 'warn' : acc.n === 0 ? 'ok' : 'neutral', iconName: 'shield', label: t('tile.accounts'), primary: true,
      value: acc.text, sub: t('tile.accounts.sub'), view: 'accounts' }));
  }

  // PIN
  if (!('clientPin' in o)) {
    notes.push(t('tile.pin.unsupportedNote'));
  } else if (!o.clientPin) {
    tiles.push(tile({ cls: 'warn', iconName: 'lock', label: t('tile.pin'), value: t('tile.pin.notSet'),
      sub: t('tile.pin.notSetHint'), tab: 'pin' }));
  } else {
    tiles.push(tile({ cls: token.force_pin_change ? 'warn' : 'ok', iconName: 'lock', label: t('tile.pin'),
      value: token.force_pin_change ? t('tile.pin.forceChange') : t('tile.pin.set'),
      sub: t('tile.pin.minLen', { n: token.min_pin_length }), tab: 'pin' }));
  }

  // Key check (the device – not the accounts)
  const secCls = { OK: 'ok', WARNING: 'warn', CRITICAL: 'crit' }[token.security_status] || 'neutral';
  const cves = token.cve_ids || [];
  const att = attestationSummary(token.attestation, token);
  tiles.push(tile({ cls: secCls, iconName: 'shield', label: t('tile.keycheck'),
    value: t(`status.${token.security_status}`),
    sub: `${cves.length ? t('tile.security.cves', { n: cves.length }) : t('tile.security.noCves')} · ${att.short}`,
    tab: 'security' }));

  // Fingerprint: a tile only when the key has a sensor
  if (isBio(token)) {
    const enrolled = (o.bioEnroll ?? o.userVerificationMgmtPreview ?? o.uv) === true;
    tiles.push(tile({ cls: enrolled ? 'ok' : 'info', iconName: 'fingerprint', label: t('tile.bio'),
      value: enrolled ? t('tile.bio.enrolled') : t('tile.bio.none'), sub: t('tile.passkeys.open'), tab: 'fingerprints' }));
  } else {
    notes.push(t('tile.bio.noSensorNote'));
  }

  $('tiles').innerHTML = tiles.join('') + (notes.length ? `<p class="tile-notes">${notes.map(n => `<span>${escHtml(n)}</span>`).join('')}</p>` : '');
}
