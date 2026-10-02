'use strict';

// Report UI errors to the Python log (the window has no visible console)
window.addEventListener('error', ev => {
  window.pywebview?.api?.client_error(`${ev.message} @ ${ev.filename}:${ev.lineno}`);
});
window.addEventListener('unhandledrejection', ev => {
  window.pywebview?.api?.client_error(`Unhandled: ${ev.reason?.stack || ev.reason}`);
});

const tokens = new Map(); // id -> token record from the server
let selectedId = null;
let activeTab = 'overview';
let pinState = null;      // last PIN status for the selected token
let mdsInfo = null;       // last MDS3 cache info
const historyKeys = new Map(); // key_id -> history summary
let selectedHist = null;  // key_id of a disconnected key shown from history
let histDetail = null;    // full history entry for the Verlauf tab
let histConfirmForget = false;
let dataStatus = null;    // freshness of advisories and FIDO metadata
const cardApps = new Map(); // token id -> { oath, piv, openpgp, otp } available on the smart card
const cardRetries = new Map();
let mainView = 'key';     // 'key' | 'backup' | 'accounts'
let appSettings = {};     // persisted settings (remember_sites, ...)
let lostKid = null;       // key selected in the lost-key assistant

const $ = id => document.getElementById(id);

// Calls a KeyService method through the pywebview bridge. Resolves with the
// result, rejects with an Error carrying the envelope (err.data.code etc.).
async function call(method, args = {}) {
  const res = await window.pywebview.api.call(method, args);
  if (!res || !res.ok) {
    const err = new Error(res?.error || 'Request failed');
    err.data = res || {};
    throw err;
  }
  return res.data;
}

// Localised message for an API error, falling back to the server's text
function errorMessage(e) {
  const code = e.data?.code;
  if (code === 'pin_invalid' && e.data.retries != null) return t('err.pin_invalid_n', { n: e.data.retries });
  // "this key cannot do that" – say what exactly
  if (code === 'unsupported' && e.data.reason && STRINGS.en[`err.unsupported.${e.data.reason}`]) return t(`err.unsupported.${e.data.reason}`);
  if (code && STRINGS[LANG][`err.${code}`]) return t(`err.${code}`);
  return e.message;
}

// Dropping a link or file would navigate the window (and hand the bridge to
// that page): swallow all drops.
for (const type of ['dragover', 'drop']) {
  document.addEventListener(type, e => e.preventDefault(), true);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  $('toast-container').appendChild(el);
  setTimeout(() => {
    el.classList.add('fade-out');
    el.addEventListener('animationend', () => el.remove());
  }, 3500);
}

const ICONS = {
  key: '<rect x="7" y="2" width="10" height="15" rx="3"/><path d="M10 17v4h4v-4"/><circle cx="12" cy="8" r="2"/>',
  fingerprint: '<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  lockOpen: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v4a6 6 0 0 1-12 0z"/><path d="M12 18v4"/>',
  pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/>',
  passkey: '<circle cx="9" cy="7" r="4"/><path d="M2 21v-2a4 4 0 0 1 4-4h6"/><circle cx="18" cy="14" r="2.5"/><path d="M18 16.5V22m0-2h2"/>',
  settings: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  more: '<circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
};

function icon(name, size = 18) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
}

// ── Key illustrations ───────────────────────────────────────────────────────

// Form factor from the key itself (YubiKey) or guessed from the model name
function formFactor(token) {
  if (token.form_factor) return token.form_factor;
  const text = `${token.mds_description || ''} ${token.product_name || ''}`.toLowerCase();
  const usbC = /usb-?c|type-?c|\bc\b|nfc-c|k33|k40|k45/.test(text);
  const shape = /nano/.test(text) ? 'nano' : (isBio(token) || /bio/.test(text)) ? 'bio' : 'keychain';
  return `usb-${usbC ? 'c' : 'a'}-${shape}`;
}

// Stylised drawing of the key (vertical, connector at the bottom)
function keyArt(token, size) {
  const ff = formFactor(token);
  const usbC = ff.includes('usb-c');
  const lightning = ff.includes('lightning');
  const nano = ff.includes('nano');
  const bio = ff.includes('bio') || isBio(token);
  const id = `g${Math.random().toString(36).slice(2, 8)}`;
  const connector = usbC
    ? `<rect x="25" y="${nano ? 44 : 47}" width="14" height="${nano ? 12 : 11}" rx="4" fill="url(#${id}m)"/><rect x="28" y="${nano ? 49 : 51.5}" width="8" height="2" rx="1" fill="#5d6679"/>`
    : `<rect x="21" y="${nano ? 44 : 47}" width="22" height="${nano ? 14 : 13}" rx="1.5" fill="url(#${id}m)"/><rect x="25" y="${nano ? 48 : 51}" width="4" height="3" fill="#5d6679"/><rect x="35" y="${nano ? 48 : 51}" width="4" height="3" fill="#5d6679"/>`;
  let body;
  if (nano) {
    body = `<rect x="20" y="30" width="24" height="15" rx="4" fill="url(#${id}b)"/><rect x="23" y="33" width="18" height="4" rx="2" fill="url(#${id}g)"/>`;
  } else if (bio) {
    body = `<rect x="16" y="4" width="32" height="44" rx="10" fill="url(#${id}b)"/><circle cx="32" cy="11" r="3" fill="#0c0f16"/>
      <rect x="23" y="19" width="18" height="18" rx="5" fill="url(#${id}g)"/>
      <g fill="none" stroke="#8a5a00" stroke-width="1.4" stroke-linecap="round"><path d="M27 31a5 5 0 0 1 10-3"/><path d="M29 33a3 3 0 0 1 6-2"/><path d="M26 27a7 7 0 0 1 12-2"/></g>`;
  } else {
    body = `<rect x="18" y="4" width="28" height="44" rx="8" fill="url(#${id}b)"/><circle cx="32" cy="11" r="3.2" fill="#0c0f16"/>
      <circle cx="32" cy="29" r="7" fill="url(#${id}g)"/>`;
  }
  const top = lightning ? `<rect x="28" y="0" width="8" height="6" rx="2" fill="url(#${id}m)"/>` : '';
  return `<svg class="key-art" width="${size}" height="${size}" viewBox="0 0 64 64" aria-hidden="true">
    <defs>
      <linearGradient id="${id}b" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3a4150"/><stop offset="1" stop-color="#151920"/></linearGradient>
      <linearGradient id="${id}g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffe89a"/><stop offset="0.5" stop-color="#f5bd12"/><stop offset="1" stop-color="#c47f00"/></linearGradient>
      <linearGradient id="${id}m" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.5" stop-color="#c9d0de"/><stop offset="1" stop-color="#7b869d"/></linearGradient>
    </defs>${top}${connector}${body}
  </svg>`;
}

// Illustration plus the vendor's logo (from the FIDO metadata) as a badge
function keyAvatar(token, size) {
  const src = token.mds_icon;
  const badge = typeof src === 'string' && src.startsWith('data:image/')
    ? `<img class="vendor-badge" src="${escHtml(src)}" alt="">` : '';
  return `<span class="key-art-wrap">${keyArt(token, size)}${badge}</span>`;
}


function isBio(token) {
  const o = token.options || {};
  return 'bioEnroll' in o || 'userVerificationMgmtPreview' in o || 'uv' in o;
}

function displayName(token) {
  const label = historyKeys.get(token.history_id)?.label;
  return label || token.mds_description || token.product_name || t('unknown');
}

function relTime(iso) {
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(LANG, { numeric: 'auto' });
  const steps = [[60, 'second'], [3600, 'minute', 60], [86400, 'hour', 3600], [2592000, 'day', 86400], [31536000, 'month', 2592000], [Infinity, 'year', 31536000]];
  for (const [limit, unit, div = 1] of steps) {
    if (Math.abs(diff) < limit) return rtf.format(Math.round(diff / div), unit);
  }
  return '';
}

// A disconnected key rendered from its last known snapshot
function offlineToken(entry) {
  return { ...entry.snapshot, history_id: entry.key_id, offline: true, last_seen: entry.last_seen };
}

// Tabs that make sense for a token (management needs the key plugged in)
const OFFLINE_TABS = ['overview', 'history', 'security', 'details'];
const CARD_TABS = { oath: 'oath', piv: 'piv', openpgp: 'openpgp', otp: 'otp' };
function tabAllowed(token, tab) {
  if (tab === 'fingerprints' && !isBio(token)) return false;
  if (CARD_TABS[tab]) return !token.offline && !!cardApps.get(token.id)?.[CARD_TABS[tab]];
  return !token.offline || OFFLINE_TABS.includes(tab);
}

function currentToken() {
  if (selectedId) return tokens.get(selectedId) || null;
  if (selectedHist && historyKeys.has(selectedHist)) return offlineToken(historyKeys.get(selectedHist));
  return null;
}

function firmwareKnown(token) {
  const fw = token.firmware_version_str || '';
  return fw && fw !== '0.0.0' && !/unknown/i.test(fw);
}

function buildKv(rows, monoKeys = []) {
  return rows.map(([k, v]) =>
    `<dt>${escHtml(k)}</dt><dd${monoKeys.includes(k) ? ' class="mono"' : ''}>${escHtml(v ?? '—')}</dd>`
  ).join('');
}

// { cls: pass|fail|partial|running, text } for an attestation result
function attestationSummary(att, token) {
  if (!att && token?.offline) return { cls: 'partial', text: t('sec.att.notRun'), short: t('tile.security.attPartial') };
  if (!att) return { cls: 'running', text: t('sec.att.running'), short: t('tile.security.attRunning') };
  if (token?.force_pin_change && !att.passed) {
    return { cls: 'partial', text: t('sec.att.needsPinChange'), short: t('tile.security.attNeedsPin') };
  }
  if (att.inconclusive) {
    // Keys that want PIN/UV for registrations: explain what this key needs
    const reason = att.inconclusive === 'needs_uv'
      ? ((token?.options || {}).uv === true ? 'needs_pin_bio' : 'needs_pin')
      : att.inconclusive;
    return { cls: 'partial', text: t(`sec.att.skip.${reason}`), short: t('tile.security.attSkipped'), skipped: true, reason: att.inconclusive };
  }
  const checks = att.checks || [];
  const pass = checks.filter(c => c.passed === true).length;
  const fail = checks.filter(c => c.passed === false).length;
  const skip = checks.filter(c => c.passed == null).length;
  if (att.status !== 'FAILED' && att.status !== 'VERIFIED') return { cls: 'partial', text: t('sec.att.unverified'), short: t('tile.security.attPartial') };
  if (fail > 0) return { cls: 'fail', text: t('sec.att.fail', { n: fail }), short: t('tile.security.attFail') };
  if (skip > 0) return { cls: 'partial', text: t('sec.att.partial', { p: pass, s: skip }), short: t('tile.security.attPartial') };
  if (att.status === 'VERIFIED' && att.passed && att.sig_valid === true && att.chain_valid === true && att.aaguid_match === true) return { cls: 'pass', text: t('sec.att.pass', { f: att.format || '—' }), short: t('tile.security.attPass') };
  return { cls: 'partial', text: t('sec.att.unverified'), short: t('tile.security.attPartial') };
}

// ── Sidebar ─────────────────────────────────────────────────────────────────

// "SN 31415926" – the serial is usually printed or engraved on the key
function serialLabel(tok) {
  return tok?.serial_number ? t('key.sn', { n: tok.serial_number }) : '';
}

function renderSidebar() {
  const list = $('key-list');
  $('key-list-empty').classList.toggle('hidden', tokens.size > 0);
  const live = new Set([...tokens.values()].map(tok => tok.history_id));
  const past = [...historyKeys.values()].filter(e => !live.has(e.key_id));
  $('history-label').classList.toggle('hidden', !past.length);
  $('history-list').innerHTML = past.map(e => {
    const tok = offlineToken(e);
    return `<button type="button" class="key-item offline${e.key_id === selectedHist && mainView === 'key' ? ' active' : ''}" data-hist="${escHtml(e.key_id)}">
      <span class="key-item-icon">${keyAvatar(tok, 28)}</span>
      <span class="key-item-text">
        <span class="key-item-name">${escHtml(displayName(tok))}</span>
        <span class="key-item-sub" title="${escHtml([serialLabel(tok), e.lost_since ? t('bk.lostBadge') : relTime(e.last_seen)].filter(Boolean).join(' · '))}">${escHtml([serialLabel(tok), e.lost_since ? t('bk.lostBadge') : relTime(e.last_seen)].filter(Boolean).join(' · '))}</span>
      </span>
      <span class="status-dot ${escHtml(tok.security_status || '')}" title="${escHtml(t(`status.${tok.security_status || 'UNKNOWN'}`))}"></span>
    </button>`;
  }).join('');
  list.innerHTML = [...tokens.values()].map(tok => `
    <button type="button" class="key-item${tok.id === selectedId && mainView === 'key' ? ' active' : ''}" data-id="${escHtml(tok.id)}">
      <span class="key-item-icon">${keyAvatar(tok, 28)}</span>
      <span class="key-item-text">
        <span class="key-item-name">${escHtml(displayName(tok))}</span>
        <span class="key-item-sub" title="${escHtml((serialLabel(tok) ? [serialLabel(tok), tok.manufacturer] : [tok.manufacturer, t(`status.${tok.security_status}`)]).filter(Boolean).join(' · '))}">${escHtml((serialLabel(tok) ? [serialLabel(tok), tok.manufacturer] : [tok.manufacturer, t(`status.${tok.security_status}`)]).filter(Boolean).join(' · '))}</span>
      </span>
      ${canManage(tok) && (tok.options?.clientPin || tok.options?.uv)
        ? `<span class="quick-lock${isUnlocked(tok.id) ? ' open' : ''}" data-unlock="${escHtml(tok.id)}" role="button" tabindex="0"
            title="${escHtml(t(isUnlocked(tok.id) ? 'ql.lock' : 'ql.unlock'))}">${icon(isUnlocked(tok.id) ? 'lockOpen' : 'lock', 15)}</span>`
        : `<span class="quick-lock" data-read="${escHtml(tok.id)}" role="button" tabindex="0" title="${escHtml(t('probe.sidebar'))}">${icon('refresh', 15)}</span>`}
      <span class="status-dot ${escHtml(tok.security_status)}" title="${escHtml(t(`status.${tok.security_status}`))}"></span>
    </button>`).join('');
}

function renderMds() {
  const box = $('mds-status');
  const text = $('mds-text');
  box.classList.remove('ok', 'error');
  if (!mdsInfo) return;
  if (mdsInfo.cached) {
    box.classList.add('ok');
    const ageH = Math.max(0, Math.round((Date.now() - new Date(mdsInfo.fetched_at).getTime()) / 3600000));
    text.textContent = t('mds.ok', { n: mdsInfo.entry_count });
    box.title = t('mds.age', { h: ageH });
  } else {
    box.classList.add('error');
    text.textContent = t('mds.unavailable');
  }
}

// ── Key view ────────────────────────────────────────────────────────────────

// Views that replace the key view (sidebar navigation)
const PANEL_VIEWS = { backup: 'backup-view', accounts: 'accounts-view', settings: 'settings-view', replace: 'replace-view',
  keys: 'keys-view' };

function render() {
  if (selectedId && !tokens.has(selectedId)) selectedId = null;
  if (selectedHist && !historyKeys.has(selectedHist)) selectedHist = null;
  if (!selectedId && !selectedHist && tokens.size) selectedId = tokens.keys().next().value;

  if (mainView === 'accounts' && !personalMode()) mainView = 'key';
  renderSidebar();
  $('nav-backup').classList.toggle('active', mainView === 'backup' || mainView === 'replace');
  $('nav-accounts').classList.toggle('active', mainView === 'accounts');
  $('nav-settings').classList.toggle('active', mainView === 'settings');
  $('nav-keys').classList.toggle('active', mainView === 'keys');
  $('nav-keys').classList.toggle('hidden', historyKeys.size + tokens.size < 2);
  $('nav-accounts').classList.toggle('hidden', !personalMode());
  for (const [view, id] of Object.entries(PANEL_VIEWS)) $(id).classList.toggle('hidden', mainView !== view);
  if (PANEL_VIEWS[mainView]) {
    $('empty-view').classList.add('hidden');
    $('key-view').classList.add('hidden');
    renderPanel();
    return;
  }
  const token = currentToken();
  $('empty-view').classList.toggle('hidden', !!token);
  $('key-view').classList.toggle('hidden', !token);
  if (token) renderKeyView(token);
  for (const tok of tokens.values()) loadCardApps(tok);  // cached; drives tabs and sidebar actions
}

// Re-render the open panel view (backup, accounts, settings, replace)
function renderPanel() {
  ({ backup: renderBackupView, accounts: renderAccountsView, settings: renderSettingsView,
    replace: renderReplaceView, keys: renderKeysView })[mainView]?.();
}

function renderKeyView(token) {
  $('key-avatar').innerHTML = keyAvatar(token, 48);
  $('key-title').textContent = displayName(token);
  const sub = [];
  if (token.offline) sub.push(t('hist.offline', { when: relTime(token.last_seen) }));
  sub.push(token.manufacturer);
  if (!token.offline && token.mds_description && token.product_name) sub.push(token.product_name);
  if (firmwareKnown(token)) sub.push(t('header.fw', { v: token.firmware_version_str }));
  sub.push(serialLabel(token));
  $('key-subtitle').textContent = sub.filter(Boolean).join(' · ');
  $('key-view').classList.toggle('offline', !!token.offline);
  $('read-btn').classList.toggle('hidden', !!token.offline);
  $('key-actions-btn').closest('.menu-wrap').classList.toggle('hidden', !!token.offline);
  $('key-actions-btn').innerHTML = icon('more', 18);
  $('key-actions-btn').setAttribute('aria-label', t('actions.more'));

  // Two separate statements: the device itself, and the accounts that depend on it
  const pill = $('key-status');
  pill.className = `status-pill ${token.security_status}`;
  pill.textContent = t('keycheck.pill', { s: t(`status.${token.security_status}`) });
  const acc = accountCheck(token);
  const accPill = $('acc-status');
  accPill.classList.toggle('hidden', !acc);
  if (acc) {
    accPill.className = `status-pill acc-pill ${acc.cls}`;
    accPill.textContent = t('acccheck.pill', { s: acc.text });
  }

  $('touch-banner').classList.toggle('hidden', !!token.attestation || !!token.offline);
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('hidden', !tabAllowed(token, b.dataset.tab)));
  if (!tabAllowed(token, activeTab)) switchTab('overview');
  syncTabMore();

  renderTiles(token);
  renderCapabilities(token);
  renderSecurityCheck(token);
  renderSettings(token);
  renderSecurity(token);
  renderDetails(token);
}

function tileHtml({ cls, iconName, label, value, sub, tab, view, primary }) {
  const target = tab || view;
  const tag = target ? 'button' : 'div';
  return `
    <${tag} ${tab ? `type="button" data-goto="${tab}"` : view ? `type="button" data-view="${view}"` : ''} class="tile ${cls}${primary ? ' primary' : ''}">
      <div class="tile-head">
        <span class="tile-icon">${icon(iconName)}</span>
        <span class="tile-label">${escHtml(label)}</span>
      </div>
      <div class="tile-value">${escHtml(value)}</div>
      ${sub ? `<div class="tile-sub">${escHtml(sub)}</div>` : ''}
    </${tag}>`;
}

// ── Security check ──────────────────────────────────────────────────────────

// Recommendations for a key, most important first. level: crit | warn | info | ok
function securityChecks(token) {
  const o = token.options || {};
  const checks = [];
  const add = (level, key, vars = {}, tab = null, group = 'device') => checks.push({ level, text: t(key, vars), tab, group });

  const revoked = ['REVOKED', 'ATTESTATION_KEY_COMPROMISE', 'USER_KEY_REMOTE_COMPROMISE', 'USER_KEY_PHYSICAL_COMPROMISE'];
  if (revoked.includes(token.mds_status)) add('crit', 'chk.mdsRevoked', { s: token.mds_status }, 'security');
  else if (token.mds_status === 'USER_VERIFICATION_BYPASS') add('crit', 'chk.uvBypass', {}, 'security');

  if ((token.cve_ids || []).length) add('warn', 'chk.vulnerable', { n: token.cve_ids.length }, 'security');
  else if (token.security_status === 'OK') add('ok', 'chk.noVulns');
  else add('info', 'status.UNKNOWN', {}, 'security');

  const att = token.attestation;
  if (att && !att.inconclusive && !token.force_pin_change) {
    if (att.status === 'VERIFIED' && att.passed) add('ok', 'chk.genuine');
    else if (att.status === 'FAILED') add('crit', 'chk.notGenuine', {}, 'security');
    else add('info', 'sec.att.unverified', {}, 'security');
  }

  if ('clientPin' in o) {
    if (!o.clientPin) add('warn', 'chk.noPin', {}, 'pin');
    else if (token.force_pin_change) add('warn', 'chk.forcePin', {}, 'pin');
    else if ((token.min_pin_length || 4) < 6 && o.setMinPINLength) add('info', 'chk.shortMinPin', { n: token.min_pin_length }, 'settings');
    else add('ok', 'chk.pinSet');
  }

  if (isBio(token)) {
    const enrolled = (o.bioEnroll ?? o.userVerificationMgmtPreview ?? o.uv) === true;
    if (!enrolled) add('info', 'chk.noFingerprint', {}, 'fingerprints');
    else add('info', 'chk.secondFinger', {}, 'fingerprints');
  }

  const backup = personalMode() ? backupStatus(token) : null;
  if (backup && backup.onlyHere.length) add('warn', 'chk.noBackup', { n: backup.onlyHere.length }, 'accounts', 'accounts');
  else if (backup) add('ok', 'chk.backupOk', {}, null, 'accounts');
  else if (personalMode()) add('info', 'acccheck.unreadLong', {}, null, 'accounts');

  const order = { crit: 0, warn: 1, info: 2, ok: 3 };
  return checks.sort((a, b) => order[a.level] - order[b.level]);
}

// What this key can do in KeyMelier – full, partly (e.g. FIDO 2.0: passkeys
// only by search), not at all, or not checked yet – so a limit is expected,
// not a surprise.
function keyCapabilities(token) {
  const o = token.options || {};
  const apps = cardApps.get(token.id);
  const card = app => (!apps || !Object.keys(apps).length ? 'unknown' : apps[app] ? 'full' : 'none');
  return [
    ['passkeys', o.credMgmt || o.credentialMgmtPreview ? 'full' : (token.fido2_versions || []).length ? 'partial' : 'none'],
    ['pin', 'clientPin' in o ? 'full' : 'none'],
    ['bio', isBio(token) ? 'full' : 'none'],
    ['config', o.authnrCfg ? 'full' : 'none'],
    ['oath', card('oath')], ['openpgp', card('openpgp')], ['piv', card('piv')],
    ['otp', card('otp')],
  ].map(([area, state]) => ({ area, state,
    // "only YubiKeys have OTP slots" is wrong on a YubiKey without them (YubiKey Bio)
    text: area === 'otp' && state === 'none' && token.vendor_id === 0x1050 ? 'cap.otp.noneYubiKey' : `cap.${area}.${state}` }));
}

function renderCapabilities(token) {
  const el = $('caps');
  if (token.offline) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  const caps = keyCapabilities(token);
  const usable = caps.filter(c => c.state === 'full' || c.state === 'partial').length;
  const icons = { full: '✓', partial: '◐', none: '–', unknown: '?' };
  el.classList.remove('hidden');
  const open = el.querySelector('details')?.open ? 'open' : '';
  el.innerHTML = `<details ${open}><summary><h2>${escHtml(t('cap.title'))}</h2>
      <span class="check-score">${escHtml(t('cap.summary', { n: usable, total: caps.length }))}</span></summary>
    <ul class="cap-list">${caps.map(c => `<li class="cap-${c.state}">
      <span class="cap-icon" aria-hidden="true">${icons[c.state]}</span>
      <span><b>${escHtml(t(`cap.area.${c.area}`))}</b> – <span class="cap-state">${escHtml(t(`cap.state.${c.state}`))}</span>
      <span class="cap-text">${escHtml(t(c.text))}</span></span></li>`).join('')}</ul>
    <p class="field-hint">${escHtml(t('cap.report'))} <button type="button" class="btn-link" data-url="https://github.com/FiraSenax/KeyMelier/issues/new?template=tested-with.yml">${escHtml(t('cap.reportLink'))}</button></p>
  </details>`;
}

function renderSecurityCheck(token) {
  const el = $('check');
  const checks = securityChecks(token);
  const icons = { crit: '✕', warn: '!', info: 'i', ok: '✓' };
  const list = (group, title) => {
    const items = checks.filter(c => c.group === group);
    if (!items.length) return '';
    const ok = items.filter(c => c.level === 'ok').length;
    return `<div class="check-head">
        <h2>${escHtml(t(title))}</h2>
        <span class="check-score">${escHtml(t('chk.score', { ok, n: items.length }))}</span>
      </div>
      <ul class="check-list">${items.map(c => `
        <li class="check-item ${c.level}">
          <span class="check-icon" aria-hidden="true">${icons[c.level]}</span>
          <span class="check-text">${escHtml(c.text)}</span>
          ${c.tab === 'accounts' ? `<button type="button" class="btn-link" data-view="accounts">${escHtml(t('bk.review'))}</button>`
            : c.tab && tabAllowed(token, c.tab) ? `<button type="button" class="btn-link" data-goto="${c.tab}">${escHtml(t('chk.fix'))}</button>` : ''}
        </li>`).join('')}
      </ul>`;
  };
  el.innerHTML = list('device', 'keycheck.title') + list('accounts', 'acccheck.title');
}


// Accounts whose only protection is this key (null = nothing known yet)
function backupStatus(token) {
  const entry = historyKeys.get(token.history_id);
  if (!entry?.sites?.length && !entry?.inventory?.oath) return null;
  const m = accountModel();
  const onlyHere = rowsOfKey(m, entry.key_id)
    .filter(r => r.kind !== 'unknown' && r.activeKeys.length === 1 && r.activeKeys[0] === entry.key_id
      && !(r.codeKeys || []).length);
  return { onlyHere, othersKnown: m.keys.length - 1 };
}

// Account coverage as seen from one key (personal mode): accounts of this
// key that need attention – not a statement about the device.
function accountCheck(token) {
  if (!personalMode()) return null;
  const entry = historyKeys.get(token.history_id);
  if (!entry) return null;
  const m = accountModel();
  const info = m.keyInfo.get(entry.key_id);
  if (!info || (info.coverage === 'none' && !info.codesKnown)) {
    return { cls: 'UNKNOWN', text: t('acccheck.unread'), n: null };
  }
  const rows = rowsOfKey(m, entry.key_id).filter(r => ['crit', 'warn', 'unclear'].includes(r.level));
  const stale = info.stale ? ` · ${t('acccheck.stale')}` : '';
  return rows.length
    ? { cls: 'WARNING', text: t(rows.length === 1 ? 'acccheck.review1' : 'acccheck.review', { n: rows.length }) + stale, n: rows.length }
    : { cls: info.stale || info.coverage === 'probe' ? 'UNKNOWN' : 'OK', text: t('acccheck.ok') + stale, n: 0 };
}

// "Read key": the existing flows, never an automatic PIN attempt.
// Managed keys: unlock dialog (PIN/fingerprint) that reads afterwards, or
// read right away while still unlocked. FIDO 2.0 keys: the passkey search.
async function readKey(tok) {
  if (!tok || tok.offline) return;
  if (!canManage(tok)) return openProbe(tok.id);
  if (!tok.options?.clientPin && !tok.options?.uv) { showToast(t('read.needPin'), 'info'); return switchTab('pin'); }
  if (!isUnlocked(tok.id)) return quickLockToggle(tok.id);
  $('read-btn').disabled = true;
  try {
    await readContentsNow(tok);
  } finally {
    $('read-btn').disabled = false;
  }
}

const READ_PARTS = { passkeys: 'tile.passkeys', oath: 'tile.oath', openpgp: 'tab.openpgp', piv: 'tab.piv' };

async function readContentsNow(tok) {
  let got;
  try {
    got = await call('read_contents', { token_id: tok.id });
  } catch (e) {
    showToast(errorMessage(e), 'error');
    return;
  }
  if (got.removed) {
    // nothing that failed was recorded – the known state stays as it was
    showToast(t('read.removed', { name: displayName(tok) }), 'error');
    await loadHistory();
    render();
    return;
  }
  const parts = [
    got.sites != null ? t('ql.got.sites', { n: got.sites }) : '',
    got.oath != null ? t('ql.got.oath', { n: got.oath }) : '',
    got.openpgp ? t('ql.got.pgp', { n: got.openpgp }) : '',
    got.piv ? t('ql.got.piv', { n: got.piv }) : '',
  ].filter(Boolean);
  if (got.failed?.length) {
    showToast(t('read.partial', { parts: got.failed.map(p => t(READ_PARTS[p] || p)).join(', ') })
      + (parts.length ? ` – ${parts.join(', ')}` : ''), 'error');
  } else {
    showToast(t('ql.done', { name: displayName(tok) }) + (parts.length ? ` – ${parts.join(', ')}` : ''), 'success');
  }
  await loadHistory();
  render();
}

// ── Backup & loss view ──────────────────────────────────────────────────────

function keyLabel(entry) {
  return displayName(offlineToken(entry));
}

function renderBackupView() {
  $('backup-avatar').innerHTML = icon('shield', 30);
  const el = $('backup-content');
  const entries = [...historyKeys.values()];
  const parts = [];

  // 1. How well the accounts are covered – the one thing to act on first
  if (personalMode()) {
    const m = accountModel();
    const rows = m.rows.filter(r => !(r.kind === 'code' && r.linkedTo));
    const todo = rows.filter(r => r.level === 'crit' || r.level === 'warn').length;
    parts.push(rows.length ? `<section class="card bk-card">
      <div class="check-head"><h2>${escHtml(t('bk.coverage'))}</h2>
        <button type="button" class="btn btn-primary" data-act="open-accounts">${escHtml(t('bk.review'))}</button></div>
      <div class="acc-summary compact">${accSummaryHtml(rows, true)}</div>
      <p class="card-text${todo ? ' warn-text' : ''}">${escHtml(todo ? t('bk.coverageText', { n: todo }) : t('bk.coverageOk'))}</p>
    </section>` : `<section class="card bk-card"><h2>${escHtml(t('bk.coverage'))}</h2>
      <p class="card-text">${escHtml(t('bk.empty.text'))}</p></section>`);
  } else {
    parts.push(`<section class="card bk-card"><h2>${escHtml(t('bk.coverage'))}</h2>
      <p class="card-text">${escHtml(t('bk.sharedMode'))}</p>
      <button type="button" class="btn-link" data-act="open-settings">${escHtml(t('sync.line.settings'))}</button></section>`);
  }

  // 2. Lost a key
  const lost = lostKid && historyKeys.get(lostKid);
  parts.push(`<section class="card bk-card">
    <div class="check-head"><h2>${escHtml(t('bk.lost.title'))}</h2>
      <select id="bk-lost-select" class="bk-select" aria-label="${escHtml(t('bk.lost.title'))}">
        <option value="">${escHtml(t('bk.lost.choose'))}</option>
        ${entries.map(e => `<option value="${escHtml(e.key_id)}"${e.key_id === lostKid ? ' selected' : ''}>${escHtml(keyLabel(e))}${e.lost_since ? ' – ' + escHtml(t('bk.lostBadge')) : ''}</option>`).join('')}
      </select></div>
    <p class="card-text">${escHtml(t('bk.lost.short'))}</p>
    ${lost ? lostAssistantHtml(lost) : ''}
  </section>`);

  // 3. Replace a key (guided view)
  const running = entries.find(e => e.replace?.new && historyKeys.has(e.replace.new));
  let runningText = '';
  if (running) {
    const plan = buildReplacePlan(accountModel(), running.key_id, running.replace.new);
    const done = new Set(running.replace.done || []);
    const open = replacePlanItems(plan).filter(i => !(i.check === 'found' && done.has(i.id))).length;
    runningText = t('rp.inProgress', { old: keyLabel(running), new: keyLabel(historyKeys.get(running.replace.new)), n: open });
  }
  const cancel = running && replaceCancelAsk ? `<div class="rp-cancel" role="group" aria-label="${escHtml(t('rp.cancel'))}">
      <p class="card-text">${escHtml(t('rp.cancel.confirm'))}</p>
      <div class="form-actions">
        <button type="button" class="btn btn-secondary" data-act="rp-cancel-no">${escHtml(t('rp.cancel.keep'))}</button>
        <button type="button" class="btn btn-danger" data-act="rp-cancel-yes" data-kid="${escHtml(running.key_id)}">${escHtml(t('rp.cancel'))}</button>
      </div></div>` : '';
  parts.push(`<section class="card bk-card">
    <div class="check-head"><h2>${escHtml(t('rp.title'))}</h2>
      <div class="form-actions bk-actions">
        ${running && !replaceCancelAsk ? `<button type="button" class="btn btn-secondary" data-act="rp-cancel-ask">${escHtml(t('rp.cancel'))}</button>` : ''}
        <button type="button" class="btn btn-secondary" data-act="open-replace" ${running ? `data-kid="${escHtml(running.key_id)}"` : ''}>${escHtml(t(running ? 'rp.continue' : 'rp.start'))}</button>
      </div></div>
    <p class="card-text">${escHtml(runningText || t('rp.short'))}</p>
    ${cancel}
  </section>`);

  // Sync: status only; configuration lives in the app settings
  parts.push(syncLineHtml());
  el.innerHTML = parts.join('');
}

// ── App settings (global, not per key) ─────────────────────────────────────

function renderSettingsView() {
  $('settings-avatar').innerHTML = icon('settings', 30);
  const remember = appSettings.remember_sites !== false;
  $('settings-content').innerHTML = `
    <div class="callout app-settings-note"><div class="callout-text">${escHtml(t('app.settings.keyHint'))}</div></div>
    <section class="card">
      <h2>${escHtml(t('app.settings.data'))}</h2>
      <label class="switch-row">
        <input type="checkbox" id="bk-remember" ${remember ? 'checked' : ''} ${appSettings.stateless ? 'disabled' : ''}>
        <span>${escHtml(t('bk.remember'))}</span>
      </label>
      <p class="field-hint bk-hint">${escHtml(t('bk.rememberText'))}</p>
      <label class="switch-row">
        <input type="checkbox" id="history-enabled" ${appSettings.history_enabled ? 'checked' : ''} ${appSettings.stateless ? 'disabled' : ''}>
        <span>${escHtml(t('privacy.history'))}</span>
      </label>
      <p class="field-hint bk-hint">${escHtml(t('privacy.hint'))}</p>
      <label class="switch-row">
        <input type="checkbox" id="personal-mode" ${personalMode() ? 'checked' : ''}>
        <span>${escHtml(t('acc.mode'))}</span>
      </label>
      <p class="field-hint bk-hint">${escHtml(t(personalMode() ? 'acc.mode.on' : 'acc.mode.off'))}</p>
    </section>
    <section class="card">
      <h2>${escHtml(t('app.settings.transfer'))}</h2>
      <p class="card-text">${escHtml(t('histx.hint'))}</p>
      <div class="form-actions att-actions">
        <button type="button" class="btn btn-secondary" data-act="hist-export" ${historyKeys.size ? '' : 'disabled'}>${escHtml(t('histx.export'))}</button>
        <button type="button" class="btn btn-secondary" data-act="hist-import">${escHtml(t('histx.import'))}</button>
      </div>
    </section>
    <section class="card" id="inventory-card">
      <h2>${escHtml(t('inv.title'))}</h2>
      <p class="card-text">${escHtml(t('inv.text'))}</p>
      <div class="inv-options">
        <label><span>${escHtml(t('inv.format'))}</span>
          <select id="inv-format" class="bk-select"><option value="json">JSON</option><option value="csv">CSV</option></select></label>
        <label><span>${escHtml(t('inv.key'))}</span>
          <select id="inv-key" class="bk-select"><option value="">${escHtml(t('inv.allKeys'))}</option>
          ${[...historyKeys.values()].map(e => `<option value="${escHtml(e.key_id)}">${escHtml(keyLabel(e))}</option>`).join('')}</select></label>
        <label><span>${escHtml(t('inv.status'))}</span>
          <select id="inv-level" class="bk-select">${ACC_CARDS.map(([lvl, k]) => `<option value="${lvl}">${escHtml(t(k))}</option>`).join('')}</select></label>
      </div>
      <p class="field-hint">${escHtml(t('inv.privacy'))}</p>
      <div class="form-actions att-actions">
        <button type="button" class="btn btn-secondary" data-act="inv-export" ${historyKeys.size ? '' : 'disabled'}>${escHtml(t('inv.export'))}</button>
      </div>
    </section>
    ${syncCardHtml()}`;
}

// Everything known about keys and accounts as JSON or CSV (names only, no secrets)
async function exportInventory() {
  const format = $('inv-format').value;
  const inv = buildInventory(accountModel(), { keyId: $('inv-key').value, level: $('inv-level').value,
    appVersion: dataStatus?.app?.current || '' });
  const text = format === 'csv' ? inventoryCsv(inv) : JSON.stringify(inv, null, 2);
  const name = `keymelier-inventory-${new Date().toISOString().slice(0, 10)}.${format}`;
  try {
    const path = await window.pywebview.api.save_text(name, text, true);
    if (path) showToast(t('inv.saved', { n: inv.accounts.length }), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

function showSettingsView() {
  mainView = 'settings';
  render();
  loadSync();
}


// ── Quantum readiness ───────────────────────────────────────────────────────

// COSE algorithm IDs (IANA); ML-DSA per RFC 9964
const COSE_ALGS = { '-7': 'ES256', '-8': 'EdDSA', '-19': 'Ed25519', '-35': 'ES384', '-36': 'ES512', '-257': 'RS256',
  '-47': 'ES256K', '-48': 'ML-DSA-44', '-49': 'ML-DSA-65', '-50': 'ML-DSA-87' };
const PQ_ALGS = new Set([-48, -49, -50]);

function renderQuantum(token) {
  const el = $('pq-card');
  if (!el) return;
  const algs = token.algorithms || [];
  const pq = algs.filter(a => PQ_ALGS.has(a));
  const names = algs.map(a => COSE_ALGS[a] || `COSE ${a}`).join(', ') || '—';
  const card = cardApps.get(token.id) || {};
  const encApps = ['openpgp', 'piv'].filter(a => card[a]).map(a => t(`hist.contents.${a}`));
  el.innerHTML = `<h2>${escHtml(t('pq.title'))}</h2>
    <div class="att-summary ${pq.length ? 'pass' : 'partial'}">${escHtml(pq.length
      ? t('pq.fido.yes', { algs: pq.map(a => COSE_ALGS[a]).join(', ') })
      : t('pq.fido.no'))}</div>
    <dl class="kv">${buildKv([[t('pq.algorithms'), names]])}</dl>
    <p class="card-text">${escHtml(t(pq.length ? 'pq.fido.yesText' : 'pq.fido.noText'))}</p>
    ${encApps.length ? `<p class="card-text"><strong>${escHtml(encApps.join(', '))}:</strong> ${escHtml(t('pq.enc'))}</p>` : ''}
    <p class="field-hint">${escHtml(t('pq.watch'))}</p>`;
}

function renderSecurity(token) {
  renderQuantum(token);
  const advs = token.advisories?.length ? token.advisories : (token.cve_ids || []).map(id => ({ id }));
  $('sec-advisories').innerHTML = advs.length
    ? advs.map(a => `<div class="advisory">
        <div class="advisory-id">${escHtml(a.id)}${a.severity ? ` · ${escHtml(t(`sev.${a.severity}`))}${a.cvss ? ` (CVSS ${escHtml(a.cvss)})` : ''}` : ''}</div>
        ${a.title ? `<div class="advisory-title">${escHtml(a.title)}</div>` : ''}
        <div class="advisory-text">${escHtml(a.note || t('sec.advisory.affects'))}</div>
        ${a.origin ? `<div class="advisory-origin">${escHtml(t('sec.advisory.origin', { name: a.origin }))}</div>` : ''}
        ${(a.references || []).map(u => `<button type="button" class="btn-link advisory-link" data-url="${escHtml(u)}">${escHtml(u.replace(/^https:\/\//, ''))}</button>`).join('')}
      </div>`).join('')
    : `<p class="muted">${escHtml(t('sec.noAdvisories'))}</p>`;
  $('sec-advisories').querySelectorAll('[data-url]').forEach(b => {
    b.onclick = () => window.pywebview?.api?.open_url(b.dataset.url);
  });

  const att = token.attestation;
  const sum = attestationSummary(att, token);
  let html = sum.cls === 'running'
    ? `<div class="loading"><span class="spinner"></span>${escHtml(sum.text)}</div>`
    : `<div class="att-summary ${sum.cls}">${escHtml(sum.text)}</div>`;
  const checks = (sum.cls === 'partial' && token.force_pin_change) || sum.skipped ? [] : (att?.checks || []);
  if (checks.length) {
    html += '<div class="att-checks">' + checks.map(c => {
      const [ic, cls] = c.passed === true ? ['✓', 'pass'] : c.passed === false ? ['✕', 'fail'] : ['○', 'skip'];
      return `<div class="att-check ${cls}">
        <span class="att-check-icon">${ic}</span>
        <div><div class="att-check-name">${escHtml(c.name)}</div>
        <div class="att-check-detail">${escHtml(c.detail || '')}</div></div>
      </div>`;
    }).join('') + '</div>';
  }
  const wantsPin = ['needs_uv', 'pin_invalid'].includes(sum.reason) && (token.options || {}).clientPin;
  if (!token.offline && sum.cls !== 'running') {
    if (wantsPin) {
      const uv = (token.options || {}).uv === true;
      html += `<form class="att-pin-form" autocomplete="off">
        <label class="field"><span>${escHtml(t('pin.form.current'))}</span>
          <input type="password" class="att-pin" autocomplete="off" spellcheck="false"></label>
        <div class="form-actions att-actions">
          ${uv ? `<button type="button" class="btn btn-secondary" id="att-uv">${icon('fingerprint', 15)} ${escHtml(t('sec.att.withUv'))}</button>` : ''}
          <button type="submit" class="btn btn-primary">${escHtml(t('sec.att.withPin'))}</button>
        </div></form>`;
    } else {
      html += `<div class="form-actions att-actions"><button type="button" class="btn btn-secondary" id="att-rerun">${escHtml(t('sec.att.rerun'))}</button></div>`;
    }
  }
  $('sec-attestation').innerHTML = html;
  const rerunWith = args => call('attestation_rerun', { token_id: token.id, ...args }).catch(e => showToast(errorMessage(e), 'error'));
  const rerun = $('att-rerun');
  if (rerun) rerun.onclick = () => rerunWith({});
  const uvBtn = $('att-uv');
  if (uvBtn) uvBtn.onclick = () => rerunWith({ method: 'uv' });
  const pinForm = $('sec-attestation').querySelector('.att-pin-form');
  if (pinForm) pinForm.onsubmit = ev => {
    ev.preventDefault();
    const pin = pinForm.querySelector('.att-pin').value;
    if (!pin) return showToast(t('pin.v.current'), 'error');
    rerunWith({ pin });
  };

  $('sec-mds').innerHTML = buildKv([
    [t('sec.mds.description'), token.mds_description || t('sec.mds.notFound')],
    [t('sec.mds.status'), token.mds_status || '—'],
    [t('sec.mds.version'), token.mds_authenticator_version != null ? String(token.mds_authenticator_version) : '—'],
  ]);
}

function renderDetails(token) {
  const aaguidKey = t('det.aaguid');
  const firstSeenLabel = token.offline ? t('hist.lastSeen') : t('det.firstSeen');
  const firstSeenValue = token.offline ? token.last_seen : token.first_seen;
  $('det-identity').innerHTML = buildKv([
    [t('det.manufacturer'), token.manufacturer],
    [t('det.product'), token.product_name || '—'],
    [t('det.serial'), token.serial_number || t('det.serialNone')],
    ...(token.form_factor ? [[t('det.formFactor'), t(`ff.${token.form_factor}`)]] : []),
    ...(token.nfc != null ? [[t('det.nfc'), token.nfc ? t('det.yes') : t('det.no')]] : []),
    ...(token.fips ? [[t('det.fips'), t('det.yes')]] : []),
    [t('det.firmware'), token.firmware_version_str || t('unknown')],
    [aaguidKey, token.aaguid],
    [firstSeenLabel, firstSeenValue ? new Date(firstSeenValue).toLocaleString(LANG) : '—'],
  ], [aaguidKey]);

  const opts = token.options || {};
  const keys = Object.keys(opts).sort();
  $('det-options').innerHTML = keys.length
    ? keys.map(k => `<span class="pill ${opts[k] ? 'on' : ''}">${opts[k] ? '✓' : '–'} ${escHtml(k)}</span>`).join('')
    : `<span class="muted">${escHtml(t('det.noOptions'))}</span>`;

  $('det-protocols').innerHTML = buildKv([
    [t('det.versions'), (token.fido2_versions || []).join(', ') || '—'],
    [t('det.extensions'), (token.extensions || []).join(', ') || '—'],
    [t('det.pinProtocols'), (token.pin_protocols || []).join(', ') || '—'],
    [t('det.maxCreds'), token.max_cred_count != null ? String(token.max_cred_count) : '—'],
  ]);
}

// ── Navigation ──────────────────────────────────────────────────────────────

function resetViewState() {
  pinState = null;
  pkState = null;
  fpState = null;
  fpEnroll = null;
  unlockBusy = null;
  histDetail = null;
  histConfirmForget = false;
  clearPinInputs();
}

function selectHistory(kid) {
  if (kid === selectedHist && !selectedId && mainView === 'key') return;
  mainView = 'key';
  selectedId = null;
  selectedHist = kid;
  resetViewState();
  render();
  switchTab(activeTab);
}

async function loadCardApps(token) {
  if (!token || token.offline || cardApps.has(token.id)) return;
  cardApps.set(token.id, {});
  let retry = false;
  try {
    const res = await call('card_apps', { token_id: token.id });
    cardApps.set(token.id, res.apps || {});
    retry = res.reader && res.code != null;  // interface exists but was busy
  } catch { retry = true; }
  const tries = (cardRetries.get(token.id) || 0) + 1;
  cardRetries.set(token.id, tries);
  if (retry && tries <= 3) {
    setTimeout(() => { cardApps.delete(token.id); if (selectedId === token.id) render(); else loadCardApps(token); }, 4000);
  }
  if (selectedId === token.id) render(); else renderSidebar();
}

function selectToken(id) {
  if (id === selectedId && mainView === 'key') return;
  mainView = 'key';
  selectedId = id;
  selectedHist = null;
  histDetail = null;
  histConfirmForget = false;
  ftState = null;
  ftRun = null;
  pinState = null;
  pkState = null;
  fpState = null;
  fpEnroll = null;
  unlockBusy = null;
  clearPinInputs();
  render();
  switchTab(activeTab);
}

function syncTabsOverflow() {
  const bar = document.querySelector('.tabs');
  if (!bar) return;
  bar.classList.toggle('more-left', bar.scrollLeft > 2);
  bar.classList.toggle('more-right', bar.scrollLeft + bar.clientWidth < bar.scrollWidth - 2);
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
    b.setAttribute(b.getAttribute('role') === 'tab' ? 'aria-selected' : 'aria-current', String(b.dataset.tab === tab));
  });
  syncTabMore();
  // the tab bar scrolls sideways in small windows: keep the active tab in view
  document.querySelector('.tabs .tab.active, .tabs .tab-more-btn.active')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  syncTabsOverflow();
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== tab));
  const current = currentToken();
  if (tab === 'history' && current) loadHistoryDetail(current.history_id);
  const token = tokens.get(selectedId);
  if (tab === 'pin' && token) loadPinStatus(token);
  if (tab === 'passkeys' && token) loadPasskeys(token);
  if (tab === 'fingerprints' && token) loadFingerprints(token);
  if (tab === 'settings' && token) loadConfig(token);
  if (tab === 'oath' && token) loadOath(token);
  if (tab === 'openpgp' && token) loadPgp(token);
  if (tab === 'piv' && token) loadPiv(token);
  if (tab === 'otp' && token) loadOtp(token);
  if (tab === 'settings' && token) loadInterfaces(token);
  if (tab !== 'oath') stopOathTimer();
  if (tab === 'security') { if (token) loadFunctionTest(token); else renderFunctionTest(); }
}

// ── Data freshness ──────────────────────────────────────────────────────────

function fmtDate(iso) {
  return iso ? `${new Date(iso).toLocaleString(LANG)} (${relTime(iso)})` : '—';
}

// null | { stage: 'downloading', pct } | { stage: 'ready', platform } | { stage: 'failed' }
let updateFlow = null;

function renderUpdateBanner() {
  const app = dataStatus?.app;
  $('version-text').textContent = app?.current || '';
  const show = !!(app && app.newer && app.url);
  $('update-banner').classList.toggle('hidden', !show);
  if (!show) return;
  const btn = $('update-btn');
  btn.disabled = false;
  if (updateFlow?.stage === 'downloading') {
    $('update-text').textContent = t('upd.downloading', { pct: updateFlow.pct || 0 });
    btn.textContent = t('upd.download');
    btn.disabled = true;
  } else if (updateFlow?.stage === 'ready') {
    const readyKey = { win32: 'upd.ready.win', linux: 'upd.ready.linux' }[updateFlow.platform] || 'upd.ready.mac';
    $('update-text').textContent = t(readyKey, { v: app.latest });
    btn.textContent = t('upd.open');
  } else {
    $('update-text').textContent = t('upd.available', { v: app.latest });
    btn.textContent = t(app.asset && updateFlow?.stage !== 'failed' ? 'upd.downloadInstall' : 'upd.download');
  }
}

async function onUpdateButton() {
  const app = dataStatus?.app;
  if (updateFlow?.stage === 'ready') {
    return call('update_open').catch(e => showToast(errorMessage(e), 'error'));
  }
  if (!app?.asset || updateFlow?.stage === 'failed') {
    if (app?.url) window.pywebview?.api?.open_url(app.url);
    return;
  }
  updateFlow = { stage: 'downloading', pct: 0 };
  renderUpdateBanner();
  try {
    await call('update_download');
  } catch (e) {
    updateFlow = { stage: 'failed' };
    showToast(errorMessage(e), 'error');
    renderUpdateBanner();
  }
}

function renderDataStatus() {
  renderUpdateBanner();
  const el = $('data-status');
  if (!el) return;
  const st = dataStatus;
  if (!st) { el.innerHTML = ''; return; }
  const adv = st.advisories || {};
  el.innerHTML = buildKv([
    [t('data.advisories'), adv.updated ? fmtDate(adv.updated) : t('data.none')],
    [t('data.source'), t(`data.source.${adv.source || 'none'}`)],
    ...(adv.policy || []).map((p, i) => [i ? '' : t('data.policy'),
      t(`data.policy.${['ok', 'invalid', 'unreachable'].includes(p.status) ? p.status : 'pending'}`, { name: p.name, n: p.count })]),
    ...(adv.policy?.length ? [['', t('data.policy.hint')]] : []),
    [t('data.mds'), st.mds?.fetched_at
      ? `${fmtDate(st.mds.fetched_at)}${st.mds.serial ? ` · #${st.mds.serial}` : ''}${st.mds.verified ? ` · ${t('data.verified')}` : ''}`
      : t('data.none')],
    ...(st.mds?.entry_count && !st.mds.revocation_checked ? [['', t('data.revocationUnknown')]] : []),
    [t('data.lastCheck'), st.last_check ? fmtDate(st.last_check) : t('data.pending')],
    [t('data.appVersion'), st.app?.current
      ? `${st.app.current}${st.app.latest ? ` · ${st.app.newer ? t('upd.available', { v: st.app.latest }) : t('upd.upToDate')}` : ''}`
      : '—'],
  ]);
}

// "Check for updates" (sidebar, macOS app menu, menu bar icon)
let updateChecking = false;
async function checkForUpdates() {
  if (updateChecking) return;
  updateChecking = true;
  showToast(t('upd.checking'), 'info');
  try {
    dataStatus = await call('check_updates');
    renderDataStatus();
    const app = dataStatus.app || {};
    if (app.failed) showToast(t('upd.checkFailed'), 'error');
    else if (app.newer) showToast(t('upd.available', { v: app.latest }), 'success');
    else showToast(t('upd.current', { v: app.current }), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  } finally {
    updateChecking = false;
  }
}
window.__kmCheckUpdates = () => checkForUpdates();


async function checkDataNow() {
  const btn = $('data-check');
  btn.disabled = true;
  try {
    const before = dataStatus?.advisories?.updated;
    dataStatus = await call('check_updates');
    renderDataStatus();
    showToast(dataStatus.advisories?.updated !== before ? t('data.updated') : t('data.current'), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  } finally {
    btn.disabled = false;
  }
}

// ── History tab ─────────────────────────────────────────────────────────────

const EVENT_ICONS = {
  connected: 'plug', disconnected: 'plug', attestation: 'shield', attestation_skipped: 'shield', pin_set: 'lock', pin_changed: 'lock',
  passkey_deleted: 'passkey', passkey_renamed: 'passkey', fingerprint_enrolled: 'fingerprint', fingerprint_renamed: 'fingerprint',
  fingerprint_removed: 'fingerprint', reset: 'trash',
  function_test: 'key', config_min_pin: 'lock',
  piv_pin_changed: 'lock', piv_puk_changed: 'lock', piv_pin_unblocked: 'lock', piv_generated: 'key', piv_imported: 'key',
  piv_deleted: 'trash', piv_mgmt_protected: 'lock', piv_reset: 'trash', otp_swapped: 'key', otp_deleted: 'trash',
  otp_programmed: 'key', interfaces_changed: 'key',
  pgp_user_pin_changed: 'lock', pgp_admin_pin_changed: 'lock', pgp_pin_unblocked: 'lock', pgp_touch_changed: 'key', pgp_reset: 'trash',
  oath_added: 'lock', oath_renamed: 'lock', oath_deleted: 'trash', oath_password_set: 'lock', oath_password_removed: 'lock', oath_reset: 'trash', config_always_uv: 'lock', config_force_pin: 'lock',
};

function eventText(ev) {
  if (ev.type === 'attestation') return t(ev.passed ? 'ev.attestation.pass' : 'ev.attestation.fail');
  if (ev.type === 'attestation_skipped') return t('ev.attestation.skipped');
  if (ev.type === 'pgp_touch_changed' && ev.slot) {
    return `${t('ev.pgp_touch_changed')}: ${t(`pgp.slot.${ev.slot}`)} → ${t(`pgp.touch.${ev.policy}`)}`;
  }
  if (/^(piv|otp)_/.test(ev.type) && (ev.slot != null)) {
    const slot = ev.type.startsWith('otp_') ? t(`otp.slot${ev.slot}`) : String(ev.slot).toUpperCase();
    return `${t(`ev.${ev.type}`)}: ${slot}`;
  }
  if (/^(oath|pgp|piv|otp|interfaces)_/.test(ev.type)) {
    const base = t(`ev.${ev.type}`);
    return ev.site || ev.user ? `${base}: ${[ev.site, ev.user].filter(Boolean).join(' · ')}` : base;
  }
  if (ev.type === 'function_test') return t(ev.passed ? 'ev.function_test.pass' : 'ev.function_test.fail');
  if (ev.type === 'config_min_pin') return t('ev.config_min_pin', { n: ev.value });
  if (ev.type === 'config_always_uv') return t(ev.value ? 'ev.config_always_uv.on' : 'ev.config_always_uv.off');
  const key = `ev.${ev.type}`;
  const base = STRINGS[LANG][key] ? t(key) : ev.type;
  if (ev.type === 'passkey_renamed' && (ev.site || ev.user)) return `${t('ev.passkey_renamed')}: ${[ev.site, ev.user].filter(Boolean).join(' · ')}`;
  if (ev.type === 'passkey_deleted' && (ev.site || ev.user)) return `${base}: ${[ev.site, ev.user].filter(Boolean).join(' · ')}`;
  if (ev.type.startsWith('fingerprint_') && ev.name) return `${base}: ${ev.name}`;
  return base;
}

// "What was on this key": passkey sites and the smart card inventories
const INVENTORY_SECTIONS = ['oath', 'openpgp', 'piv', 'otp'];
function inventoryLabel(item) {
  if (item.otp_slot) return t(`otp.slot${item.otp_slot}`);
  if (item.slot && item.fingerprint) return `${t(`pgp.slot.${item.slot}`)}: ${item.algorithm || '?'} · ${item.fingerprint}`;
  return item.label || [item.issuer, item.name].filter(Boolean).join(' · ');
}
function contentsCardHtml(entry) {
  const sections = [];
  if (entry.sites) {
    sections.push({ title: t('hist.contents.passkeys'), updated: entry.sites_updated,
      items: entry.sites.map(s => s.name && s.name !== s.rp_id ? `${s.name} (${s.rp_id})` : s.rp_id) });
  }
  for (const key of INVENTORY_SECTIONS) {
    const inv = entry.inventory?.[key];
    if (inv) sections.push({ title: t(`hist.contents.${key}`), updated: inv.updated, items: (inv.items || []).map(inventoryLabel) });
  }
  const body = sections.length
    ? sections.map(s => `<div class="inv-section">
        <div class="inv-head"><span class="inv-title">${escHtml(s.title)}</span>
          <span class="muted inv-updated">${escHtml(t('hist.contents.read', { time: relTime(s.updated) }))}</span></div>
        ${s.items.length ? `<ul class="inv-list">${s.items.map(i => `<li>${escHtml(i)}</li>`).join('')}</ul>`
          : `<p class="muted">${escHtml(t('hist.contents.empty'))}</p>`}
      </div>`).join('')
    : `<p class="muted">${escHtml(t(appSettings.remember_sites === false ? 'hist.contents.off' : 'hist.contents.none'))}</p>`;
  return `<section class="card"><h2>${escHtml(t('hist.contents.title'))}</h2>
    <p class="card-text">${escHtml(t('hist.contents.text'))}</p>${body}</section>`;
}

function renderHistoryTab() {
  const el = $('hist-content');
  const token = currentToken();
  const entry = histDetail;
  if (!token || !entry || entry.key_id !== token.history_id) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  const events = [...(entry.events || [])].reverse();
  const important = events.filter(ev => ev.type !== 'connected' && ev.type !== 'disconnected');
  el.innerHTML = `
    <form class="card form-card hist-name-form" autocomplete="off">
      <h2>${escHtml(t('hist.name.title'))}</h2>
      <p class="card-text">${escHtml(t('hist.name.text'))}</p>
      <div class="inline-form">
        <input type="text" class="hist-name" maxlength="60" value="${escHtml(entry.label || '')}"
          placeholder="${escHtml(token.mds_description || token.product_name || '')}" spellcheck="false">
        <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
      </div>
    </form>
    <section class="card">
      <h2>${escHtml(t('hist.facts'))}</h2>
      <dl class="kv">${buildKv([
        [t('hist.firstSeen'), new Date(entry.first_seen).toLocaleString(LANG)],
        [t('hist.lastSeen'), new Date(entry.last_seen).toLocaleString(LANG)],
        [t('hist.connectCount'), String(entry.connect_count || 0)],
        [t('det.serial'), entry.snapshot?.serial_number || t('det.serialNone')],
        [t('det.aaguid'), entry.snapshot?.aaguid || '—'],
      ], [t('det.serial'), t('det.aaguid')])}</dl>
    </section>
    ${contentsCardHtml(entry)}
    <section class="card">
      <h2>${escHtml(t('hist.activity'))}</h2>
      ${events.length ? `<ol class="timeline">${events.map(ev => `
        <li class="tl-item${important.includes(ev) ? '' : ' minor'}${ev.type === 'attestation' && !ev.passed ? ' bad' : ''}">
          <span class="tl-icon">${icon(EVENT_ICONS[ev.type] || 'key', 14)}</span>
          <span class="tl-text">${escHtml(eventText(ev))}</span>
          <time class="tl-time" title="${escHtml(new Date(ev.ts).toLocaleString(LANG))}">${escHtml(relTime(ev.ts))}</time>
        </li>`).join('')}</ol>` : `<p class="muted">${escHtml(t('hist.noEvents'))}</p>`}
    </section>
    ${token.offline ? `<section class="card">
      <h2>${escHtml(t('hist.forget.title'))}</h2>
      <p class="card-text">${escHtml(t('hist.forget.text'))}</p>
      <div class="form-actions">
        ${histConfirmForget
          ? `<button type="button" class="btn btn-secondary" data-act="forget-cancel">${escHtml(t('pk.delete.cancel'))}</button>
             <button type="button" class="btn btn-danger" data-act="forget">${escHtml(t('hist.forget.do'))}</button>`
          : `<button type="button" class="btn btn-secondary" data-act="forget-ask">${escHtml(t('hist.forget.do'))}</button>`}
      </div>
    </section>` : ''}`;
}

async function loadHistoryDetail(kid) {
  histDetail = null;
  renderHistoryTab();
  try {
    const entry = await call('history_get', { kid });
    if (currentToken()?.history_id !== kid) return;
    histDetail = entry;
  } catch {
    histDetail = null;
  }
  renderHistoryTab();
}

async function historyAction(act) {
  const token = currentToken();
  if (!token) return;
  if (act === 'forget-ask') { histConfirmForget = true; return renderHistoryTab(); }
  if (act === 'forget-cancel') { histConfirmForget = false; return renderHistoryTab(); }
  if (act === 'forget') {
    await call('history_forget', { kid: token.history_id }).catch(() => {});
    historyKeys.delete(token.history_id);
    selectedHist = null;
    resetViewState();
    render();
    switchTab('overview');
  }
}

async function saveHistoryName(label) {
  const token = currentToken();
  if (!token) return;
  try {
    const summary = await call('history_rename', { kid: token.history_id, label });
    historyKeys.set(summary.key_id, summary);
    render();
    showToast(t('hist.name.saved'), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

function onHistoryUpdated(summary) {
  if (mainView === 'backup' || mainView === 'accounts') {
    if (summary.replaces) historyKeys.delete(summary.replaces);
    historyKeys.set(summary.key_id, summary);
    render();
    return;
  }
  if (summary.replaces) {
    historyKeys.delete(summary.replaces);
    if (selectedHist === summary.replaces) selectedHist = summary.key_id;
  }
  historyKeys.set(summary.key_id, summary);
  const token = currentToken();
  if (token && token.history_id === summary.key_id) {
    if (token.offline) render(); else renderSidebar();
    if (activeTab === 'history') loadHistoryDetail(summary.key_id);
  } else {
    renderSidebar();
  }
}

async function exportHistory() {
  try {
    const res = await call('history_export');
    const path = await window.pywebview.api.save_text(res.filename, res.text, true);
    if (path) showToast(t('pgp.res.saved', { path }), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

async function importHistory() {
  const text = await window.pywebview.api.open_text('json');
  if (!text) return;
  try {
    const res = await call('history_import', { text });
    await loadHistory();
    render();
    showToast(t(res.saved ? 'histx.imported' : 'histx.importedSession', { added: res.added, merged: res.merged }), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

async function loadHistory() {
  try {
    const data = await call('history_list');
    historyKeys.clear();
    for (const e of data.keys || []) historyKeys.set(e.key_id, e);
  } catch { /* history is optional */ }
}

// ── Export ──────────────────────────────────────────────────────────────────

async function exportTokens() {
  try {
    const data = await call('export_all');
    const n = (data.exports || []).filter(e => !e.error).length;
    showToast(t('toast.exported', { n }), 'success');
  } catch {
    showToast(t('toast.exportFailed'), 'error');
  }
}

// ── Language ────────────────────────────────────────────────────────────────

function renderLangSelect() {
  const sel = $('lang-select');
  const opts = [['', t('lang.system', { name: LANGUAGES[SYSTEM_LANG] })],
    ...Object.entries(LANGUAGES).filter(([code]) => STRINGS[code])];
  sel.innerHTML = opts.map(([code, name]) =>
    `<option value="${code}"${code === LANG_CHOICE ? ' selected' : ''}>${escHtml(name)}</option>`).join('');
}

// choice: '' follows the OS language, otherwise a language code
function changeLang(choice, persist = true) {
  LANG_CHOICE = STRINGS[choice] ? choice : '';
  setLang(LANG_CHOICE || SYSTEM_LANG);
  window.pywebview?.api?.set_ui_language?.(LANG, {
    open: t('menu.open'), quit: t('menu.quit'), none: t('sidebar.none'), updates: t('upd.checkMenu'),
    OK: t('status.OK'), WARNING: t('status.WARNING'), CRITICAL: t('status.CRITICAL'), PENDING: t('status.PENDING'),
    // "About KeyMelier" panel (macOS)
    'about.lead': t('app.tagline'), 'about.what': t('about.what'), 'about.privacy': t('about.privacy'),
    'about.site': t('about.site'), 'about.source': t('about.source'), 'about.issues': t('about.issues'),
  });
  if (persist) call('set_settings', { values: { lang: LANG_CHOICE || null } }).catch(() => {});
  renderLangSelect();
  renderMds();
  render();
  if (pinState) renderPinStatus(pinState);
  renderManagement();
  renderResetOverlay();
  if (activeTab === 'history') renderHistoryTab();
  renderDataStatus();
}

// ── Live updates ────────────────────────────────────────────────────────────

function flashSidebarItem(id) {
  requestAnimationFrame(() => {
    document.querySelector(`.key-item[data-id="${CSS.escape(id)}"]`)?.classList.add('flash');
  });
}

function onTokenConnected(token) {
  tokens.set(token.id, token);
  if (!selectedId || selectedHist === token.history_id) selectToken(token.id);
  else render();
  flashSidebarItem(token.id);
  showToast(t('toast.connected', { name: displayName(token) }), 'info');
}

function onTokenDisconnected(data) {
  unlockedUntil.delete(data.id);
  if (quickUnlock?.id === data.id) { quickUnlock = null; renderQuickUnlock(); }
  cardApps.delete(data.id);
  cardRetries.delete(data.id);
  const token = tokens.get(data.id);
  tokens.delete(data.id);
  const wasSelected = selectedId === data.id;
  if (wasSelected) {
    selectedId = null;
    // Keep showing the key, now from history, unless another one is plugged in
    selectedHist = token && historyKeys.has(token.history_id) && !tokens.size ? token.history_id : null;
    resetViewState();
  }
  render();
  if (wasSelected) switchTab(activeTab);
  showToast(t('toast.removed', { name: token ? displayName(token) : (data.product_name || t('unknown')) }), 'warning');
}

function onTokenUpdated(token) {
  // A delayed update must not resurrect a disconnected connection.
  if (!tokens.has(token.id)) return;
  const prev = tokens.get(token.id);
  tokens.set(token.id, token);
  render();
  // The attestation test released the key: load what was waiting for it
  if (token.id === selectedId && prev && !prev.attestation && token.attestation) {
    if (activeTab === 'pin' && pinWaiting) loadPinStatus(token);
    if (activeTab === 'passkeys' && pkState?.busy) loadPasskeys(token);
    if (activeTab === 'fingerprints' && fpState?.busy) loadFingerprints(token);
  }
}

async function loadTokens() {
  try {
    const data = await call('tokens');
    tokens.clear();
    for (const token of data.tokens || []) tokens.set(token.id, token);
    const before = selectedId;
    render();
    if (selectedId !== before) switchTab(activeTab);
  } catch (e) {
    window.pywebview?.api?.client_error(`loadTokens: ${e.message}`);
    showToast(t('toast.loadFailed'), 'error');
  }
}

async function loadMds() {
  try {
    mdsInfo = await call('mds_status');
  } catch {
    mdsInfo = { cached: false };
  }
  renderMds();
}

const EVENT_HANDLERS = {
  token_connected: p => onTokenConnected(p),
  token_disconnected: p => onTokenDisconnected(p),
  token_updated: p => onTokenUpdated(p),
  enroll_progress: p => onEnrollProgress(p),
  enroll_done: p => onEnrollDone(p),
  reset_progress: p => onResetProgress(p),
  reset_done: p => onResetDone(p),
  history_updated: p => onHistoryUpdated(p),
  history_synced: async () => { await loadHistory(); render(); if (mainView === 'backup') loadSync(); },
  history_reloaded: () => loadHistory().then(render),
  mds_ready: p => { mdsInfo = p; renderMds(); },
  data_status: p => { dataStatus = p; mdsInfo = p.mds; renderMds(); renderDataStatus(); },
  app_update: p => { dataStatus = { ...(dataStatus || {}), app: p }; renderDataStatus(); },
  probe_progress: p => {
    if (quickUnlock?.mode === 'probe' && quickUnlock.id === p.id) {
      quickUnlock = { ...quickUnlock, done: p.done, total: p.total };
      const bar = document.querySelector('.probe-bar > div');
      if (bar) {
        bar.style.width = `${Math.round(p.done * 100 / p.total)}%`;
        bar.parentElement.nextElementSibling.textContent = t('probe.progress', { done: p.done, total: p.total });
      } else renderQuickUnlock();
    }
  },
  update_progress: p => { updateFlow = { stage: 'downloading', pct: p.pct }; renderUpdateBanner(); },
  update_ready: p => { updateFlow = { stage: 'ready', platform: p.platform }; renderUpdateBanner(); call('update_open').catch(() => {}); },
  update_failed: p => {
    updateFlow = { stage: 'failed' };
    showToast(t(p.code === 'update_checksum' ? 'err.update_checksum' : 'upd.failed'), 'error');
    renderUpdateBanner();
  },
};

// Called from the macOS menu bar item: show a key
window.__kmSelectToken = id => { if (tokens.has(id)) { selectToken(id); switchTab('overview'); } };

// Called from Python (EventPump) for every live event
window.__kmEvent = (name, payload) => {
  try { EVENT_HANDLERS[name]?.(payload); } catch (e) { console.error(name, e); }
};

// ── Init ────────────────────────────────────────────────────────────────────

// The bridge object can exist before its functions are attached, so wait
// until `call` is actually callable.
function whenBridgeReady(fn) {
  let done = false;
  const check = () => {
    if (done) return;
    if (typeof window.pywebview?.api?.call === 'function') { done = true; fn(); return; }
    setTimeout(check, 50);
  };
  window.addEventListener('pywebviewready', check);
  check();
}

async function start() {
  try {
    const settings = await call('get_settings');
    appSettings = settings;
    SYSTEM_LANG = pickLanguage(settings.system_languages);
    changeLang(settings.lang || '', false);
    // Linux: a key that does not appear usually lacks device permissions (udev)
    $('empty-linux').classList.toggle('hidden', settings.platform !== 'linux');
    // A data file could not be read at start: it was kept aside, not overwritten
    for (const p of settings.problems || []) showToast(t(`problem.${p.code}`, { file: p.file }), 'error');
  } catch { /* defaults */ }
  loadMds();
  call('data_status').then(st => { dataStatus = st; renderDataStatus(); }).catch(() => {});
  await loadHistory();
  await loadTokens();
  maybeStartOnboarding();
  window.pywebview.api.client_log(`started: ${tokens.size} key(s), ${historyKeys.size} in history`);
}

function init() {
  $('key-list').addEventListener('click', ev => {
    const lockBtn = ev.target.closest('[data-unlock]');
    if (lockBtn) { ev.stopPropagation(); quickLockToggle(lockBtn.dataset.unlock); return; }
    const readBtn = ev.target.closest('[data-read]');
    if (readBtn) { ev.stopPropagation(); openProbe(readBtn.dataset.read); return; }
    const item = ev.target.closest('.key-item');
    if (item) selectToken(item.dataset.id);
  });
  // The lock / read icons are role="button" spans inside the key button: Enter and Space act on them
  $('key-list').addEventListener('keydown', ev => {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    const el = ev.target.closest('[data-unlock], [data-read]');
    if (!el || el !== ev.target) return;
    ev.preventDefault();
    ev.stopPropagation();
    if (el.dataset.unlock) quickLockToggle(el.dataset.unlock); else openProbe(el.dataset.read);
  });
  $('nav-backup').addEventListener('click', showBackupView);
  $('nav-backup-icon').innerHTML = icon('shield', 18);
  $('nav-accounts').addEventListener('click', showAccountsView);
  initUnlockDialog();
  $('nav-accounts-icon').innerHTML = icon('passkey', 18);
  $('nav-settings-icon').innerHTML = icon('settings', 18);
  $('nav-settings').addEventListener('click', showSettingsView);
  $('nav-keys-icon').innerHTML = icon('key', 18);
  $('nav-keys').addEventListener('click', showKeysView);
  initKeysView();
  $('replace-back').addEventListener('click', showBackupView);
  $('accounts-content').addEventListener('input', ev => {
    if (ev.target.id === 'acc-search') {
      accFilter = ev.target.value;
      const pos = ev.target.selectionStart;
      renderAccountsView();
      const box = $('acc-search');
      box.focus();
      box.setSelectionRange(pos, pos);
    }
  });
  $('accounts-content').addEventListener('click', ev => {
    const card = ev.target.closest('[data-acc-filter]');
    if (card) {
      accLevel = accLevel === card.dataset.accFilter ? '' : card.dataset.accFilter;
      renderAccountsView();
      document.querySelector(`#accounts-content [data-acc-filter="${accLevel}"]`)?.focus();
      return;
    }
    if (ev.target.closest('[data-acc-reset]')) {
      accLevel = '';
      accFilter = '';
      renderAccountsView();
      $('acc-search')?.focus();
      return;
    }
    const next = ev.target.closest('[data-next]');
    if (next) {
      const id = next.dataset.next;
      if (accNextOpen.has(id)) accNextOpen.delete(id); else accNextOpen.add(id);
      renderAccountsView();
      document.querySelector(`#accounts-content [data-next="${CSS.escape(id)}"]`)?.focus();
    }
  });
  for (const panel of ['backup-content', 'settings-content', 'replace-content']) $(panel).addEventListener('change', async ev => {
    const el = ev.target;
    if (el.id === 'rp-open-only') { replaceOpenOnly = el.checked; return renderPanel(); }
    if (el.id === 'history-enabled') {
      appSettings = await call('set_settings', { values: { history_enabled: el.checked } }).catch(() => appSettings);
      renderPanel();
    }
    if (el.id === 'personal-mode') {
      appSettings = await call('set_settings', { values: { personal_mode: el.checked } }).catch(() => appSettings);
      render();
      return;
    }
    if (el.id === 'bk-remember') {
      appSettings = await call('set_settings', { values: { remember_sites: el.checked } }).catch(() => appSettings);
      if (!el.checked) await loadHistory();
      render();
    } else if (el.id === 'rp-old') {
      replaceOld = el.value || null;
      renderPanel();
    } else if (el.id === 'rp-new' && replaceOld) {
      const summary = await call('history_replace', { kid: replaceOld, new_kid: el.value || null })
        .catch(e => { showToast(errorMessage(e), 'error'); return null; });
      if (summary) historyKeys.set(summary.key_id, summary);
      renderPanel();
    } else if (el.dataset.rpItem && replaceOld) {
      const summary = await call('history_replace_done', { kid: replaceOld, item: el.dataset.rpItem, done: el.checked })
        .catch(e => { showToast(errorMessage(e), 'error'); return null; });
      if (summary) historyKeys.set(summary.key_id, summary);
      renderPanel();
    } else if (el.id === 'bk-lost-select') {
      lostKid = el.value || null;
      renderPanel();
    } else if (el.dataset.site && lostKid) {
      const summary = await call('history_lost_done', { kid: lostKid, rp_id: el.dataset.site, done: el.checked }).catch(() => null);
      if (summary) { historyKeys.set(summary.key_id, summary); renderPanel(); }
    }
  });
  for (const panel of ['backup-content', 'settings-content', 'replace-content']) $(panel).addEventListener('submit', ev => {
    if (ev.target.id === 'sync-form') { ev.preventDefault(); syncSubmit(); }
  });
  for (const panel of ['backup-content', 'settings-content', 'replace-content']) $(panel).addEventListener('click', async ev => {
    const step = ev.target.closest('[data-rp-step]');
    if (step && !step.disabled) { replaceStep = Number(step.dataset.rpStep); renderPanel(); $('replace-view').scrollTop = 0; return; }
    const filter = ev.target.closest('[data-acc-filter]');
    if (filter) { accLevel = filter.dataset.accFilter || ''; return showAccountsView(); }
    const b = ev.target.closest('[data-act]');
    if (b?.dataset.act === 'open-settings') return showSettingsView();
    if (b?.dataset.act === 'open-replace') return showReplaceView(b.dataset.kid);
    if (b?.dataset.act === 'rp-cancel-ask' || b?.dataset.act === 'rp-cancel-no') {
      replaceCancelAsk = b.dataset.act === 'rp-cancel-ask';
      renderPanel();
      document.querySelector(replaceCancelAsk ? '[data-act="rp-cancel-no"]' : '[data-act="rp-cancel-ask"]')?.focus();
      return;
    }
    if (b?.dataset.act === 'rp-cancel-yes') {
      // forgets the progress only – nothing happens on either key
      const summary = await call('history_replace', { kid: b.dataset.kid, new_kid: null }).catch(e => { showToast(errorMessage(e), 'error'); return null; });
      if (summary) historyKeys.set(summary.key_id, summary);
      replaceCancelAsk = false;
      replaceStep = 1;
      if (summary) showToast(t('rp.cancel.done'), 'success');
      return renderPanel();
    }
    if (b?.dataset.act === 'open-accounts') return showAccountsView();
    if (b?.dataset.act === 'hist-export') return exportHistory();
    if (b?.dataset.act === 'inv-export') return exportInventory();
    if (b?.dataset.act === 'hist-import') return importHistory();
    if (b?.dataset.act?.startsWith('sync-')) return syncAction(b.dataset.act);
    if (b?.dataset.act === 'rp-open-new') {
      const newId = historyKeys.get(replaceOld)?.replace?.new;
      const live = [...tokens.values()].find(tk => tk.history_id === newId && !tk.offline);
      return live ? selectToken(live.id) : newId && selectHistory(newId);
    }
    if (b?.dataset.act === 'rp-stop') {
      const summary = await call('history_replace', { kid: replaceOld, new_kid: null }).catch(() => null);
      if (summary) historyKeys.set(summary.key_id, summary);
      replaceStep = 1;
      return renderPanel();
    }
    if (!b || !lostKid || !['lost', 'unlost'].includes(b.dataset.act)) return;
    const summary = await call('history_set_lost', { kid: lostKid, lost: b.dataset.act === 'lost' }).catch(() => null);
    if (summary) { historyKeys.set(summary.key_id, summary); render(); }
  });
  $('history-list').addEventListener('click', ev => {
    const item = ev.target.closest('.key-item');
    if (item) selectHistory(item.dataset.hist);
  });
  $('hist-content').addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (b) historyAction(b.dataset.act);
  });
  $('hist-content').addEventListener('submit', ev => {
    ev.preventDefault();
    saveHistoryName(ev.target.querySelector('.hist-name').value);
  });
  $('tiles').addEventListener('click', ev => {
    const tileEl = ev.target.closest('[data-goto]');
    if (tileEl) switchTab(tileEl.dataset.goto);
    if (ev.target.closest('[data-view="accounts"]')) showAccountsView();
  });
  $('check').addEventListener('click', ev => {
    if (ev.target.closest('[data-view="accounts"]')) showAccountsView();
  });
  $('caps').addEventListener('click', ev => {
    const link = ev.target.closest('[data-url]');
    if (link) window.pywebview?.api?.open_url(link.dataset.url);
  });
  $('acc-status').addEventListener('click', showAccountsView);
  $('read-btn').addEventListener('click', () => readKey(currentToken()));
  setupMenu('key-actions-btn', 'key-actions-menu');
  $('ft-card').addEventListener('submit', ev => {
    ev.preventDefault();
    runFunctionTest(ev.target.querySelector('.ft-pin')?.value);
  });
  $('check').addEventListener('click', ev => {
    const b = ev.target.closest('[data-goto]');
    if (b) switchTab(b.dataset.goto);
  });
  document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => {
    switchTab(b.dataset.tab);
    if (b.closest('#tab-more-menu')) { setTabMenu(false); $('tab-more-btn').focus(); }
  }));
  $('tab-more-btn').addEventListener('click', () => setTabMenu($('tab-more-menu').classList.contains('hidden')));
  // Tab bar in small windows: fade the edge where more tabs are; the mouse wheel scrolls it sideways
  const tabsBar = document.querySelector('.tabs');
  tabsBar.addEventListener('scroll', syncTabsOverflow, { passive: true });
  tabsBar.addEventListener('wheel', ev => {
    if (Math.abs(ev.deltaY) > Math.abs(ev.deltaX) && tabsBar.scrollWidth > tabsBar.clientWidth) {
      tabsBar.scrollLeft += ev.deltaY;
      ev.preventDefault();
    }
  }, { passive: false });
  new ResizeObserver(syncTabsOverflow).observe(tabsBar);
  // the menu is fixed to the window: close it when its button moves
  for (const ev of ['resize', 'scroll']) {
    addEventListener(ev, e => {
      if (!$('tab-more-menu').classList.contains('hidden') && !$('tab-more-menu').contains(e.target)) setTabMenu(false);
    }, { capture: true, passive: true });
  }
  $('tab-more-btn').addEventListener('keydown', ev => {
    if (ev.key === 'ArrowDown') { ev.preventDefault(); setTabMenu(true, true); }
    if (ev.key === 'Escape') setTabMenu(false);
  });
  $('tab-more-menu').addEventListener('keydown', tabMenuKey);
  document.addEventListener('click', ev => { if (!ev.target.closest('#tab-more')) setTabMenu(false); });
  $('lang-select').addEventListener('change', ev => changeLang(ev.target.value));
  $('about-open').addEventListener('click', () => openAbout());
  $('about-dialog').addEventListener('click', ev => {
    if (ev.target.id === 'about-dialog') return openAbout(false);   // backdrop
    const link = ev.target.closest('[data-url]');
    if (link) return window.pywebview?.api?.open_url(link.dataset.url);
    const act = ev.target.closest('[data-about]')?.dataset.about;
    if (act === 'close') openAbout(false);
    if (act === 'licenses') window.pywebview?.api?.open_licenses();
    if (act === 'updates') { openAbout(false); checkForUpdates(); }
    if (act === 'intro') { openAbout(false); openOnboarding(); }
    if (act === 'diag') openDiagnostics();
    if (act === 'diag-save') saveDiagnostics();
    if (act === 'diag-cancel') openAbout();
  });
  trapFocus($('quick-unlock'));
  initOnboarding();
  trapFocus($('about-dialog'));
  $('about-dialog').addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { ev.preventDefault(); openAbout(false); }
  });
  $('pin-form').addEventListener('submit', submitPinForm);
  $('rs-confirm').addEventListener('change', ev => { $('rs-start').disabled = !ev.target.checked; });
  $('rs-start').addEventListener('click', startReset);
  $('rs-ov-secondary').addEventListener('click', () => closeReset(false));
  $('rs-ov-primary').addEventListener('click', () => closeReset(true));
  initOathPane();
  initPgpPane();
  initPivPane();
  initOtpPane();
  initInterfacesPane();
  initManagementPane('pk-content', passkeyAction);
  $('pk-content').addEventListener('input', ev => {
    if (ev.target.id !== 'pk-search') return;
    pkFilter = ev.target.value;
    const pos = ev.target.selectionStart;
    renderPasskeys();
    const box = $('pk-search');   // keep focus and caret while the list updates
    box?.focus();
    box?.setSelectionRange(pos, pos);
  });
  $('pk-content').addEventListener('toggle', ev => {
    const id = ev.target.dataset?.cred;
    if (id) ev.target.open ? pkOpenDetails.add(id) : pkOpenDetails.delete(id);
  }, true);
  initManagementPane('fp-content', fingerprintAction);
  initManagementPane('cfg-content', configAction);
  $('cfg-content').addEventListener('change', ev => {
    if (ev.target.classList.contains('cfg-alwaysuv')) updateConfig({ always_uv: ev.target.checked }, 'cfg.saved');
  });
  $('pin-show').addEventListener('change', ev => setPinVisible(ev.target.checked));
  $('export-btn').addEventListener('click', () => { closeMenu('key-actions-menu'); exportTokens(); });
  $('data-check').addEventListener('click', checkDataNow);
  $('licenses-open').addEventListener('click', () => window.pywebview?.api?.open_licenses());
  $('update-btn').addEventListener('click', onUpdateButton);

  changeLang('', false);
  switchTab('overview');
  whenBridgeReady(start);
}

// pywebview may inject the page after DOMContentLoaded has already fired
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
