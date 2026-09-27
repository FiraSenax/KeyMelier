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
let replaceOld = null;    // key being replaced (replace view)
let replaceStep = 1;      // 1 choose · 2 compare · 3 test & confirm · 4 summary
let replaceOpenOnly = false;
let replaceCancelAsk = false;   // backup page: confirm cancelling a running replacement
let syncState = null;     // sync_status from the service
let syncForm = { folder: '', error: null, busy: false, confirmOff: false };

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
const PANEL_VIEWS = { backup: 'backup-view', accounts: 'accounts-view', settings: 'settings-view', replace: 'replace-view' };

function render() {
  if (selectedId && !tokens.has(selectedId)) selectedId = null;
  if (selectedHist && !historyKeys.has(selectedHist)) selectedHist = null;
  if (!selectedId && !selectedHist && tokens.size) selectedId = tokens.keys().next().value;

  if (mainView === 'accounts' && !personalMode()) mainView = 'key';
  renderSidebar();
  $('nav-backup').classList.toggle('active', mainView === 'backup' || mainView === 'replace');
  $('nav-accounts').classList.toggle('active', mainView === 'accounts');
  $('nav-settings').classList.toggle('active', mainView === 'settings');
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
    replace: renderReplaceView })[mainView]?.();
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

// One model for account overview, backup view, lost-key assistant and the
// security check (static/accounts.js) – so they can never disagree.
function accountModel() {
  return buildAccountModel([...historyKeys.values()]);
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

async function readContentsNow(tok) {
  const got = await call('read_contents', { token_id: tok.id }).catch(() => ({}));
  const parts = [
    got.sites != null ? t('ql.got.sites', { n: got.sites }) : '',
    got.oath != null ? t('ql.got.oath', { n: got.oath }) : '',
    got.openpgp ? t('ql.got.pgp', { n: got.openpgp }) : '',
    got.piv ? t('ql.got.piv', { n: got.piv }) : '',
  ].filter(Boolean);
  showToast(t('ql.done', { name: displayName(tok) }) + (parts.length ? ` – ${parts.join(', ')}` : ''), 'success');
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
    ${syncCardHtml()}`;
}

function showSettingsView() {
  mainView = 'settings';
  render();
  loadSync();
}

function showReplaceView(kid) {
  if (kid) replaceOld = kid;
  const e = replaceOld && historyKeys.get(replaceOld);
  replaceStep = e?.replace?.new && historyKeys.has(e.replace.new) ? Math.max(replaceStep, 2) : 1;
  mainView = 'replace';
  render();
}

// ── Sync between computers ──────────────────────────────────────────────────
// Through a folder the user already syncs; files are encrypted with a
// passphrase kept in the OS credential store (fido2tool_core/sync.py).

async function loadSync() {
  try { syncState = await call('sync_status'); } catch { syncState = null; }
  if (PANEL_VIEWS[mainView]) renderPanel();
}

// One line on the backup page; details and setup live in the app settings.
// "Synced" means: this computer read the folder and wrote its file – not
// that the cloud has already delivered it everywhere.
function syncLineHtml() {
  const st = syncState;
  if (!st) return '';
  const problem = st.active && (st.errors.length || st.notice);
  const text = !st.available ? t('sync.line.unavailable')
    : st.active ? t('sync.line.on', { when: st.last_sync ? relTime(st.last_sync) : '—', n: st.devices.length })
      : t('sync.line.off');
  return `<div class="sync-line${problem ? ' warn' : ''}" role="status">${icon('refresh', 15)}
    <span>${escHtml(text)}${problem ? ` · ${escHtml(t('sync.line.problem'))}` : ''}</span>
    <button type="button" class="btn-link" data-act="open-settings">${escHtml(t('sync.line.settings'))}</button></div>`;
}

function syncErrorText(e) {
  return t(`sync.err.${e.code}`, { file: e.file || '' });
}

function syncCardHtml() {
  const st = syncState;
  if (!st) return '';
  const head = `<h2>${escHtml(t('sync.title'))}</h2><p class="card-text">${escHtml(t('sync.textShort'))}</p>
    <details class="acc-more"><summary>${escHtml(t('sync.how'))}</summary><p class="field-hint">${escHtml(t('sync.text'))}</p>
      <p class="field-hint">${escHtml(t('sync.privacy'))}</p></details>`;
  if (!st.available) {
    return `<section class="card" id="sync-card">${head}<p class="field-hint bk-hint">${escHtml(t('sync.needsHistory'))}</p></section>`;
  }
  if (st.active) {
    const devices = st.devices.length
      ? `<ul class="sync-devices">${st.devices.map(d => `<li><span>${escHtml(d.name || d.device)}</span>
          <span class="muted">${escHtml(t('sync.written', { when: relTime(d.written) }))}</span></li>`).join('')}</ul>`
      : `<p class="field-hint bk-hint">${escHtml(t('sync.noOthers'))}</p>`;
    const off = syncForm.confirmOff ? `<div class="sync-off">
        <label class="check"><input type="checkbox" id="sync-remove-file"><span>${escHtml(t('sync.removeFile'))}</span></label>
        <div class="form-actions">
          <button type="button" class="btn btn-secondary" data-act="sync-off-cancel">${escHtml(t('pk.delete.cancel'))}</button>
          <button type="button" class="btn btn-danger" data-act="sync-off">${escHtml(t('sync.off'))}</button>
        </div></div>` : '';
    return `<section class="card" id="sync-card">${head}
      <p class="sync-state"><b>${escHtml(t('sync.on.state'))}</b> · ${escHtml(t('sync.last'))}: ${escHtml(st.last_sync ? relTime(st.last_sync) : '—')}
        · ${escHtml(t('sync.othersN', { n: st.devices.length }))}</p>
      <p class="field-hint">${escHtml(t('sync.lastHint'))}</p>
      ${st.notice ? `<p class="field-hint bk-hint warn-text">${escHtml(t(`sync.notice.${st.notice.code}`, { file: st.notice.file }))}</p>` : ''}
      ${st.errors.map(e => `<p class="field-hint bk-hint warn-text">${escHtml(syncErrorText(e))}</p>`).join('')}
      <div class="form-actions att-actions">
        <button type="button" class="btn btn-secondary" data-act="sync-now">${escHtml(t('sync.now'))}</button>
        ${syncForm.confirmOff ? '' : `<button type="button" class="btn btn-secondary" data-act="sync-off-ask">${escHtml(t('sync.off'))}</button>`}
      </div>
      ${off}
      <details class="acc-more"><summary>${escHtml(t('sync.details'))}</summary>
        <dl class="kv">
          <dt>${escHtml(t('sync.folder'))}</dt><dd class="mono">${escHtml(st.folder)}</dd>
          <dt>${escHtml(t('sync.thisComputer'))}</dt><dd>${escHtml(st.device_name)}</dd>
        </dl>
        <h3 class="bk-group">${escHtml(t('sync.others'))}</h3>
        ${devices}
      </details>
    </section>`;
  }
  const problem = st.problem ? `<p class="field-hint bk-hint warn-text">${escHtml(t(`sync.err.${st.problem}`, { file: '' }))}</p>` : '';
  const folder = syncForm.folder || st.configured_folder || '';
  return `<section class="card" id="sync-card">${head}${problem}
    <form id="sync-form" class="sync-form" autocomplete="off">
      <div class="sync-folder">
        <button type="button" class="btn btn-secondary" data-act="sync-choose">${escHtml(t('sync.choose'))}</button>
        <span class="mono ${folder ? '' : 'muted'}">${escHtml(folder || t('sync.noFolder'))}</span>
      </div>
      <label class="field"><span>${escHtml(t('sync.passphrase'))}</span>
        <input type="password" id="sync-pass" minlength="${st.min_passphrase}" maxlength="200" required></label>
      <label class="field"><span>${escHtml(t('sync.passphrase2'))}</span>
        <input type="password" id="sync-pass2" maxlength="200" required></label>
      <p class="field-hint">${escHtml(t('sync.passHint', { n: st.min_passphrase }))}</p>
      ${syncForm.error ? `<p class="field-error">${escHtml(syncForm.error)}</p>` : ''}
      <div class="form-actions">
        <button type="submit" class="btn btn-primary" ${folder && !syncForm.busy ? '' : 'disabled'}>${escHtml(t(syncForm.busy ? 'sync.working' : 'sync.on'))}</button>
      </div>
    </form>
  </section>`;
}

async function syncAction(act) {
  if (act === 'sync-choose') {
    const folder = await window.pywebview.api.choose_folder();
    if (folder) { syncForm.folder = folder; syncForm.error = null; renderPanel(); }
    return;
  }
  if (act === 'sync-off-ask' || act === 'sync-off-cancel') {
    syncForm.confirmOff = act === 'sync-off-ask';
    return renderPanel();
  }
  try {
    if (act === 'sync-now') syncState = await call('sync_now');
    if (act === 'sync-off') {
      syncState = await call('sync_disable', { remove_file: !!$('sync-remove-file')?.checked });
      syncForm = { folder: '', error: null, busy: false, confirmOff: false };
      showToast(t('sync.turnedOff'), 'success');
    }
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
  await loadHistory();
  render();
}

async function syncSubmit() {
  const pass = $('sync-pass'), pass2 = $('sync-pass2');
  const folder = syncForm.folder || syncState?.configured_folder;
  if (pass.value !== pass2.value) { syncForm.error = t('sync.mismatch'); return renderPanel(); }
  if (pass.value.length < (syncState?.min_passphrase || 10)) {
    syncForm.error = t('sync.passHint', { n: syncState?.min_passphrase || 10 });
    return renderPanel();
  }
  syncForm.busy = true;
  syncForm.error = null;
  const passphrase = pass.value;
  pass.value = pass2.value = '';
  renderPanel();
  try {
    syncState = await call('sync_enable', { folder, passphrase });
    syncForm = { folder: '', error: null, busy: false, confirmOff: false };
    await loadHistory();
    showToast(t('sync.turnedOn'), 'success');
    render();
  } catch (e) {
    syncForm.busy = false;
    const code = e?.data?.code;
    syncForm.error = code && STRINGS.en[`sync.err.${code}`] ? syncErrorText({ code }) : errorMessage(e);
    renderPanel();
  }
}

// ── Replace an old key ──────────────────────────────────────────────────────
// Guides moving everything to a new key. Technical checks come from what the
// new key showed when it was read; "done" is only the user's confirmation.
// Nothing is ever reset or deleted on either key.

function replaceKeyOption(e, selected) {
  const sn = serialLabel(e.snapshot);
  return `<option value="${escHtml(e.key_id)}"${selected ? ' selected' : ''}>${escHtml(keyLabel(e))}${sn ? ' · ' + escHtml(sn) : ''}${e.lost_since ? ' – ' + escHtml(t('bk.lostBadge')) : ''}</option>`;
}

const RP_CHECK = {
  found: ['ok', 'rp.check.found'],
  similar: ['warn', 'rp.check.similar'],
  missing: ['warn', 'rp.check.missing'],
  unknown: ['muted', 'rp.check.unknown'],
};

// "2 accounts without a known name (shown as “Administrator”)" – display names only for reading
function unknownAccountLabel(r) {
  const base = t(r.count === 1 ? 'acc.unknownAccount1' : 'acc.unknownAccounts', { n: r.count });
  return r.displays?.length ? `${base} (${t('acc.shownAs', { name: r.displays.join(', ') })})` : base;
}

function replaceItemLabel(i) {
  if (i.kind === 'passkey') return `${i.rpId} · ${i.account}`;
  if (i.kind === 'unknown') return `${i.rpId} · ${unknownAccountLabel(i)}`;
  if (i.kind === 'code') return [i.issuer, i.account].filter(Boolean).join(' · ');
  return inventoryLabel(i.item);
}

const RP_STEPS = ['rp.step.choose', 'rp.step.compare', 'rp.step.confirm', 'rp.step.summary'];

// Guided replacement: 1 choose keys · 2 compare · 3 test at the service and
// confirm · 4 what is still open. "Found on the new key" (technical) and
// "confirmed by you" stay separate; a tick never replaces the technical check.
function renderReplaceView() {
  $('replace-avatar').innerHTML = icon('refresh', 30);
  const el = $('replace-content');
  const entries = [...historyKeys.values()];
  const old = replaceOld && historyKeys.get(replaceOld);
  const newId = old?.replace?.new && historyKeys.has(old.replace.new) ? old.replace.new : null;
  if (!newId && replaceStep > 1) replaceStep = 1;
  const stepper = `<nav class="rp-steps" aria-label="${escHtml(t('rp.title'))}">${RP_STEPS.map((k, i) => {
    const n = i + 1;
    const enabled = n === 1 || newId;
    return `<button type="button" class="rp-step${n === replaceStep ? ' active' : ''}" data-rp-step="${n}"
      ${enabled ? '' : 'disabled'} ${n === replaceStep ? 'aria-current="step"' : ''}><b>${n}</b><span>${escHtml(t(k))}</span></button>`;
  }).join('')}</nav>`;

  if (replaceStep === 1) {
    el.innerHTML = `${stepper}<section class="card">
      <h2>${escHtml(t('rp.step.choose'))}</h2>
      <div class="rp-pick">
        <label><span>${escHtml(t('rp.old'))}</span>
          <select id="rp-old" class="bk-select"><option value="">${escHtml(t('rp.choose'))}</option>
          ${entries.map(e => replaceKeyOption(e, e.key_id === replaceOld)).join('')}</select></label>
        <label><span>${escHtml(t('rp.new'))}</span>
          <select id="rp-new" class="bk-select" ${old ? '' : 'disabled'}><option value="">${escHtml(t('rp.choose'))}</option>
          ${entries.filter(e => e.key_id !== replaceOld && !e.lost_since).map(e => replaceKeyOption(e, e.key_id === newId)).join('')}</select></label>
      </div>
      <p class="field-hint bk-hint">${escHtml(t('rp.never'))}</p>
      <div class="form-actions"><button type="button" class="btn btn-primary" data-rp-step="2" ${newId ? '' : 'disabled'}>${escHtml(t('rp.next'))}</button></div>
    </section>`;
    return;
  }

  const m = accountModel();
  const plan = buildReplacePlan(m, old.key_id, newId);
  const items = replacePlanItems(plan);
  const done = new Set(old.replace.done || []);
  const remember = appSettings.remember_sites !== false && !appSettings.stateless;
  const isOpen = i => !(i.check === 'found' && done.has(i.id));
  const info = m.keyInfo.get(newId);
  const notes = [];
  if (info.coverage === 'none' || (plan.codes.length && !info.codesKnown)) notes.push(t('rp.readNew'));
  else if (info.coverage === 'probe') notes.push(t('rp.probeOnly', { n: info.probedCount }));
  if (!remember) notes.push(t('rp.noRemember'));
  else if (!appSettings.history_enabled) notes.push(t('rp.session'));
  const connected = [...tokens.values()].some(tk => tk.history_id === newId && !tk.offline);
  const pair = `<p class="rp-pair">${escHtml(keyLabel(old))} → ${escHtml(keyLabel(historyKeys.get(newId)))}</p>`;
  const notesHtml = notes.map(n => `<p class="field-hint bk-hint warn-text">${escHtml(n)}</p>`).join('');

  const itemHtml = (i, withTick, strike = withTick) => {
    const [cls, key] = RP_CHECK[i.check];
    const src = [i.source ? t(`acc.src.${i.source}`) : '', i.checked ? relTime(i.checked) : ''].filter(Boolean).join(' · ');
    const chips = `<span class="rp-state">
        <span class="rp-chip ${cls}">${escHtml(t(key))}${src ? `<span class="rp-src"> · ${escHtml(src)}</span>` : ''}</span>
        ${done.has(i.id) ? `<span class="rp-chip user">${escHtml(t('rp.confirmed'))}</span>` : ''}
        ${done.has(i.id) && i.check !== 'found' ? `<span class="rp-chip warn">${escHtml(t('rp.notProven'))}</span>` : ''}
      </span>`;
    const label = `<span class="bk-site">${escHtml(replaceItemLabel(i))}</span>`;
    return `<li class="${strike && done.has(i.id) ? 'done' : ''}">${withTick
      ? `<label><input type="checkbox" data-rp-item="${escHtml(i.id)}" ${done.has(i.id) ? 'checked' : ''} ${remember ? '' : 'disabled'}>${label}</label>`
      : label}${chips}</li>`;
  };
  const section = (list, title, hint, withTick) => {
    const shown = replaceOpenOnly ? list.filter(isOpen) : list;
    if (!list.length) return '';
    return `<h3 class="bk-group">${escHtml(t(title))}</h3>
      <details class="rp-howto"><summary>${escHtml(t('rp.howto'))}</summary><p class="field-hint">${escHtml(t(hint))}</p></details>
      ${shown.length ? `<ul class="bk-lost-list rp-list">${shown.map(i => itemHtml(i, withTick)).join('')}</ul>`
        : `<p class="field-hint">${escHtml(t('rp.noneOpen'))}</p>`}`;
  };
  const sections = withTick => [
    section(plan.passkeys, 'rp.pk.title', 'rp.pk.hint', withTick),
    section(plan.codes, 'hist.contents.oath', 'rp.oath.hint', withTick),
    section(plan.openpgp, 'hist.contents.openpgp', 'rp.pgp.hint', withTick),
    section(plan.piv, 'hist.contents.piv', 'rp.piv.hint', withTick),
    section(plan.otp, 'hist.contents.otp', 'rp.otp.hint', withTick)].join('');
  const openToggle = `<label class="check rp-open-only"><input type="checkbox" id="rp-open-only" ${replaceOpenOnly ? 'checked' : ''}><span>${escHtml(t('rp.openOnly'))}</span></label>`;
  const nav = (back, next) => `<div class="form-actions">
      ${back ? `<button type="button" class="btn btn-secondary" data-rp-step="${back}">${escHtml(t('rp.prev'))}</button>` : ''}
      ${next ? `<button type="button" class="btn btn-primary" data-rp-step="${next}">${escHtml(t('rp.next'))}</button>` : ''}
    </div>`;

  if (!items.length) {
    el.innerHTML = `${stepper}<section class="card">${pair}<p class="card-text">${escHtml(t(remember ? 'rp.empty' : 'rp.noRemember'))}</p>${nav(1)}</section>`;
    return;
  }
  const found = items.filter(i => i.check === 'found').length;
  const confirmed = items.filter(i => done.has(i.id)).length;
  const complete = items.filter(i => !isOpen(i)).length;

  if (replaceStep === 2) {
    el.innerHTML = `${stepper}<section class="card">
      <div class="check-head"><h2>${escHtml(t('rp.step.compare'))}</h2>${openToggle}</div>${pair}
      <p class="card-text">${escHtml(t('rp.compare.text', { n: items.length, found }))}</p>
      <p class="field-hint bk-hint">${escHtml(t('rp.legend'))}</p>
      ${notesHtml}${sections(false)}
      <div class="form-actions"><button type="button" class="btn btn-secondary" data-act="rp-open-new">${escHtml(t(connected ? 'rp.openNew' : 'rp.openNewOffline'))}</button></div>
      ${nav(1, 3)}</section>`;
  } else if (replaceStep === 3) {
    el.innerHTML = `${stepper}<section class="card">
      <div class="check-head"><h2>${escHtml(t('rp.step.confirm'))}</h2>${openToggle}</div>${pair}
      <p class="card-text">${escHtml(t('rp.confirm.text'))}</p>
      ${notesHtml}${sections(true)}${nav(2, 4)}</section>`;
  } else {
    const openItems = items.filter(isOpen);
    const group = (list, key) => (list.length ? `<h3 class="bk-group">${escHtml(t(key, { n: list.length }))}</h3>
      <ul class="bk-lost-list rp-list">${list.map(i => itemHtml(i, false)).join('')}</ul>` : '');
    el.innerHTML = `${stepper}<section class="card">
      <h2>${escHtml(t('rp.step.summary'))}</h2>${pair}
      <div class="acc-summary rp-summary">
        <div class="acc-stat"><b>${items.length}</b><span>${escHtml(t('rp.sum.total'))}</span></div>
        <div class="acc-stat ok"><b>${complete}</b><span>${escHtml(t('rp.sum.complete'))}</span></div>
        <div class="acc-stat ok"><b>${found}</b><span>${escHtml(t('rp.sum.found'))}</span></div>
        <div class="acc-stat info"><b>${confirmed}</b><span>${escHtml(t('rp.sum.confirmed'))}</span></div>
      </div>
      ${notesHtml}
      ${openItems.length ? `<p class="card-text warn-text">${escHtml(t('rp.summary.open', { n: openItems.length }))}</p>` : `<p class="card-text">${escHtml(t('rp.summary.done'))}</p>`}
      ${group(openItems.filter(i => done.has(i.id)), 'rp.group.confirmedOnly')}
      ${group(openItems.filter(i => !done.has(i.id) && i.check === 'found'), 'rp.group.foundOnly')}
      ${group(openItems.filter(i => !done.has(i.id) && i.check !== 'found'), 'rp.group.open')}
      <p class="field-hint bk-hint rp-never">${escHtml(t('rp.never'))}</p>
      <div class="form-actions">
        <button type="button" class="btn btn-secondary" data-rp-step="3">${escHtml(t('rp.prev'))}</button>
        <button type="button" class="btn btn-secondary" data-act="rp-stop">${escHtml(t('rp.stop'))}</button>
      </div></section>`;
  }
}

function lostAssistantHtml(entry) {
  const done = new Set(entry.lost_done || []);
  const toggle = entry.lost_since
    ? `<button type="button" class="btn btn-secondary" data-act="unlost">${escHtml(t('bk.lost.unmark'))}</button>`
    : `<button type="button" class="btn btn-danger" data-act="lost">${escHtml(t('bk.lost.mark'))}</button>`;
  const m = accountModel();
  const mine = rowsOfKey(m, entry.key_id);
  const backupHtml = r => {
    if (!personalMode()) return '';
    if (r.kind === 'unknown') return `<span class="bk-backup warn">${escHtml(t('bk.lost.unknownAccount'))}</span>`;
    const others = r.activeKeys.filter(k => k !== entry.key_id).map(k => keyLabel(historyKeys.get(k)));
    const codes = (r.codeKeys || []).map(k => keyLabel(historyKeys.get(k)));
    if (others.length) return `<span class="bk-backup ok">${escHtml(t('bk.lost.backupOn', { names: others.join(', ') }))}</span>`;
    if (codes.length) return `<span class="bk-backup warn">${escHtml(t('bk.lost.codeOn', { names: codes.join(', ') }))}</span>`;
    return `<span class="bk-backup warn">${escHtml(t('bk.lost.noBackup'))}</span>`;
  };
  const item = (id, label, r) => `<li class="${done.has(id) ? 'done' : ''}">
      <label><input type="checkbox" data-site="${escHtml(id)}" ${done.has(id) ? 'checked' : ''}>
        <span class="bk-site">${escHtml(label)}</span></label>${backupHtml(r)}</li>`;
  const passkeys = mine.filter(r => r.kind !== 'code');
  const list = !entry.lost_since ? '' : passkeys.length ? `
    <p class="card-text bk-steps">${escHtml(t('bk.lost.steps'))}</p>
    <ul class="bk-lost-list">${passkeys.map(r => item(r.kind === 'unknown' ? r.rpId : `${r.rpId}|${r.account}`,
      r.kind === 'unknown' ? `${r.rpId} · ${unknownAccountLabel(r)}` : `${r.rpId} · ${r.account}`, r)).join('')}</ul>
    <p class="field-hint bk-hint">${escHtml(t('bk.lost.u2f'))}</p>` : `<p class="field-hint bk-hint">${escHtml(t(entry.sites ? 'bk.lost.emptyKey' : 'bk.lost.notRecorded'))}</p>
    <p class="field-hint bk-hint">${escHtml(t('bk.lost.u2f'))}</p>`;
  const codes = mine.filter(r => r.kind === 'code');
  const inv = entry.inventory || {};
  const extra = [];
  if (codes.length) extra.push(`<h3 class="bk-group">${escHtml(t('hist.contents.oath'))}</h3>
    <p class="field-hint bk-hint">${escHtml(t('bk.lost.oathHint'))}</p>
    <ul class="bk-lost-list">${codes.map(r => item(`oath:${r.issuer}:${r.account}`, [r.issuer, r.account].filter(Boolean).join(' · '), r)).join('')}</ul>`);
  const pgp = inv.openpgp?.items || [];
  if (pgp.length) extra.push(`<h3 class="bk-group">${escHtml(t('hist.contents.openpgp'))}</h3>
    <p class="field-hint bk-hint">${escHtml(t('bk.lost.pgpHint'))}</p>
    <ul class="bk-lost-list">${pgp.map(k => item(`pgp:${k.fingerprint}`, inventoryLabel(k), { kind: 'none' }).replace(/<span class="bk-backup[^"]*">[^<]*<\/span>/, '')).join('')}</ul>`);
  const piv = inv.piv?.items || [];
  if (piv.length) extra.push(`<h3 class="bk-group">${escHtml(t('hist.contents.piv'))}</h3>
    <p class="field-hint bk-hint">${escHtml(t('bk.lost.pivHint'))}</p>
    <ul class="bk-lost-list">${piv.map(c => item(`piv:${c.label}`, c.label, { kind: 'none' }).replace(/<span class="bk-backup[^"]*">[^<]*<\/span>/, '')).join('')}</ul>`);
  return `<div class="bk-lost">
    <div class="form-actions bk-lost-actions">${toggle}</div>
    ${entry.lost_since ? `<p class="bk-lost-since">${escHtml(t('bk.lost.since', { when: new Date(entry.lost_since).toLocaleDateString(LANG) }))}</p>` : ''}
    ${list}
    ${entry.lost_since ? extra.join('') : ''}
  </div>`;
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
  pinState = null;
  pkState = null;
  fpState = null;
  fpEnroll = null;
  unlockBusy = null;
  clearPinInputs();
  render();
  switchTab(activeTab);
}

// "Advanced" menu of the tab bar: shown when it has an item for this key;
// names the active area when one of its items is open
function syncTabMore() {
  const items = [...document.querySelectorAll('#tab-more-menu .tab')];
  $('tab-more').classList.toggle('hidden', !items.some(b => !b.classList.contains('hidden')));
  const active = items.find(b => b.dataset.tab === activeTab);
  $('tab-more-btn').classList.toggle('active', !!active);
  $('tab-more-current').textContent = active ? ` · ${t(`tab.${activeTab}`)}` : '';
}

function setTabMenu(open, focusFirst = false) {
  const menu = $('tab-more-menu');
  menu.classList.toggle('hidden', !open);
  $('tab-more-btn').setAttribute('aria-expanded', String(open));
  if (open) {
    const items = [...menu.querySelectorAll('.tab:not(.hidden)')];
    (focusFirst ? items[0] : items.find(b => b.dataset.tab === activeTab) || items[0])?.focus();
  }
}

function tabMenuKey(ev) {
  const items = [...$('tab-more-menu').querySelectorAll('.tab:not(.hidden)')];
  const i = items.indexOf(document.activeElement);
  const go = n => { ev.preventDefault(); items[(n + items.length) % items.length]?.focus(); };
  if (ev.key === 'ArrowDown') go(i + 1);
  else if (ev.key === 'ArrowUp') go(i - 1);
  else if (ev.key === 'Home') go(0);
  else if (ev.key === 'End') go(items.length - 1);
  else if (ev.key === 'Escape') { ev.preventDefault(); setTabMenu(false); $('tab-more-btn').focus(); }
  else if (ev.key === 'Tab') setTabMenu(false);
}

// A button that opens a menu: arrows, Home/End move, Esc closes and returns focus
function closeMenu(menuId) {
  const menu = $(menuId);
  if (!menu || menu.classList.contains('hidden')) return;
  menu.classList.add('hidden');
  document.querySelector(`[aria-controls="${menuId}"]`)?.setAttribute('aria-expanded', 'false');
}

function setupMenu(btnId, menuId) {
  const btn = $(btnId), menu = $(menuId);
  const items = () => [...menu.querySelectorAll('[role="menuitem"]:not(.hidden):not(:disabled)')];
  const open = first => {
    menu.classList.remove('hidden');
    btn.setAttribute('aria-expanded', 'true');
    (first ? items()[0] : items()[0])?.focus();
  };
  btn.addEventListener('click', () => (menu.classList.contains('hidden') ? open(true) : closeMenu(menuId)));
  btn.addEventListener('keydown', ev => { if (ev.key === 'ArrowDown') { ev.preventDefault(); open(true); } });
  menu.addEventListener('keydown', ev => {
    const list = items();
    const i = list.indexOf(document.activeElement);
    const go = n => { ev.preventDefault(); list[(n + list.length) % list.length]?.focus(); };
    if (ev.key === 'ArrowDown') go(i + 1);
    else if (ev.key === 'ArrowUp') go(i - 1);
    else if (ev.key === 'Home') go(0);
    else if (ev.key === 'End') go(list.length - 1);
    else if (ev.key === 'Escape') { ev.preventDefault(); closeMenu(menuId); btn.focus(); }
    else if (ev.key === 'Tab') closeMenu(menuId);
  });
  document.addEventListener('click', ev => { if (!ev.target.closest(`#${btnId}`) && !ev.target.closest(`#${menuId}`)) closeMenu(menuId); });
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
    b.setAttribute(b.getAttribute('role') === 'tab' ? 'aria-selected' : 'aria-current', String(b.dataset.tab === tab));
  });
  syncTabMore();
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
    $('update-text').textContent = t(updateFlow.platform === 'win32' ? 'upd.ready.win' : 'upd.ready.mac', { v: app.latest });
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

// "About KeyMelier" inside the app (Windows has no app menu; also from the sidebar on macOS)
const ABOUT_LINKS = [['about.site', 'https://firasenax.github.io/KeyMelier/'],
  ['about.source', 'https://github.com/FiraSenax/KeyMelier'],
  ['about.issues', 'https://github.com/FiraSenax/KeyMelier/issues']];

function openAbout(open = true) {
  const el = $('about-dialog');
  el.classList.toggle('hidden', !open);
  if (!open) { el.innerHTML = ''; $('about-open').focus(); return; }
  const v = dataStatus?.app?.current;
  el.innerHTML = `<div class="ql-dialog card about-dialog">
    <img src="${escHtml(document.querySelector('.brand img')?.src || '')}" width="64" height="64" alt="">
    <h2 id="about-title">KeyMelier</h2>
    ${v ? `<p class="muted">${escHtml(t('upd.version', { v }))}</p>` : ''}
    <p class="about-lead">${escHtml(t('app.tagline'))}</p>
    <p class="card-text">${escHtml(t('about.what'))}</p>
    <p class="field-hint">${escHtml(t('about.privacy'))}</p>
    <p class="about-links">${ABOUT_LINKS.map(([k, url]) => `<button type="button" class="btn-link" data-url="${escHtml(url)}">${escHtml(t(k))}</button>`).join(' · ')}</p>
    <div class="form-actions about-actions">
      <button type="button" class="btn btn-secondary" data-about="licenses">${escHtml(t('about.licenses'))}</button>
      <button type="button" class="btn btn-secondary" data-about="updates">${escHtml(t('upd.check'))}</button>
      <button type="button" class="btn btn-primary" data-about="close">${escHtml(t('about.close'))}</button>
    </div>
    <p class="field-hint">© 2026 Sven Frank · MIT License</p>
  </div>`;
  el.querySelector('[data-about="close"]').focus();
}

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

// ── Unlock (shared by Passkeys and Fingerprints) ────────────────────────────

// Shown while the plug-in attestation test holds the key; the tab reloads by
// itself once the test finishes (see onTokenUpdated).
function waitingHtml() {
  return `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.waitAttestation'))}</div></div>`;
}

function isBusy(e) {
  return e.data?.code === 'busy';
}

function isLocked(e) {
  return e.data?.code === 'locked';
}

let unlockBusy = null;    // null | 'pin' | 'uv' while unlocking
let unlockError = null;   // error message shown in the unlock form

function managementGateHtml(st, unsupportedKey) {
  if (!st) {
    return `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
  }
  if (st.busy) return waitingHtml();
  if (st.error) {
    return `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
  }
  if (!st.supported) {
    return `<div class="callout"><div class="callout-text">${escHtml(t(unsupportedKey))}</div></div>`;
  }
  if (!st.pin_set) {
    return `<div class="callout warn"><div class="callout-title">${escHtml(t('pk.needPin.title'))}</div>
      <div class="callout-text">${escHtml(t('pk.needPin.text'))}</div>
      <button type="button" class="btn-link" data-goto-tab="pin">${escHtml(t('pk.needPin.action'))}</button></div>`;
  }
  if (!st.unlocked) {
    const waitingUv = unlockBusy === 'uv';
    return `
      <form class="card form-card unlock-form" autocomplete="off">
        <h2>${escHtml(t('pk.unlock.title'))}</h2>
        <p class="card-text">${escHtml(t('pk.unlock.text'))}</p>
        ${waitingUv ? `<div class="uv-wait"><span class="uv-icon">${icon('fingerprint', 30)}</span>
            <span>${escHtml(t('pk.unlock.uvWaiting'))}</span></div>` : `
        <label class="field">
          <span>${escHtml(t('pin.form.current'))}</span>
          <input type="password" class="unlock-pin" autocomplete="off" spellcheck="false" ${unlockBusy ? 'disabled' : ''}>
        </label>`}
        ${unlockError ? `<p class="field-error">${escHtml(unlockError)}</p>` : ''}
        ${waitingUv ? '' : `<div class="form-actions">
          ${st.uv_unlock ? `<button type="button" class="btn btn-secondary" data-act="unlock-uv" ${unlockBusy ? 'disabled' : ''}>${icon('fingerprint', 15)} ${escHtml(t('pk.unlock.uv'))}</button>` : ''}
          <button type="submit" class="btn btn-primary" ${unlockBusy ? 'disabled' : ''}>${escHtml(unlockBusy === 'pin' ? t('pk.unlock.working') : t('pk.unlock.pin'))}</button>
        </div>`}
      </form>`;
  }
  return null; // unlocked: caller renders its content
}

function toolbarHtml(summary) {
  return `<div class="pk-toolbar">
      <span class="pk-summary">${escHtml(summary)}</span>
      <button type="button" class="btn btn-secondary" data-act="lock">${icon('lock', 15)} ${escHtml(t('pk.lock'))}</button>
    </div>`;
}

function focusUnlockPin(pane) {
  if (!unlockBusy) document.querySelector(`[data-pane="${pane}"] .unlock-pin`)?.focus();
}

function renderManagement() {
  if (activeTab === 'passkeys') renderPasskeys();
  if (activeTab === 'fingerprints') renderFingerprints();
  if (activeTab === 'settings') renderConfig();
}

function loadManagement(token) {
  if (activeTab === 'passkeys') return loadPasskeys(token);
  if (activeTab === 'fingerprints') return loadFingerprints(token);
  if (activeTab === 'settings') return loadConfig(token);
}

// ── Quick unlock from the sidebar ───────────────────────────────────────────

const unlockedUntil = new Map();   // token id -> ms timestamp (mirrors the server-side TTL)
let quickUnlock = null;            // { id, busy, error }

// Something a PIN unlock gives access to (passkey list, fingerprints, settings)
function canManage(tok) {
  const o = tok?.options || {};
  return !!(o.credMgmt || o.credentialMgmtPreview || o.bioEnroll || o.userVerificationMgmtPreview || o.authnrCfg);
}

function isUnlocked(id) {
  return (unlockedUntil.get(id) || 0) > Date.now();
}

function markUnlocked(id, ttlSeconds) {
  unlockedUntil.set(id, Date.now() + (ttlSeconds || 300) * 1000);
  setTimeout(() => { if (!isUnlocked(id)) renderSidebar(); }, (ttlSeconds || 300) * 1000 + 200);
  renderSidebar();
}

function openProbe(id) {
  quickUnlock = { id, mode: 'probe', busy: false, error: null };
  renderQuickUnlock();
}

function renderProbeDialog(el, tok) {
  const q = quickUnlock;
  const pct = q.total ? Math.round((q.done || 0) * 100 / q.total) : 0;
  el.innerHTML = `<form class="ql-dialog card" autocomplete="off">
    <h2>${escHtml(t('probe.dialogTitle', { name: displayName(tok) }))}</h2>
    <p class="card-text">${escHtml(t('probe.dialogText'))}</p>
    ${tok.options?.clientPin ? `<label class="field"><span>${escHtml(t('probe.pin'))}</span>
      <input type="password" class="ql-pin" autocomplete="off" spellcheck="false" ${q.busy ? 'disabled' : ''}></label>` : ''}
    <label class="field"><span>${escHtml(t('probe.extra'))}</span>
      <input type="text" class="ql-extra" placeholder="firma.okta.com, adfs.firma.de" spellcheck="false" ${q.busy ? 'disabled' : ''}></label>
    ${q.busy ? `<div class="oath-bar probe-bar"><div style="width:${pct}%"></div></div>
      <p class="field-hint">${escHtml(t('probe.progress', { done: q.done || 0, total: q.total || '…' }))}</p>` : ''}
    ${q.error ? `<p class="field-error">${escHtml(q.error)}</p>` : ''}
    <p class="field-hint">${escHtml(t('probe.note'))}</p>
    <div class="form-actions">
      ${q.busy ? `<button type="button" class="btn btn-secondary" data-ql="stop" ${q.stopping ? 'disabled' : ''}>${escHtml(t('probe.stop'))}</button>`
        : `<button type="button" class="btn btn-secondary" data-ql="cancel">${escHtml(t('pk.delete.cancel'))}</button>`}
      <button type="submit" class="btn btn-primary" ${q.busy ? 'disabled' : ''}>${escHtml(t('probe.start'))}</button>
    </div></form>`;
  el.querySelector('.ql-pin')?.focus();
}

async function probeSubmit() {
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  if (!tok) return;
  const root = $('quick-unlock');
  const pin = root.querySelector('.ql-pin')?.value || '';
  const extra = (root.querySelector('.ql-extra')?.value || '').split(/[\s,;]+/).filter(Boolean);
  quickUnlock = { ...quickUnlock, busy: true, error: null, done: 0, total: 0 };
  renderQuickUnlock();
  try {
    const res = await call('passkeys_probe', { token_id: tok.id, pin: pin || null, extra });
    const got = await call('read_contents', { token_id: tok.id }).catch(() => ({}));
    const accounts = res.found.reduce((n, f) => n + f.count, 0);
    const parts = [t('probe.found', { n: accounts, sites: res.found.length }),
      res.complete ? '' : t('probe.sum.stoppedShort'),
      got.oath != null ? t('ql.got.oath', { n: got.oath }) : '', got.openpgp ? t('ql.got.pgp', { n: got.openpgp }) : '',
      got.piv ? t('ql.got.piv', { n: got.piv }) : ''].filter(Boolean);
    showToast(`${displayName(tok)}: ${parts.filter(Boolean).join(', ')}`, res.complete ? 'success' : 'info');
    quickUnlock = null;
    renderQuickUnlock();
    await loadHistory();
    render();
    if (selectedId === tok.id && activeTab === 'passkeys') renderPasskeys();
  } catch (e) {
    quickUnlock = { ...quickUnlock, busy: false, error: errorMessage(e) };
    renderQuickUnlock();
  }
}

let dialogOpener = null;   // element to focus again when a dialog closes

function renderQuickUnlock() {
  const el = $('quick-unlock');
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  const wasOpen = !el.classList.contains('hidden');
  el.classList.toggle('hidden', !tok);
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-modal', 'true');
  if (!tok) {
    el.innerHTML = '';
    if (wasOpen && dialogOpener?.isConnected) dialogOpener.focus();
    dialogOpener = null;
    return;
  }
  if (!wasOpen) dialogOpener = document.activeElement;
  if (quickUnlock.mode === 'probe') return renderProbeDialog(el, tok);
  const uv = tok.options?.uv === true;
  el.innerHTML = `<form class="ql-dialog card" autocomplete="off">
    <h2>${escHtml(t('ql.title', { name: displayName(tok) }))}</h2>
    <p class="card-text">${escHtml(t('ql.text'))}</p>
    ${tok.options?.clientPin ? `<label class="field"><span>${escHtml(t('pin.form.current'))}</span>
      <input type="password" class="ql-pin" autocomplete="off" spellcheck="false" ${quickUnlock.busy ? 'disabled' : ''}></label>` : ''}
    ${quickUnlock.error ? `<p class="field-error">${escHtml(quickUnlock.error)}</p>` : ''}
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" data-ql="cancel">${escHtml(t('pk.delete.cancel'))}</button>
      ${uv ? `<button type="button" class="btn btn-secondary" data-ql="uv" ${quickUnlock.busy ? 'disabled' : ''}>${icon('fingerprint', 15)} ${escHtml(t('sec.att.withUv'))}</button>` : ''}
      ${tok.options?.clientPin ? `<button type="submit" class="btn btn-primary" ${quickUnlock.busy ? 'disabled' : ''}>${quickUnlock.busy ? `<span class="spinner"></span>${escHtml(t('ql.reading'))}` : escHtml(t('ql.do'))}</button>` : ''}
    </div></form>`;
  el.querySelector('.ql-pin')?.focus();
}

async function quickUnlockSubmit(method) {
  const tok = quickUnlock && tokens.get(quickUnlock.id);
  if (!tok) return;
  const pin = $('quick-unlock').querySelector('.ql-pin')?.value || '';
  if (method !== 'uv' && !pin) { quickUnlock.error = t('pin.v.current'); return renderQuickUnlock(); }
  quickUnlock = { ...quickUnlock, busy: true, error: null };
  renderQuickUnlock();
  try {
    const res = await call('unlock', method === 'uv' ? { token_id: tok.id, method: 'uv' } : { token_id: tok.id, pin });
    markUnlocked(tok.id, res.ttl);
    quickUnlock = null;
    renderQuickUnlock();
    await readContentsNow(tok);
    if (selectedId === tok.id && ['passkeys', 'fingerprints', 'settings'].includes(activeTab)) loadManagement(tok);
  } catch (e) {
    quickUnlock = { ...quickUnlock, busy: false, error: errorMessage(e) };
    renderQuickUnlock();
  }
}

async function quickLockToggle(id) {
  if (isUnlocked(id)) {
    await call('lock', { token_id: id }).catch(() => {});
    unlockedUntil.delete(id);
    renderSidebar();
    const tok = tokens.get(id);
    if (tok && selectedId === id) loadManagement(tok);
    return;
  }
  quickUnlock = { id, busy: false, error: null };
  renderQuickUnlock();
}

async function unlockKey(method) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const pin = document.querySelector(`[data-pane="${activeTab}"] .unlock-pin`)?.value || '';
  if (method !== 'uv' && !pin) { unlockError = t('pin.v.current'); renderManagement(); return; }
  unlockBusy = method;
  unlockError = null;
  renderManagement();
  try {
    const res = await call('unlock', method === 'uv' ? { token_id: token.id, method: 'uv' } : { token_id: token.id, pin });
    markUnlocked(token.id, res.ttl);
    unlockBusy = null;
    if (selectedId === token.id) await loadManagement(token);
  } catch (e) {
    unlockBusy = null;
    if (selectedId === token.id) { unlockError = errorMessage(e); renderManagement(); }
  }
}

async function lockKey() {
  const token = tokens.get(selectedId);
  if (!token) return;
  await call('lock', { token_id: token.id }).catch(() => {});
  unlockedUntil.delete(token.id);
  renderSidebar();
  loadManagement(token);
}

// An action failed because the unlock expired: show the unlock form again
function handleActionError(e, state) {
  if (e.data?.code === 'locked' && state) {
    state.unlocked = false;
    unlockError = errorMessage(e);
  } else {
    showToast(errorMessage(e), 'error');
  }
  renderManagement();
}

// ── Passkeys tab ────────────────────────────────────────────────────────────

let pkState = null;       // last passkeys response for the selected token
let pkFilter = '';        // search in the passkey list
const pkOpenDetails = new Set();   // credentials whose details are open
let pkConfirm = null;     // credential_id awaiting delete confirmation
let pkRename = null;      // credential_id being renamed

function credProtectLabel(level) {
  return level === 3 ? t('pk.protect3') : null;
}

function probeSummaryHtml(entry) {
  const p = entry?.probe;
  if (!p) return '';
  const c = p.counts || {};
  const parts = ['found', 'none', 'unsupported', 'uv_required', 'error'].filter(k => c[k])
    .map(k => `<li class="probe-${k}"><b>${c[k]}</b> ${escHtml(t(`probe.st.${k}`))}</li>`).join('');
  return `<div class="callout ${p.complete ? '' : 'warn'}">
    <div class="callout-title">${escHtml(t(p.complete ? 'probe.sum.complete' : 'probe.sum.partial', { asked: p.asked, when: relTime(p.at) }))}</div>
    <ul class="probe-counts">${parts}</ul>
    <div class="callout-text">${escHtml(t('probe.notLogin'))}</div></div>`;
}

function probedPasskeysHtml(token) {
  const entry = historyKeys.get(token.history_id);
  const sites = entry?.sites || [];
  const list = sites.length ? `<section class="card"><ul class="pk-list">${sites.map(s => `<li class="pk-item probe-item">
      ${serviceAvatar(s.rp_id, s.name)}
      <div class="pk-user"><div class="pk-user-name">${escHtml(s.rp_id)}</div>
        <div class="pk-user-sub">${escHtml(t('probe.accounts', { n: s.count }))}${s.partial ? ` · ${escHtml(t('probe.partialNames'))}` : ''}${s.source === 'probe' ? ` · ${escHtml(t('acc.src.probe'))}` : s.source === 'import' ? ` · ${escHtml(t('acc.src.import'))}` : ''}</div>
        ${(s.users || []).some(u => u.name || u.display) ? `<ul class="probe-users">${s.users.map(u => `<li>${escHtml(u.name || u.display || t('probe.unnamed'))}</li>`).join('')}</ul>` : ''}
      </div></li>`).join('')}</ul>
      <p class="field-hint">${escHtml(t('probe.checked', { n: entry.sites_probed || 0, when: relTime(entry.sites_updated) }))}</p></section>` : '';
  return `<div class="callout"><div class="callout-title">${escHtml(t('probe.title'))}</div>
      <div class="callout-text">${escHtml(t('probe.intro'))}</div>
      <div class="form-actions att-actions"><button type="button" class="btn btn-primary" data-act="probe">${escHtml(t(sites.length ? 'probe.again' : 'probe.start'))}</button></div></div>${probeSummaryHtml(entry)}${list}`;
}

function renderPasskeys() {
  const el = $('pk-content');
  const st = pkState;
  const token = tokens.get(selectedId);
  if (st && !st.supported && token && !token.offline) {
    el.innerHTML = probedPasskeysHtml(token);
    el.querySelector('[data-act=probe]').onclick = () => openProbe(token.id);
    return;
  }
  const gate = managementGateHtml(st, 'pk.unsupported');
  if (gate !== null) { el.innerHTML = gate; focusUnlockPin('passkeys'); return; }

  const total = st.rps.reduce((n, rp) => n + rp.credentials.length, 0);
  const summary = [t('pk.count', { n: total })];
  if (st.remaining != null) summary.push(t('tile.passkeys.free', { n: st.remaining }));
  let html = toolbarHtml(summary.join(' · '));

  if (!st.rps.length) {
    el.innerHTML = html + `<div class="callout"><div class="callout-title">${escHtml(t('pk.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('pk.empty.text'))}</div></div>`;
    return;
  }

  // Search by website, service name or account
  const q = pkFilter.toLowerCase().trim();
  const hit = (rp, c) => !q || [rp.rp_id, rp.rp_name, c.user_name, c.display_name].some(v => String(v || '').toLowerCase().includes(q));
  const groups = st.rps.map(rp => ({ rp, creds: rp.credentials.filter(c => hit(rp, c)) })).filter(g => g.creds.length);
  html += `<div class="pk-search">${icon('search', 16)}
    <input type="search" id="pk-search" value="${escHtml(pkFilter)}" placeholder="${escHtml(t('pk.search'))}" aria-label="${escHtml(t('pk.search'))}" spellcheck="false">
    ${q ? `<span class="muted">${escHtml(t('pk.search.count', { n: groups.reduce((n, g) => n + g.creds.length, 0), total }))}</span>` : ''}</div>`;
  if (!groups.length) {
    el.innerHTML = html + `<p class="field-hint">${escHtml(t('pk.search.none'))}</p>`;
    return;
  }

  html += '<section class="card pk-compact">' + groups.map(({ rp, creds }) => {
    const name = rp.rp_id || rp.rp_name || t('pk.unknownSite');
    return `<div class="pk-group">
      <div class="pk-group-head">${serviceAvatar(rp.rp_id, rp.rp_name)}
        <span class="pk-rp-name">${escHtml(name)}</span>
        ${rp.rp_name && rp.rp_name !== name ? `<span class="pk-rp-sub">${escHtml(rp.rp_name)}</span>` : ''}
        ${creds.length > 1 ? `<span class="pill">${escHtml(t('pk.accountsN', { n: creds.length }))}</span>` : ''}
      </div>
      <ul class="pk-list">` + creds.map(c => {
        const main = c.user_name || c.display_name || t('pk.noName');
        const sub = c.display_name && c.user_name && c.user_name !== c.display_name ? c.display_name : '';
        const prot = credProtectLabel(c.cred_protect);
        const confirming = pkConfirm === c.credential_id;
        if (pkRename === c.credential_id) {
          return `<li class="pk-item">
            <form class="pk-rename-form" data-id="${escHtml(c.credential_id)}">
              <input type="text" class="pk-rename-display" value="${escHtml(c.display_name)}" placeholder="${escHtml(t('pk.rename.display'))}" aria-label="${escHtml(t('pk.rename.display'))}" maxlength="64" spellcheck="false">
              <input type="text" class="pk-rename-name" value="${escHtml(c.user_name)}" placeholder="${escHtml(t('pk.rename.name'))}" aria-label="${escHtml(t('pk.rename.name'))}" maxlength="64" spellcheck="false">
              <div class="pk-rename-actions">
                <button type="button" class="btn btn-secondary" data-act="rename-cancel">${escHtml(t('pk.delete.cancel'))}</button>
                <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
              </div>
            </form></li>`;
        }
        return `<li class="pk-item${confirming ? ' confirming' : ''}">
          <div class="pk-user">
            <div class="pk-user-name">${escHtml(main)}${sub ? ` <span class="pk-user-sub">· ${escHtml(sub)}</span>` : ''}</div>
            <details class="pk-details" data-cred="${escHtml(c.credential_id)}" ${pkOpenDetails.has(c.credential_id) ? 'open' : ''}>
              <summary>${escHtml(t('pk.details'))}</summary>
              <dl class="kv pk-kv">
                ${prot ? `<dt>${escHtml(t('pk.protection'))}</dt><dd>${escHtml(prot)}</dd>` : ''}
                <dt>${escHtml(t('pk.largeBlob'))}</dt><dd>${escHtml(t(c.large_blob ? 'pk.yes' : 'pk.no'))}</dd>
                <dt>${escHtml(t('pk.credId'))}</dt><dd class="mono">${escHtml(String(c.credential_id).slice(0, 24))}…</dd>
              </dl>
            </details>
          </div>
          ${confirming ? `
            <div class="pk-confirm" role="group" aria-label="${escHtml(t('pk.delete.confirm'))}">
              <span>${escHtml(t('pk.delete.confirm'))}</span>
              <button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
              <button type="button" class="btn btn-danger" data-act="delete" data-id="${escHtml(c.credential_id)}">${escHtml(t('pk.delete.do'))}</button>
            </div>` : `<div class="pk-actions">
            ${st.rename ? `<button type="button" class="btn-small" data-act="rename" data-id="${escHtml(c.credential_id)}">${icon('pencil', 14)}<span>${escHtml(t('fp.rename'))}</span></button>` : ''}
            <button type="button" class="btn-small danger" data-act="ask-delete" data-id="${escHtml(c.credential_id)}">${icon('trash', 14)}<span>${escHtml(t('pk.delete.do'))}</span></button></div>`}
        </li>`;
      }).join('') + '</ul></div>';
  }).join('') + '</section>';
  if (pkConfirm) html += `<p class="field-hint">${escHtml(t('pk.delete.warning'))}</p>`;
  el.innerHTML = html;
}

// retried: the key rejected the unlock (expired) – reload once to get the
// locked state and show the unlock form with a hint instead of an error
async function loadPasskeys(token, retried = false) {
  pkState = null;
  if (!retried) unlockError = null;
  pkConfirm = null;
  renderPasskeys();
  try {
    const st = await call('passkeys', { token_id: token.id });
    if (selectedId !== token.id) return;
    pkState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isLocked(e) && !retried) { unlockError = errorMessage(e); return loadPasskeys(token, true); }
    pkState = isBusy(e) ? { busy: true } : { error: errorMessage(e) };
  }
  renderPasskeys();
}

function findPasskey(credId) {
  for (const rp of pkState?.rps || []) {
    const c = rp.credentials.find(x => x.credential_id === credId);
    if (c) return { rp, c };
  }
  return null;
}

async function renamePasskey(credId, displayName, name) {
  const token = tokens.get(selectedId);
  const found = findPasskey(credId);
  if (!token || !found) return;
  try {
    pkState = await call('passkey_rename', {
      token_id: token.id, credential_id: credId, user_id: found.c.user_id,
      name, display_name: displayName, site: found.rp.rp_id || found.rp.rp_name,
    });
    pkRename = null;
    renderPasskeys();
    showToast(t('pk.rename.done'), 'success');
  } catch (e) {
    handleActionError(e, pkState);
  }
}

async function passkeyAction(action, credId) {
  const token = tokens.get(selectedId);
  if (!token) return;
  if (action === 'reload') return loadPasskeys(token);
  if (action === 'ask-delete') { pkConfirm = credId; pkRename = null; return renderPasskeys(); }
  if (action === 'rename') { pkRename = credId; pkConfirm = null; return renderPasskeys(); }
  if (action === 'rename-cancel') { pkRename = null; return renderPasskeys(); }
  if (action === 'cancel') { pkConfirm = null; return renderPasskeys(); }
  if (action === 'delete') {
    pkConfirm = null;
    try {
      const found = (pkState?.rps || []).flatMap(rp => rp.credentials.map(c => ({ rp, c }))).find(x => x.c.credential_id === credId);
      pkState = await call('passkey_delete', {
        token_id: token.id,
        credential_id: credId,
        site: found ? (found.rp.rp_id || found.rp.rp_name) : '',
        user: found ? (found.c.user_name || found.c.display_name) : '',
      });
      renderPasskeys();
      showToast(t('pk.delete.done'), 'success');
    } catch (e) {
      handleActionError(e, pkState);
    }
  }
}

// ── Fingerprints tab ────────────────────────────────────────────────────────

let fpState = null;       // last fingerprints response for the selected token
let fpConfirm = null;     // template id awaiting delete confirmation
let fpRename = null;      // template id being renamed
let fpEnroll = null;      // running enrollment: { stage, feedback, remaining, total, error }

function fingerprintLabel(fp, i) {
  return fp.name || t('fp.unnamed', { n: i + 1 });
}

function enrollHtml(st) {
  const e = fpEnroll;
  if (!e) {
    const max = Number.isInteger(st.max_name_bytes) ? `maxlength="${st.max_name_bytes}"` : '';
    return `<form class="card form-card fp-enroll-form" autocomplete="off">
        <h2>${escHtml(t('fp.enroll.title'))}</h2>
        <p class="card-text">${escHtml(t('fp.enroll.text'))}</p>
        <label class="field">
          <span>${escHtml(t('fp.enroll.name'))}</span>
          <input type="text" class="fp-name" ${max} placeholder="${escHtml(t('fp.enroll.namePlaceholder'))}" spellcheck="false">
        </label>
        <div class="form-actions">
          <button type="submit" class="btn btn-primary">${icon('fingerprint', 15)} ${escHtml(t('fp.enroll.start'))}</button>
        </div>
      </form>`;
  }
  if (e.error) {
    return `<div class="callout crit">
        <div class="callout-title">${escHtml(t('fp.enroll.failed'))}</div>
        <div class="callout-text">${escHtml(e.error)}</div>
        <button type="button" class="btn-link" data-act="enroll-reset">${escHtml(t('pin.retry'))}</button>
      </div>`;
  }
  const total = e.total || 0;
  const done = total ? total - (e.remaining ?? total) : 0;
  const pct = total ? Math.round((done / total) * 100) : 0;
  const good = !e.feedback || e.feedback === 'FP_GOOD';
  const hint = e.stage === 'sample' && e.feedback
    ? t(`fp.fb.${e.feedback}`)
    : t(e.remaining == null ? 'fp.enroll.first' : 'fp.enroll.again');
  return `<div class="card fp-progress">
      <div class="fp-progress-icon${good ? '' : ' bad'}">${icon('fingerprint', 44)}</div>
      <div class="fp-progress-text${good ? '' : ' bad'}">${escHtml(hint)}</div>
      <div class="progress"><div class="progress-bar" style="width:${pct}%"></div></div>
      <div class="fp-progress-count">${total ? escHtml(t('fp.enroll.count', { done, total })) : '&nbsp;'}</div>
      <button type="button" class="btn btn-secondary" data-act="enroll-cancel">${escHtml(t('pk.delete.cancel'))}</button>
    </div>`;
}

function renderFingerprints() {
  const el = $('fp-content');
  const st = fpState;
  const gate = managementGateHtml(st, 'fp.unsupported');
  if (gate !== null) { el.innerHTML = gate; focusUnlockPin('fingerprints'); return; }

  const fps = st.fingerprints || [];
  let html = toolbarHtml(t('fp.count', { n: fps.length }));

  if (fps.length) {
    html += '<section class="card"><ul class="pk-list">' + fps.map((fp, i) => {
      let actions;
      if (fpRename === fp.id) {
        const max = Number.isInteger(st.max_name_bytes) ? `maxlength="${st.max_name_bytes}"` : '';
        return `<li class="pk-item">
          <form class="fp-rename-form" data-id="${escHtml(fp.id)}">
            <input type="text" class="fp-rename-input" value="${escHtml(fp.name)}" ${max} spellcheck="false">
            <button type="button" class="btn btn-secondary" data-act="rename-cancel">${escHtml(t('pk.delete.cancel'))}</button>
            <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
          </form></li>`;
      }
      if (fpConfirm === fp.id) {
        actions = `<div class="pk-confirm">
            <span>${escHtml(t('pk.delete.confirm'))}</span>
            <button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
            <button type="button" class="btn btn-danger" data-act="delete" data-id="${escHtml(fp.id)}">${escHtml(t('pk.delete.do'))}</button>
          </div>`;
      } else {
        actions = `<button type="button" class="btn-icon" data-act="rename" data-id="${escHtml(fp.id)}" title="${escHtml(t('fp.rename'))}">${icon('pencil', 16)}</button>
          <button type="button" class="btn-icon danger" data-act="ask-delete" data-id="${escHtml(fp.id)}" title="${escHtml(t('pk.delete.do'))}">${icon('trash', 16)}</button>`;
      }
      return `<li class="pk-item">
          <span class="fp-item-icon">${icon('fingerprint', 18)}</span>
          <div class="pk-user"><div class="pk-user-name">${escHtml(fingerprintLabel(fp, i))}</div></div>
          ${actions}
        </li>`;
    }).join('') + '</ul></section>';
    if (fpConfirm) html += `<p class="field-hint">${escHtml(t('fp.delete.warning'))}</p>`;
  } else {
    html += `<div class="callout warn"><div class="callout-title">${escHtml(t('fp.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('fp.empty.text'))}</div></div>`;
  }

  html += enrollHtml(st);
  el.innerHTML = html;
  if (fpRename) el.querySelector('.fp-rename-input')?.focus();
}

async function loadFingerprints(token, retried = false) {
  fpState = null;
  if (!retried) unlockError = null;
  fpConfirm = null;
  fpRename = null;
  renderFingerprints();
  try {
    const st = await call('fingerprints', { token_id: token.id });
    if (selectedId !== token.id) return;
    fpState = st;
    if (st.enrolling && !fpEnroll) fpEnroll = { stage: 'touch' };
    if (!st.enrolling && fpEnroll && !fpEnroll.error) fpEnroll = null;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isLocked(e) && !retried) { unlockError = errorMessage(e); return loadFingerprints(token, true); }
    fpState = isBusy(e) ? { busy: true } : { error: errorMessage(e) };
  }
  renderFingerprints();
}

async function fingerprintAction(action, id) {
  const token = tokens.get(selectedId);
  if (!token) return;
  if (action === 'reload') return loadFingerprints(token);
  if (action === 'ask-delete') { fpConfirm = id; fpRename = null; return renderFingerprints(); }
  if (action === 'cancel') { fpConfirm = null; return renderFingerprints(); }
  if (action === 'rename') { fpRename = id; fpConfirm = null; return renderFingerprints(); }
  if (action === 'rename-cancel') { fpRename = null; return renderFingerprints(); }
  if (action === 'enroll-reset') { fpEnroll = null; return renderFingerprints(); }
  if (action === 'enroll-cancel') {
    call('fingerprint_enroll_cancel', { token_id: token.id }).catch(() => {});
    return;
  }
  if (action === 'delete') {
    fpConfirm = null;
    try {
      const idx = (fpState?.fingerprints || []).findIndex(f => f.id === id);
      const label = idx >= 0 ? fingerprintLabel(fpState.fingerprints[idx], idx) : '';
      fpState = await call('fingerprint_delete', { token_id: token.id, template_id: id, name: label });
      renderFingerprints();
      showToast(t('fp.delete.done'), 'success');
    } catch (e) {
      handleActionError(e, fpState);
    }
  }
}

async function renameFingerprint(id, name) {
  const token = tokens.get(selectedId);
  if (!token) return;
  try {
    fpState = await call('fingerprint_rename', { token_id: token.id, template_id: id, name });
    fpRename = null;
    renderFingerprints();
  } catch (e) {
    handleActionError(e, fpState);
  }
}

async function startEnrollment(name) {
  const token = tokens.get(selectedId);
  if (!token) return;
  fpEnroll = { stage: 'touch' };
  renderFingerprints();
  try {
    await call('fingerprint_enroll', { token_id: token.id, name });
  } catch (e) {
    fpEnroll = null;
    handleActionError(e, fpState);
  }
}

function onEnrollProgress(p) {
  if (p.id !== selectedId || !fpEnroll) return;
  fpEnroll = { ...fpEnroll, ...p };
  renderFingerprints();
}

function onEnrollDone(r) {
  if (r.id !== selectedId) return;
  if (r.ok) {
    fpEnroll = null;
    showToast(t('fp.enroll.done'), 'success');
    const token = tokens.get(selectedId);
    if (token && activeTab === 'fingerprints') loadFingerprints(token);
  } else if (r.code === 'cancelled') {
    fpEnroll = null;
    renderFingerprints();
  } else if (r.code === 'locked') {
    fpEnroll = null;
    if (fpState) fpState.unlocked = false;
    unlockError = errorMessage({ data: r, message: r.error });
    renderFingerprints();
  } else {
    fpEnroll = { error: errorMessage({ data: r, message: r.error }) };
    renderFingerprints();
  }
}

function initManagementPane(paneId, onAction) {
  const el = $(paneId);
  el.addEventListener('click', ev => {
    const g = ev.target.closest('[data-goto-tab]');
    if (g) return switchTab(g.dataset.gotoTab);
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    if (act === 'unlock-uv') return unlockKey('uv');
    if (act === 'lock') return lockKey();
    onAction(act, b.dataset.id);
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    if (f.classList.contains('unlock-form')) unlockKey('pin');
    else if (f.classList.contains('fp-enroll-form')) startEnrollment(f.querySelector('.fp-name').value.trim());
    else if (f.classList.contains('fp-rename-form')) renameFingerprint(f.dataset.id, f.querySelector('.fp-rename-input').value);
    else if (f.classList.contains('pk-rename-form')) renamePasskey(f.dataset.id, f.querySelector('.pk-rename-display').value, f.querySelector('.pk-rename-name').value);
    else if (f.classList.contains('cfg-minpin-form')) updateConfig({ min_pin_length: Number(f.querySelector('.cfg-minpin').value) }, 'cfg.saved');
  });
}

// ── Function test ───────────────────────────────────────────────────────────

let ftState = null;       // { needsPin, running, touch, result }

function renderFunctionTest() {
  const el = $('ft-card');
  const token = currentToken();
  if (!el || !token || token.offline) { if (el) el.innerHTML = ''; el?.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  const st = ftState || {};
  const r = st.result;
  let body = '';
  if (st.running) {
    body = `<div class="uv-wait"><span class="uv-icon">${icon('key', 26)}</span>
      <span>${escHtml(t(st.needsPin ? 'ft.touchUv' : 'ft.touch'))}</span></div>`;
  } else if (r) {
    const names = { register: 'ft.step.register', sign_in: 'ft.step.signIn', signature: 'ft.step.signature' };
    body = `<div class="att-summary ${r.ok ? 'pass' : 'fail'}">${escHtml(r.ok ? t('ft.ok', { s: r.seconds }) : (r.error ? errorMessage({ data: r, message: r.error }) : t('ft.failed')))}</div>
      <div class="att-checks">${(r.steps || []).map(s => `<div class="att-check ${s.ok ? 'pass' : 'fail'}">
        <span class="att-check-icon">${s.ok ? '✓' : '✕'}</span><div><div class="att-check-name">${escHtml(t(names[s.step] || s.step))}</div></div></div>`).join('')}
        ${r.ok ? `<div class="att-check pass"><span class="att-check-icon">${r.user_verified ? '✓' : '○'}</span><div><div class="att-check-name">${escHtml(t(r.user_verified ? 'ft.uv' : 'ft.noUv'))}</div></div></div>` : ''}
      </div>`;
  }
  el.innerHTML = `<h2>${escHtml(t('ft.title'))}</h2>
    <p class="card-text">${escHtml(t('ft.text'))}</p>
    ${body}
    ${st.running ? '' : `<form class="ft-form" autocomplete="off">
      ${st.needsPin ? `<label class="field"><span>${escHtml(t('pin.form.current'))}</span>
        <input type="password" class="ft-pin" autocomplete="off" spellcheck="false"></label>` : ''}
      <div class="form-actions att-actions"><button type="submit" class="btn btn-secondary">${escHtml(t(r ? 'ft.again' : 'ft.start'))}</button></div>
    </form>`}`;
}

async function loadFunctionTest(token) {
  ftState = { needsPin: false };
  renderFunctionTest();
  try {
    const info = await call('function_test_info', { token_id: token.id });
    if (selectedId === token.id) { ftState = { ...ftState, ...info }; renderFunctionTest(); }
  } catch { /* busy during attestation – button still works */ }
}

async function runFunctionTest(pin) {
  const token = tokens.get(selectedId);
  if (!token) return;
  ftState = { ...ftState, running: true, result: null };
  renderFunctionTest();
  try {
    const result = await call('function_test', { token_id: token.id, pin: pin || null });
    ftState = { ...ftState, running: false, result, needsPin: ftState.needsPin || result.code === 'pin_required' };
  } catch (e) {
    ftState = { ...ftState, running: false, result: { ok: false, error: e.message, code: e.data?.code, steps: [] } };
  }
  if (selectedId === token.id) renderFunctionTest();
}

// ── Authenticator (OATH) tab ────────────────────────────────────────────────

let oathState = null;     // server response (status + accounts)
let oathForm = null;      // null | 'add' | 'password'
let oathEdit = null;      // account id being renamed
let oathConfirm = null;   // account id awaiting delete confirmation, or 'reset'
let oathBusy = null;      // account id whose touch code is being calculated
let oathTimer = null;
let oathError = null;

function stopOathTimer() {
  clearInterval(oathTimer);
  oathTimer = null;
}

function startOathTimer(token) {
  stopOathTimer();
  oathTimer = setInterval(() => {
    if (activeTab !== 'oath' || selectedId !== token.id) return stopOathTimer();
    const now = Date.now() / 1000;
    let expired = false;
    document.querySelectorAll('#oath-content [data-valid-to]').forEach(el => {
      const to = Number(el.dataset.validTo), period = Number(el.dataset.period) || 30;
      const left = Math.max(0, to - now);
      el.style.width = `${(left / period) * 100}%`;
      if (left <= 0) expired = true;
    });
    if (expired && !oathForm && !oathEdit) loadOath(token, true);
  }, 500);
}

function formatCode(code) {
  if (!code) return '';
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code;
}

function oathAccountHtml(a, st) {
  const label = a.issuer || a.name;
  if (oathEdit === a.id) {
    return `<li class="pk-item"><form class="oath-rename-form pk-rename-form" data-id="${escHtml(a.id)}">
      <input type="text" class="oath-rename-issuer" value="${escHtml(a.issuer)}" placeholder="${escHtml(t('oath.issuer'))}" maxlength="60">
      <input type="text" class="oath-rename-name" value="${escHtml(a.name)}" placeholder="${escHtml(t('oath.account'))}" maxlength="60">
      <div class="pk-rename-actions">
        <button type="button" class="btn btn-secondary" data-act="edit-cancel">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
      </div></form></li>`;
  }
  let codeHtml;
  if (a.code) {
    codeHtml = `<button type="button" class="oath-code" data-act="copy" data-code="${escHtml(a.code)}" title="${escHtml(t('oath.copy'))}">${escHtml(formatCode(a.code))}</button>
      ${a.valid_to ? `<div class="oath-bar"><div data-valid-to="${a.valid_to}" data-period="${a.period || 30}"></div></div>` : ''}`;
  } else if (oathBusy === a.id) {
    codeHtml = `<span class="oath-wait"><span class="spinner"></span>${escHtml(t('oath.touch'))}</span>`;
  } else {
    codeHtml = `<button type="button" class="btn btn-secondary oath-get" data-act="code" data-id="${escHtml(a.id)}">${icon(a.touch ? 'key' : 'lock', 14)} ${escHtml(t(a.touch ? 'oath.touchForCode' : 'oath.generate'))}</button>`;
  }
  const actions = oathConfirm === a.id
    ? `<div class="pk-confirm"><span>${escHtml(t('pk.delete.confirm'))}</span>
        <button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="button" class="btn btn-danger" data-act="delete" data-id="${escHtml(a.id)}">${escHtml(t('pk.delete.do'))}</button></div>`
    : `${st.can_rename ? `<button type="button" class="btn-icon" data-act="edit" data-id="${escHtml(a.id)}" title="${escHtml(t('fp.rename'))}">${icon('pencil', 16)}</button>` : ''}
       <button type="button" class="btn-icon danger" data-act="ask-delete" data-id="${escHtml(a.id)}" title="${escHtml(t('pk.delete.do'))}">${icon('trash', 16)}</button>`;
  return `<li class="pk-item oath-item">
    ${serviceAvatar(a.issuer, label)}
    <div class="pk-user"><div class="pk-user-name">${escHtml(label)}</div>
      ${a.issuer ? `<div class="pk-user-sub">${escHtml(a.name)}</div>` : ''}</div>
    <div class="oath-code-wrap">${codeHtml}</div>
    ${actions}
  </li>`;
}

function renderOath() {
  const el = $('oath-content');
  if (!el) return;
  const st = oathState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
    return;
  }
  if (!st.unlocked) {
    el.innerHTML = `<form class="card form-card oath-unlock-form" autocomplete="off">
      <h2>${escHtml(t('oath.locked.title'))}</h2>
      <p class="card-text">${escHtml(t('oath.locked.text'))}</p>
      <label class="field"><span>${escHtml(t('oath.password'))}</span>
        <input type="password" class="oath-password" autocomplete="off" spellcheck="false"></label>
      ${oathError ? `<p class="field-error">${escHtml(oathError)}</p>` : ''}
      <div class="form-actions"><button type="submit" class="btn btn-primary">${escHtml(t('pk.unlock.pin'))}</button></div>
    </form>`;
    el.querySelector('.oath-password')?.focus();
    return;
  }
  const accounts = st.accounts || [];
  const parts = [`<div class="pk-toolbar"><span class="pk-summary">${escHtml(t('oath.count', { n: accounts.length }))}</span>
    <button type="button" class="btn btn-primary" data-act="show-add">${escHtml(t('oath.add'))}</button></div>`];
  if (oathError) parts.push(`<p class="field-error">${escHtml(oathError)}</p>`);
  if (oathForm === 'add') {
    parts.push(`<form class="card form-card oath-add-form" autocomplete="off">
      <h2>${escHtml(t('oath.add'))}</h2>
      <label class="field"><span>${escHtml(t('oath.uri'))}</span>
        <input type="text" class="oath-uri" placeholder="otpauth://totp/…" spellcheck="false"></label>
      <p class="field-hint">${escHtml(t('oath.orManual'))}</p>
      <div class="oath-grid">
        <label class="field"><span>${escHtml(t('oath.issuer'))}</span><input type="text" class="oath-issuer" maxlength="60"></label>
        <label class="field"><span>${escHtml(t('oath.account'))}</span><input type="text" class="oath-name" maxlength="60"></label>
        <label class="field oath-wide"><span>${escHtml(t('oath.secret'))}</span><input type="text" class="oath-secret" spellcheck="false" autocomplete="off"></label>
        <label class="field"><span>${escHtml(t('oath.type'))}</span><select class="oath-type bk-select"><option>TOTP</option><option>HOTP</option></select></label>
        <label class="field"><span>${escHtml(t('oath.digits'))}</span><select class="oath-digits bk-select"><option>6</option><option>7</option><option>8</option></select></label>
      </div>
      <label class="check"><input type="checkbox" class="oath-touch"><span>${escHtml(t('oath.requireTouch'))}</span></label>
      <div class="form-actions">
        <button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="submit" class="btn btn-primary">${escHtml(t('oath.save'))}</button>
      </div></form>`);
  }
  if (accounts.length) {
    parts.push(`<section class="card"><ul class="pk-list">${accounts.map(a => oathAccountHtml(a, st)).join('')}</ul></section>`);
  } else if (oathForm !== 'add') {
    parts.push(`<div class="callout"><div class="callout-title">${escHtml(t('oath.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('oath.empty.text'))}</div></div>`);
  }
  // Password & reset
  parts.push(oathForm === 'password'
    ? `<form class="card form-card oath-password-form" autocomplete="off">
        <h2>${escHtml(t(st.password ? 'oath.pw.change' : 'oath.pw.set'))}</h2>
        <label class="field"><span>${escHtml(t('oath.pw.new'))}</span><input type="password" class="oath-pw-new" autocomplete="new-password"></label>
        <label class="field"><span>${escHtml(t('pin.form.confirm'))}</span><input type="password" class="oath-pw-confirm" autocomplete="new-password"></label>
        <p class="field-hint">${escHtml(t('oath.pw.hint'))}</p>
        <div class="form-actions">
          ${st.password ? `<button type="button" class="btn btn-secondary" data-act="pw-remove">${escHtml(t('oath.pw.remove'))}</button>` : ''}
          <button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
          <button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button>
        </div></form>`
    : `<section class="card"><h2>${escHtml(t('oath.protect.title'))}</h2>
        <p class="card-text">${escHtml(t(st.password ? 'oath.protect.on' : 'oath.protect.off'))}</p>
        <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="show-password">${escHtml(t(st.password ? 'oath.pw.change' : 'oath.pw.set'))}</button></div>
      </section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('oath.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('oath.reset.text'))}</p>
    <div class="form-actions att-actions">${oathConfirm === 'reset'
      ? `<button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('oath.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="ask-reset">${escHtml(t('oath.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
}

async function loadOath(token, quiet = false) {
  if (!quiet) { oathState = null; oathError = null; renderOath(); }
  try {
    const st = await call('oath', { token_id: token.id });
    if (selectedId !== token.id) return;
    oathState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (e.data?.code === 'oath_locked') oathState = { unlocked: false };
    else oathState = isBusy(e) ? { error: t('err.busy') } : { error: errorMessage(e) };
  }
  renderOath();
  if (oathState?.unlocked) startOathTimer(token);
}

async function oathCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  oathError = null;
  try {
    oathState = await call(method, { token_id: token.id, ...args });
    oathForm = null; oathEdit = null; oathConfirm = null;
    if (doneKey) showToast(t(doneKey), 'success');
  } catch (e) {
    if (e.data?.code === 'oath_locked') oathState = { unlocked: false };
    oathError = errorMessage(e);
  }
  renderOath();
  if (oathState?.unlocked) startOathTimer(token);
}

async function oathAction(act, id, el) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const st = oathState || {};
  if (act === 'reload') return loadOath(token);
  if (act === 'show-add') { oathForm = 'add'; oathError = null; return renderOath(); }
  if (act === 'show-password') { oathForm = 'password'; oathError = null; return renderOath(); }
  if (act === 'hide-form') { oathForm = null; return renderOath(); }
  if (act === 'edit') { oathEdit = id; oathConfirm = null; return renderOath(); }
  if (act === 'edit-cancel') { oathEdit = null; return renderOath(); }
  if (act === 'ask-delete') { oathConfirm = id; oathEdit = null; return renderOath(); }
  if (act === 'ask-reset') { oathConfirm = 'reset'; return renderOath(); }
  if (act === 'cancel') { oathConfirm = null; return renderOath(); }
  if (act === 'copy') {
    const ok = await window.pywebview?.api?.copy_text(el.dataset.code);
    return showToast(t(ok ? 'oath.copied' : 'oath.copyFailed'), ok ? 'success' : 'error');
  }
  if (act === 'code') {
    oathBusy = id; renderOath();
    try {
      const acc = await call('oath_code', { token_id: token.id, account_id: id });
      const list = st.accounts || [];
      const i = list.findIndex(a => a.id === id);
      if (i >= 0) list[i] = { ...list[i], code: acc.code, valid_to: acc.valid_to };
    } catch (e) { showToast(errorMessage(e), 'error'); }
    oathBusy = null; renderOath();
    return;
  }
  if (act === 'delete') {
    const acc = (st.accounts || []).find(a => a.id === id);
    return oathCall('oath_delete', { account_id: id, label: acc ? [acc.issuer, acc.name].filter(Boolean).join(': ') : '' }, 'oath.deleted');
  }
  if (act === 'reset') return oathCall('oath_reset', { confirm: true }, 'oath.resetDone');
  if (act === 'pw-remove') return oathCall('oath_password', { password: null }, 'oath.pw.removed');
}

function initOathPane() {
  const el = $('oath-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (b) oathAction(b.dataset.act, b.dataset.id, b);
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    if (f.classList.contains('oath-unlock-form')) {
      const token = tokens.get(selectedId);
      return call('oath_unlock', { token_id: token.id, password: f.querySelector('.oath-password').value })
        .then(st => { oathState = st; oathError = null; renderOath(); startOathTimer(token); })
        .catch(e => { oathError = errorMessage(e); renderOath(); });
    }
    if (f.classList.contains('oath-add-form')) {
      const uri = f.querySelector('.oath-uri').value.trim();
      return oathCall('oath_add', uri ? { uri, touch: f.querySelector('.oath-touch').checked } : {
        issuer: f.querySelector('.oath-issuer').value, name: f.querySelector('.oath-name').value,
        secret: f.querySelector('.oath-secret').value.replace(/\s+/g, ''),
        oath_type: f.querySelector('.oath-type').value, digits: Number(f.querySelector('.oath-digits').value),
        touch: f.querySelector('.oath-touch').checked,
      }, 'oath.added');
    }
    if (f.classList.contains('oath-rename-form')) {
      return oathCall('oath_rename', { account_id: f.dataset.id, issuer: f.querySelector('.oath-rename-issuer').value,
        name: f.querySelector('.oath-rename-name').value }, 'oath.renamed');
    }
    if (f.classList.contains('oath-password-form')) {
      const a = f.querySelector('.oath-pw-new').value, b = f.querySelector('.oath-pw-confirm').value;
      if (!a) { oathError = t('oath.pw.empty'); return renderOath(); }
      if (a !== b) { oathError = t('pin.v.mismatch'); return renderOath(); }
      return oathCall('oath_password', { password: a }, 'oath.pw.saved');
    }
  });
}

// ── OpenPGP tab ─────────────────────────────────────────────────────────────

let pgpState = null;
let pgpForm = null;       // null | 'pin' | 'admin' | 'unblock' | 'holder' | 'sigpin' | 'touch:<slot>'
let pgpConfirmReset = false;
let pgpError = null;
let pgpResult = null;     // freshly generated public key + revocation certificate
let gpgAvailable = null;

function pgpField(cls, label, type = 'password', value = '', extra = '') {
  return `<label class="field"><span>${escHtml(label)}</span>
    <input type="${type}" class="${cls}" value="${escHtml(value)}" autocomplete="off" spellcheck="false" ${extra}></label>`;
}

function pgpFormHtml(st) {
  const cancel = `<button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>`;
  const err = pgpError ? `<p class="field-error">${escHtml(pgpError)}</p>` : '';
  const admin = pgpField('pgp-admin', t('pgp.adminPin'));
  const wrap = (title, text, fields) => `<form class="card form-card pgp-form" data-form="${escHtml(pgpForm)}" autocomplete="off">
      <h2>${escHtml(title)}</h2>${text ? `<p class="card-text">${escHtml(text)}</p>` : ''}${fields}${err}
      <div class="form-actions">${cancel}<button type="submit" class="btn btn-primary">${escHtml(t('fp.save'))}</button></div></form>`;
  if (pgpForm === 'pin') return wrap(t('pgp.pin.change'), t('pgp.pin.hint'),
    pgpField('pgp-current', t('pgp.pin.current')) + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'admin') return wrap(t('pgp.admin.change'), t('pgp.admin.hint'),
    pgpField('pgp-current', t('pgp.admin.current')) + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'unblock') return wrap(t('pgp.unblock'), t('pgp.unblock.text'),
    admin + pgpField('pgp-new', t('pin.form.new')) + pgpField('pgp-confirm', t('pin.form.confirm')));
  if (pgpForm === 'holder') return wrap(t('pgp.holder.edit'), t('pgp.holder.text'),
    pgpField('pgp-name', t('pgp.name'), 'text', st.name, 'maxlength="39"') +
    pgpField('pgp-url', t('pgp.url'), 'url', st.url, 'maxlength="254" placeholder="https://…"') + admin);
  if (pgpForm === 'sigpin') return wrap(t('pgp.sigpin.title'), t('pgp.sigpin.text'),
    `<label class="check"><input type="checkbox" class="pgp-sigpin" ${st.pin.sign_every_time ? 'checked' : ''}><span>${escHtml(t('pgp.sigpin.every'))}</span></label>` + admin);
  if (pgpForm === 'generate') {
    const replacing = st.keys.some(k => k.present);
    const algos = st.algorithms || ['rsa2048'];
    return `<form class="card form-card pgp-form" data-form="generate" autocomplete="off">
      <h2>${escHtml(t('pgp.gen.title'))}</h2>
      <p class="card-text">${escHtml(t('pgp.gen.text'))}</p>
      ${replacing ? `<div class="callout crit"><div class="callout-text">${escHtml(t('pgp.gen.replace'))}</div></div>` : ''}
      ${['on', 'fixed', 'cached', 'cached_fixed'].includes(st.keys.find(k => k.slot === 'sig')?.touch)
        ? `<div class="callout warn"><div class="callout-text">${escHtml(t('pgp.gen.touchHint'))}</div></div>` : ''}
      <div class="oath-grid">
        ${pgpField('pgp-gname', t('pgp.gen.name'), 'text', st.name || '', 'maxlength="100"')}
        ${pgpField('pgp-gemail', t('pgp.gen.email'), 'email', '', 'maxlength="120"')}
        <label class="field"><span>${escHtml(t('pgp.gen.algorithm'))}</span><select class="pgp-galgo bk-select">
          ${algos.map(a => `<option value="${a}">${escHtml(t(`pgp.gen.algo.${a}`))}</option>`).join('')}</select></label>
        <label class="field"><span>${escHtml(t('pgp.gen.validity'))}</span><select class="pgp-gexpire bk-select">
          ${[[730, 'pgp.gen.years2'], [365, 'pgp.gen.years1'], [1825, 'pgp.gen.years5'], [0, 'pgp.gen.never']].map(([d, k]) => `<option value="${d}">${escHtml(t(k))}</option>`).join('')}</select></label>
      </div>
      ${pgpField('pgp-guser', t('pgp.userPin'))}${pgpField('pgp-admin', t('pgp.adminPin'))}
      ${replacing ? `<label class="check"><input type="checkbox" class="pgp-gconfirm"><span>${escHtml(t('pgp.gen.confirm'))}</span></label>` : ''}
      ${err}
      <div class="form-actions">${cancel}<button type="submit" class="btn btn-primary">${escHtml(t('pgp.gen.do'))}</button></div></form>`;
  }
  if (pgpForm?.startsWith('touch:')) {
    const slot = pgpForm.slice(6);
    const cur = st.keys.find(k => k.slot === slot)?.touch;
    return wrap(t('pgp.touch.title', { slot: t(`pgp.slot.${slot}`) }), t('pgp.touch.text'),
      `<label class="field"><span>${escHtml(t('pgp.touch'))}</span><select class="pgp-touch bk-select">
        ${['off', 'on', 'cached'].map(p => `<option value="${p}" ${p === cur ? 'selected' : ''}>${escHtml(t(`pgp.touch.${p}`))}</option>`).join('')}
      </select></label>` + admin);
  }
  return '';
}

function renderPgp() {
  const el = $('pgp-content');
  if (!el) return;
  const st = pgpState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
    return;
  }
  const parts = [];
  if (pgpResult) parts.push(pgpResultHtml(pgpResult));
  if (pgpForm) parts.push(pgpFormHtml(st));
  else if (pgpError) parts.push(`<p class="field-error">${escHtml(pgpError)}</p>`);
  const anyKey = st.keys.some(k => k.present);
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.keys'))}</h2>
    ${anyKey ? '' : `<p class="card-text">${escHtml(t('pgp.noKeys'))}</p>`}
    <ul class="pgp-keys">${st.keys.map(k => `<li class="pgp-key${k.present ? '' : ' empty'}">
      <div class="pgp-key-head"><span class="pgp-slot">${escHtml(t(`pgp.slot.${k.slot}`))}</span>
        ${k.present ? `<span class="pill">${escHtml(k.algorithm || '?')}</span>` : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}
        ${st.can_touch && k.touch ? `<button type="button" class="btn-link pgp-touch-btn" data-act="touch" data-slot="${k.slot}">${icon('key', 12)} ${escHtml(t(`pgp.touch.${k.touch}`) || k.touch)}</button>` : ''}
      </div>
      ${k.present ? `<div class="pgp-fp">${escHtml(k.fingerprint)}</div>
        <div class="muted pgp-meta">${escHtml([k.created ? t('pgp.created', { date: new Date(k.created).toLocaleDateString(LANG) }) : '',
          k.origin ? t(`pgp.origin.${k.origin}`) : ''].filter(Boolean).join(' · '))}</div>` : ''}
    </li>`).join('')}</ul>
    <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="form" data-form="generate">${escHtml(t('pgp.gen.title'))}</button></div>
    <p class="field-hint">${escHtml(t('pgp.gpgHint'))}</p>
  </section>`);
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.card'))}</h2>
    <dl class="kv">${buildKv([
      [t('pgp.name'), st.name || '–'],
      [t('pgp.url'), st.url || '–'],
      [t('pgp.serial'), st.serial || '–'],
      [t('pgp.spec'), st.spec],
      [t('pgp.counter'), st.signature_counter == null ? '–' : String(st.signature_counter)],
      [t('pgp.sigpin.title'), t(st.pin.sign_every_time ? 'pgp.sigpin.always' : 'pgp.sigpin.once')],
    ])}</dl>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="holder">${escHtml(t('pgp.holder.edit'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="sigpin">${escHtml(t('pgp.sigpin.title'))}</button>
    </div></section>`);
  const tries = (n, max = 3) => `<span class="${n === 0 ? 'bad-text' : n < max ? 'warn-text' : ''}">${escHtml(t('pgp.tries', { n }))}</span>`;
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.pins'))}</h2>
    <dl class="kv"><dt>${escHtml(t('pgp.userPin'))}</dt><dd>${tries(st.pin.user)}</dd>
      <dt>${escHtml(t('pgp.adminPin'))}</dt><dd>${tries(st.pin.admin)}</dd></dl>
    ${st.pin.user === 0 ? `<p class="card-text">${escHtml(t('pgp.userBlocked'))}</p>` : ''}
    ${st.pin.admin === 0 ? `<p class="card-text">${escHtml(t('pgp.adminBlocked'))}</p>` : ''}
    <p class="field-hint">${escHtml(t('pgp.defaults'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="pin">${escHtml(t('pgp.pin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="admin">${escHtml(t('pgp.admin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="unblock">${escHtml(t('pgp.unblock'))}</button>
    </div></section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('pgp.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('pgp.reset.text'))}</p>
    <div class="form-actions att-actions">${pgpConfirmReset
      ? `<button type="button" class="btn btn-secondary" data-act="reset-cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('pgp.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="reset-ask">${escHtml(t('pgp.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.pgp-form input')?.focus();
}

function pgpResultHtml(r) {
  return `<section class="card pgp-result">
    <h2>${escHtml(t('pgp.res.title'))}</h2>
    <p class="card-text">${escHtml(r.user_id)}</p>
    <div class="pgp-fp">${escHtml(r.fingerprint)}</div>
    <div class="callout warn"><div class="callout-title">${escHtml(t('pgp.res.revTitle'))}</div>
      <div class="callout-text">${escHtml(t('pgp.res.revText'))}</div>
      <div class="form-actions att-actions"><button type="button" class="btn btn-primary" data-act="save-rev">${escHtml(t('pgp.res.saveRev'))}</button></div></div>
    <p class="card-text">${escHtml(t('pgp.res.pubText'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="save-pub">${escHtml(t('pgp.res.savePub'))}</button>
      <button type="button" class="btn btn-secondary" data-act="copy-pub">${escHtml(t('pgp.res.copyPub'))}</button>
      ${gpgAvailable ? `<button type="button" class="btn btn-secondary" data-act="gpg-import">${escHtml(t('pgp.res.gpgImport'))}</button>` : ''}
      <button type="button" class="btn-link" data-act="result-done">${escHtml(t('otp.secret.done'))}</button>
    </div>
    <p class="field-hint">${escHtml(t(gpgAvailable ? 'pgp.res.hintGpg' : 'pgp.res.hintNoGpg'))}</p>
  </section>`;
}

async function loadPgp(token) {
  pgpState = null; pgpError = null; pgpForm = null; pgpConfirmReset = false;
  renderPgp();
  try {
    const st = await call('openpgp', { token_id: token.id });
    if (selectedId !== token.id) return;
    pgpState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    pgpState = { error: isBusy(e) ? t('err.busy') : errorMessage(e) };
  }
  renderPgp();
}

async function pgpCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  pgpError = null;
  try {
    pgpState = await call(method, { token_id: token.id, ...args });
    pgpForm = null; pgpConfirmReset = false;
    showToast(t(doneKey), 'success');
  } catch (e) {
    pgpError = e.data?.retries != null && e.data.code?.endsWith('_invalid')
      ? t('pgp.wrongPin', { n: e.data.retries }) : errorMessage(e);
    // Retry counters changed: refresh them without losing the open form
    try { const st = await call('openpgp', { token_id: token.id }); pgpState = st; } catch { /* keep old */ }
  }
  renderPgp();
}

async function pgpGenerate(f) {
  const token = tokens.get(selectedId);
  if (!token) return;
  const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
  const confirm = f.querySelector('.pgp-gconfirm');
  if (confirm && !confirm.checked) { pgpError = t('pgp.gen.confirmNeeded'); return renderPgp(); }
  pgpError = null;
  const btn = f.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>${escHtml(t(val('pgp-galgo').startsWith('rsa') ? 'pgp.gen.workingRsa' : 'piv.working'))}`;
  try {
    const res = await call('openpgp_generate', { token_id: token.id, algorithm: val('pgp-galgo'), name: val('pgp-gname'),
      email: val('pgp-gemail'), expire_days: Number(val('pgp-gexpire')), admin_pin: val('pgp-admin'), user_pin: val('pgp-guser'),
      replace: !!confirm?.checked });
    pgpState = res.state;
    pgpResult = res;
    pgpForm = null;
    if (gpgAvailable === null) gpgAvailable = await window.pywebview.api.gpg_available().catch(() => false);
    showToast(t('pgp.res.title'), 'success');
  } catch (e) {
    pgpError = wrongSecretMessage(e);
    try { pgpState = await call('openpgp', { token_id: token.id }); } catch { /* keep */ }
  }
  renderPgp();
}

function initPgpPane() {
  const el = $('pgp-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadPgp(token);
    if (act === 'form') { pgpForm = b.dataset.form; pgpError = null; return renderPgp(); }
    if (act === 'touch') { pgpForm = `touch:${b.dataset.slot}`; pgpError = null; return renderPgp(); }
    if (act === 'hide-form') { pgpForm = null; pgpError = null; return renderPgp(); }
    if (act === 'reset-ask') { pgpConfirmReset = true; return renderPgp(); }
    if (act === 'reset-cancel') { pgpConfirmReset = false; return renderPgp(); }
    if (act === 'reset') return pgpCall('openpgp_reset', { confirm: true }, 'pgp.reset.done');
    if (act === 'save-pub' || act === 'save-rev') {
      const rev = act === 'save-rev';
      const name = `${pgpResult.filename}${rev ? '-revocation' : ''}.asc`;
      window.pywebview.api.save_text(name, rev ? pgpResult.revocation : pgpResult.public_key, rev)
        .then(path => { if (path) showToast(t('pgp.res.saved', { path }), 'success'); });
      return;
    }
    if (act === 'copy-pub') return copyText(pgpResult.public_key);
    if (act === 'gpg-import') {
      b.disabled = true;
      window.pywebview.api.gpg_import(pgpResult.public_key).then(res => {
        b.disabled = false;
        showToast(t(res?.ok ? 'pgp.res.gpgDone' : 'pgp.res.gpgFailed'), res?.ok ? 'success' : 'error');
      });
      return;
    }
    if (act === 'result-done') { pgpResult = null; return renderPgp(); }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const form = f.dataset.form;
    if (['pin', 'admin', 'unblock'].includes(form) && val('pgp-new') !== val('pgp-confirm')) {
      pgpError = t('pin.v.mismatch'); return renderPgp();
    }
    if (form === 'pin' || form === 'admin') {
      return pgpCall('openpgp_change_pin', { which: form === 'admin' ? 'admin' : 'user', current: val('pgp-current'), new: val('pgp-new') }, 'pgp.saved');
    }
    if (form === 'unblock') return pgpCall('openpgp_unblock_pin', { admin_pin: val('pgp-admin'), new_pin: val('pgp-new') }, 'pgp.saved');
    if (form === 'holder') return pgpCall('openpgp_cardholder', { name: val('pgp-name'), url: val('pgp-url'), admin_pin: val('pgp-admin') }, 'pgp.saved');
    if (form === 'sigpin') return pgpCall('openpgp_signature_pin', { every_time: f.querySelector('.pgp-sigpin').checked, admin_pin: val('pgp-admin') }, 'pgp.saved');
    if (form === 'generate') return pgpGenerate(f);
    if (form?.startsWith('touch:')) {
      return pgpCall('openpgp_touch', { slot: form.slice(6), policy: val('pgp-touch'), admin_pin: val('pgp-admin') }, 'pgp.saved');
    }
  });
}

// ── Shared form helpers (PIV, OTP) ──────────────────────────────────────────

function fieldHtml(cls, label, type = 'password', value = '', extra = '') {
  return `<label class="field"><span>${escHtml(label)}</span>
    <input type="${type}" class="${cls}" value="${escHtml(value)}" autocomplete="off" spellcheck="false" ${extra}></label>`;
}

function formCardHtml(id, title, text, fields, error, submitKey = 'fp.save') {
  return `<form class="card form-card app-form" data-form="${escHtml(id)}" autocomplete="off">
    <h2>${escHtml(title)}</h2>${text ? `<p class="card-text">${escHtml(text)}</p>` : ''}${fields}
    ${error ? `<p class="field-error">${escHtml(error)}</p>` : ''}
    <div class="form-actions"><button type="button" class="btn btn-secondary" data-act="hide-form">${escHtml(t('pk.delete.cancel'))}</button>
      <button type="submit" class="btn btn-primary">${escHtml(t(submitKey))}</button></div></form>`;
}

function wrongSecretMessage(e) {
  const code = e.data?.code || '';
  if (e.data?.retries != null && code.endsWith('_invalid')) return t('pgp.wrongPin', { n: e.data.retries });
  return errorMessage(e);
}

async function copyText(text) {
  const ok = await window.pywebview?.api?.copy_text(text);
  showToast(t(ok ? 'oath.copied' : 'oath.copyFailed'), ok ? 'success' : 'error');
}

// ── PIV tab ─────────────────────────────────────────────────────────────────

let pivState = null;
let pivForm = null;        // 'pin' | 'puk' | 'unblock' | 'protect' | 'gen:<slot>' | 'import:<slot>' | 'delete:<slot>'
let pivError = null;
let pivConfirmReset = false;

function pivNeedsMgmtKey(st) {
  return st.management_key.protected === false && st.management_key.default === false;
}

function pivAuthFields(st, withPin = true) {
  return (withPin || st.management_key.protected ? fieldHtml('piv-pin', t('piv.pin')) : '') +
    (pivNeedsMgmtKey(st) ? fieldHtml('piv-mgmt', t('piv.mgmt.key'), 'password', '', 'placeholder="010203…"') : '');
}

function pivFormHtml(st) {
  const [kind, slot] = (pivForm || '').split(':');
  if (kind === 'pin') return formCardHtml(pivForm, t('piv.pin.change'), t('piv.pin.hint'),
    fieldHtml('piv-current', t('pgp.pin.current')) + fieldHtml('piv-new', t('pin.form.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'puk') return formCardHtml(pivForm, t('piv.puk.change'), t('piv.puk.hint'),
    fieldHtml('piv-current', t('piv.puk.current')) + fieldHtml('piv-new', t('piv.puk.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'unblock') return formCardHtml(pivForm, t('pgp.unblock'), t('piv.unblock.text'),
    fieldHtml('piv-puk', t('piv.puk')) + fieldHtml('piv-new', t('pin.form.new')) + fieldHtml('piv-confirm', t('pin.form.confirm')), pivError);
  if (kind === 'protect') return formCardHtml(pivForm, t('piv.mgmt.protect'), t('piv.mgmt.protectText'), pivAuthFields(st), pivError);
  if (kind === 'gen') return formCardHtml(pivForm, t('piv.gen.title', { slot: slotName(slot) }), t('piv.gen.text'),
    fieldHtml('piv-subject', t('piv.gen.subject'), 'text', '', 'placeholder="Erika Mustermann"') +
    `<div class="oath-grid">
      <label class="field"><span>${escHtml(t('piv.gen.type'))}</span><select class="piv-type bk-select">${st.key_types.map(k => `<option>${k}</option>`).join('')}</select></label>
      <label class="field"><span>${escHtml(t('piv.gen.days'))}</span><input type="number" class="piv-days" value="365" min="1" max="3650"></label>
      <label class="field"><span>${escHtml(t('piv.gen.pinPolicy'))}</span><select class="piv-pinpol bk-select">
        ${['default', 'once', 'always', 'never'].map(p => `<option value="${p}">${escHtml(t(`piv.policy.${p}`))}</option>`).join('')}</select></label>
      <label class="field"><span>${escHtml(t('piv.gen.touchPolicy'))}</span><select class="piv-touchpol bk-select">
        ${['default', 'never', 'always', 'cached'].map(p => `<option value="${p}">${escHtml(t(`piv.touch.${p}`))}</option>`).join('')}</select></label>
    </div>` + (pivSlotUsed(st, slot) ? replaceCheck() : '') + pivAuthFields(st), pivError, 'piv.gen.do');
  if (kind === 'import') return formCardHtml(pivForm, t('piv.import.title', { slot: slotName(slot) }), t('piv.import.text'),
    `<label class="field"><span>PEM</span><textarea class="piv-pem" rows="6" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>` +
    pivAuthFields(st, false), pivError, 'piv.import.do');
  if (kind === 'delete') return formCardHtml(pivForm, t('piv.delete.title', { slot: slotName(slot) }), t('piv.delete.text'),
    (st.can_delete_key ? `<label class="check"><input type="checkbox" class="piv-delkey"><span>${escHtml(t('piv.delete.key'))}</span></label>` : '') +
    pivAuthFields(st, false), pivError, 'pk.delete.do');
  return '';
}

function pivSlotUsed(st, slot) {
  return st.slots.some(s => s.slot === slot && (s.cert || s.key));
}

function replaceCheck() {
  return `<label class="check"><input type="checkbox" class="app-replace"><span>${escHtml(t('confirm.replace'))}</span></label>`;
}

function slotName(slot) {
  const key = `piv.slot.${slot}`;
  const name = STRINGS[LANG][key] || STRINGS.en[key];
  return name ? `${name} (${slot.toUpperCase()})` : t('piv.slot.retired', { slot: slot.toUpperCase() });
}

function renderPiv() {
  const el = $('piv-content');
  if (!el) return;
  const st = pivState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout crit"><div class="callout-text">${escHtml(st.error)}</div>
      <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div>`;
    return;
  }
  const parts = [];
  if (pivForm) parts.push(pivFormHtml(st));
  else if (pivError) parts.push(`<p class="field-error">${escHtml(pivError)}</p>`);
  const warn = [];
  if (st.pin.default) warn.push(t('piv.warn.pin'));
  if (st.pin.puk_default) warn.push(t('piv.warn.puk'));
  if (st.management_key.default) warn.push(t('piv.warn.mgmt'));
  if (warn.length) parts.push(`<div class="callout warn"><div class="callout-title">${escHtml(t('piv.warn.title'))}</div>
    <ul class="callout-list">${warn.map(w => `<li>${escHtml(w)}</li>`).join('')}</ul></div>`);
  parts.push(`<section class="card"><h2>${escHtml(t('piv.slots'))}</h2>
    <ul class="pgp-keys">${st.slots.map(s => {
      const c = s.cert;
      const k = s.key;
      const status = c ? (c.expired ? `<span class="pill bad">${escHtml(t('piv.expired'))}</span>` : c.expires_soon ? `<span class="pill warn">${escHtml(t('piv.expiresSoon'))}</span>` : '') : '';
      return `<li class="pgp-key${c || k ? '' : ' empty'}">
        <div class="pgp-key-head"><span class="pgp-slot">${escHtml(slotName(s.slot))}</span>
          ${c ? `<span class="pill">${escHtml(c.algorithm)}</span>` : k ? `<span class="pill">${escHtml(k.type)}</span>` : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}
          ${status}</div>
        ${c ? `<div class="piv-subject">${escHtml(c.subject)}</div>
          <div class="muted pgp-meta">${escHtml([c.self_signed ? t('piv.selfSigned') : t('piv.issuer', { name: c.issuer }),
            t('piv.validUntil', { date: new Date(c.not_after).toLocaleDateString(LANG) })].join(' · '))}</div>` : ''}
        ${k ? `<div class="muted pgp-meta">${escHtml([t(k.generated ? 'pgp.origin.generated' : 'pgp.origin.imported'),
            `${t('piv.gen.pinPolicy')}: ${t(`piv.policy.${k.pin_policy}`) || k.pin_policy}`,
            `${t('piv.gen.touchPolicy')}: ${t(`piv.touch.${k.touch_policy}`) || k.touch_policy}`].join(' · '))}</div>` : ''}
        <div class="piv-actions">
          <button type="button" class="btn-link" data-act="form" data-form="gen:${s.slot}">${escHtml(t('piv.gen.short'))}</button>
          <button type="button" class="btn-link" data-act="form" data-form="import:${s.slot}">${escHtml(t('piv.import.short'))}</button>
          ${c ? `<button type="button" class="btn-link" data-act="export" data-slot="${s.slot}">${escHtml(t('piv.export'))}</button>` : ''}
          ${c || k ? `<button type="button" class="btn-link danger-link" data-act="form" data-form="delete:${s.slot}">${escHtml(t('pk.delete.do'))}</button>` : ''}
        </div>
      </li>`;
    }).join('')}</ul>
    <p class="field-hint">${escHtml(t('piv.hint'))}</p></section>`);
  const tries = n => n == null ? '–' : `<span class="${n === 0 ? 'bad-text' : n < 3 ? 'warn-text' : ''}">${escHtml(t('pgp.tries', { n }))}</span>`;
  parts.push(`<section class="card"><h2>${escHtml(t('pgp.pins'))}</h2>
    <dl class="kv"><dt>${escHtml(t('piv.pin'))}</dt><dd>${tries(st.pin.attempts)}</dd>
      ${st.pin.puk_attempts != null ? `<dt>${escHtml(t('piv.puk'))}</dt><dd>${tries(st.pin.puk_attempts)}</dd>` : ''}</dl>
    <p class="field-hint">${escHtml(t('piv.defaults'))}</p>
    <div class="form-actions att-actions">
      <button type="button" class="btn btn-secondary" data-act="form" data-form="pin">${escHtml(t('piv.pin.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="puk">${escHtml(t('piv.puk.change'))}</button>
      <button type="button" class="btn btn-secondary" data-act="form" data-form="unblock">${escHtml(t('pgp.unblock'))}</button>
    </div></section>`);
  const m = st.management_key;
  parts.push(`<section class="card"><h2>${escHtml(t('piv.mgmt.title'))}</h2>
    <p class="card-text">${escHtml(t(m.protected ? 'piv.mgmt.protected' : m.default ? 'piv.mgmt.default' : m.default === false ? 'piv.mgmt.custom' : 'piv.mgmt.unknown'))}</p>
    ${m.protected ? '' : `<div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="form" data-form="protect">${escHtml(t('piv.mgmt.protect'))}</button></div>`}
  </section>`);
  parts.push(`<section class="card danger-card"><h2>${escHtml(t('piv.reset.title'))}</h2>
    <p class="card-text">${escHtml(t('piv.reset.text'))}</p>
    <div class="form-actions att-actions">${pivConfirmReset
      ? `<button type="button" class="btn btn-secondary" data-act="reset-cancel">${escHtml(t('pk.delete.cancel'))}</button>
         <button type="button" class="btn btn-danger" data-act="reset">${escHtml(t('piv.reset.do'))}</button>`
      : `<button type="button" class="btn btn-secondary" data-act="reset-ask">${escHtml(t('piv.reset.do'))}</button>`}</div>
  </section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.app-form input, .app-form textarea')?.focus();
}

async function loadPiv(token) {
  pivState = null; pivError = null; pivForm = null; pivConfirmReset = false;
  renderPiv();
  try {
    const st = await call('piv', { token_id: token.id });
    if (selectedId !== token.id) return;
    pivState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    pivState = { error: isBusy(e) ? t('err.busy') : errorMessage(e) };
  }
  renderPiv();
}

async function pivCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  pivError = null;
  const busy = $('piv-content').querySelector('.app-form button[type=submit]');
  if (busy) { busy.disabled = true; busy.innerHTML = `<span class="spinner"></span>${escHtml(t('piv.working'))}`; }
  try {
    pivState = await call(method, { token_id: token.id, ...args });
    pivForm = null; pivConfirmReset = false;
    showToast(t(doneKey), 'success');
  } catch (e) {
    pivError = wrongSecretMessage(e);
    try { pivState = await call('piv', { token_id: token.id }); } catch { /* keep old */ }
  }
  renderPiv();
}

function initPivPane() {
  const el = $('piv-content');
  el.addEventListener('click', async ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadPiv(token);
    if (act === 'form') { pivForm = b.dataset.form; pivError = null; return renderPiv(); }
    if (act === 'hide-form') { pivForm = null; pivError = null; return renderPiv(); }
    if (act === 'reset-ask') { pivConfirmReset = true; return renderPiv(); }
    if (act === 'reset-cancel') { pivConfirmReset = false; return renderPiv(); }
    if (act === 'reset') return pivCall('piv_reset', { confirm: true }, 'piv.reset.done');
    if (act === 'export' && token) {
      try { const res = await call('piv_export', { token_id: token.id, slot: b.dataset.slot }); copyText(res.pem); }
      catch (e) { showToast(errorMessage(e), 'error'); }
    }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const [kind, slot] = (f.dataset.form || '').split(':');
    const auth = { pin: val('piv-pin') || null, management_key: val('piv-mgmt') || null };
    if (['pin', 'puk', 'unblock'].includes(kind) && val('piv-new') !== val('piv-confirm')) {
      pivError = t('pin.v.mismatch'); return renderPiv();
    }
    if (kind === 'pin' || kind === 'puk') return pivCall('piv_change_pin', { which: kind, current: val('piv-current'), new: val('piv-new') }, 'pgp.saved');
    if (kind === 'unblock') return pivCall('piv_unblock_pin', { puk: val('piv-puk'), new_pin: val('piv-new') }, 'pgp.saved');
    if (kind === 'protect') return pivCall('piv_protect_management_key', { pin: val('piv-pin'), management_key: auth.management_key }, 'pgp.saved');
    if (kind === 'gen') {
      return pivCall('piv_generate', { slot, key_type: val('piv-type'), subject: val('piv-subject'), days: Number(val('piv-days')) || 365,
        pin: val('piv-pin'), management_key: auth.management_key, pin_policy: val('piv-pinpol'), touch_policy: val('piv-touchpol'),
        replace: !!f.querySelector('.app-replace')?.checked }, 'piv.gen.done');
    }
    if (kind === 'import') return pivCall('piv_import', { slot, pem: val('piv-pem'), ...auth }, 'piv.import.done');
    if (kind === 'delete') return pivCall('piv_delete', { slot, key: !!f.querySelector('.piv-delkey')?.checked, confirm: true, ...auth }, 'piv.deleted');
  });
}

// ── OTP tab (YubiKey slots) ─────────────────────────────────────────────────

let otpState = null;
let otpForm = null;        // 'static:<n>' | 'hmac:<n>' | 'delete:<n>'
let otpError = null;
let otpSecret = null;      // challenge-response secret to show once

function renderOtp() {
  const el = $('otp-content');
  if (!el) return;
  const st = otpState;
  if (!st) {
    el.innerHTML = `<div class="callout"><div class="loading"><span class="spinner"></span>${escHtml(t('mg.loading'))}</div></div>`;
    return;
  }
  if (st.error) {
    el.innerHTML = `<div class="callout ${st.code === 'otp_permission' ? 'warn' : 'crit'}">
      <div class="callout-title">${escHtml(t(st.code === 'otp_permission' ? 'otp.perm.title' : 'otp.error'))}</div>
      <div class="callout-text">${escHtml(st.code === 'otp_permission' ? t('otp.perm.text') : st.error)}</div>
      <div class="form-actions att-actions">
        ${st.code === 'otp_permission' ? `<button type="button" class="btn btn-secondary" data-act="privacy">${escHtml(t('otp.perm.open'))}</button>` : ''}
        <button type="button" class="btn-link" data-act="reload">${escHtml(t('pin.retry'))}</button></div></div>`;
    return;
  }
  const access = `<details class="otp-access"><summary>${escHtml(t('otp.access'))}</summary>${fieldHtml('otp-acc', t('otp.accessCode'), 'password', '', 'placeholder="000000000000"')}</details>`;
  const parts = [];
  if (otpSecret) {
    parts.push(`<div class="callout warn"><div class="callout-title">${escHtml(t('otp.secret.title'))}</div>
      <div class="callout-text">${escHtml(t('otp.secret.text'))}</div>
      <div class="pgp-fp">${escHtml(otpSecret.match(/.{1,4}/g).join(' '))}</div>
      <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="copy-secret">${escHtml(t('otp.secret.copy'))}</button>
        <button type="button" class="btn btn-primary" data-act="secret-done">${escHtml(t('otp.secret.done'))}</button></div></div>`);
  }
  const [kind, n] = (otpForm || '').split(':');
  const used = st.slots.some(s => String(s.slot) === n && s.configured);
  const replace = used ? (n === '1' ? `<p class="field-hint">${escHtml(t('otp.delete.text1'))}</p>` : '') + replaceCheck() : '';
  if (kind === 'static') parts.push(formCardHtml(otpForm, t('otp.static.title', { slot: t(`otp.slot${n}`) }), t('otp.static.text'),
    fieldHtml('otp-pw', t('otp.static.password'), 'password', '', 'maxlength="38"') + replace + access, otpError));
  if (kind === 'hmac') parts.push(formCardHtml(otpForm, t('otp.hmac.title', { slot: t(`otp.slot${n}`) }), t('otp.hmac.text'),
    fieldHtml('otp-secret', t('otp.hmac.secret'), 'text', '', `placeholder="${escHtml(t('otp.hmac.random'))}"`) +
    `<label class="check"><input type="checkbox" class="otp-touch" checked><span>${escHtml(t('oath.requireTouch'))}</span></label>` + replace + access, otpError));
  if (kind === 'delete') parts.push(formCardHtml(otpForm, t('otp.delete.title', { slot: t(`otp.slot${n}`) }),
    t(n === '1' ? 'otp.delete.text1' : 'otp.delete.text'), access, otpError, 'pk.delete.do'));
  if (!otpForm && otpError) parts.push(`<p class="field-error">${escHtml(otpError)}</p>`);
  parts.push(`<section class="card"><h2>${escHtml(t('otp.slots'))}</h2><p class="card-text">${escHtml(t('otp.intro'))}</p>
    <ul class="pgp-keys">${st.slots.map(s => `<li class="pgp-key${s.configured ? '' : ' empty'}">
      <div class="pgp-key-head"><span class="pgp-slot">${escHtml(t(`otp.slot${s.slot}`))}</span>
        ${s.configured ? `<span class="pill on">${escHtml(t('otp.configured'))}</span>${s.touch === false ? `<span class="muted">${escHtml(t('otp.noTouch'))}</span>` : ''}`
          : `<span class="muted">${escHtml(t('pgp.empty'))}</span>`}</div>
      <div class="piv-actions">
        <button type="button" class="btn-link" data-act="form" data-form="static:${s.slot}">${escHtml(t('otp.static.short'))}</button>
        <button type="button" class="btn-link" data-act="form" data-form="hmac:${s.slot}">${escHtml(t('otp.hmac.short'))}</button>
        ${s.configured ? `<button type="button" class="btn-link danger-link" data-act="form" data-form="delete:${s.slot}">${escHtml(t('pk.delete.do'))}</button>` : ''}
      </div></li>`).join('')}</ul>
    <div class="form-actions att-actions"><button type="button" class="btn btn-secondary" data-act="swap">${escHtml(t('otp.swap'))}</button></div>
    <p class="field-hint">${escHtml(t('otp.hint'))}</p></section>`);
  el.innerHTML = parts.join('');
  el.querySelector('.app-form input')?.focus();
}

async function loadOtp(token) {
  otpState = null; otpError = null; otpForm = null;
  renderOtp();
  try {
    const st = await call('otp', { token_id: token.id });
    if (selectedId !== token.id) return;
    otpState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    otpState = { error: isBusy(e) ? t('err.busy') : errorMessage(e), code: e.data?.code };
  }
  renderOtp();
}

async function otpCall(method, args, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  otpError = null;
  try {
    const st = await call(method, { token_id: token.id, ...args });
    if (st.secret) otpSecret = st.secret;
    otpState = st; otpForm = null;
    showToast(t(doneKey), 'success');
  } catch (e) {
    otpError = errorMessage(e);
  }
  renderOtp();
}

function initOtpPane() {
  const el = $('otp-content');
  el.addEventListener('click', ev => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    const token = tokens.get(selectedId);
    if (act === 'reload' && token) return loadOtp(token);
    if (act === 'privacy') return call('open_privacy_settings', {}).catch(() => {});
    if (act === 'form') { otpForm = b.dataset.form; otpError = null; return renderOtp(); }
    if (act === 'hide-form') { otpForm = null; otpError = null; return renderOtp(); }
    if (act === 'swap') return otpCall('otp_swap', {}, 'otp.swapped');
    if (act === 'copy-secret') return copyText(otpSecret);
    if (act === 'secret-done') { otpSecret = null; return renderOtp(); }
  });
  el.addEventListener('submit', ev => {
    ev.preventDefault();
    const f = ev.target;
    const val = cls => f.querySelector(`.${cls}`)?.value ?? '';
    const [kind, n] = (f.dataset.form || '').split(':');
    const access_code = val('otp-acc').trim() || null;
    const replace = !!f.querySelector('.app-replace')?.checked;
    const slot = Number(n);
    if (kind === 'static') return otpCall('otp_static', { slot, password: val('otp-pw'), access_code, replace }, 'otp.programmed');
    if (kind === 'hmac') return otpCall('otp_hmac', { slot, secret: val('otp-secret').trim() || null, touch: f.querySelector('.otp-touch').checked, access_code, replace }, 'otp.programmed');
    if (kind === 'delete') return otpCall('otp_delete', { slot, access_code }, 'otp.deleted');
  });
}

// ── Applications per USB/NFC (YubiKey, settings tab) ────────────────────────

let ifState = null;

function renderInterfaces() {
  const el = $('if-content');
  if (!el) return;
  const token = currentToken();
  if (!token || token.offline || !cardApps.get(token.id)?.interfaces) { el.innerHTML = ''; return; }
  const st = ifState;
  if (!st || st.error) {
    el.innerHTML = st?.error ? `<div class="callout"><div class="callout-text">${escHtml(st.error)}</div></div>` : '';
    return;
  }
  el.innerHTML = `<section class="card"><h2>${escHtml(t('if.title'))}</h2>
    <p class="card-text">${escHtml(t(st.locked ? 'if.locked' : 'if.text'))}</p>
    ${Object.entries(st.transports).map(([tr, apps]) => `<form class="if-form" data-transport="${tr}">
      <h3 class="if-head">${escHtml(t(`if.${tr}`))}</h3>
      <div class="if-grid">${Object.entries(apps).map(([app, on]) => {
        const locked = st.locked || (tr === 'usb' && app === 'FIDO2');
        return `<label class="check"><input type="checkbox" data-app="${app}" ${on ? 'checked' : ''} ${locked ? 'disabled' : ''}>
          <span>${escHtml(t(`if.app.${app}`))}</span></label>`;
      }).join('')}</div>
      ${st.locked ? '' : `<div class="form-actions att-actions"><button type="submit" class="btn btn-secondary">${escHtml(t('if.apply'))}</button></div>`}
    </form>`).join('')}
    <p class="field-hint">${escHtml(t('if.hint'))}</p>
  </section>`;
}

async function loadInterfaces(token) {
  ifState = null;
  renderInterfaces();
  if (!cardApps.get(token.id)?.interfaces) return;
  try {
    ifState = await call('interfaces', { token_id: token.id });
  } catch (e) {
    ifState = { error: errorMessage(e) };
  }
  if (selectedId === token.id) renderInterfaces();
}

function initInterfacesPane() {
  $('if-content').addEventListener('submit', async ev => {
    ev.preventDefault();
    const f = ev.target;
    const token = tokens.get(selectedId);
    if (!token) return;
    const apps = {};
    f.querySelectorAll('input[data-app]:not(:disabled)').forEach(i => { apps[i.dataset.app] = i.checked; });
    try {
      await call('interfaces_set', { token_id: token.id, transport: f.dataset.transport, apps });
      showToast(t('if.restarting'), 'success');
    } catch (e) {
      showToast(errorMessage(e), 'error');
    }
  });
}

// ── Settings tab / key configuration ────────────────────────────────────────

let cfgState = null;
let cfgBusy = false;

function renderConfig() {
  const el = $('cfg-content');
  if (!el) return;
  const st = cfgState;
  if (st && !st.supported) {
    el.innerHTML = `<div class="callout"><div class="callout-text">${escHtml(t('cfg.unsupported'))}</div></div>`;
    return;
  }
  const gate = managementGateHtml(st, 'cfg.unsupported');
  if (gate !== null) { el.innerHTML = gate; focusUnlockPin('settings'); return; }

  const parts = [toolbarHtml(t('cfg.title'))];
  if (st.can_set_min_pin) {
    parts.push(`<form class="card form-card cfg-minpin-form" autocomplete="off">
      <h2>${escHtml(t('cfg.minPin.title'))}</h2>
      <p class="card-text">${escHtml(t('cfg.minPin.text', { n: st.min_pin_length }))}</p>
      <div class="inline-form">
        <input type="number" class="cfg-minpin" min="${st.min_pin_length + 1}" max="63" value="${Math.max(st.min_pin_length + 1, 6)}">
        <button type="submit" class="btn btn-primary" ${cfgBusy ? 'disabled' : ''}>${escHtml(t('cfg.minPin.do'))}</button>
      </div>
      <p class="field-hint">${escHtml(t('cfg.minPin.warn'))}</p>
    </form>`);
  }
  if (st.always_uv !== null && st.always_uv !== undefined) {
    parts.push(`<section class="card">
      <h2>${escHtml(t('cfg.alwaysUv.title'))}</h2>
      <p class="card-text">${escHtml(t('cfg.alwaysUv.text'))}</p>
      <label class="switch-row">
        <input type="checkbox" class="cfg-alwaysuv" ${st.always_uv ? 'checked' : ''} ${cfgBusy ? 'disabled' : ''}>
        <span>${escHtml(st.always_uv ? t('cfg.alwaysUv.on') : t('cfg.alwaysUv.off'))}</span>
      </label>
    </section>`);
  }
  if (st.can_set_min_pin) {
    parts.push(`<section class="card">
      <h2>${escHtml(t('cfg.force.title'))}</h2>
      <p class="card-text">${escHtml(st.force_pin_change ? t('cfg.force.active') : t('cfg.force.text'))}</p>
      ${st.force_pin_change ? '' : `<div class="form-actions"><button type="button" class="btn btn-secondary" data-act="force-pin" ${cfgBusy ? 'disabled' : ''}>${escHtml(t('cfg.force.do'))}</button></div>`}
    </section>`);
  }
  el.innerHTML = parts.join('');
}

async function loadConfig(token, retried = false) {
  cfgState = null;
  if (!retried) unlockError = null;
  renderConfig();
  try {
    const st = await call('config', { token_id: token.id });
    if (selectedId !== token.id) return;
    cfgState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isLocked(e) && !retried) { unlockError = errorMessage(e); return loadConfig(token, true); }
    cfgState = isBusy(e) ? { busy: true } : { error: errorMessage(e) };
  }
  renderConfig();
}

async function updateConfig(changes, doneKey) {
  const token = tokens.get(selectedId);
  if (!token) return;
  cfgBusy = true;
  renderConfig();
  try {
    cfgState = await call('config_update', { token_id: token.id, ...changes });
    showToast(t(doneKey), 'success');
  } catch (e) {
    cfgBusy = false;
    handleActionError(e, cfgState);
    return;
  }
  cfgBusy = false;
  renderConfig();
}

function configAction(act) {
  if (act === 'reload') return loadConfig(tokens.get(selectedId));
  if (act === 'force-pin') return updateConfig({ force_pin_change: true }, 'cfg.saved');
}

// ── Settings tab / factory reset ────────────────────────────────────────────

let resetFlow = null;     // { stage, name, deadline, id, error }
let resetTimer = null;

function renderSettings(token) {
  $('rs-prereg').classList.toggle('hidden', !token.force_pin_change);
  $('rs-vuln').classList.toggle('hidden', !(token.cve_ids || []).length);
}

function renderResetOverlay() {
  const ov = $('reset-overlay');
  const f = resetFlow;
  ov.classList.toggle('hidden', !f);
  clearInterval(resetTimer);
  if (!f) return;

  const primary = $('rs-ov-primary');
  const secondary = $('rs-ov-secondary');
  primary.classList.add('hidden');
  secondary.classList.remove('hidden');
  $('rs-ov-count').textContent = '';
  let iconName = 'key', cls = '';

  if (f.stage === 'armed') {
    $('rs-ov-title').textContent = t('rs.ov.armed.title');
    $('rs-ov-text').textContent = t('rs.ov.armed.text', { name: f.name });
    secondary.textContent = t('pk.delete.cancel');
    const tick = () => {
      const s = Math.max(0, Math.ceil((f.deadline - Date.now()) / 1000));
      $('rs-ov-count').textContent = t('rs.ov.armed.count', { s });
    };
    tick();
    resetTimer = setInterval(tick, 500);
  } else if (f.stage === 'running' || f.stage === 'touch') {
    $('rs-ov-title').textContent = t('rs.ov.touch.title');
    $('rs-ov-text').textContent = t('rs.ov.touch.text');
    secondary.classList.add('hidden');
    cls = 'pulse';
  } else if (f.stage === 'done') {
    iconName = 'shield'; cls = 'ok';
    $('rs-ov-title').textContent = t('rs.ov.done.title');
    $('rs-ov-text').textContent = t('rs.ov.done.text');
    secondary.textContent = t('rs.ov.close');
    primary.textContent = t('pin.form.set');
    primary.classList.remove('hidden');
  } else {
    cls = 'bad';
    $('rs-ov-title').textContent = t('rs.ov.failed.title');
    $('rs-ov-text').textContent = f.error || '';
    secondary.textContent = t('rs.ov.close');
  }
  $('rs-ov-icon').className = `rs-ov-icon ${cls}`;
  $('rs-ov-icon').innerHTML = icon(iconName, 34);
}

async function startReset() {
  const token = tokens.get(selectedId);
  if (!token) return;
  try {
    const res = await call('reset_arm', { token_id: token.id, confirm: true });
    resetFlow = { stage: 'armed', name: displayName(token), deadline: Date.now() + res.window * 1000 };
    $('rs-confirm').checked = false;
    $('rs-start').disabled = true;
    renderResetOverlay();
  } catch (e) {
    showToast(errorMessage(e), 'error');
  }
}

function closeReset(goToPin) {
  if (resetFlow?.stage === 'armed') call('reset_disarm').catch(() => {});
  const id = resetFlow?.id;
  resetFlow = null;
  renderResetOverlay();
  if (goToPin && id && tokens.has(id)) {
    selectToken(id);
    switchTab('pin');
  }
}

function onResetProgress(p) {
  if (!resetFlow) return;
  resetFlow = { ...resetFlow, stage: p.stage, id: p.id };
  renderResetOverlay();
}

function onResetDone(r) {
  if (!resetFlow) return;
  if (r.ok) {
    resetFlow = { ...resetFlow, stage: 'done', id: r.id };
  } else {
    resetFlow = { ...resetFlow, stage: 'failed', error: r.code === 'expired' ? t('rs.ov.expired') : errorMessage({ data: r, message: r.error }) };
  }
  renderResetOverlay();
}

// ── PIN tab ─────────────────────────────────────────────────────────────────

function renderPinStatus(st) {
  const el = $('pin-status');
  const form = $('pin-form');

  if (!st.supported) {
    el.className = 'callout';
    el.innerHTML = `<div class="callout-text">${escHtml(t('pin.unsupported'))}</div>`;
    form.classList.add('hidden');
    return;
  }

  const blocked = st.is_set && st.retries === 0;
  const parts = [];
  if (!st.is_set) {
    el.className = 'callout warn';
    parts.push(`<div class="callout-title">${escHtml(t('pin.notSet.title'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.notSet.text'))}</div>`);
  } else if (blocked) {
    el.className = 'callout crit';
    parts.push(`<div class="callout-title">${escHtml(t('pin.blocked.title'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.blocked.text'))}</div>`);
  } else {
    const low = st.retries != null && st.retries <= 3;
    el.className = `callout ${low || st.force_change ? 'warn' : 'ok'}`;
    parts.push(`<div class="callout-title">${escHtml(t('pin.set.title'))}</div>`);
    if (st.retries != null) {
      parts.push(`<div class="callout-text">${escHtml(st.retries === 1 ? t('pin.retries1') : t('pin.retries', { n: st.retries }))}</div>`);
    }
  }
  if (st.power_cycle_required) parts.push(`<div class="callout-text">${escHtml(t('pin.powerCycle'))}</div>`);
  if (st.force_change) {
    parts.push(`<div class="callout-text">${escHtml(t('pin.forceChange'))}</div>`);
    parts.push(`<div class="callout-text">${escHtml(t('pin.forceChangeHint'))}</div>`);
  }

  const facts = [[t('pin.fact.minLen'), t('pin.fact.minLenValue', { n: st.min_length })]];
  if (st.uv != null) {
    facts.push([t('pin.fact.bio'), st.uv ? t('pin.fact.bioEnrolled') : t('pin.fact.bioNone')]);
    if (st.uv_retries != null) facts.push([t('pin.fact.bioRetries'), String(st.uv_retries)]);
  }
  parts.push(`<dl class="kv">${buildKv(facts)}</dl>`);
  el.innerHTML = parts.join('');

  form.classList.toggle('hidden', blocked);
  $('pin-current-row').classList.toggle('hidden', !st.is_set);
  const label = st.is_set ? t('pin.form.change') : t('pin.form.set');
  $('pin-form-title').textContent = label;
  $('pin-submit').textContent = label;
  $('pin-hint').textContent = t('pin.form.hint', { min: st.min_length });
}

let pinWaiting = false;   // PIN status deferred until the attestation test ends

async function loadPinStatus(token) {
  pinWaiting = false;
  const el = $('pin-status');
  el.className = 'callout';
  el.innerHTML = `<div class="loading"><span class="spinner"></span>${escHtml(t('pin.loading'))}</div>`;
  $('pin-form').classList.add('hidden');
  hidePinError();
  try {
    const st = await call('pin_status', { token_id: token.id });
    if (selectedId !== token.id) return; // selection changed meanwhile
    pinState = st;
    renderPinStatus(st);
  } catch (e) {
    if (selectedId !== token.id) return;
    if (isBusy(e)) {
      pinWaiting = true;
      el.className = 'callout';
      el.innerHTML = `<div class="loading"><span class="spinner"></span>${escHtml(t('mg.waitAttestation'))}</div>`;
      return;
    }
    el.className = 'callout crit';
    el.innerHTML = `<div class="callout-text">${escHtml(errorMessage(e))}</div>
      <button type="button" class="btn-link" id="pin-retry">${escHtml(t('pin.retry'))}</button>`;
    $('pin-retry').onclick = () => loadPinStatus(token);
  }
}

function showPinError(msg) {
  $('pin-error').textContent = msg;
  $('pin-error').classList.remove('hidden');
}

function hidePinError() {
  $('pin-error').classList.add('hidden');
}

function clearPinInputs() {
  for (const id of ['pin-current', 'pin-new', 'pin-confirm']) $(id).value = '';
  $('pin-show').checked = false;
  setPinVisible(false);
}

function setPinVisible(visible) {
  for (const id of ['pin-current', 'pin-new', 'pin-confirm']) $(id).type = visible ? 'text' : 'password';
}

async function submitPinForm(ev) {
  ev.preventDefault();
  hidePinError();
  const token = tokens.get(selectedId);
  if (!token || !pinState) return;

  const current = $('pin-current').value;
  const next = $('pin-new').value;
  const confirm = $('pin-confirm').value;

  if (pinState.is_set && !current) return showPinError(t('pin.v.current'));
  if ([...next].length < pinState.min_length) return showPinError(t('pin.v.tooShort', { n: pinState.min_length }));
  if (new TextEncoder().encode(next).length > 63) return showPinError(t('pin.v.tooLong'));
  if (next !== confirm) return showPinError(t('pin.v.mismatch'));

  const btn = $('pin-submit');
  btn.disabled = true;
  try {
    const body = { new_pin: next };
    if (pinState.is_set) body.current_pin = current;
    const res = await call('pin_update', { token_id: token.id, ...body });
    clearPinInputs();
    showToast(res.result === 'set' ? t('pin.done.set') : t('pin.done.changed'), 'success');
    loadPinStatus(token);
  } catch (e) {
    $('pin-current').value = '';
    showPinError(errorMessage(e));
    if (['pin_invalid', 'pin_blocked', 'pin_auth_blocked'].includes(e.data?.code)) {
      // Refresh the retry counter without wiping the error message
      call('pin_status', { token_id: token.id }).then(st => { pinState = st; renderPinStatus(st); }).catch(() => {});
    }
  } finally {
    btn.disabled = false;
  }
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
  } catch { /* defaults */ }
  loadMds();
  call('data_status').then(st => { dataStatus = st; renderDataStatus(); }).catch(() => {});
  await loadHistory();
  await loadTokens();
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
  $('nav-backup').addEventListener('click', showBackupView);
  $('nav-backup-icon').innerHTML = icon('shield', 18);
  $('nav-accounts').addEventListener('click', showAccountsView);
  $('quick-unlock').addEventListener('submit', ev => {
    ev.preventDefault();
    if (quickUnlock?.mode === 'probe') probeSubmit(); else quickUnlockSubmit();
  });
  $('quick-unlock').addEventListener('click', ev => {
    const b = ev.target.closest('[data-ql]');
    if ((ev.target.id === 'quick-unlock' && !quickUnlock?.busy) || b?.dataset.ql === 'cancel') { quickUnlock = null; renderQuickUnlock(); return; }
    if (b?.dataset.ql === 'uv') quickUnlockSubmit('uv');
    if (b?.dataset.ql === 'stop' && quickUnlock) {
      quickUnlock = { ...quickUnlock, stopping: true };
      call('passkeys_probe_cancel', { token_id: quickUnlock.id }).catch(() => {});
      renderQuickUnlock();
    }
  });
  document.addEventListener('keydown', ev => {
    if (ev.key === 'Escape' && quickUnlock && !quickUnlock.busy) { quickUnlock = null; renderQuickUnlock(); }
  });
  $('nav-accounts-icon').innerHTML = icon('passkey', 18);
  $('nav-settings-icon').innerHTML = icon('settings', 18);
  $('nav-settings').addEventListener('click', showSettingsView);
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
  });
  $('quick-unlock').addEventListener('keydown', ev => {   // keep focus inside the dialog
    if (ev.key !== 'Tab') return;
    const f = [...$('quick-unlock').querySelectorAll('button:not(:disabled), input:not(:disabled), [tabindex="0"]')];
    const i = f.indexOf(document.activeElement);
    if (ev.shiftKey && i <= 0) { ev.preventDefault(); f[f.length - 1]?.focus(); }
    else if (!ev.shiftKey && i === f.length - 1) { ev.preventDefault(); f[0]?.focus(); }
  });
  $('about-dialog').addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { ev.preventDefault(); openAbout(false); }
    if (ev.key === 'Tab') {   // keep focus inside the dialog
      const f = [...$('about-dialog').querySelectorAll('button')];
      const i = f.indexOf(document.activeElement);
      if (ev.shiftKey && i <= 0) { ev.preventDefault(); f[f.length - 1].focus(); }
      else if (!ev.shiftKey && i === f.length - 1) { ev.preventDefault(); f[0].focus(); }
    }
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
