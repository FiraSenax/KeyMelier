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
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v4a6 6 0 0 1-12 0z"/><path d="M12 18v4"/>',
  pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/>',
  passkey: '<circle cx="9" cy="7" r="4"/><path d="M2 21v-2a4 4 0 0 1 4-4h6"/><circle cx="18" cy="14" r="2.5"/><path d="M18 16.5V22m0-2h2"/>',
};

function icon(name, size = 18) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
}

// Vendor logo from the FIDO metadata if available, otherwise a generic glyph
function keyIcon(token, size) {
  const src = token.mds_icon;
  if (typeof src === 'string' && src.startsWith('data:image/')) {
    return `<img class="vendor-icon" src="${escHtml(src)}" width="${size}" height="${size}" alt="">`;
  }
  return icon(isBio(token) ? 'fingerprint' : 'key', size);
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
function tabAllowed(token, tab) {
  if (tab === 'fingerprints' && !isBio(token)) return false;
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
  if (!att) return { cls: 'running', text: t('sec.att.running'), short: t('tile.security.attRunning') };
  if (token?.force_pin_change && !att.passed) {
    return { cls: 'partial', text: t('sec.att.needsPinChange'), short: t('tile.security.attNeedsPin') };
  }
  if (att.inconclusive) {
    return { cls: 'partial', text: t(`sec.att.skip.${att.inconclusive}`), short: t('tile.security.attSkipped'), skipped: true };
  }
  const checks = att.checks || [];
  const pass = checks.filter(c => c.passed === true).length;
  const fail = checks.filter(c => c.passed === false).length;
  const skip = checks.filter(c => c.passed == null).length;
  if (att.error && !att.passed) {
    return { cls: 'fail', text: t('sec.att.failErr', { e: att.error }), short: t('tile.security.attFail') };
  }
  if (fail > 0) return { cls: 'fail', text: t('sec.att.fail', { n: fail }), short: t('tile.security.attFail') };
  if (skip > 0) return { cls: 'partial', text: t('sec.att.partial', { p: pass, s: skip }), short: t('tile.security.attPartial') };
  return { cls: 'pass', text: t('sec.att.pass', { f: att.format || '—' }), short: t('tile.security.attPass') };
}

// ── Sidebar ─────────────────────────────────────────────────────────────────

function renderSidebar() {
  const list = $('key-list');
  $('key-list-empty').classList.toggle('hidden', tokens.size > 0);
  const live = new Set([...tokens.values()].map(tok => tok.history_id));
  const past = [...historyKeys.values()].filter(e => !live.has(e.key_id));
  $('history-label').classList.toggle('hidden', !past.length);
  $('history-list').innerHTML = past.map(e => {
    const tok = offlineToken(e);
    return `<button type="button" class="key-item offline${e.key_id === selectedHist ? ' active' : ''}" data-hist="${escHtml(e.key_id)}">
      <span class="key-item-icon">${keyIcon(tok, 22)}</span>
      <span class="key-item-text">
        <span class="key-item-name">${escHtml(displayName(tok))}</span>
        <span class="key-item-sub">${escHtml(relTime(e.last_seen))}</span>
      </span>
      <span class="status-dot ${escHtml(tok.security_status || '')}"></span>
    </button>`;
  }).join('');
  list.innerHTML = [...tokens.values()].map(tok => `
    <button type="button" class="key-item${tok.id === selectedId ? ' active' : ''}" data-id="${escHtml(tok.id)}">
      <span class="key-item-icon">${keyIcon(tok, 22)}</span>
      <span class="key-item-text">
        <span class="key-item-name">${escHtml(displayName(tok))}</span>
        <span class="key-item-sub">${escHtml(tok.manufacturer || '')} · ${escHtml(t(`status.${tok.security_status}`))}</span>
      </span>
      <span class="status-dot ${escHtml(tok.security_status)}"></span>
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

function render() {
  if (selectedId && !tokens.has(selectedId)) selectedId = null;
  if (selectedHist && !historyKeys.has(selectedHist)) selectedHist = null;
  if (!selectedId && !selectedHist && tokens.size) selectedId = tokens.keys().next().value;

  renderSidebar();
  const token = currentToken();
  $('empty-view').classList.toggle('hidden', !!token);
  $('key-view').classList.toggle('hidden', !token);
  if (token) renderKeyView(token);
}

function renderKeyView(token) {
  $('key-avatar').innerHTML = keyIcon(token, 36);
  $('key-title').textContent = displayName(token);
  const sub = [];
  if (token.offline) sub.push(t('hist.offline', { when: relTime(token.last_seen) }));
  sub.push(token.manufacturer);
  if (!token.offline && token.mds_description && token.product_name) sub.push(token.product_name);
  if (firmwareKnown(token)) sub.push(t('header.fw', { v: token.firmware_version_str }));
  $('key-subtitle').textContent = sub.filter(Boolean).join(' · ');
  $('key-view').classList.toggle('offline', !!token.offline);
  $('export-btn').classList.toggle('hidden', !!token.offline);

  const pill = $('key-status');
  pill.className = `status-pill ${token.security_status}`;
  pill.textContent = t(`status.${token.security_status}`);

  $('touch-banner').classList.toggle('hidden', !!token.attestation || !!token.offline);
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('hidden', !tabAllowed(token, b.dataset.tab)));
  if (!tabAllowed(token, activeTab)) switchTab('overview');

  renderTiles(token);
  renderSettings(token);
  renderSecurity(token);
  renderDetails(token);
}

function tileHtml({ cls, iconName, label, value, sub, tab }) {
  const tag = tab ? 'button' : 'div';
  return `
    <${tag} ${tab ? `type="button" data-goto="${tab}"` : ''} class="tile ${cls}">
      <div class="tile-head">
        <span class="tile-icon">${icon(iconName)}</span>
        <span class="tile-label">${escHtml(label)}</span>
      </div>
      <div class="tile-value">${escHtml(value)}</div>
      ${sub ? `<div class="tile-sub">${escHtml(sub)}</div>` : ''}
    </${tag}>`;
}

function renderTiles(token) {
  const o = token.options || {};
  const tiles = [];
  const tile = spec => tileHtml({ ...spec, tab: spec.tab && tabAllowed(token, spec.tab) ? spec.tab : null });

  // PIN
  if (!('clientPin' in o)) {
    tiles.push(tile({ cls: 'neutral', iconName: 'lock', label: t('tile.pin'), value: t('tile.pin.unsupported') }));
  } else if (!o.clientPin) {
    tiles.push(tile({ cls: 'warn', iconName: 'lock', label: t('tile.pin'), value: t('tile.pin.notSet'),
      sub: t('tile.pin.notSetHint'), tab: 'pin' }));
  } else {
    tiles.push(tile({ cls: token.force_pin_change ? 'warn' : 'ok', iconName: 'lock', label: t('tile.pin'),
      value: token.force_pin_change ? t('tile.pin.forceChange') : t('tile.pin.set'),
      sub: t('tile.pin.minLen', { n: token.min_pin_length }), tab: 'pin' }));
  }

  // Passkeys
  if (o.credMgmt || o.credentialMgmtPreview) {
    tiles.push(tile({ cls: 'info', iconName: 'passkey', label: t('tile.passkeys'),
      value: token.remaining_disc_creds != null
        ? t('tile.passkeys.free', { n: token.remaining_disc_creds })
        : t('tile.passkeys.supported'),
      sub: t('tile.passkeys.open'), tab: 'passkeys' }));
  } else {
    tiles.push(tile({ cls: 'neutral', iconName: 'passkey', label: t('tile.passkeys'),
      value: t('tile.passkeys.unsupported') }));
  }

  // Fingerprint
  if (isBio(token)) {
    const enrolled = (o.bioEnroll ?? o.userVerificationMgmtPreview ?? o.uv) === true;
    tiles.push(tile({ cls: enrolled ? 'ok' : 'info', iconName: 'fingerprint', label: t('tile.bio'),
      value: enrolled ? t('tile.bio.enrolled') : t('tile.bio.none'), sub: t('tile.passkeys.open'), tab: 'fingerprints' }));
  } else {
    tiles.push(tile({ cls: 'neutral', iconName: 'fingerprint', label: t('tile.bio'),
      value: t('tile.bio.noSensor'), sub: t('tile.bio.noSensorHint') }));
  }

  // Security
  const secCls = { OK: 'ok', WARNING: 'warn', CRITICAL: 'crit' }[token.security_status] || 'neutral';
  const cves = token.cve_ids || [];
  const att = attestationSummary(token.attestation, token);
  tiles.push(tile({ cls: secCls, iconName: 'shield', label: t('tile.security'),
    value: t(`status.${token.security_status}`),
    sub: `${cves.length ? t('tile.security.cves', { n: cves.length }) : t('tile.security.noCves')} · ${att.short}`,
    tab: 'security' }));

  $('tiles').innerHTML = tiles.join('');
}

function renderSecurity(token) {
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
  if (!token.offline && sum.cls !== 'running') {
    html += `<div class="form-actions att-actions"><button type="button" class="btn btn-secondary" id="att-rerun">${escHtml(t('sec.att.rerun'))}</button></div>`;
  }
  $('sec-attestation').innerHTML = html;
  const rerun = $('att-rerun');
  if (rerun) rerun.onclick = () => call('attestation_rerun', { token_id: token.id }).catch(e => showToast(errorMessage(e), 'error'));

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
  if (kid === selectedHist && !selectedId) return;
  selectedId = null;
  selectedHist = kid;
  resetViewState();
  render();
  switchTab(activeTab);
}

function selectToken(id) {
  if (id === selectedId) return;
  selectedId = id;
  selectedHist = null;
  histDetail = null;
  histConfirmForget = false;
  pinState = null;
  pkState = null;
  fpState = null;
  fpEnroll = null;
  unlockBusy = null;
  clearPinInputs();
  render();
  switchTab(activeTab);
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== tab));
  const current = currentToken();
  if (tab === 'history' && current) loadHistoryDetail(current.history_id);
  const token = tokens.get(selectedId);
  if (tab === 'pin' && token) loadPinStatus(token);
  if (tab === 'passkeys' && token) loadPasskeys(token);
  if (tab === 'fingerprints' && token) loadFingerprints(token);
}

// ── Data freshness ──────────────────────────────────────────────────────────

function fmtDate(iso) {
  return iso ? `${new Date(iso).toLocaleString(LANG)} (${relTime(iso)})` : '—';
}

function renderUpdateBanner() {
  const app = dataStatus?.app;
  const show = !!(app && app.newer && app.url);
  $('update-banner').classList.toggle('hidden', !show);
  if (show) $('update-text').textContent = t('upd.available', { v: app.latest });
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
    [t('data.lastCheck'), st.last_check ? fmtDate(st.last_check) : t('data.pending')],
    [t('data.appVersion'), st.app?.current
      ? `${st.app.current}${st.app.latest ? ` · ${st.app.newer ? t('upd.available', { v: st.app.latest }) : t('upd.upToDate')}` : ''}`
      : '—'],
  ]);
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
  passkey_deleted: 'passkey', fingerprint_enrolled: 'fingerprint', fingerprint_renamed: 'fingerprint',
  fingerprint_removed: 'fingerprint', reset: 'trash',
};

function eventText(ev) {
  if (ev.type === 'attestation') return t(ev.passed ? 'ev.attestation.pass' : 'ev.attestation.fail');
  if (ev.type === 'attestation_skipped') return t('ev.attestation.skipped');
  const key = `ev.${ev.type}`;
  const base = STRINGS[LANG][key] ? t(key) : ev.type;
  if (ev.type === 'passkey_deleted' && (ev.site || ev.user)) return `${base}: ${[ev.site, ev.user].filter(Boolean).join(' · ')}`;
  if (ev.type.startsWith('fingerprint_') && ev.name) return `${base}: ${ev.name}`;
  return base;
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
      ])}</dl>
    </section>
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
}

function loadManagement(token) {
  if (activeTab === 'passkeys') return loadPasskeys(token);
  if (activeTab === 'fingerprints') return loadFingerprints(token);
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
    await call('unlock', method === 'uv' ? { token_id: token.id, method: 'uv' } : { token_id: token.id, pin });
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
let pkConfirm = null;     // credential_id awaiting delete confirmation

function credProtectLabel(level) {
  return level === 3 ? t('pk.protect3') : null;
}

function renderPasskeys() {
  const el = $('pk-content');
  const st = pkState;
  const gate = managementGateHtml(st, 'pk.unsupported');
  if (gate !== null) { el.innerHTML = gate; focusUnlockPin('passkeys'); return; }

  const total = st.rps.reduce((n, rp) => n + rp.credentials.length, 0);
  const summary = [t('pk.count', { n: total })];
  if (st.remaining != null) summary.push(t('tile.passkeys.free', { n: st.remaining }));
  let html = toolbarHtml(summary.join(' · '));

  if (!st.rps.length) {
    html += `<div class="callout"><div class="callout-title">${escHtml(t('pk.empty.title'))}</div>
      <div class="callout-text">${escHtml(t('pk.empty.text'))}</div></div>`;
  }

  for (const rp of st.rps) {
    const name = rp.rp_id || rp.rp_name || t('pk.unknownSite');
    const letter = (name.replace(/^www\./, '')[0] || '?').toUpperCase();
    html += `<section class="card pk-rp">
      <header class="pk-rp-head">
        <span class="pk-avatar">${escHtml(letter)}</span>
        <div class="pk-rp-text">
          <div class="pk-rp-name">${escHtml(name)}</div>
          ${rp.rp_name && rp.rp_name !== name ? `<div class="pk-rp-sub">${escHtml(rp.rp_name)}</div>` : ''}
        </div>
      </header>
      <ul class="pk-list">` + rp.credentials.map(c => {
        const main = c.display_name || c.user_name || t('pk.noName');
        const sub = c.display_name && c.user_name && c.user_name !== c.display_name ? c.user_name : '';
        const prot = credProtectLabel(c.cred_protect);
        const confirming = pkConfirm === c.credential_id;
        return `<li class="pk-item">
          <div class="pk-user">
            <div class="pk-user-name">${escHtml(main)}</div>
            ${sub ? `<div class="pk-user-sub">${escHtml(sub)}</div>` : ''}
            ${prot ? `<div class="pk-user-sub">${escHtml(prot)}</div>` : ''}
          </div>
          ${confirming ? `
            <div class="pk-confirm">
              <span>${escHtml(t('pk.delete.confirm'))}</span>
              <button type="button" class="btn btn-secondary" data-act="cancel">${escHtml(t('pk.delete.cancel'))}</button>
              <button type="button" class="btn btn-danger" data-act="delete" data-id="${escHtml(c.credential_id)}">${escHtml(t('pk.delete.do'))}</button>
            </div>` : `
            <button type="button" class="btn-icon danger" data-act="ask-delete" data-id="${escHtml(c.credential_id)}" title="${escHtml(t('pk.delete.do'))}">${icon('trash', 16)}</button>`}
        </li>`;
      }).join('') + '</ul></section>';
  }
  if (pkConfirm) html += `<p class="field-hint">${escHtml(t('pk.delete.warning'))}</p>`;
  el.innerHTML = html;
}

async function loadPasskeys(token) {
  pkState = null;
  unlockError = null;
  pkConfirm = null;
  renderPasskeys();
  try {
    const st = await call('passkeys', { token_id: token.id });
    if (selectedId !== token.id) return;
    pkState = st;
  } catch (e) {
    if (selectedId !== token.id) return;
    pkState = isBusy(e) ? { busy: true } : { error: errorMessage(e) };
  }
  renderPasskeys();
}

async function passkeyAction(action, credId) {
  const token = tokens.get(selectedId);
  if (!token) return;
  if (action === 'reload') return loadPasskeys(token);
  if (action === 'ask-delete') { pkConfirm = credId; return renderPasskeys(); }
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
    const max = st.max_name_bytes ? `maxlength="${st.max_name_bytes}"` : '';
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
        const max = st.max_name_bytes ? `maxlength="${st.max_name_bytes}"` : '';
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

async function loadFingerprints(token) {
  fpState = null;
  unlockError = null;
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
  });
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
  mds_ready: p => { mdsInfo = p; renderMds(); },
  data_status: p => { dataStatus = p; mdsInfo = p.mds; renderMds(); renderDataStatus(); },
  app_update: p => { dataStatus = { ...(dataStatus || {}), app: p }; renderDataStatus(); },
};

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
    const item = ev.target.closest('.key-item');
    if (item) selectToken(item.dataset.id);
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
  });
  document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  $('lang-select').addEventListener('change', ev => changeLang(ev.target.value));
  $('pin-form').addEventListener('submit', submitPinForm);
  $('rs-confirm').addEventListener('change', ev => { $('rs-start').disabled = !ev.target.checked; });
  $('rs-start').addEventListener('click', startReset);
  $('rs-ov-secondary').addEventListener('click', () => closeReset(false));
  $('rs-ov-primary').addEventListener('click', () => closeReset(true));
  initManagementPane('pk-content', passkeyAction);
  initManagementPane('fp-content', fingerprintAction);
  $('pin-show').addEventListener('change', ev => setPinVisible(ev.target.checked));
  $('export-btn').addEventListener('click', exportTokens);
  $('data-check').addEventListener('click', checkDataNow);
  $('update-btn').addEventListener('click', () => {
    if (dataStatus?.app?.url) window.pywebview?.api?.open_url(dataStatus.app.url);
  });

  changeLang('', false);
  switchTab('overview');
  whenBridgeReady(start);
}

// pywebview may inject the page after DOMContentLoaded has already fired
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
