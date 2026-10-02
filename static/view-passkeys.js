'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
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
