'use strict';

// Classic-script view module; loaded before app.js, invoked after app initialization.
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
