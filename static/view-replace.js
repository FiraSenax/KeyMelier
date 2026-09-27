// KeyMelier – guided key replacement
//
// Four steps: choose, compare, test & confirm, summary. The technical check
// (found on the new key) and the user's tick always stay separate.
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js ($, t, escHtml, call,
// icon, render …) only inside functions, never while loading.

let replaceOld = null;    // key being replaced (replace view)
let replaceStep = 1;      // 1 choose · 2 compare · 3 test & confirm · 4 summary
let replaceOpenOnly = false;
let replaceCancelAsk = false;   // backup page: confirm cancelling a running replacement

function showReplaceView(kid) {
  if (kid) replaceOld = kid;
  const e = replaceOld && historyKeys.get(replaceOld);
  replaceStep = e?.replace?.new && historyKeys.has(e.replace.new) ? Math.max(replaceStep, 2) : 1;
  mainView = 'replace';
  render();
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
