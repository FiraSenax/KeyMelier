// KeyMelier – all keys at once
//
// Status of every known key in one table; re-check all connected keys
// (advisories, metadata, rating); read them one after another with the
// usual unlock dialog; and change the PIN on several keys – one explicit
// click per key, stop at the first error, never an automatic retry.
//
// Classic script loaded before app.js (see fido2tool_core/page.py SCRIPTS);
// shares the global scope. Uses helpers from app.js only inside functions.

let keysBusy = null;      // 'recheck' | 'read' while a bulk action runs
let keysPin = null;       // PIN assistant: { step, selected, newPin, index, results, error }

function allKeyRows() {
  const live = [...tokens.values()];
  const liveIds = new Set(live.map(tok => tok.history_id));
  const offline = [...historyKeys.values()].filter(e => !liveIds.has(e.key_id)).map(e => offlineToken(e));
  return [...live, ...offline];
}

function pinCapable(tok) {
  return !tok.offline && 'clientPin' in (tok.options || {});
}

function renderKeysView() {
  $('keys-avatar').innerHTML = icon('key', 30);
  const m = accountModel();
  const rows = allKeyRows();
  const live = rows.filter(tok => !tok.offline);
  const cell = (tok) => {
    const info = m.keyInfo.get(tok.history_id);
    const acc = accountCheck(tok);
    const read = info && info.coverage !== 'none' ? relTime(info.checked) : t('tile.notRead');
    const pin = tok.offline ? '—' : !('clientPin' in (tok.options || {})) ? t('keys.pin.none') : tok.options.clientPin ? t('tile.pin.set') : t('tile.pin.notSet');
    return `<tr>
      <th scope="row"><span class="keys-name">${escHtml(displayName(tok))}</span>
        <span class="acc-sub">${escHtml([tok.mds_description || tok.product_name, serialLabel(tok), firmwareKnown(tok) ? t('header.fw', { v: tok.firmware_version_str }) : ''].filter(Boolean).join(' · '))}</span></th>
      <td>${historyKeys.get(tok.history_id)?.lost_since ? `<span class="warn-text">${escHtml(t('bk.lostBadge'))}</span>`
        : tok.offline ? `<span class="muted">${escHtml(t('keys.offline', { when: relTime(tok.last_seen) }))}</span>` : `<span class="ok-text">${escHtml(t('keys.connected'))}</span>`}</td>
      <td><span class="status-pill ${escHtml(tok.security_status || 'UNKNOWN')}">${escHtml(t(`status.${tok.security_status || 'UNKNOWN'}`))}</span></td>
      <td>${escHtml(pin)}</td>
      <td>${acc ? `<span class="status-pill acc-pill ${acc.cls}">${escHtml(acc.text)}</span>` : '—'}</td>
      <td>${escHtml(read)}</td>
      <td><button type="button" class="btn-small" data-open-key="${escHtml(tok.offline ? tok.history_id : tok.id)}" data-offline="${tok.offline ? 1 : ''}">${escHtml(t('keys.open'))}</button></td>
    </tr>`;
  };
  $('keys-content').innerHTML = `
    <section class="card">
      <div class="check-head"><h2>${escHtml(t('keys.status'))}</h2>
        <div class="form-actions bk-actions">
          <button type="button" class="btn btn-secondary" data-act="keys-recheck" ${keysBusy || !live.length ? 'disabled' : ''}>${escHtml(t(keysBusy === 'recheck' ? 'keys.rechecking' : 'keys.recheck'))}</button>
          <button type="button" class="btn btn-primary" data-act="keys-readall" ${keysBusy || !live.length ? 'disabled' : ''}>${escHtml(t(keysBusy === 'read' ? 'keys.reading' : 'keys.readAll'))}</button>
        </div></div>
      <p class="card-text">${escHtml(t('keys.text', { n: live.length, total: rows.length }))}</p>
      <div class="bk-table-wrap"><table class="bk-table keys-table">
        <thead><tr><th scope="col">${escHtml(t('keys.col.key'))}</th><th scope="col">${escHtml(t('keys.col.state'))}</th>
          <th scope="col">${escHtml(t('keycheck.title'))}</th><th scope="col">PIN</th><th scope="col">${escHtml(t('acccheck.title'))}</th>
          <th scope="col">${escHtml(t('keys.col.read'))}</th><th scope="col"><span class="sr-only">${escHtml(t('keys.open'))}</span></th></tr></thead>
        <tbody>${rows.map(cell).join('') || `<tr><td colspan="7" class="muted">${escHtml(t('sidebar.none'))}</td></tr>`}</tbody>
      </table></div>
    </section>
    ${pinAssistantHtml(live.filter(pinCapable))}`;
}

function showKeysView() {
  mainView = 'keys';
  render();
}

// ── Re-check and read all ────────────────────────────────────────────────────

async function recheckAllKeys() {
  keysBusy = 'recheck';
  renderPanel();
  try {
    dataStatus = await call('check_updates');   // advisories + metadata, then every connected key is rated again
    renderDataStatus();
    await loadTokens();
    showToast(t('keys.rechecked', { n: [...tokens.values()].filter(tok => !tok.offline).length }), 'success');
  } catch (e) {
    showToast(errorMessage(e), 'error');
  } finally {
    keysBusy = null;
    renderPanel();
  }
}

// Resolves once the unlock / search dialog is closed again
function dialogClosed() {
  return new Promise(resolve => {
    const tick = () => (quickUnlock ? setTimeout(tick, 150) : resolve());
    tick();
  });
}

// One key after another with the existing flows; stops when the user cancels
async function readAllKeys() {
  keysBusy = 'read';
  renderPanel();
  const ids = [...tokens.values()].filter(tok => !tok.offline).map(tok => tok.id);
  let done = 0;
  try {
    for (const id of ids) {
      const tok = tokens.get(id);
      if (!tok) continue;
      if (canManage(tok) && (tok.options?.clientPin || tok.options?.uv) && isUnlocked(id)) {
        await readContentsNow(tok);
        done++;
        continue;
      }
      await readKey(tok);                       // opens the unlock or search dialog
      await dialogClosed();
      const handled = canManage(tok) ? isUnlocked(id) : !!historyKeys.get(tok.history_id)?.probe;
      if (!handled) { showToast(t('keys.readStopped', { n: done }), 'info'); break; }
      done++;
    }
  } finally {
    keysBusy = null;
    await loadHistory();
    render();
  }
}

// ── PIN on several keys ──────────────────────────────────────────────────────

function pinAssistantHtml(capable) {
  const head = `<h2>${escHtml(t('kpin.title'))}</h2><p class="card-text">${escHtml(t('kpin.text'))}</p>`;
  if (!keysPin) {
    return `<section class="card" id="kpin">${head}
      <button type="button" class="btn btn-secondary" data-act="kpin-start" ${capable.length ? '' : 'disabled'}>${escHtml(t('kpin.start'))}</button>
      ${capable.length ? '' : `<p class="field-hint">${escHtml(t('kpin.noKeys'))}</p>`}</section>`;
  }
  const p = keysPin;
  const label = id => displayName(tokens.get(id) || {});
  if (p.step === 'choose') {
    return `<section class="card" id="kpin">${head}
      <p class="field-hint warn-text">${escHtml(t('kpin.warn'))}</p>
      <fieldset class="kpin-keys"><legend>${escHtml(t('kpin.choose'))}</legend>
        ${capable.map(tok => `<label class="check"><input type="checkbox" data-kpin-key="${escHtml(tok.id)}" ${p.selected.includes(tok.id) ? 'checked' : ''}>
          <span>${escHtml(displayName(tok))} <span class="muted">${escHtml(serialLabel(tok))}</span></span></label>`).join('')}
      </fieldset>
      <div class="form-actions"><button type="button" class="btn btn-secondary" data-act="kpin-cancel">${escHtml(t('pk.delete.cancel'))}</button>
        <button type="button" class="btn btn-primary" data-act="kpin-next" ${p.selected.length ? '' : 'disabled'}>${escHtml(t('rp.next'))}</button></div>
    </section>`;
  }
  if (p.step === 'pin') {
    const min = Math.max(4, ...p.selected.map(id => tokens.get(id)?.min_pin_length || 4));
    return `<section class="card" id="kpin">${head}
      <form class="sync-form" data-kpin-form="pin" autocomplete="off">
        <label class="field"><span>${escHtml(t('kpin.new'))}</span><input type="password" id="kpin-new" autocomplete="new-password" minlength="${min}" maxlength="63" required></label>
        <label class="field"><span>${escHtml(t('kpin.repeat'))}</span><input type="password" id="kpin-new2" autocomplete="new-password" maxlength="63" required></label>
        <p class="field-hint">${escHtml(t('kpin.minHint', { n: min }))}</p>
        ${p.error ? `<p class="field-error">${escHtml(p.error)}</p>` : ''}
        <div class="form-actions"><button type="button" class="btn btn-secondary" data-act="kpin-back">${escHtml(t('rp.prev'))}</button>
          <button type="submit" class="btn btn-primary">${escHtml(t('rp.next'))}</button></div>
      </form></section>`;
  }
  const resultsHtml = `<ul class="kpin-results">${p.selected.map(id => {
    const r = p.results[id];
    return `<li><span>${escHtml(label(id))}</span><span class="rp-chip ${r === 'changed' || r === 'set' ? 'ok' : r ? 'warn' : 'muted'}">${escHtml(t(`kpin.r.${r ? (r === 'changed' || r === 'set' || r === 'skipped' ? r : 'error') : 'open'}`))}</span></li>`;
  }).join('')}</ul>`;
  if (p.step === 'run') {
    const id = p.selected[p.index];
    const tok = tokens.get(id);
    const needsCurrent = tok?.options?.clientPin === true;
    return `<section class="card" id="kpin">${head}${resultsHtml}
      <form class="sync-form" data-kpin-form="key" autocomplete="off">
        <h3 class="bk-group">${escHtml(t('kpin.keyStep', { n: p.index + 1, total: p.selected.length, key: label(id) }))}</h3>
        ${!tok ? `<p class="field-error">${escHtml(t('kpin.gone'))}</p>` : needsCurrent
          ? `<label class="field"><span>${escHtml(t('pin.form.current'))}</span><input type="password" id="kpin-current" autocomplete="off" maxlength="63" required></label>` : `<p class="field-hint">${escHtml(t('kpin.noPinYet'))}</p>`}
        ${p.error ? `<p class="field-error">${escHtml(p.error)}</p>` : ''}
        <div class="form-actions">
          <button type="button" class="btn btn-secondary" data-act="kpin-stop">${escHtml(t('kpin.stop'))}</button>
          <button type="button" class="btn btn-secondary" data-act="kpin-skip">${escHtml(t('kpin.skip'))}</button>
          <button type="submit" class="btn btn-primary" ${tok && !p.busy ? '' : 'disabled'}>${escHtml(t(needsCurrent ? 'kpin.change' : 'kpin.set', { key: label(id) }))}</button>
        </div>
      </form></section>`;
  }
  return `<section class="card" id="kpin">${head}${resultsHtml}
    ${p.error ? `<p class="field-error">${escHtml(p.error)}</p>` : ''}
    <p class="field-hint">${escHtml(t(p.stopped ? 'kpin.stopped' : 'kpin.finished'))}</p>
    <div class="form-actions"><button type="button" class="btn btn-primary" data-act="kpin-close">${escHtml(t('about.close'))}</button></div>
  </section>`;
}

function finishPin(stopped) {
  keysPin.newPin = '';          // never kept longer than needed
  keysPin.step = 'done';
  keysPin.stopped = stopped;
}

async function keysPinSubmit(form) {
  const p = keysPin;
  if (form === 'pin') {
    const a = $('kpin-new').value, b = $('kpin-new2').value;
    const min = Math.max(4, ...p.selected.map(id => tokens.get(id)?.min_pin_length || 4));
    $('kpin-new').value = $('kpin-new2').value = '';
    if (a !== b) { p.error = t('pin.v.mismatch'); return renderPanel(); }
    if ([...a].length < min) { p.error = t('kpin.minHint', { n: min }); return renderPanel(); }
    Object.assign(p, { newPin: a, step: 'run', index: 0, error: null });
    renderPanel();
    return $('kpin-current')?.focus();
  }
  // one key, on the user's click; the PIN is sent once – never retried
  const id = p.selected[p.index];
  const current = $('kpin-current')?.value || null;
  if ($('kpin-current')) $('kpin-current').value = '';
  p.busy = true;
  renderPanel();
  try {
    const res = await call('pin_update', { token_id: id, new_pin: p.newPin, current_pin: current });
    p.results[id] = res.result;
    p.error = null;
    p.index++;
    if (p.index >= p.selected.length) finishPin(false);
  } catch (e) {
    p.results[id] = 'error';
    p.error = `${displayName(tokens.get(id) || {})}: ${errorMessage(e)}`;
    finishPin(true);            // stop at the first error; the remaining keys are not touched
  } finally {
    p.busy = false;
    renderPanel();
    (document.querySelector('#kpin input, #kpin [data-act="kpin-close"]'))?.focus();
  }
}

function keysAction(act, el) {
  if (act === 'keys-recheck') return recheckAllKeys();
  if (act === 'keys-readall') return readAllKeys();
  if (act === 'kpin-start') keysPin = { step: 'choose', selected: [], newPin: '', index: 0, results: {}, error: null };
  if (act === 'kpin-cancel' || act === 'kpin-close') keysPin = null;
  if (act === 'kpin-next') keysPin.step = 'pin';
  if (act === 'kpin-back') { keysPin.step = 'choose'; keysPin.error = null; }
  if (act === 'kpin-skip') {
    keysPin.results[keysPin.selected[keysPin.index]] = 'skipped';
    keysPin.index++;
    keysPin.error = null;
    if (keysPin.index >= keysPin.selected.length) finishPin(false);
  }
  if (act === 'kpin-stop') finishPin(true);
  renderPanel();
  document.querySelector('#kpin input, #kpin .btn-primary')?.focus();
  return el;
}

function initKeysView() {
  const el = $('keys-content');
  el.addEventListener('click', ev => {
    const open = ev.target.closest('[data-open-key]');
    if (open) return open.dataset.offline ? selectHistory(open.dataset.openKey) : selectToken(open.dataset.openKey);
    const b = ev.target.closest('[data-act]');
    if (b && !b.disabled) keysAction(b.dataset.act, b);
  });
  el.addEventListener('change', ev => {
    const id = ev.target.dataset?.kpinKey;
    if (!id || !keysPin) return;
    keysPin.selected = ev.target.checked ? [...new Set([...keysPin.selected, id])] : keysPin.selected.filter(x => x !== id);
    const next = document.querySelector('#kpin [data-act="kpin-next"]');
    if (next) next.disabled = !keysPin.selected.length;
  });
  el.addEventListener('submit', ev => {
    const form = ev.target.closest('[data-kpin-form]');
    if (!form) return;
    ev.preventDefault();
    keysPinSubmit(form.dataset.kpinForm);
  });
}
