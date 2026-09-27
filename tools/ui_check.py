"""UI navigation checks against the demo data in headless Chrome.

Run: venv/bin/python tools/ui_check.py   (needs Chrome, Edge or Chromium)

Covers what the unit tests cannot: the backup page fits 1280 x 800, the
account filter cards work by keyboard and combine with search, "next step"
disclosures, the guided replacement (steps, open-only, tick vs. technical
check), the key actions menu and the passkey search keeping focus.
Uses only the demo bridge (tools/docs_demo.js) – no real keys.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import screenshots  # noqa: E402

CHECKS = r"""
(async () => {
  const out = [];
  const ok = (name, cond, info = '') => out.push({ name, ok: !!cond, info: String(info) });
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const key = (el, k) => el.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }));
  await wait(1500);

  // 1. Backup page: coverage, lost key and replacement visible without scrolling
  showBackupView(); await wait(300);
  const cards = [...document.querySelectorAll('#backup-content .bk-card')];
  ok('backup: three entry cards', cards.length === 3, cards.length);
  ok('backup: all within 800px', cards.every(c => c.getBoundingClientRect().bottom <= window.innerHeight),
     cards.map(c => Math.round(c.getBoundingClientRect().bottom)).join(','));
  ok('backup: sync status line links to settings', !!document.querySelector('#backup-content .sync-line [data-act="open-settings"]'));
  document.querySelector('#backup-content [data-act="open-settings"]').click(); await wait(300);
  ok('settings: global settings reachable', mainView === 'settings' && !!$('history-enabled') && !!$('personal-mode') && !!$('bk-remember')
     && !!document.querySelector('#settings-content [data-act="hist-export"]') && !!$('sync-card'));

  // 2. Account filters: buttons, keyboard, combined with search, reset, empty state
  showAccountsView(); await wait(300);
  const card = lvl => document.querySelector(`#accounts-content [data-acc-filter="${lvl}"]`);
  const rows = () => document.querySelectorAll('#accounts-content .acc-sub-row').length;
  const total = rows();
  ok('filters: cards are buttons with aria-pressed', card('warn')?.tagName === 'BUTTON' && card('warn').getAttribute('aria-pressed') === 'false');
  card('warn').focus(); card('warn').click(); await wait(50);   // Enter/Space on a button = click
  ok('filters: warn only', [...document.querySelectorAll('#accounts-content .acc-sub-row')].every(r => r.classList.contains('acc-warn')) && rows() > 0, rows());
  ok('filters: active + focus kept', card('warn').getAttribute('aria-pressed') === 'true' && document.activeElement === card('warn'));
  ok('filters: totals unchanged', card('').querySelector('b').textContent === String(total), card('').querySelector('b').textContent);
  const box = $('acc-search'); box.value = 'zzzz-no-match'; box.dispatchEvent(new Event('input', { bubbles: true })); await wait(50);
  ok('filters: empty state with reset', !!document.querySelector('#accounts-content .acc-empty [data-acc-reset]'));
  document.querySelector('#accounts-content [data-acc-reset]').click(); await wait(50);
  ok('filters: reset shows all', rows() === total && accLevel === '' && accFilter === '', rows());
  const next = document.querySelector('#accounts-content [data-next]');
  next.click(); await wait(50);
  const again = document.querySelector('#accounts-content [data-next]');
  ok('next step: expands with aria-expanded', again.getAttribute('aria-expanded') === 'true' && !!document.querySelector('.acc-next-row'));
  ok('matrix: legend above table', (() => { const l = document.querySelector('.acc-legend'), tb = document.querySelector('.acc-wrap');
    return l && tb && l.getBoundingClientRect().top < tb.getBoundingClientRect().top; })());
  ok('matrix: sticky header + column', getComputedStyle(document.querySelector('.acc-table thead th')).position === 'sticky'
     && getComputedStyle(document.querySelector('.acc-table th.acc-name')).position === 'sticky');

  // 3. Guided replacement
  const old = historyKeys.get('a1a1a1a1a1a1a1a1');
  // bitwarden: ticked but not on the new key; github: found and ticked (complete)
  old.replace = { new: 'b2b2b2b2b2b2b2b2', since: new Date().toISOString(), done: ['pk:bitwarden.com|erika@example.com', 'pk:github.com|erika'] };
  showReplaceView(old.key_id); await wait(100);
  ok('replace: opens at step 2 when keys are chosen', replaceStep === 2);
  document.querySelector('[data-rp-step="3"]').click(); await wait(50);
  ok('replace: step 3 has ticks', document.querySelectorAll('#replace-content [data-rp-item]').length > 0);
  const tickedNotFound = document.querySelector('#replace-content li .rp-chip.warn + .rp-chip.user, #replace-content li .rp-chip.user');
  ok('replace: tick without proof is marked', [...document.querySelectorAll('#replace-content li')].some(li =>
     li.textContent.includes('bitwarden.com') && li.querySelector('.rp-chip.user') && !li.querySelector('.rp-chip.ok')), !!tickedNotFound);
  const all = document.querySelectorAll('#replace-content li').length;
  $('rp-open-only').click(); await wait(50);
  const openOnly = [...document.querySelectorAll('#replace-content li')];
  ok('replace: open only hides complete entries', openOnly.length === all - 1 && !openOnly.some(li => li.textContent.includes('github.com · erika'))
     && openOnly.some(li => li.textContent.includes('bitwarden.com')), `${all}->${openOnly.length}`);
  document.querySelector('[data-rp-step="4"]').click(); await wait(50);
  ok('replace: summary separates confirmed-only', document.querySelector('#replace-content').textContent.length > 0
     && document.querySelectorAll('#replace-content h3.bk-group').length >= 2);
  document.querySelector('[data-rp-step="1"]').click(); await wait(50);
  ok('replace: step 1 pickers', !!$('rp-old') && !!$('rp-new'));

  // 4. Key header: two separate statements, actions menu by keyboard
  selectToken('demo-yk5'); switchTab('overview'); await wait(200);
  ok('header: key check pill', $('key-status').textContent.length > 0);
  ok('header: account coverage pill', !$('acc-status').classList.contains('hidden'), $('acc-status').textContent);
  const more = $('key-actions-btn'); more.focus(); key(more, 'ArrowDown'); await wait(20);
  ok('menu: opens by keyboard, focus on first item', !$('key-actions-menu').classList.contains('hidden') && document.activeElement.id === 'export-btn');
  key(document.activeElement, 'Escape'); await wait(20);
  ok('menu: Esc closes and returns focus', $('key-actions-menu').classList.contains('hidden') && document.activeElement === more);

  // 5. Passkey search keeps focus
  switchTab('passkeys'); await wait(300);
  const s = $('pk-search'); s.focus(); s.value = 'git'; s.setSelectionRange(3, 3);
  s.dispatchEvent(new Event('input', { bubbles: true })); await wait(50);
  ok('passkeys: search keeps focus', document.activeElement.id === 'pk-search' && $('pk-search').selectionStart === 3);

  document.body.setAttribute('data-ui-check', JSON.stringify(out));
})();
"""


def main() -> int:
    chrome = next((c for c in screenshots.CHROME_CANDIDATES if c and Path(c).exists()), None)
    if not chrome:
        print("Chrome, Edge or Chromium is needed.")
        return 2
    page = screenshots.demo_page()
    page.write_text(page.read_text(encoding="utf-8").replace("</body>", f"<script>{CHECKS}</script></body>", 1),
                    encoding="utf-8")
    dom = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--window-size=1280,800",
                          "--virtual-time-budget=15000", "--dump-dom", f"{page.as_uri()}#overview"],
                         capture_output=True, text=True, timeout=180).stdout
    m = re.search(r'data-ui-check="([^"]*)"', dom)
    if not m:
        print("No result – the page did not finish the checks.")
        return 1
    results = json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    failed = [r for r in results if not r["ok"]]
    for r in results:
        print(("ok   " if r["ok"] else "FAIL ") + r["name"] + (f"  ({r['info']})" if r["info"] and not r["ok"] else ""))
    print(f"{len(results) - len(failed)}/{len(results)} UI checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
