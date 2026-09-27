"""Start test of the packaged app (KeyMelier --self-test RESULT.json).

Run by tools/smoke_packaged.py against the built app in dist/, with a
temporary home directory. The app starts its real window but neither
scans for keys nor goes online. Checks:

- backend: bundled runtime libraries import and work, bundled data and
  resources are present (Python side);
- page: the UI loaded with CSS, all translations, icons and service logos,
  and bridge round trips reach the backend (JavaScript side, reported back
  through the bridge – which itself proves JS → Python works).

The result is written as JSON; the app then quits with exit code 0 (all
checks passed) or 1. A watchdog ends a hung start with exit code 3.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger("keymelier.selftest")

WATCHDOG_SECONDS = 90

# Runs inside the page once it has loaded; reports via the bridge.
PAGE_CHECKS = r"""
(async () => {
  const out = [];
  const ok = (name, cond, info = '') => out.push({ name, ok: !!cond, info: String(info).slice(0, 300) });
  const wait = ms => new Promise(r => setTimeout(r, ms));
  for (let i = 0; i < 200 && !(typeof tokens !== 'undefined' && window.pywebview?.api?.call && document.getElementById('key-list')); i++) await wait(100);
  try {
    ok('page: app script initialised', typeof tokens !== 'undefined' && typeof render === 'function');
    const langs = Object.keys(STRINGS);
    const n = Object.keys(STRINGS.en).length;
    ok('page: 11 languages, complete', langs.length === 11 && langs.every(l => Object.keys(STRINGS[l]).length >= n), `${langs.length} languages, ${n} keys`);
    ok('page: translated text rendered', ($('nav-backup')?.textContent || '').trim().length > 0, $('nav-backup')?.textContent);
    ok('page: UI icons', typeof ICONS === 'object' && Object.keys(ICONS).length >= 10 && $('nav-backup-icon').querySelector('svg'), Object.keys(ICONS || {}).length);
    ok('page: service logos', typeof SERVICE_ICONS === 'object' && Object.keys(SERVICE_ICONS).length >= 20, Object.keys(SERVICE_ICONS || {}).length);
    const img = document.querySelector('.brand img');
    ok('page: app icon (inlined image) decoded', img && img.complete && img.naturalWidth > 0, img?.naturalWidth);
    ok('page: stylesheet applied', getComputedStyle(document.querySelector('.sidebar')).display !== 'inline' && document.querySelector('.sidebar').getBoundingClientRect().width > 150,
       Math.round(document.querySelector('.sidebar').getBoundingClientRect().width));
    ok('page: account model loaded', typeof buildAccountModel === 'function' && typeof filterAccountRows === 'function');
    const st = await call('data_status');
    ok('bridge: data_status', st && st.advisories && st.advisories.count > 0, JSON.stringify(st?.advisories));
    const tk = await call('tokens');
    ok('bridge: tokens (scanner off in self-test)', Array.isArray(tk?.tokens) && tk.tokens.length === 0, tk?.tokens?.length);
    const set = await call('get_settings');
    ok('bridge: get_settings', set && typeof set.history_enabled === 'boolean', JSON.stringify(set).slice(0, 120));
    const hist = await call('history_list');
    ok('bridge: history_list', Array.isArray(hist?.keys), hist?.keys?.length);
    const sync = await call('sync_status');
    ok('bridge: sync_status', sync && sync.active === false, JSON.stringify(sync).slice(0, 120));
    let refused = false;
    try { await call('no_such_method'); } catch (e) { refused = e?.data?.code === 'unknown_method' || /Unknown method/.test(e?.message || ''); }
    ok('bridge: unknown methods refused', refused);
    showBackupView(); await wait(200);
    ok('page: backup view renders', document.querySelectorAll('#backup-content .bk-card').length === 3);
    showSettingsView(); await wait(200);
    ok('page: app settings render', !!$('history-enabled'));
  } catch (e) {
    ok('page: checks ran without exception', false, e?.stack || e);
  }
  // on failure: what the page showed (visible text and markup), for the CI artifacts
  const snapshot = out.every(c => c.ok) ? null
    : { text: (document.body?.innerText || '').slice(0, 20000), html: (document.body?.outerHTML || '').slice(0, 150000) };
  await window.pywebview.api.self_test_report(JSON.stringify({ checks: out, snapshot }));
})();
"""


def backend_checks(root: Path, data_dir: Path, static_dir: Path, advisories) -> list[dict]:
    out = []

    def check(name, fn):
        try:
            info = fn()
            out.append({"name": name, "ok": info is not False, "info": "" if info in (True, None) else str(info)[:300]})
        except Exception as e:  # a missing library shows up here
            out.append({"name": name, "ok": False, "info": f"{type(e).__name__}: {e}"[:300]})

    def crypto():
        import os as _os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        key = Scrypt(salt=b"s" * 16, length=32, n=2 ** 10, r=8, p=1).derive(b"self-test")
        nonce = _os.urandom(12)
        return AESGCM(key).decrypt(nonce, AESGCM(key).encrypt(nonce, b"ok", b""), b"") == b"ok"

    def fido():
        import fido2.ctap2  # noqa: F401
        import fido2.hid
        return fido2.hid.__name__

    def smartcard():
        import smartcard.System  # noqa: F401  (PC/SC; no reader access here)
        return "pyscard"

    def ykman():
        import ykman  # noqa: F401
        return "yubikey-manager"

    def tls():
        import certifi
        import requests  # noqa: F401
        return Path(certifi.where()).is_file()

    def keychain():
        import keyring
        return type(keyring.get_keyring()).__module__

    def webview():
        import webview as wv
        return getattr(wv, "__version__", "pywebview")

    check("runtime: fido2 (CTAP/HID)", fido)
    check("runtime: cryptography (scrypt, AES-GCM)", crypto)
    check("runtime: pyscard (PC/SC)", smartcard)
    check("runtime: yubikey-manager", ykman)
    check("runtime: requests + CA bundle", tls)
    check("runtime: keyring backend", keychain)
    check("runtime: pywebview", webview)
    check("data: signed advisory database loaded", lambda: advisories.info().get("count", 0) > 0 and advisories.info())

    def managed_policy():
        # Registry (winreg) / plist reader is bundled; the report shows what is configured
        from fido2tool_core import policy
        raw = policy.read_raw()
        return {"sources": [s["name"] for s in policy.advisory_sources(raw)], "configured": bool(raw)}
    check("runtime: managed configuration reader", managed_policy)
    for name in ("advisories.json", "advisories.json.sig"):
        check(f"data: {name}", lambda n=name: (data_dir / n).is_file())
    from fido2tool_core.page import SCRIPTS
    for name in ("index.html", "style.css", *SCRIPTS, "icon.svg", "icon.png", "menubar.png"):
        check(f"resource: static/{name}", lambda n=name: (static_dir / n).is_file() and (static_dir / n).stat().st_size > 0)
    for name in ("LICENSE", "THIRD_PARTY_LICENSES.txt", "keymelier-sbom.cdx.json"):
        check(f"resource: {name}", lambda n=name: (root / n).is_file())
    return out


class SelfTest:
    def __init__(self, result_path: str, root: Path, data_dir: Path, static_dir: Path, advisories):
        self.result_path = Path(result_path)
        self.root, self.data_dir, self.static_dir, self.advisories = root, data_dir, static_dir, advisories
        self.window = None
        self.ui_errors: list[str] = []
        self.passed = False
        self._done = threading.Event()
        log = logging.FileHandler(self.result_path.with_suffix(".log"), encoding="utf-8")
        log.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logging.getLogger().addHandler(log)   # windowed Windows builds have no console

    def start(self, window):
        self.window = window
        threading.Thread(target=self._watchdog, daemon=True, name="self-test-watchdog").start()
        window.events.loaded += self._on_loaded

    def _on_loaded(self, *_):
        logger.info("Page loaded, running page checks")
        self.window.evaluate_js(PAGE_CHECKS)

    def report(self, page_json: str):
        """Called from the page through the bridge."""
        snapshot = None
        try:
            data = json.loads(page_json)
            page, snapshot = (data["checks"], data.get("snapshot")) if isinstance(data, dict) else (data, None)
        except (ValueError, KeyError, TypeError):
            page = [{"name": "page: report readable", "ok": False, "info": str(page_json)[:200]}]
        if snapshot:
            self.result_path.with_name("page-snapshot.txt").write_text(snapshot.get("text", ""), encoding="utf-8")
            self.result_path.with_name("page-snapshot.html").write_text(snapshot.get("html", ""), encoding="utf-8")
        checks = backend_checks(self.root, self.data_dir, self.static_dir, self.advisories) + page
        checks.append({"name": "page: no JavaScript errors", "ok": not self.ui_errors, "info": "; ".join(self.ui_errors)[:300]})
        self.passed = all(c["ok"] for c in checks)
        self.result_path.write_text(json.dumps({"passed": self.passed, "checks": checks}, indent=1), encoding="utf-8")
        for c in checks:
            logger.info("%s %s %s", "ok  " if c["ok"] else "FAIL", c["name"], c["info"])
        self._done.set()
        threading.Timer(0.5, self.window.destroy).start()
        return True

    def _watchdog(self):
        if self._done.wait(WATCHDOG_SECONDS):
            return
        logger.error("Self-test did not finish within %ss", WATCHDOG_SECONDS)
        self.result_path.write_text(json.dumps({"passed": False, "checks": [
            {"name": "start within time limit", "ok": False, "info": f"no page report after {WATCHDOG_SECONDS}s"}]}),
            encoding="utf-8")
        logging.shutdown()
        os._exit(3)

    def exit_code(self) -> int:
        time.sleep(0.1)
        return 0 if self.passed else 1
