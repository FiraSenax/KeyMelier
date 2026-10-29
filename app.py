"""KeyMelier desktop app.

Opens a native window (pywebview: WKWebView on macOS, Edge WebView2 on
Windows) with the HTML/JS UI from static/. JavaScript talks to Python
directly through the pywebview bridge; there is no local HTTP server, so
nothing else on the machine (other programs, browser extensions, websites)
can reach the app.
"""

import os
import json
import logging
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path

# Apply the no-persistence policy before importing application/GUI packages.
if "--stateless" in sys.argv:
    os.environ["KEYMELIER_STATELESS"] = "1"
if os.environ.get("KEYMELIER_STATELESS") == "1":
    sys.dont_write_bytecode = True

# Make the repo root importable regardless of where the script is launched from.
# In a PyInstaller bundle, data files live under sys._MEIPASS.
ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
sys.path.insert(0, str(ROOT_DIR))

if sys.platform.startswith("linux"):
    os.environ.setdefault("QT_API", "pyside6")   # pywebview's Qt backend (bundled in the AppImage)

import webview

from keymelier_core.bridge import ALLOWED, dispatch
from keymelier_core import diagnostics
from keymelier_core.advisories import AdvisoryChecker
from keymelier_core.desktop import host_env, linux_copy, open_with_system, private_page_file
from keymelier_core.exporter import CSVExporter
from keymelier_core.mds3 import MDS3Client
from keymelier_core.page import build_html
from keymelier_core.scanner import TokenScanner
from keymelier_core.service import KeyService
from keymelier_core.storage import stateless
from keymelier_core.desktop_io import gpg_path, read_import
from keymelier_core.safe_errors import log_failure
from keymelier_core import native_ui
from keymelier_core.consent import NativeConsent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("keymelier")

DATA_DIR = ROOT_DIR / "data"
STATIC_DIR = ROOT_DIR / "static"
LOCK_FILE = Path.home() / "keymelier" / "app.lock"


# ── JS bridge ────────────────────────────────────────────────────────────────

# Hosts the UI may open in the external browser (advisory references)
ALLOWED_LINK_HOSTS = {"github.com", "firasenax.github.io", "www.yubico.com", "nvd.nist.gov", "fidoalliance.org", "www.ftsafe.com", "www.token2.com",
                      "www.atlassian.com", "pypi.org", "vercel.com"}


def _gpg():
    return gpg_path()


# Functions the page may call. pywebview resolves js_api names as dotted
# attribute paths without filtering private members ("_window.gui.os…"), so
# the page gets plain wrapper functions only – never an object.
BRIDGE = ("call", "open_url", "copy_text", "save_text", "open_text", "read_oath_qr", "choose_folder", "open_licenses", "get_licenses",
          "save_license", "gpg_available", "gpg_import", "set_ui_language", "client_log", "client_error")


def _lock_navigation(window, page_url=None):
    return native_ui.install(window, page_url)


def _expose_bridge(window, api, extra=()):
    def wrap(name):
        method = getattr(api, name)

        def bridge(*args):
            try:
                return method(*args)
            except Exception as e:
                # Direct desktop callbacks (file dialogs, clipboard, etc.) do
                # not pass through dispatch. Never let pywebview serialize a
                # raw exception, its private file path or traceback to the UI.
                log_failure(logger, "Desktop callback " + name, e)
                if name in {"call", "gpg_import", "read_oath_qr"}:
                    return {"ok": False, "error": "The operation could not be completed.",
                            "code": "error", "status": 500}
                if name in {"copy_text", "open_licenses", "gpg_available", "save_license"}:
                    return False
                return None
        bridge.__name__ = name
        bridge.__qualname__ = name
        return bridge

    window.expose(*(wrap(name) for name in (*BRIDGE, *extra)))


class Api:
    """Exposed to JavaScript as window.pywebview.api.

    Every call returns an envelope {ok, data} or {ok: false, error, code,
    status, ...} so the UI gets stable error codes instead of exceptions.
    """

    def __init__(self, service: KeyService):
        self._service = service
        self._menubar = None  # private: pywebview only exposes public members
        self._window = None
        self._selftest = None  # set by --self-test
        self._selected_sync_folder = None
        self._consent = NativeConsent(service, lambda title, message: native_ui.confirm(self._window, title, message),
                                      DATA_DIR / "native-ui.json")

    def set_ui_language(self, lang, texts=None):
        """The page tells the menu bar which language and texts it shows."""
        if self._menubar is not None and isinstance(lang, str) and re.fullmatch(r"[a-z]{2}", lang):
            self._menubar.set_language(lang, texts if isinstance(texts, dict) else None)

    def save_text(self, filename, text, private=False):
        """Save generated text (OpenPGP public key, revocation certificate)
        where the user chooses. Returns the path or None if cancelled."""
        name = Path(str(filename)).name[:120] or "keymelier.txt"
        text = str(text)
        if len(text) > 1_000_000:
            return None
        return self._save_document(name, text, private)

    def _save_document(self, name, text, private=False):
        if stateless() or self._window is None:
            return None
        chosen = self._window.create_file_dialog(
            webview.FileDialog.SAVE, directory=str(Path.home() / "Documents"), save_filename=name)
        if not chosen:
            return None
        path = Path(chosen[0] if isinstance(chosen, (list, tuple)) else chosen)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600 if private else 0o644)
        if private and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)  # an existing file keeps its mode otherwise
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        return str(path)

    def open_text(self, kind="json"):
        """Let the user pick a file to import; returns its text (or None)."""
        if self._window is None:
            return None
        chosen = self._window.create_file_dialog(
            webview.FileDialog.OPEN, directory=str(Path.home() / "Documents"),
            file_types=("KeyMelier (*.json)", "All files (*.*)"))
        if not chosen:
            return None
        path = Path(chosen[0] if isinstance(chosen, (list, tuple)) else chosen)
        return read_import(path)

    def choose_folder(self):
        """Let the user pick the sync folder; returns its path (or None)."""
        self._selected_sync_folder = None
        if self._window is None:
            return None
        chosen = self._window.create_file_dialog(webview.FileDialog.FOLDER, directory=str(Path.home()))
        if not chosen:
            return None
        path = Path(chosen[0] if isinstance(chosen, (list, tuple)) else chosen)
        self._selected_sync_folder = str(path) if path.is_dir() else None
        return self._selected_sync_folder

    def read_oath_qr(self):
        """Preview only the image selected in the native dialog, never a JS path."""
        from keymelier_core import oath_qr
        from keymelier_core.pin import PinError
        if self._window is None:
            return {"ok": True, "data": None}
        chosen = self._window.create_file_dialog(
            webview.FileDialog.OPEN, allow_multiple=False,
            file_types=("QR image (*.png;*.jpg;*.jpeg)",))
        if not chosen:
            return {"ok": True, "data": None}
        path = chosen[0] if isinstance(chosen, (list, tuple)) else chosen
        try:
            return {"ok": True, "data": oath_qr.read_image(path)}
        except PinError as e:
            return {"ok": False, "code": e.code, "error": e.message}
        except OSError:
            return {"ok": False, "code": "qr_image", "error": "The image could not be read."}

    def gpg_available(self):
        return _gpg() is not None

    def gpg_import(self, public_key):
        """Import the public key into GnuPG and let it link the card
        (`gpg --card-status`), then release the card for KeyMelier again."""
        if stateless():
            return {"ok": False, "output": "Imports are disabled in stateless mode."}
        gpg = _gpg()
        text = str(public_key)
        if gpg is None or not text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            return {"ok": False}
        try:
            imp = subprocess.run([gpg, "--batch", "--import"], input=text.encode(), capture_output=True, timeout=60,
                                 env=host_env())
            subprocess.run([gpg, "--batch", "--card-status"], capture_output=True, timeout=60, env=host_env())
            gpgconf = Path(gpg).with_name("gpgconf")
            if gpgconf.exists():
                subprocess.run([str(gpgconf), "--kill", "scdaemon"], capture_output=True, timeout=30, env=host_env())
            return {"ok": imp.returncode == 0,
                    "output": "" if imp.returncode == 0 else "GnuPG could not import the public key."}
        except Exception as e:
            logger.warning("GnuPG import failed (%s)", type(e).__name__)
            return {"ok": False, "output": "GnuPG could not import the public key."}

    def open_licenses(self):
        """Show the bundled third-party licenses in the system text viewer."""
        path = ROOT_DIR / "THIRD_PARTY_LICENSES.txt"
        if not path.exists():  # running from source
            if stateless():
                return False
            sys.path.insert(0, str(ROOT_DIR / "tools"))
            import third_party_licenses
            path = third_party_licenses.write(ROOT_DIR / "build" / "THIRD_PARTY_LICENSES.txt")
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-e", str(path)])
            elif sys.platform == "win32":
                os.startfile(str(path))  # noqa: S606 – fixed local file
            else:
                open_with_system(str(path))
            return True
        except Exception as e:
            logger.debug("Opening licenses failed: %s", type(e).__name__)
            return False

    def get_licenses(self):
        """Return only fixed, local legal documents for the in-app reader."""
        from keymelier_core.licenses import documents
        return documents(ROOT_DIR, bundled=bool(getattr(sys, "frozen", False)))

    def save_license(self, document_id):
        # Read the document ourselves: no arbitrary paths or large bridge input.
        from keymelier_core.licenses import document
        name, text = document(ROOT_DIR, document_id, bundled=bool(getattr(sys, "frozen", False)))
        return self._save_document(name, text)

    def copy_text(self, text):
        """Put a code or certificate on the system clipboard (the web view's clipboard API is unreliable)."""
        text = str(text)[:16384]
        try:
            if sys.platform == "darwin":
                subprocess.run(["pbcopy"], input=text.encode(), check=True)
            elif sys.platform == "win32":
                subprocess.run(["clip"], input=text.encode("utf-16-le"), check=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                return linux_copy(text)
            return True
        except Exception as e:
            logger.debug("Clipboard failed: %s", type(e).__name__)
            return False

    def client_log(self, message):
        logger.info("UI event received")

    def client_error(self, message):
        """JavaScript errors from the page, so they show up in the terminal."""
        logger.error("UI script error")
        self._service.error_log.ui_errors += 1
        if self._selftest is not None:
            self._selftest.ui_errors.append(str(message)[:300])

    def self_test_report(self, page_json):
        """Only exposed with --self-test: the page's check results."""
        return self._selftest.report(str(page_json)[:1_000_000]) if self._selftest is not None else None

    def open_url(self, url):
        """Open advisory links in the default browser (never inside the app)."""
        from urllib.parse import urlparse
        if not isinstance(url, str) or re.search(r"[\s\\\x00-\x1f\x7f-\x9f]", url):
            return
        try:
            parsed = urlparse(url)
            parsed.port  # validate the port syntax; managed intranet links may use non-default ports
            if parsed.username is not None or parsed.password is not None:
                return
        except ValueError:
            return
        # Fixed hosts, or exactly a link from a signed company advisory source
        if parsed.scheme == "https" and (parsed.hostname in ALLOWED_LINK_HOSTS
                                         or self._service._link_allowed(str(url))):
            if sys.platform.startswith("linux"):
                open_with_system(parsed.geturl())   # host browser, without the AppImage's libraries
            else:
                import webbrowser
                webbrowser.open(parsed.geturl())

    def call(self, method, kwargs=None):
        if method == "sync_enable":
            # A JS argument alone must never initiate SMB/UNC access. Existing
            # saved configuration remains usable when re-entering the passphrase.
            folder = kwargs.get("folder") if isinstance(kwargs, dict) else None
            configured = self._service._stored_settings().get("sync_folder")
            if not isinstance(folder, str) or not folder or folder not in (self._selected_sync_folder, configured):
                return {"ok": False, "error": "Choose the sync folder in the folder dialog.",
                        "code": "invalid_input", "status": 400}
        return dispatch(self._service, method, kwargs, authorize=self._consent.authorize)


class EventPump:
    """Delivers service events to the page on a dedicated thread, so scanner
    and worker threads never block on the UI."""

    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._window = None
        self._ready = threading.Event()
        threading.Thread(target=self._run, daemon=True, name="event-pump").start()

    def attach(self, window):
        self._window = window
        # pywebview passes the window to handlers; Event.set() takes no arguments
        window.events.loaded += lambda *_: self._ready.set()

    def emit(self, name, payload):
        self._queue.put((name, payload))

    def _run(self):
        while True:
            name, payload = self._queue.get()
            self._ready.wait()
            try:
                self._window.evaluate_js(f"window.__kmEvent && window.__kmEvent({json.dumps(name)}, {json.dumps(payload)})")
            except Exception as e:
                logger.warning("Event delivery failed (%s): %s", name, type(e).__name__)


# ── Page assembly ────────────────────────────────────────────────────────────

# ── Platform niceties ────────────────────────────────────────────────────────

def _macos_dark_mode() -> bool:
    try:
        out = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True, text=True)
        return "dark" in out.stdout.lower()
    except Exception:
        return False


def _macos_app_identity():
    """When run from source, show 'KeyMelier' and its icon instead of Python's."""
    try:
        from AppKit import NSApplication, NSImage
        from Foundation import NSBundle

        info = NSBundle.mainBundle().infoDictionary()
        if info is not None:
            info["CFBundleName"] = "KeyMelier"
        image = NSImage.alloc().initWithContentsOfFile_(str(STATIC_DIR / "icon.png"))
        if image is not None and image.isValid():
            NSApplication.sharedApplication().setApplicationIconImage_(image)
    except Exception as e:
        logger.debug("Could not set macOS app identity: %s", type(e).__name__)


def _single_instance():
    """Return a held lock file, or None if another KeyMelier is already running."""
    if stateless():
        return True
    LOCK_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = open(LOCK_FILE, "a+")
    try:
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    from keymelier_core.version import __version__
    logger.info("KeyMelier %s", __version__)
    if "--stateless" in sys.argv:
        os.environ["KEYMELIER_STATELESS"] = "1"
    lock = True if os.environ.get("KEYMELIER_STATELESS") == "1" else _single_instance()
    if lock is None:
        logger.error("KeyMelier is already running.")
        sys.exit(1)

    selftest = None
    if "--self-test" in sys.argv:
        # Start test of the packaged app: real window, no key access, no network
        from keymelier_core.selftest import SelfTest
        idx = sys.argv.index("--self-test")
        result = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "keymelier-self-test.json"
        selftest = True

    mds3 = MDS3Client()
    advisories = AdvisoryChecker(DATA_DIR, defer_policy=True)   # company sources: in the update thread
    scanner = TokenScanner(
        poll_interval=1.0,
        mds3_client=mds3,
        advisory_checker=advisories,
    )
    service = KeyService(scanner, CSVExporter(), mds3_client=mds3, advisories=advisories)
    pump = EventPump()
    menubar = None

    def emit(name, payload):
        pump.emit(name, payload)
        if menubar is not None:
            menubar.on_event(name, payload)

    service.emit = emit

    if selftest:
        selftest = SelfTest(result, ROOT_DIR, DATA_DIR, STATIC_DIR, advisories)

    def background_start():
        if selftest:
            logger.info("Self-test: scanner, metadata download and update checks are off")
            return
        # Metadata first (downloads on first run, then cached 24h) so the
        # scanner can enrich keys; the window is already visible meanwhile.
        logger.info("Loading FIDO Alliance MDS3 metadata...")
        try:
            mds3.ensure_loaded()
        except Exception as e:
            logger.warning("MDS3 unavailable: %s", type(e).__name__)
        pump.emit("mds_ready", service.mds_status())
        threading.Thread(target=scanner.run_forever, daemon=True, name="fido2-scanner").start()
        threading.Thread(target=service._run_update_loop, daemon=True, name="updates").start()

    dark = sys.platform == "darwin" and _macos_dark_mode()
    service.error_log = diagnostics.ErrorLog(ALLOWED)
    service.gui_backend = lambda: getattr(webview, "renderer", None)   # set by pywebview once the window runs
    api = Api(service)
    webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False
    webview.settings['ALLOW_DOWNLOADS'] = False
    # Linux (Qt): the page is too large for setHtml, so it is loaded from a private file
    page_url, remove_page = None, None
    if sys.platform.startswith("linux"):
        page_path, remove_page = private_page_file(build_html())
        page_url = page_path.as_uri()
    window = webview.create_window(
        "KeyMelier",
        url=page_url,
        html=None if page_url else build_html(),
        js_api=None,  # see _expose_bridge: never hand pywebview an object
        width=1180,
        height=780,
        min_size=(820, 560),
        background_color="#15171c" if dark else "#f5f6f8",
        text_select=True,
    )
    pump.attach(window)
    api._window = window
    if selftest:
        api._selftest = selftest
        selftest.start(window)
    _expose_bridge(window, api, extra=("self_test_report",) if selftest else ())
    _lock_navigation(window, page_url)

    if sys.platform == "darwin":
        _macos_app_identity()
        from keymelier_core.menubar import MenuBar
        menubar = MenuBar(service, window, STATIC_DIR / "menubar.png")
        menubar.start()
        api._menubar = menubar

    try:
        webview.start(background_start, debug="--debug" in sys.argv,
                      gui="qt" if sys.platform.startswith("linux") else None)
    finally:
        if remove_page:
            remove_page()
    service._sync_flush()
    scanner.stop()
    logger.info("Window closed, exiting.")
    if selftest:
        sys.exit(selftest.exit_code())



if __name__ == "__main__":
    main()
