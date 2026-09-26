"""KeyMelier desktop app.

Opens a native window (pywebview: WKWebView on macOS, Edge WebView2 on
Windows) with the HTML/JS UI from static/. JavaScript talks to Python
directly through the pywebview bridge; there is no local HTTP server, so
nothing else on the machine (other programs, browser extensions, websites)
can reach the app.
"""

import base64
import json
import logging
import queue
import subprocess
import sys
import threading
from pathlib import Path

# Make the repo root importable regardless of where the script is launched from.
# In a PyInstaller bundle, data files live under sys._MEIPASS.
ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
sys.path.insert(0, str(ROOT_DIR))

import webview

from fido2tool_core.advisories import AdvisoryChecker
from fido2tool_core.exporter import CSVExporter
from fido2tool_core.mds3 import MDS3Client
from fido2tool_core.pin import PinError
from fido2tool_core.scanner import DeviceBusy, DeviceNotFound, TokenScanner
from fido2tool_core.service import KeyService

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

# Service methods the UI may call. Everything else is unreachable from JS.
ALLOWED = {
    "tokens", "mds_status", "data_status", "check_updates",
    "history_list", "history_get", "history_rename", "history_forget",
    "history_set_lost", "history_lost_done",
    "get_settings", "set_settings",
    "pin_status", "pin_update", "attestation_rerun",
    "unlock", "lock",
    "passkeys", "passkey_delete", "passkey_rename",
    "fingerprints", "fingerprint_rename", "fingerprint_delete",
    "fingerprint_enroll", "fingerprint_enroll_cancel",
    "reset_arm", "reset_disarm", "config", "config_update",
    "export_all",
}


# Hosts the UI may open in the external browser (advisory references)
ALLOWED_LINK_HOSTS = {"github.com", "www.yubico.com", "nvd.nist.gov", "fidoalliance.org", "www.ftsafe.com", "www.token2.com"}


class Api:
    """Exposed to JavaScript as window.pywebview.api.

    Every call returns an envelope {ok, data} or {ok: false, error, code,
    status, ...} so the UI gets stable error codes instead of exceptions.
    """

    def __init__(self, service: KeyService):
        self._service = service

    def client_log(self, message):
        logger.info("UI: %s", str(message)[:500])

    def client_error(self, message):
        """JavaScript errors from the page, so they show up in the terminal."""
        logger.error("UI: %s", str(message)[:500])

    def open_url(self, url):
        """Open advisory links in the default browser (never inside the app)."""
        from urllib.parse import urlparse
        parsed = urlparse(str(url))
        if parsed.scheme == "https" and parsed.hostname in ALLOWED_LINK_HOSTS:
            import webbrowser
            webbrowser.open(parsed.geturl())

    def call(self, method, kwargs=None):
        if method not in ALLOWED:
            return {"ok": False, "error": "Unknown method.", "code": "unknown_method", "status": 400}
        try:
            return {"ok": True, "data": getattr(self._service, method)(**(kwargs or {}))}
        except PinError as e:
            logger.warning("%s -> %s", method, e.code)
            return {"ok": False, "error": e.message, "code": e.code, "status": e.status, **e.extra}
        except DeviceBusy:
            return {"ok": False, "error": "The key is busy.", "code": "busy", "status": 409}
        except DeviceNotFound:
            return {"ok": False, "error": "The key is no longer connected.", "code": "not_found", "status": 404}
        except TypeError as e:
            logger.warning("%s: bad arguments (%s)", method, e)
            return {"ok": False, "error": "Invalid request.", "code": "invalid_input", "status": 400}
        except Exception as e:
            logger.exception("%s failed", method)
            return {"ok": False, "error": str(e), "code": "error", "status": 500}


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
                logger.warning("Event delivery failed (%s): %s", name, e)


# ── Page assembly ────────────────────────────────────────────────────────────

def build_html() -> str:
    """Inline CSS, JS and the icon into one document (no server, no file URLs)."""
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    css = (STATIC_DIR / "style.css").read_text(encoding="utf-8")
    icon = base64.b64encode((STATIC_DIR / "icon.svg").read_bytes()).decode()
    html = html.replace('<link rel="stylesheet" href="style.css">', f"<style>\n{css}\n</style>")
    html = html.replace('src="icon.svg"', f'src="data:image/svg+xml;base64,{icon}"')
    for name in ("i18n.js", "app.js"):
        js = (STATIC_DIR / name).read_text(encoding="utf-8").replace("</script", "<\\/script")
        html = html.replace(f'<script src="{name}"></script>', f"<script>\n{js}\n</script>")
    return html


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
        logger.debug("Could not set macOS app identity: %s", e)


def _single_instance():
    """Return a held lock file, or None if another KeyMelier is already running."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
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
    from fido2tool_core.version import __version__
    logger.info("KeyMelier %s", __version__)
    lock = _single_instance()
    if lock is None:
        logger.error("KeyMelier is already running.")
        sys.exit(1)

    mds3 = MDS3Client()
    advisories = AdvisoryChecker(DATA_DIR)
    scanner = TokenScanner(
        poll_interval=1.0,
        mds3_client=mds3,
        advisory_checker=advisories,
    )
    service = KeyService(scanner, CSVExporter(), mds3_client=mds3, advisories=advisories)
    pump = EventPump()
    service.emit = pump.emit

    def background_start():
        # Metadata first (downloads on first run, then cached 24h) so the
        # scanner can enrich keys; the window is already visible meanwhile.
        logger.info("Loading FIDO Alliance MDS3 metadata...")
        try:
            mds3.ensure_loaded()
        except Exception as e:
            logger.warning("MDS3 unavailable: %s", e)
        pump.emit("mds_ready", service.mds_status())
        threading.Thread(target=scanner.run_forever, daemon=True, name="fido2-scanner").start()
        threading.Thread(target=service.run_update_loop, daemon=True, name="updates").start()

    dark = sys.platform == "darwin" and _macos_dark_mode()
    window = webview.create_window(
        "KeyMelier",
        html=build_html(),
        js_api=Api(service),
        width=1180,
        height=780,
        min_size=(820, 560),
        background_color="#15171c" if dark else "#f5f6f8",
        text_select=True,
    )
    pump.attach(window)

    if sys.platform == "darwin":
        _macos_app_identity()

    webview.start(background_start, debug="--debug" in sys.argv)
    scanner.stop()
    logger.info("Window closed, exiting.")



if __name__ == "__main__":
    main()
