"""Isolated native WebView probe: no devices, credentials, user files or network."""
import json
import faulthandler
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webview
from keymelier_core import native_ui
from keymelier_core.selftest import native_navigation_checks
from keymelier_core.page import build_html

from native_dialog_checks import dialog_checks, clipboard_checks

results = {}
started = time.monotonic()
loaded = threading.Event()
faulthandler.dump_traceback_later(70, exit=True)
temporary = tempfile.TemporaryDirectory()
page = Path(temporary.name) / 'initial.html'
page.write_text(build_html(), encoding='utf-8')
page_url = page.as_uri() if sys.platform.startswith('linux') else None
window = webview.create_window('KeyMelier security test', url=page_url,
                              html=None if page_url else page.read_text(encoding='utf-8'), width=400, height=250)
native_ui.install(window, page_url)


def trace_windows_navigation(renderer):
    """Synthetic probe diagnostics: distinguish startup from cancelled loads."""
    if renderer != 'edgechromium':
        return
    from webview.platforms import edgechromium
    start = edgechromium.EdgeChrome.on_navigation_start
    finish = edgechromium.EdgeChrome.on_navigation_completed

    def starting(self, sender, args):
        print('navigation starting', str(args.Uri)[:160], self.ishtml, args.NavigationId, flush=True)
        start(self, sender, args)
        print('navigation cancelled', args.Cancel, flush=True)

    def completed(self, sender, args):
        print('navigation completed', args.NavigationId, args.IsSuccess, str(args.WebErrorStatus), flush=True)
        finish(self, sender, args)

    edgechromium.EdgeChrome.on_navigation_start = starting
    edgechromium.EdgeChrome.on_navigation_completed = completed


window.events.initialized += trace_windows_navigation


def page_loaded():
    print(f'page loaded after {time.monotonic() - started:.2f}s', flush=True)
    loaded.set()


window.events.loaded += page_loaded
webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False
webview.settings['ALLOW_DOWNLOADS'] = False


def ping():
    return 'synthetic'


window.expose(ping)


def check():
    try:
        if not loaded.wait(60):
            raise TimeoutError('Native page startup exceeded 60 seconds')
        faulthandler.dump_traceback_later(30, exit=True)
        window.evaluate_js('window.pywebview.api.ping().then(value => { document.body.dataset.ping = value; }); undefined')
        for _ in range(30):
            if window.evaluate_js('document.body.dataset.ping') == 'synthetic':
                break
            time.sleep(0.1)
        results['bridge'] = window.evaluate_js('document.body.dataset.ping') == 'synthetic'
        results['scripts'] = window.evaluate_js('typeof STRINGS === "object" && typeof render === "function"') is True
        for check in native_navigation_checks(window):
            results[check['name'].split()[1] + '_blocked'] = check['ok']
        results.update(dialog_checks(window))
        results.update(clipboard_checks(window))
    except Exception as error:
        results['error'] = type(error).__name__
        import traceback
        traceback.print_exc()
    finally:
        print(json.dumps(results), flush=True)
        window.destroy()


webview.start(check, gui='qt' if sys.platform.startswith('linux') else None)
faulthandler.cancel_dump_traceback_later()
temporary.cleanup()
expected = {'bridge', 'scripts', 'file_blocked', 'data_blocked', 'enter_cancelled'}
if sys.platform == 'darwin':
    expected.add('default_cancel')
else:
    expected |= {'escape_cancelled', 'close_cancelled'}
raise SystemExit(0 if expected <= set(results) and all(value is True for value in results.values()) else 1)
