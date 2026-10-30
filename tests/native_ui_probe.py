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

results = {}
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
webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False
webview.settings['ALLOW_DOWNLOADS'] = False


def ping():
    return 'synthetic'


window.expose(ping)


def check():
    faulthandler.dump_traceback_later(15, exit=True)
    try:
        window.evaluate_js('window.pywebview.api.ping().then(value => { document.body.dataset.ping = value; }); undefined')
        for _ in range(30):
            if window.evaluate_js('document.body.dataset.ping') == 'synthetic':
                break
            time.sleep(0.1)
        results['bridge'] = window.evaluate_js('document.body.dataset.ping') == 'synthetic'
        results['scripts'] = window.evaluate_js('typeof STRINGS === "object" && typeof render === "function"') is True
        for check in native_navigation_checks(window):
            results[check['name'].split()[1] + '_blocked'] = check['ok']
        if sys.platform == 'darwin':
            from webview.platforms import cocoa

            def press_default(attempt=0):
                modal = cocoa.AppKit.NSApp.modalWindow()
                if modal is None:
                    if attempt < 20:
                        schedule_default(attempt + 1)
                    return
                cell = modal.defaultButtonCell()
                results['default_cancel'] = str(cell.title()) == window.localization['global.cancel']
                cell.performClick_(None)

            def schedule_default(attempt=0):
                def enqueue():
                    cocoa.Foundation.NSRunLoop.mainRunLoop().performInModes_block_(
                        [cocoa.AppKit.NSModalPanelRunLoopMode, cocoa.Foundation.NSDefaultRunLoopMode],
                        lambda: press_default(attempt))
                threading.Timer(0.3, enqueue).start()

            schedule_default()
            results['cancelled'] = native_ui.confirm(window, 'KeyMelier test', 'Synthetic test. No device operation.') is False
    except Exception as error:
        results['error'] = type(error).__name__
    finally:
        print(json.dumps(results), flush=True)
        window.destroy()


webview.start(check, gui='qt' if sys.platform.startswith('linux') else None)
faulthandler.cancel_dump_traceback_later()
temporary.cleanup()
expected = {'bridge', 'scripts', 'file_blocked', 'data_blocked'}
if sys.platform == 'darwin':
    expected |= {'default_cancel', 'cancelled'}
raise SystemExit(0 if set(results) == expected and all(value is True for value in results.values()) else 1)
