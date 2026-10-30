"""Native navigation and confirmation adapters for the pinned pywebview backends.

Install during `initialized`, before backend widgets load the first document.
Never use a loaded-event redirect as an authorization boundary.
"""
import logging
import threading
from urllib.parse import unquote, urlsplit

from keymelier_core.safe_errors import log_failure

logger = logging.getLogger(__name__)


class NavigationPolicy:
    def __init__(self, page_url=None):
        self.expected = self._canonical(page_url or "about:blank")
        self._initial = True
        self._lock = threading.Lock()

    @staticmethod
    def _canonical(url):
        if not isinstance(url, str) or any(ord(c) < 32 for c in url):
            return None
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if parts.query or parts.fragment or parts.username or parts.password:
            return None
        if url == "about:blank":
            return url
        if parts.scheme == "file" and not parts.netloc:
            return "file:" + unquote(parts.path)
        return None

    def allow(self, url, main=True):
        with self._lock:
            if main and self._initial and self.expected is not None and self._canonical(url) == self.expected:
                self._initial = False
                return True
            return False


def install(window, page_url=None):
    policy = NavigationPolicy(page_url)

    def initialized(renderer):
        try:
            if renderer == "wkwebview":
                _cocoa(policy)
            elif renderer == "edgechromium":
                _edge(policy)
            elif renderer == "qtwebengine":
                _qt(policy)
            else:
                raise RuntimeError("Unsupported native navigation backend")
        except Exception as error:
            log_failure(logger, "Native navigation setup", error)
            return False  # pywebview cancels window creation
        return True

    window.events.initialized += initialized
    return policy


def _cocoa(policy):
    from webview.platforms import cocoa

    class KeyMelierBrowserDelegate(cocoa.BrowserView.BrowserDelegate):
        def webView_decidePolicyForNavigationAction_decisionHandler_(self, webview, action, handler):
            try:
                frame = action.targetFrame()
                allowed = policy.allow(str(action.request().URL().absoluteString()),
                                       frame is not None and frame.isMainFrame())
            except Exception:
                allowed = False
            handler(1 if allowed else 0)  # WKNavigationActionPolicyAllow / Cancel

        def webView_createWebViewWithConfiguration_forNavigationAction_windowFeatures_(self, view, config, action, features):
            return None

    cocoa.BrowserView.BrowserDelegate = KeyMelierBrowserDelegate


def _edge(policy):
    from webview.platforms import edgechromium
    original = edgechromium.EdgeChrome.on_navigation_start
    completed = edgechromium.EdgeChrome.on_navigation_completed

    def navigate(self, sender, args):
        args.Cancel = True
        # WebView2 can navigate its empty bootstrap document before loading our
        # HTML. Only the backend's actual HTML request may consume the one permit.
        if not self.ishtml:
            return
        if not policy.allow(str(args.Uri)):
            return
        self._keymelier_navigation_id = args.NavigationId
        original(self, sender, args)
        args.Cancel = False

    def finish(self, sender, args):
        # pywebview otherwise injects its bridge and emits loaded even for a
        # cancelled navigation, replacing callbacks in the surviving document.
        if args.IsSuccess and args.NavigationId == getattr(self, '_keymelier_navigation_id', None):
            completed(self, sender, args)

    def popup(self, sender, args):
        args.Handled = True

    edgechromium.EdgeChrome.on_navigation_start = navigate
    edgechromium.EdgeChrome.on_navigation_completed = finish
    edgechromium.EdgeChrome.on_new_window_request = popup


def _qt(policy):
    from webview.platforms import qt

    def navigate(self, url, kind, main):
        return policy.allow(url.toString(), main)

    def confirm(self, title, message, ident):
        result = self._confirmation_dialog_results[qt.BrowserView._convert_string(ident)]
        result['result'] = False
        try:
            dialog = qt.QMessageBox(self)
            dialog.setWindowTitle(title)
            dialog.setTextFormat(qt.QtCore.Qt.PlainText)
            dialog.setText(message)
            dialog.setStandardButtons(qt.QMessageBox.Ok | qt.QMessageBox.Cancel)
            dialog.setDefaultButton(qt.QMessageBox.Cancel)
            dialog.setEscapeButton(qt.QMessageBox.Cancel)
            result['result'] = dialog.exec() == qt.QMessageBox.Ok
        except Exception as error:
            log_failure(logger, "Native confirmation", error)
        finally:
            result['semaphore'].release()

    qt.BrowserView.WebPage.acceptNavigationRequest = navigate
    qt.BrowserView.WebPage.createWindow = lambda *_: None
    qt.BrowserView.on_confirmation_dialog = confirm


def confirm(window, title, message):
    """The default button and Escape cancel. No HTML/JS supplies the decision."""
    if window is None:
        return False
    renderer = getattr(window.gui, "renderer", None)
    if renderer == "wkwebview":
        from webview.platforms import cocoa
        done, result = threading.Event(), [False]

        def show():
            try:
                alert = cocoa.AppKit.NSAlert.alloc().init()
                alert.setMessageText_(title)
                alert.setInformativeText_(message)
                cancel = alert.addButtonWithTitle_(window.localization['global.cancel'])
                cancel.setKeyEquivalent_("\r")
                proceed = alert.addButtonWithTitle_(window.localization['global.ok'])
                proceed.setKeyEquivalent_("")
                alert.window().setDefaultButtonCell_(cancel.cell())
                result[0] = alert.runModal() == cocoa.AppKit.NSAlertSecondButtonReturn
            except Exception as error:
                log_failure(logger, "Native confirmation", error)
            finally:
                done.set()

        cocoa.AppHelper.callAfter(show)
        done.wait()
        return result[0]
    if renderer == "edgechromium":
        from webview.platforms import winforms
        from System import Boolean
        native = winforms.BrowserView.instances.get(window.uid)
        if native is None:
            return False

        def show():
            forms = winforms.WinForms
            return forms.MessageBox.Show(native, message, title, forms.MessageBoxButtons.OKCancel,
                                         forms.MessageBoxIcon.Warning, forms.MessageBoxDefaultButton.Button2
                                         ) == forms.DialogResult.OK

        return bool(native.Invoke(winforms.Func[Boolean](show))) if native.InvokeRequired else show()
    if renderer == "qtwebengine":
        return window.create_confirmation_dialog(title, message) is True
    return False
