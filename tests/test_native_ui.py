"""Native adapters cancel before load; mocks exercise the backend callback contracts."""
import unittest
import base64
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from keymelier_core import native_ui


class NativeNavigationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform in ('darwin', 'win32'), 'native desktop session required')
    def test_native_desktop_startup_and_navigation(self):
        probe = Path(__file__).with_name('native_ui_probe.py')
        result = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"scripts": true', result.stdout)
        if sys.platform == 'darwin':
            self.assertIn('"default_cancel": true', result.stdout)

    def test_only_the_first_exact_main_document_can_load(self):
        policy = native_ui.NavigationPolicy()
        for url in ('data:text/html,hello', 'https://example.invalid/', 'http://[', 'file:///etc/passwd',
                    'about:blank#other', 'about:blank?other', None):
            self.assertFalse(policy.allow(url))
        self.assertFalse(policy.allow('about:blank', main=False))
        self.assertTrue(policy.allow('about:blank'))
        self.assertFalse(policy.allow('about:blank'))

    def test_private_file_matches_qt_decoding_but_no_other_file_or_replay(self):
        policy = native_ui.NavigationPolicy('file:///run/user/1000/keymelier-a%20b/keymelier.html')
        self.assertFalse(policy.allow('file:///run/user/1000/other.html'))
        self.assertFalse(policy.allow('file://remote/run/user/1000/keymelier-a%20b/keymelier.html'))
        self.assertTrue(policy.allow('file:///run/user/1000/keymelier-a b/keymelier.html'))
        self.assertFalse(policy.allow('file:///run/user/1000/keymelier-a b/keymelier.html'))

    def test_webview2_data_url_is_bound_to_exact_backend_html_and_single_use(self):
        html = '<html><body>Trusted app ä</body></html>'
        own = 'data:text/html;charset=utf-8;base64,' + base64.b64encode(html.encode()).decode()
        policy = native_ui.NavigationPolicy(html=html)
        self.assertFalse(policy.allow('data:text/html;charset=utf-8;base64,Zm9yZWlnbg=='))
        self.assertFalse(policy.allow(own + '#extra'))
        self.assertFalse(policy.allow(own, main=False))
        self.assertTrue(policy.allow(own))
        self.assertFalse(policy.allow(own))
        self.assertFalse(policy.allow('about:blank'))
        self.assertFalse(native_ui.NavigationPolicy().allow(own))
        older_runtime = native_ui.NavigationPolicy(html=html)
        self.assertTrue(older_runtime.allow('about:blank'))
        self.assertFalse(older_runtime.allow(own))

    def test_edge_cancels_navigation_and_handles_popups(self):
        original, completed = Mock(), Mock()
        edge = SimpleNamespace(EdgeChrome=type('Edge', (), {'on_navigation_start': original,
                                                          'on_navigation_completed': completed}))
        with patch.dict('sys.modules', {'webview.platforms.edgechromium': edge}), \
             patch('webview.platforms.edgechromium', edge, create=True):
            native_ui._edge(native_ui.NavigationPolicy())
        view = edge.EdgeChrome()
        view.ishtml = False
        bootstrap = SimpleNamespace(Uri='about:blank', Cancel=False, NavigationId=1)
        view.on_navigation_start(None, bootstrap)
        self.assertTrue(bootstrap.Cancel)
        view.on_navigation_completed(None, SimpleNamespace(IsSuccess=False, NavigationId=1))
        completed.assert_not_called()
        view.ishtml = True
        event = SimpleNamespace(Uri='about:blank', Cancel=False, NavigationId=2)
        view.on_navigation_start(None, event)
        self.assertFalse(event.Cancel)
        original.assert_called_once()
        view.on_navigation_completed(None, SimpleNamespace(IsSuccess=True, NavigationId=2))
        completed.assert_called_once()
        completed.reset_mock()
        for url in ('about:blank', 'https://example.invalid/', 'data:text/html,foreign'):
            event = SimpleNamespace(Uri=url, Cancel=False)
            view.on_navigation_start(None, event)
            self.assertTrue(event.Cancel)
        view.on_navigation_completed(None, SimpleNamespace(IsSuccess=False, NavigationId=3))
        view.on_navigation_completed(None, SimpleNamespace(IsSuccess=True, NavigationId=3))
        completed.assert_not_called()
        popup = SimpleNamespace(Handled=False)
        view.on_new_window_request(None, popup)
        self.assertTrue(popup.Handled)

    def test_cocoa_cancels_before_calling_the_decision_handler(self):
        cocoa = SimpleNamespace(BrowserView=SimpleNamespace(BrowserDelegate=object))
        with patch.dict('sys.modules', {'webview.platforms.cocoa': cocoa}), \
             patch('webview.platforms.cocoa', cocoa, create=True):
            native_ui._cocoa(native_ui.NavigationPolicy())
        view = cocoa.BrowserView.BrowserDelegate()
        action, handler = Mock(), Mock()
        action.targetFrame.return_value.isMainFrame.return_value = True
        action.request.return_value.URL.return_value.absoluteString.return_value = 'about:blank'
        view.webView_decidePolicyForNavigationAction_decisionHandler_(None, action, handler)
        handler.assert_called_once_with(1)
        handler.reset_mock()
        action.request.return_value.URL.return_value.absoluteString.return_value = 'data:text/html,foreign'
        view.webView_decidePolicyForNavigationAction_decisionHandler_(None, action, handler)
        handler.assert_called_once_with(0)
        self.assertIsNone(view.webView_createWebViewWithConfiguration_forNavigationAction_windowFeatures_(None, None, None, None))

    def test_qt_cancels_navigation_and_no_popup_page_is_created(self):
        qt = SimpleNamespace(BrowserView=type('Browser', (), {'WebPage': type('Page', (), {})}))
        with patch.dict('sys.modules', {'webview.platforms.qt': qt}), patch('webview.platforms.qt', qt, create=True):
            native_ui._qt(native_ui.NavigationPolicy('file:///synthetic/keymelier.html'))
        page = qt.BrowserView.WebPage()
        url = SimpleNamespace(toString=lambda: 'file:///synthetic/keymelier.html')
        self.assertTrue(page.acceptNavigationRequest(url, 0, True))
        self.assertFalse(page.acceptNavigationRequest(url, 0, True))
        self.assertIsNone(page.createWindow(0))

    def test_unknown_backend_aborts_window_creation_and_dialog_fails_closed(self):
        from webview.event import Event
        window = SimpleNamespace(events=SimpleNamespace(), gui=SimpleNamespace(renderer='unknown'))
        window.events.initialized = Event(window, True)
        native_ui.install(window)
        with self.assertLogs('keymelier_core.native_ui', level='ERROR'):
            self.assertTrue(window.events.initialized.set('unknown'))
        self.assertFalse(native_ui.confirm(window, 'title', 'message'))
        self.assertFalse(native_ui.confirm(None, 'title', 'message'))
