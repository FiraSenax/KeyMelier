"""Exercise owned synthetic modal dialogs; never send input to other apps."""
import os
import sys
import threading
import time

from keymelier_core import native_ui


def dialog_checks(window):
    results = {}
    if sys.platform == 'darwin':
        from webview.platforms import cocoa

        def press_default(attempt=0):
            modal = cocoa.AppKit.NSApp.modalWindow()
            if modal is None:
                if attempt < 30:
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
            threading.Timer(0.1, enqueue).start()

        schedule_default()
        results['enter_cancelled'] = native_ui.confirm(window, 'KeyMelier test', 'Synthetic test. No device operation.') is False
        return results

    for action in ('enter', 'escape', 'close'):
        title = f'KeyMelier synthetic {action} {os.getpid()}'
        if sys.platform == 'win32':
            watcher = threading.Thread(target=_windows_press, args=(title, action, results), daemon=True)
            watcher.start()
        else:
            _qt_press(window, action, results)
        results[f'{action}_cancelled'] = native_ui.confirm(window, title, 'Synthetic test. No device operation.') is False
        if sys.platform == 'win32':
            watcher.join(1)
    return results


def _windows_press(title, action, results):
    import ctypes
    from ctypes import wintypes as w
    user = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    for name, args, result in (
            ('EnumWindows', [callback_type, w.LPARAM], w.BOOL),
            ('GetWindowThreadProcessId', [w.HWND, ctypes.POINTER(w.DWORD)], w.DWORD),
            ('GetWindowTextW', [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            ('GetClassNameW', [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            ('SendMessageW', [w.HWND, w.UINT, w.WPARAM, w.LPARAM], ctypes.c_ssize_t),
            ('PostMessageW', [w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL)):
        fn = getattr(user, name)
        fn.argtypes, fn.restype = args, result
    found = []

    @callback_type
    def inspect(hwnd, _):
        process = w.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(process))
        if process.value != os.getpid():
            return True
        caption, kind = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(64)
        user.GetWindowTextW(hwnd, caption, len(caption))
        user.GetClassNameW(hwnd, kind, len(kind))
        if caption.value == title and kind.value == '#32770':
            found.append(hwnd)
            return False
        return True

    for _ in range(80):
        user.EnumWindows(inspect, 0)
        if found:
            hwnd = found[0]
            # DM_GETDEFID, IDCANCEL=2. The high word is DC_HASDEFID.
            default = user.SendMessageW(hwnd, 0x400, 0, 0)
            results[f'{action}_default_cancel'] = default & 0xffff == 2
            if action == 'close':
                user.PostMessageW(hwnd, 0x10, 0, 0)  # WM_CLOSE
            else:
                key = 13 if action == 'enter' else 27
                user.PostMessageW(hwnd, 0x100, key, 0)  # WM_KEYDOWN
                user.PostMessageW(hwnd, 0x101, key, 0)  # WM_KEYUP
            return
        time.sleep(0.1)
    results[f'{action}_found'] = False


def _qt_press(window, action, results):
    from webview.platforms import qt
    from qtpy.QtTest import QTest
    native = qt.BrowserView.instances[window.uid]

    def press(attempt=0):
        modal = qt.QApplication.activeModalWidget()
        if not isinstance(modal, qt.QMessageBox):
            if attempt < 80:
                qt.QtCore.QTimer.singleShot(100, native, lambda: press(attempt + 1))
            else:
                results[f'{action}_found'] = False
            return
        results[f'{action}_default_cancel'] = modal.defaultButton() == modal.button(qt.QMessageBox.Cancel)
        results[f'{action}_escape_cancel'] = modal.escapeButton() == modal.button(qt.QMessageBox.Cancel)
        if action == 'close':
            modal.close()
        else:
            QTest.keyClick(modal, qt.QtCore.Qt.Key_Return if action == 'enter' else qt.QtCore.Qt.Key_Escape)

    qt.QtCore.QTimer.singleShot(100, native, press)


def clipboard_checks(window):
    """Use a private macOS board locally; real clipboard only on disposable CI."""
    from keymelier_core.clipboard import Clipboard, MARKER, _Mac
    if sys.platform != 'darwin' and os.environ.get('CI') != 'true':
        return {}

    def check():
        board = None
        if sys.platform == 'darwin':
            from AppKit import NSPasteboard
            board = NSPasteboard.pasteboardWithUniqueName()
        clipboard = Clipboard(lambda: window, backend=_Mac(board) if board is not None else None)
        try:
            backend = clipboard._backend()
            generation = backend.write('synthetic secret', True)
            if sys.platform == 'darwin':
                hints = all(hint in board.types() for hint in ('org.nspasteboard.ConcealedType', 'org.nspasteboard.TransientType'))
                read = lambda: board.stringForType_(backend.text_type)
            elif sys.platform == 'win32':
                from webview.platforms import winforms
                hints = all(winforms.WinForms.Clipboard.ContainsData(hint) for hint in
                            ('CanIncludeInClipboardHistory', 'CanUploadToCloudClipboard', MARKER))
                read = lambda: str(winforms.WinForms.Clipboard.GetText())
            else:
                hints = bytes(backend.board.mimeData().data('x-kde-passwordManagerHint')) == b'secret'
                read = backend.board.text
            written = read() == 'synthetic secret'
            backend.clear(generation)
            cleared = not read()
            old = backend.write('same text', True)
            new = backend.write('same text', False)
            backend.clear(old)
            preserved = read() == 'same text'
            backend.clear(new)
            return {'clipboard_write': written, 'clipboard_hints': hints, 'clipboard_expiry': cleared,
                    'clipboard_preserves_new_owner': preserved}
        finally:
            if board is not None:
                board.releaseGlobally()

    # Also tests that bridge/timer threads can dispatch to the native GUI thread.
    return native_ui.on_ui(window, check)
