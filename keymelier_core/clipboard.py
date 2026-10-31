"""Native clipboard ownership and best-effort expiry of sensitive copies.

No clipboard contents are retained by the timer. Markers discourage supported
history/cloud managers; they cannot recall copies already read by another app.
macOS/Qt have no atomic compare-and-clear API: ownership is checked immediately
before clearing on the UI thread. Windows checks and clears under OpenClipboard.
"""
import ctypes
import logging
import secrets
import threading

from keymelier_core import native_ui
from keymelier_core.safe_errors import log_failure

logger = logging.getLogger(__name__)
EXPIRY_SECONDS = 30
MARKER = 'org.keymelier.clipboard-owner'


class Clipboard:
    def __init__(self, window, *, backend=None, invoke=None, timer=threading.Timer):
        self.window = window
        self.backend = backend
        self.invoke = invoke or (lambda action: native_ui.on_ui(window(), action))
        self.timer = timer
        self._expiry = None
        self._generation = None

    def _backend(self):
        if self.backend is None:
            renderer = self.window().gui.renderer
            if renderer == 'wkwebview':
                self.backend = _Mac()
            elif renderer == 'edgechromium':
                from webview.platforms import winforms
                native = winforms.BrowserView.instances[self.window().uid]
                self.backend = _Windows(int(native.Handle.ToInt64()))
            elif renderer == 'qtwebengine':
                self.backend = _Qt()
            else:
                raise RuntimeError('Native clipboard unavailable')
        return self.backend

    def copy(self, text, sensitive=False):
        if not isinstance(text, str) or len(text) > 16384 or type(sensitive) is not bool:
            return False

        def write():
            generation = self._backend().write(text, sensitive)
            if self._expiry is not None:
                self._expiry.cancel()
                self._expiry = None
            self._generation = generation if sensitive else None
            if sensitive:
                self._expiry = self.timer(EXPIRY_SECONDS, lambda: self.expire(generation))
                self._expiry.daemon = True
                self._expiry.start()
            return True

        try:
            return self.invoke(write)
        except Exception as error:
            log_failure(logger, 'Clipboard copy', error)
            return False

    def expire(self, generation):
        def clear():
            if generation == self._generation:
                self._backend().clear(generation)
                self._generation = None
                self._expiry = None
        try:
            self.invoke(clear)
        except Exception as error:
            log_failure(logger, 'Clipboard expiry', error)


class _Mac:
    def __init__(self, board=None):
        from AppKit import NSPasteboard, NSPasteboardTypeString
        self.board = board if board is not None else NSPasteboard.generalPasteboard()
        self.text_type = NSPasteboardTypeString

    def write(self, text, sensitive):
        token = secrets.token_hex(16)
        self.board.clearContents()
        if not self.board.setString_forType_(text, self.text_type):
            raise OSError('Clipboard write failed')
        self.board.setString_forType_(token, MARKER)
        if sensitive:
            for hint in ('org.nspasteboard.ConcealedType', 'org.nspasteboard.TransientType'):
                self.board.setString_forType_('', hint)
        return int(self.board.changeCount()), token

    def clear(self, generation):
        count, token = generation
        if (self.board.changeCount() == count and self.board.stringForType_(MARKER) == token
                and self.board.changeCount() == count):
            self.board.clearContents()


class _Qt:
    def __init__(self):
        from webview.platforms import qt
        self.qt = qt
        self.board = qt.QApplication.clipboard()
        self.generation = 0
        self.board.dataChanged.connect(self._changed)

    def _changed(self):
        self.generation += 1

    def write(self, text, sensitive):
        token = secrets.token_hex(16).encode('ascii')
        data = self.qt.QtCore.QMimeData()
        data.setText(text)
        data.setData(MARKER, self.qt.QByteArray(token))
        if sensitive:
            data.setData('x-kde-passwordManagerHint', self.qt.QByteArray(b'secret'))
        self.board.setMimeData(data)
        return self.generation, token

    def clear(self, generation):
        count, token = generation
        if (self.generation == count and self.board.ownsClipboard()
                and bytes(self.board.mimeData().data(MARKER)) == token):
            self.board.clear()


class _Windows:
    """Raw formats, no .NET object serialization; pointers remain 64-bit safe."""
    def __init__(self, hwnd):
        from ctypes import wintypes as w
        self.hwnd = hwnd
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        specs = {
            'OpenClipboard': ([w.HWND], w.BOOL), 'CloseClipboard': ([], w.BOOL),
            'EmptyClipboard': ([], w.BOOL), 'GetClipboardSequenceNumber': ([], w.DWORD),
            'RegisterClipboardFormatW': ([w.LPCWSTR], w.UINT),
            'SetClipboardData': ([w.UINT, w.HANDLE], w.HANDLE),
            'GetClipboardData': ([w.UINT], w.HANDLE),
        }
        for name, (args, result) in specs.items():
            fn = getattr(self.user, name)
            fn.argtypes, fn.restype = args, result
        for name, args, result in (
                ('GlobalAlloc', [w.UINT, ctypes.c_size_t], w.HGLOBAL),
                ('GlobalLock', [w.HGLOBAL], ctypes.c_void_p),
                ('GlobalSize', [w.HGLOBAL], ctypes.c_size_t),
                ('GlobalUnlock', [w.HGLOBAL], w.BOOL),
                ('GlobalFree', [w.HGLOBAL], w.HGLOBAL)):
            fn = getattr(self.kernel, name)
            fn.argtypes, fn.restype = args, result

    def _format(self, name):
        result = self.user.RegisterClipboardFormatW(name)
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def _set(self, kind, data):
        handle = self.kernel.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        if not handle:
            raise MemoryError('Clipboard allocation failed')
        try:
            pointer = self.kernel.GlobalLock(handle)
            if not pointer:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                ctypes.memmove(pointer, data, len(data))
            finally:
                self.kernel.GlobalUnlock(handle)
            if not self.user.SetClipboardData(kind, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.kernel.GlobalFree(handle)
            raise
        # The OS now owns the allocation.

    def write(self, text, sensitive):
        token = secrets.token_bytes(16)
        if not self.user.OpenClipboard(self.hwnd):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.user.EmptyClipboard():
                raise ctypes.WinError(ctypes.get_last_error())
            # Write suppression markers before the secret; consumers see the
            # complete set only after CloseClipboard.
            if sensitive:
                for hint in ('CanIncludeInClipboardHistory', 'CanUploadToCloudClipboard'):
                    self._set(self._format(hint), bytes(4))
            self._set(self._format(MARKER), token)
            self._set(13, (text + '\0').encode('utf-16-le'))  # CF_UNICODETEXT
        finally:
            self.user.CloseClipboard()
        return int(self.user.GetClipboardSequenceNumber()), token

    def clear(self, generation):
        count, token = generation
        if not self.user.OpenClipboard(self.hwnd):
            return  # another app owns the lock; never clear it later blindly
        try:
            if self.user.GetClipboardSequenceNumber() != count:
                return
            handle = self.user.GetClipboardData(self._format(MARKER))
            if not handle or self.kernel.GlobalSize(handle) < 16:
                return
            pointer = self.kernel.GlobalLock(handle) if handle else None
            if not pointer:
                return
            try:
                ours = ctypes.string_at(pointer, 16) == token
            finally:
                self.kernel.GlobalUnlock(handle)
            if ours:
                self.user.EmptyClipboard()
        finally:
            self.user.CloseClipboard()
