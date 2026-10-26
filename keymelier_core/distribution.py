"""Detect Windows package identity without depending on a Store account."""

import ctypes
import sys


def _package_status() -> int:
    from ctypes import wintypes

    query = ctypes.WinDLL("kernel32", use_last_error=True).GetCurrentPackageFullName
    query.argtypes = [ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
    query.restype = wintypes.LONG
    length = wintypes.UINT(0)
    return query(ctypes.byref(length), None)


def is_msix() -> bool:
    """True for installed/sideloaded MSIX, False for the normal desktop build.

    An unexpected Windows error must not enable the standalone updater.
    Package identity is not evidence of Store approval or trusted signing.
    """
    if sys.platform != "win32":
        return False
    status = _package_status()
    if status == 122:  # ERROR_INSUFFICIENT_BUFFER: a package name exists
        return True
    if status == 15700:  # APPMODEL_ERROR_NO_PACKAGE
        return False
    raise OSError("Windows package identity could not be determined.")
