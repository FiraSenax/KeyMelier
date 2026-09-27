"""Starting desktop programs (browser, file manager, clipboard, gpg).

In the Linux AppImage the process runs with the bundled Qt and libraries on
LD_LIBRARY_PATH; programs of the host must not inherit that, or they load
the wrong libraries. PyInstaller keeps the original value as *_ORIG.
"""

import logging
import os
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)

_BUNDLE_VARS = ("LD_LIBRARY_PATH", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QTWEBENGINEPROCESS_PATH",
                "QTWEBENGINE_RESOURCES_PATH", "QTWEBENGINE_LOCALES_PATH", "QT_API")


def host_env() -> dict | None:
    """Environment for host programs; None (inherit) outside a frozen Linux build."""
    if not (sys.platform.startswith("linux") and getattr(sys, "frozen", False)):
        return None
    env = dict(os.environ)
    for var in _BUNDLE_VARS:
        orig = env.pop(var + "_ORIG", None)
        env.pop(var, None)
        if orig:
            env[var] = orig
    return env


def open_with_system(target: str) -> bool:
    """Open a URL or file with the desktop's default program (Linux: xdg-open)."""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", target])
        elif sys.platform == "win32":
            os.startfile(target)  # noqa: S606 – callers pass fixed files or checked URLs
        else:
            subprocess.Popen(["xdg-open", target], env=host_env(),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except Exception as e:
        logger.info("Could not open %s: %s", target, e)
        return False


def linux_copy(text: str) -> bool:
    """Clipboard on Linux: wl-copy (Wayland) or xclip/xsel (X11), whichever exists."""
    candidates = [["wl-copy"]] if os.environ.get("WAYLAND_DISPLAY") else []
    candidates += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for cmd in candidates:
        if shutil.which(cmd[0]):
            subprocess.run(cmd, input=text.encode(), check=True, timeout=5, env=host_env())
            return True
    logger.info("No clipboard tool found (wl-copy, xclip or xsel)")
    return False


def private_page_file(html: str):
    """Write the app page to a file only this user can read; returns (path, cleanup).

    Linux only: Qt WebEngine cannot show documents over 2 MB through setHtml
    (a data: URL), so the page is loaded from this file instead. The folder is
    in $XDG_RUNTIME_DIR (a per-user tmpfs) when available and removed on exit.
    """
    import tempfile
    from pathlib import Path

    base = os.environ.get("XDG_RUNTIME_DIR")
    folder = Path(tempfile.mkdtemp(prefix="keymelier-", dir=base if base and os.path.isdir(base) else None))
    path = folder / "keymelier.html"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html)
    return path, lambda: shutil.rmtree(folder, ignore_errors=True)
