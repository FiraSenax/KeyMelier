"""Native-picker imports and deterministic discovery of a host GnuPG install."""
import os
import stat
import sys
from pathlib import Path

MAX_IMPORT = 20_000_000


def _executable(path):
    path = Path(path)
    if not path.is_absolute() or path.parent == Path.cwd():
        return None
    try:
        resolved = path.resolve(strict=True)
        if resolved.parent == Path.cwd().resolve() or not resolved.is_file() or not os.access(resolved, os.X_OK):
            return None
        if os.name != "nt" and any(p.stat().st_mode & stat.S_IWOTH
                                   for p in (resolved, *resolved.parents)):
            return None
        return str(resolved)
    except (OSError, RuntimeError):
        return None


def gpg_path():
    if sys.platform == "win32":
        candidates = [r"C:\Program Files\GnuPG\bin\gpg.exe",
                      r"C:\Program Files (x86)\GnuPG\bin\gpg.exe"]
        names = ("gpg.exe", "gpg2.exe")
    elif sys.platform == "darwin":
        candidates = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg2"]
        names = ("gpg", "gpg2")
    else:
        candidates = ["/usr/bin/gpg", "/usr/bin/gpg2", "/usr/local/bin/gpg"]
        names = ("gpg", "gpg2")
    # Explicit absolute PATH entries keep custom installations working, without
    # shutil.which's current-directory/relative-directory search on Windows.
    folders = [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep)
               if p and Path(p).is_absolute() and Path(p) != Path.cwd()]
    for candidate in [*candidates, *(folder / name for name in names for folder in folders)]:
        found = _executable(candidate)
        if found:
            return found
    return None


def read_import(path):
    """Preserve the successful string/None API; report failures explicitly."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError("Not a regular file")
            raw = stream.read(MAX_IMPORT + 1)
        if len(raw) > MAX_IMPORT:
            return {"ok": False, "code": "history_too_large", "error": "The file is too large (maximum 20 MB)."}
        return raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        return {"ok": False, "code": "history_encoding", "error": "The file must contain valid UTF-8 text."}
    except OSError:
        return {"ok": False, "code": "history_invalid", "error": "The selected file could not be read."}
