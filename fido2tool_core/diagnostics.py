"""Privacy-preserving diagnostic report (About → Diagnostic report).

The report is BUILT from an explicit list of fields; every value passes a
type or enumeration filter. Nothing is collected wholesale and cleaned up
afterwards: no log lines, no error messages, no names, serial numbers, paths,
URLs, host names, sync ids or passphrases can enter it, because no field
carries free text. Unknown fields are never copied.

The user sees the exact text before saving; it is only written to a file the
user chooses and never sent anywhere.
"""

import platform
import re
import sys
import threading
from datetime import datetime, timezone

from fido2tool_core.version import __version__

FORMAT = "keymelier-diagnostics"
MAX_ERRORS = 20
_CODE = re.compile(r"[a-z][a-z0-9_]{0,39}")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?(Z|[+-]\d{2}:\d{2})?")
_LANG = re.compile(r"[a-z]{2,3}(-[A-Za-z0-9]{2,8})?")
_DISTRO = re.compile(r"[a-z0-9][a-z0-9._-]{0,30}")
_KERNEL = re.compile(r"\d+(\.\d+){0,3}")
GUIS = {"cocoa", "edgechromium", "qt", "gtk", "winforms", "cef", "mshtml"}
KEYRINGS = {"keyring.backends.macOS", "keyring.backends.Windows", "keyring.backends.SecretService",
            "keyring.backends.libsecret", "keyring.backends.kwallet", "keyring.backends.chainer",
            "keyring.backends.fail"}
SOURCES = {"downloaded", "bundled", "none"}
POLICY_STATES = {"ok", "invalid", "unreachable", "pending"}


def code(value) -> str | None:
    """A machine code such as 'pin_invalid'; anything else becomes 'other'."""
    if value is None:
        return None
    return value if isinstance(value, str) and _CODE.fullmatch(value) else "other"


def enum(value, allowed) -> str | None:
    if value is None:
        return None
    return value if value in allowed else "other"


def count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**9 else None


def flag(value) -> bool | None:
    return value if isinstance(value, bool) else None


def timestamp(value) -> str | None:
    return value if isinstance(value, str) and _ISO.fullmatch(value) else None


def _minute() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


class ErrorLog:
    """Recent failed operations: operation name (from the bridge's fixed list), error code, minute."""

    def __init__(self, operations):
        self._operations = frozenset(operations)
        self._items: list[dict] = []
        self._lock = threading.Lock()
        self.ui_errors = 0   # script errors in the page: counted, never their text

    def record(self, operation, error_code, reason=None):
        item = {"time": _minute(), "operation": enum(operation, self._operations), "code": code(error_code)}
        if reason is not None:
            item["reason"] = code(reason)
        with self._lock:
            self._items = (self._items + [item])[-MAX_ERRORS:]

    def items(self) -> list[dict]:
        with self._lock:
            return list(self._items)


def _distribution() -> str | None:
    """Linux: ID and VERSION_ID of /etc/os-release, e.g. 'ubuntu 24.04'."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        fields = dict(line.split("=", 1) for line in open("/etc/os-release", encoding="utf-8").read().splitlines()
                      if "=" in line)
    except OSError:
        return None
    parts = [fields.get(k, "").strip().strip('"').lower() for k in ("ID", "VERSION_ID")]
    return " ".join(p if _DISTRO.fullmatch(p) else "other" for p in parts if p) or None


def build(*, settings: dict, data_status: dict, sync_status: dict, connected: int, in_history: int,
          keyring: str | None, gui: str | None, errors: ErrorLog | None) -> dict:
    """The report. Each line picks one value and filters it; add fields only here."""
    adv = data_status.get("advisories") or {}
    mds = data_status.get("mds") or {}
    build_state = settings.get("build") or {}
    policy_states: dict[str, int] = {}
    for source in adv.get("policy") or []:
        state = enum(source.get("status") if isinstance(source, dict) else None, POLICY_STATES) or "other"
        policy_states[state] = policy_states.get(state, 0) + 1
    kernel = platform.release().split("-")[0]
    return {
        "format": FORMAT,
        "created": _minute(),
        "app": {
            "version": __version__,
            "build": {"signed": flag(build_state.get("signed")), "notarized": flag(build_state.get("notarized")),
                      "ci": flag(build_state.get("ci"))},
        },
        "system": {
            "platform": enum(sys.platform, {"darwin", "win32", "linux"}),
            "os": enum(platform.system(), {"Darwin", "Windows", "Linux"}),
            "os_release": kernel if _KERNEL.fullmatch(kernel) else "other",
            "distribution": _distribution(),
            "arch": enum(platform.machine().lower(), {"x86_64", "amd64", "arm64", "aarch64"}),
            "python": ".".join(map(str, sys.version_info[:3])),
            "gui": enum(gui, GUIS),
            "keyring": enum(keyring, KEYRINGS),
        },
        "settings": {
            "language": settings.get("lang") if isinstance(settings.get("lang"), str) and _LANG.fullmatch(settings["lang"]) else None,
            "history_enabled": flag(settings.get("history_enabled")),
            "remember_sites": flag(settings.get("remember_sites")),
            "stateless": flag(settings.get("stateless")),
            "onboarding_done": flag(settings.get("onboarding_done")),
        },
        "keys": {"connected": count(connected), "in_history": count(in_history)},
        "sync": {
            "configured": flag(sync_status.get("configured")),
            "active": flag(sync_status.get("active")),
            "problem": code(sync_status.get("problem")),
        },
        "data": {
            "advisories": {"source": enum(adv.get("source"), SOURCES), "updated": timestamp(adv.get("updated")),
                           "count": count(adv.get("count")), "company_sources": policy_states},
            "metadata": {"entries": count(mds.get("entry_count")), "verified": flag(mds.get("verified")),
                         "current": flag(mds.get("current")), "revocation_checked": flag(mds.get("revocation_checked")),
                         "fetched": timestamp(mds.get("fetched_at"))},
            "last_check": timestamp(data_status.get("last_check")),
        },
        "recent_errors": errors.items() if errors else [],
        "ui_script_errors": count(errors.ui_errors) if errors else 0,
    }
