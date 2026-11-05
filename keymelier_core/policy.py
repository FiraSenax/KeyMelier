"""Machine-wide managed configuration (set by an administrator, never in the UI).

Read only from places a normal user cannot write:

    Windows  HKLM\\SOFTWARE\\Policies\\KeyMelier          (Group Policy / Intune)
    macOS    /Library/Managed Preferences/com.keymelier.app.plist   (MDM profile)
    Linux    /etc/keymelier/policy.json

On macOS and Linux the file must belong to root and must not be writable by
group or others; otherwise it is ignored. The user's own registry hive
(HKCU) and user preferences are deliberately not read.

Supported today: additional advisory sources (see ENTERPRISE.md).

    AdvisorySources: [{Name, Location, PublicKey}, ...]

Location is an https:// URL or an absolute file path; the Ed25519 signature
is expected next to it (Location + ".sig"). PublicKey is the raw public key,
base64. Invalid entries are skipped and logged; incomplete configuration also
prevents a successful assessment and is surfaced separately in the UI.
"""

import base64
import json
import logging
import sys
from pathlib import Path
from urllib.parse import urlsplit

from keymelier_core.advisories import clean_text

logger = logging.getLogger(__name__)

MAC_PLIST = Path("/Library/Managed Preferences/com.keymelier.app.plist")
LINUX_JSON = Path("/etc/keymelier/policy.json")
WIN_KEY = r"SOFTWARE\Policies\KeyMelier"
MAX_SOURCES = 10
MAX_NAME = 64


class PolicyRead(dict):
    """Keep the legacy mapping contract while retaining incomplete reads."""

    def __init__(self, *args, failed=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.failed = failed


def _protected(path: Path) -> bool:
    """Owned by root and not writable by group/others (POSIX only)."""
    try:
        st = path.stat()
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def _read_mac(path: Path = MAC_PLIST) -> dict:
    import plistlib

    try:
        path.stat()
    except FileNotFoundError:
        return {}
    except OSError:
        return PolicyRead(failed=True)
    if not _protected(path):
        logger.warning("Ignoring %s: not owned by root or writable by others", path)
        return PolicyRead(failed=True)
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
        return data if isinstance(data, dict) else PolicyRead(failed=True)
    except Exception as e:
        logger.warning("Ignoring %s: %s", path, type(e).__name__)
        return PolicyRead(failed=True)


def _read_linux(path: Path = LINUX_JSON) -> dict:
    try:
        path.stat()
    except FileNotFoundError:
        return {}
    except OSError:
        return PolicyRead(failed=True)
    if not _protected(path):
        logger.warning("Ignoring %s: not owned by root or writable by others", path)
        return PolicyRead(failed=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else PolicyRead(failed=True)
    except Exception as e:
        logger.warning("Ignoring %s: %s", path, type(e).__name__)
        return PolicyRead(failed=True)


def _read_windows() -> dict:
    """HKLM\\SOFTWARE\\Policies\\KeyMelier\\AdvisorySources\\<Name> with Location and PublicKey."""
    import winreg

    sources = []
    failed = False
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_KEY + r"\AdvisorySources")
    except FileNotFoundError:
        return {}
    except OSError:
        return PolicyRead(failed=True)
    with root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError as e:
                if getattr(e, "winerror", None) != 259:  # ERROR_NO_MORE_ITEMS
                    failed = True
                break
            i += 1
            try:
                with winreg.OpenKey(root, name) as sub:
                    entry = {"Name": name}
                    for value in ("Location", "PublicKey"):
                        try:
                            entry[value] = winreg.QueryValueEx(sub, value)[0]
                        except OSError:
                            pass
                    sources.append(entry)
            except OSError as e:
                failed = True
                logger.warning("Ignoring policy source %s: %s", name, type(e).__name__)
    return PolicyRead({"AdvisorySources": sources}, failed=failed)


def read_raw() -> dict:
    """The managed configuration of this platform – from the protected locations only.

    There is deliberately no switch (environment variable, argument, user file)
    to read it from elsewhere: whoever could set it could replace or hide the
    organisation's sources. Tests mock the platform readers instead.
    """
    try:
        if sys.platform == "win32":
            return _read_windows()
        if sys.platform == "darwin":
            return _read_mac()
        return _read_linux()
    except Exception as e:
        logger.warning("Managed configuration not readable: %s", type(e).__name__)
        return PolicyRead(failed=True)


def _valid_key(value) -> bool:
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def _valid_location(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("https://"):
        try:
            url = urlsplit(value)
            return bool(url.hostname) and not url.username and not url.password and url.port != 0
        except ValueError:
            return False
    if "://" in value:
        return False   # only https for remote sources
    return Path(value).is_absolute()


def advisory_sources(raw: dict | None = None) -> list[dict]:
    """Validated [{name, location, public_key}] from the managed configuration."""
    return advisory_configuration(raw)[0]


def advisory_configuration(raw: dict | None = None) -> tuple[list[dict], bool]:
    """Return usable sources and whether any configured input was rejected."""
    raw = read_raw() if raw is None else raw
    failed = bool(getattr(raw, "failed", False))
    if not isinstance(raw, dict):
        return [], True
    if "AdvisorySources" not in raw:
        return [], failed
    entries = raw.get("AdvisorySources") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        return [], True
    result, names = [], set()
    for e in entries:
        if len(result) >= MAX_SOURCES:
            failed = True
            logger.warning("Only the first %d advisory sources are used", MAX_SOURCES)
            break
        if not isinstance(e, dict):
            failed = True
            continue
        name = clean_text(e.get("Name"), MAX_NAME) or ""
        if not name or name in names:
            failed = True
            logger.warning("Ignoring advisory source without a unique name")
            continue
        if not _valid_location(e.get("Location")) or clean_text(e.get("Location"), 2000) != e.get("Location"):
            failed = True
            logger.warning("Ignoring advisory source %s: Location must be https:// or an absolute path", name)
            continue
        if not _valid_key(e.get("PublicKey")):
            failed = True
            logger.warning("Ignoring advisory source %s: PublicKey must be a base64 Ed25519 public key", name)
            continue
        names.add(name)
        result.append({"name": name, "location": e["Location"], "public_key": e["PublicKey"]})
    if result:
        logger.info("Managed advisory sources: %s", ", ".join(s["name"] for s in result))
    return result, failed
