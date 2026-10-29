"""Signed, self-updating advisory database.

The curated advisories.json is published in the GitHub repository together
with an Ed25519 signature (advisories.json.sig). The app fetches both
periodically, verifies the signature against the public key below and only
accepts a document that is newer than what it already has (no rollback to an
older signed file). Anything that fails verification is ignored; the bundled
copy is the fallback, so the app works offline.

Sign with tools/advisories_sign.py; the private key never lives in the repo.
"""

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from keymelier_core.network import read_limited
from keymelier_core.storage import atomic_write, stateless

logger = logging.getLogger(__name__)

ADVISORY_URL = "https://raw.githubusercontent.com/FiraSenax/KeyMelier/main/data/advisories.json"
SIGNATURE_URL = ADVISORY_URL + ".sig"
CACHE_DIR = Path.home() / ".keymelier"
CACHE_FILE = CACHE_DIR / "advisories.json"
CACHE_SIG = CACHE_DIR / "advisories.json.sig"

# Ed25519 public key (raw, base64) of the advisory signing key
PUBLIC_KEY_B64 = "ggYXnLxwx1iO6YQlNOG7fP0IpqbK7s8HZsiIayMikJQ="


def verify(data: bytes, signature_b64: str, public_key_b64: str = PUBLIC_KEY_B64) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64.strip()), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def parse(data: bytes) -> dict | None:
    try:
        doc = json.loads(data.decode("utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("advisories"), list) and doc.get("updated"):
            datetime.fromisoformat(doc["updated"].replace("Z", "+00:00"))
            return doc
    except Exception:
        pass
    return None


def _updated(doc: dict) -> datetime:
    """The document's date; a date or time without zone counts as UTC (comparable either way)."""
    value = datetime.fromisoformat(doc["updated"].replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _read_signed(path: Path, sig_path: Path) -> dict | None:
    try:
        data = path.read_bytes()
        sig = sig_path.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    if not verify(data, sig):
        logger.warning("Ignoring %s: signature invalid", path)
        return None
    return parse(data)


def load_best(bundled_dir: Path) -> tuple[dict | None, str]:
    """Return (document, source) of the newest valid advisory file.

    Source is "downloaded" or "bundled". The bundled file ships inside the
    app; its signature is required just like a downloaded copy.
    """
    source = "bundled"
    best = _read_signed(Path(bundled_dir) / "advisories.json",
                        Path(bundled_dir) / "advisories.json.sig")
    cached = None if stateless() else _read_signed(CACHE_FILE, CACHE_SIG)
    if cached and (best is None or _updated(cached) > _updated(best)):
        best, source = cached, "downloaded"
    return best, source


FRESH_FOR = 45  # days since the maintainer's signed review timestamp


def is_fresh(document: dict | None) -> bool:
    """A positive verdict requires a recent, signed review timestamp.

    Retrieving a valid signature proves authenticity, not freshness: the source
    can replay an old signed document. Network contact must not extend its life.
    """
    from datetime import timedelta
    if document is None:
        return False
    now = datetime.now(timezone.utc)
    try:
        updated = _updated(document)
    except (KeyError, TypeError, AttributeError, ValueError):
        return False
    return now - timedelta(days=FRESH_FOR) < updated <= now + timedelta(days=1)


def fetch(current: dict | None) -> dict | None:
    """Download, verify and cache a newer advisory file. Returns it, or None."""
    import requests

    try:
        with requests.get(ADVISORY_URL, timeout=15, stream=True) as response:
            data = read_limited(response, 4 * 1024 * 1024)
        with requests.get(SIGNATURE_URL, timeout=15, stream=True) as response:
            sig = read_limited(response, 4096).decode("ascii")
    except Exception as e:
        logger.info("Advisory update check failed: %s", type(e).__name__)
        return None
    if not verify(data, sig):
        logger.warning("Downloaded advisories rejected: signature invalid")
        return None
    doc = parse(data)
    if doc is None:
        logger.warning("Downloaded advisories rejected: malformed")
        return None
    if current is not None and _updated(doc) <= _updated(current):
        return None
    if not stateless():
        atomic_write(CACHE_FILE, data)
        atomic_write(CACHE_SIG, sig.strip())
    logger.info("Advisory database updated (%s, %d entries)", doc["updated"], len(doc["advisories"]))
    return doc


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
