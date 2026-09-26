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

logger = logging.getLogger(__name__)

ADVISORY_URL = "https://raw.githubusercontent.com/FiraSenax/KeyMelier/main/data/advisories.json"
SIGNATURE_URL = ADVISORY_URL + ".sig"
CACHE_DIR = Path.home() / ".keymelier"
CACHE_FILE = CACHE_DIR / "advisories.json"
CACHE_SIG = CACHE_DIR / "advisories.json.sig"

# Ed25519 public key (raw, base64) of the advisory signing key
PUBLIC_KEY_B64 = "ggYXnLxwx1iO6YQlNOG7fP0IpqbK7s8HZsiIayMikJQ="


def verify(data: bytes, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))
        key.verify(base64.b64decode(signature_b64.strip()), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def _parse(data: bytes) -> dict | None:
    try:
        doc = json.loads(data.decode("utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("advisories"), list) and doc.get("updated"):
            datetime.fromisoformat(doc["updated"].replace("Z", "+00:00"))
            return doc
    except Exception:
        pass
    return None


def _updated(doc: dict) -> datetime:
    return datetime.fromisoformat(doc["updated"].replace("Z", "+00:00"))


def _read_signed(path: Path, sig_path: Path) -> dict | None:
    try:
        data = path.read_bytes()
        sig = sig_path.read_text(encoding="ascii")
    except OSError:
        return None
    if not verify(data, sig):
        logger.warning("Ignoring %s: signature invalid", path)
        return None
    return _parse(data)


def load_best(bundled_dir: Path) -> tuple[dict | None, str]:
    """Return (document, source) of the newest valid advisory file.

    Source is "downloaded" or "bundled". The bundled file ships inside the
    app; it is used even without a valid signature (e.g. during development).
    """
    best, source = None, "bundled"
    bundled_path = Path(bundled_dir) / "advisories.json"
    try:
        best = _parse(bundled_path.read_bytes())
    except OSError:
        pass
    cached = _read_signed(CACHE_FILE, CACHE_SIG)
    if cached and (best is None or _updated(cached) > _updated(best)):
        best, source = cached, "downloaded"
    return best, source


def fetch(current: dict | None) -> dict | None:
    """Download, verify and cache a newer advisory file. Returns it, or None."""
    import requests

    try:
        data = requests.get(ADVISORY_URL, timeout=15).content
        sig = requests.get(SIGNATURE_URL, timeout=15).text
    except Exception as e:
        logger.info("Advisory update check failed: %s", e)
        return None
    if not verify(data, sig):
        logger.warning("Downloaded advisories rejected: signature invalid")
        return None
    doc = _parse(data)
    if doc is None:
        logger.warning("Downloaded advisories rejected: malformed")
        return None
    if current is not None and _updated(doc) <= _updated(current):
        return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_bytes(data)
    CACHE_SIG.write_text(sig.strip(), encoding="ascii")
    logger.info("Advisory database updated (%s, %d entries)", doc["updated"], len(doc["advisories"]))
    return doc


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
