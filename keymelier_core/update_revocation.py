"""Best-effort repository emergency stop, never a source of trusted new keys.

Only SHA-256 hashes of raw public keys are accepted. Observed revocations are
sticky across checks and restarts; a missing/older remote list cannot undo them.
The repository can withhold a revocation before its first observation. This is
not independent compromise recovery or a substitute for update signatures.
"""

import hashlib
import json
import logging
from pathlib import Path
import re
import threading

from keymelier_core.build_info import ROOT_DIR
from keymelier_core.network import bounded_get, read_limited
from keymelier_core.storage import atomic_write, stateless

BUNDLED = ROOT_DIR / 'data' / 'revoked-update-keys.json'
CACHE = Path.home() / '.keymelier' / 'revoked-update-keys.json'
URL = 'https://raw.githubusercontent.com/FiraSenax/KeyMelier/main/data/revoked-update-keys.json'
MAX_BYTES = 64 * 1024
_seen: set[str] = set()
_lock = threading.Lock()
logger = logging.getLogger(__name__)


class RevokedKeyError(ValueError):
    pass


class RevocationStateError(ValueError):
    """Local revocation evidence cannot be read; never discard it to recover."""


def fingerprint() -> str:
    from keymelier_core.update_auth import public_key
    return hashlib.sha256(public_key().public_bytes_raw()).hexdigest()


def parse(data: bytes) -> set[str]:
    if len(data) > MAX_BYTES:
        raise ValueError('Revocation list is too large.')
    doc = json.loads(data)
    if not isinstance(doc, dict) or type(doc.get('version')) is not int or doc['version'] != 1:
        raise ValueError('Invalid revocation list version.')
    revoked = doc.get('revoked')
    if not isinstance(revoked, list) or len(revoked) > 256 or any(
            not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value) for value in revoked):
        raise ValueError('Invalid public-key fingerprints.')
    return set(revoked)


def _read(path: Path, *, optional=False) -> set[str]:
    try:
        with path.open('rb') as stream:
            return parse(stream.read(MAX_BYTES + 1))
    except FileNotFoundError:
        if optional:
            return set()
        raise RevocationStateError('Local update revocation data is missing.') from None
    except (OSError, ValueError, RecursionError):
        raise RevocationStateError('Local update revocation data is unreadable.') from None


def _remember(values: set[str]) -> None:
    """Called under _lock; persist additions before reporting a revoked key."""
    key = fingerprint()
    marker = CACHE.with_name('revoked-update-key-' + key)
    if key in _seen or (not stateless() and marker.exists()):
        raise RevokedKeyError('Update signing key has been revoked.')
    saved = set() if stateless() else _read(CACHE, optional=True)
    _seen.update(saved | values)
    if not stateless() and marker.exists():
        _seen.add(key)
    if len(_seen) > 256:
        raise ValueError('Too many revoked update keys.')
    if key in _seen and not stateless() and not marker.exists():
        # Separate monotonic marker for this installed key: concurrent app
        # processes rewriting the aggregate cache cannot lose its revocation.
        atomic_write(marker, key + '\n')
    if _seen != saved and not stateless():
        atomic_write(CACHE, json.dumps({'version': 1, 'revoked': sorted(_seen)}) + '\n')
    if key in _seen:
        raise RevokedKeyError('Update signing key has been revoked.')


def ensure_allowed(*, refresh=False) -> None:
    """Block a revoked key even offline; invalid local state fails closed.

    Remote failures leave the known state intact. The list is an additional
    deny-only signal, so an unavailable endpoint cannot grant new authority.
    """
    with _lock:
        _remember(_read(BUNDLED))
    if not refresh:
        return
    try:
        with bounded_get(URL, timeout=10, stream=True) as response:
            remote = parse(read_limited(response, MAX_BYTES))
    except Exception as error:
        logger.info('Update revocation check unavailable: %s', type(error).__name__)
        return
    with _lock:
        # Re-read under the lock before merging; remote lists can only add.
        _remember(remote)
