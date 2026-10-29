"""Release checksums authenticated independently of the download host.

The key is pinned in the installed app, never supplied by the release server.
The signature covers both the exact tag and the checksum file, with a protocol
prefix distinct from advisory signatures. Ed25519 keys have no expiry date.
"""

import base64
import re
from pathlib import Path

from keymelier_core.build_info import ROOT_DIR

PUBLIC_KEY_FILE = ROOT_DIR / 'data' / 'update-public-key.txt'
VERSION_PATTERN = r'v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.([1-9]\d*))?'
SIGNATURE_FILE = 'SHA256SUMS.txt.sig'
MAX_CHECKSUM_BYTES = 128 * 1024
DOMAIN = b'KeyMelier release checksums v1\n'


class SignatureError(ValueError):
    pass


def public_key(path: Path | None = None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        raw = base64.b64decode((path or PUBLIC_KEY_FILE).read_text(encoding='ascii').strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (OSError, UnicodeError, ValueError):
        raise SignatureError('Update verification key is missing or invalid.') from None


def signing_payload(tag: str, checksums: bytes) -> bytes:
    if not isinstance(tag, str) or len(tag) > 64 or not re.fullmatch(VERSION_PATTERN, tag):
        raise SignatureError('Invalid release tag.')
    if not isinstance(checksums, bytes) or not 0 < len(checksums) <= MAX_CHECKSUM_BYTES:
        raise SignatureError('Invalid checksum file size.')
    return DOMAIN + tag.encode('ascii') + b'\n' + checksums


def verify(tag: str, checksums: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    key = public_key()
    payload = signing_payload(tag, checksums)
    try:
        if not isinstance(signature, bytes) or len(signature) > 256:
            raise ValueError('Invalid signature size')
        key.verify(base64.b64decode(signature.strip(), validate=True), payload)
    except (InvalidSignature, ValueError):
        raise SignatureError('Update signature is invalid.') from None
