#!/usr/bin/env python3
"""Sign data/advisories.json for distribution to KeyMelier installations.

    python3 tools/advisories_sign.py keygen          # once: create the signing key
    python3 tools/advisories_sign.py sign            # after editing advisories.json
    python3 tools/advisories_sign.py verify          # check the committed signature

The private key is read from $KEYMELIER_SIGNING_KEY (a PEM file path, or the
PEM itself, e.g. from a GitHub secret) or ~/.config/keymelier/advisory-signing-key.pem.
Never commit it: whoever holds it can change what every KeyMelier reports.
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
ADVISORIES = ROOT / "data" / "advisories.json"
SIGNATURE = ROOT / "data" / "advisories.json.sig"
DEFAULT_KEY = Path.home() / ".config" / "keymelier" / "advisory-signing-key.pem"

sys.path.insert(0, str(ROOT))


def _load_private_key() -> Ed25519PrivateKey:
    value = os.environ.get("KEYMELIER_SIGNING_KEY")
    if value and "BEGIN" in value:
        pem = value.encode()
    else:
        pem = Path(value or DEFAULT_KEY).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def keygen():
    if DEFAULT_KEY.exists():
        sys.exit(f"{DEFAULT_KEY} already exists – refusing to overwrite.")
    key = Ed25519PrivateKey.generate()
    DEFAULT_KEY.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_KEY.touch(mode=0o600)
    DEFAULT_KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"Private key: {DEFAULT_KEY}  (back it up, never commit it)")
    print(f"Public key for fido2tool_core/updates.py PUBLIC_KEY_B64:\n{base64.b64encode(raw).decode()}")


def sign():
    doc = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    doc["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    signature = _load_private_key().sign(data)
    ADVISORIES.write_bytes(data)
    SIGNATURE.write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")
    print(f"Signed {ADVISORIES.name} (updated {doc['updated']}, {len(doc['advisories'])} entries)")
    verify()


def verify():
    from fido2tool_core.updates import verify as check

    ok = check(ADVISORIES.read_bytes(), SIGNATURE.read_text(encoding="ascii"))
    print("Signature valid" if ok else "SIGNATURE INVALID")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    {"keygen": keygen, "sign": sign, "verify": verify}.get(
        sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
