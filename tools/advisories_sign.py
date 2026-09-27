#!/usr/bin/env python3
"""Sign data/advisories.json for distribution to KeyMelier installations.

    python3 tools/advisories_sign.py keygen          # once: create the signing key
    python3 tools/advisories_sign.py sign            # after editing advisories.json
    python3 tools/advisories_sign.py verify          # check the committed signature

Company advisory sources (ENTERPRISE.md) use the same format with their own key:

    python3 tools/advisories_sign.py keygen KEYFILE
    KEYMELIER_SIGNING_KEY=KEYFILE python3 tools/advisories_sign.py sign FILE
    python3 tools/advisories_sign.py verify FILE PUBLICKEY

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


def _arg(i: int, default=None):
    return sys.argv[i] if len(sys.argv) > i else default


def keygen():
    path = Path(_arg(2, DEFAULT_KEY))
    if path.exists():
        sys.exit(f"{path} already exists – refusing to overwrite.")
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"Private key: {path}  (back it up, never commit it)")
    target = "fido2tool_core/updates.py PUBLIC_KEY_B64" if path == DEFAULT_KEY else "the PublicKey policy value"
    print(f"Public key for {target}:\n{base64.b64encode(raw).decode()}")


def sign():
    advisories = Path(_arg(2, ADVISORIES))
    doc = json.loads(advisories.read_text(encoding="utf-8"))
    if not isinstance(doc.get("advisories"), list):
        sys.exit(f"{advisories}: expected an object with an \"advisories\" list")
    doc["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    key = _load_private_key()
    signature = key.sign(data)
    advisories.write_bytes(data)
    Path(str(advisories) + ".sig").write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")
    print(f"Signed {advisories.name} (updated {doc['updated']}, {len(doc['advisories'])} entries)")
    # The official file is checked against the key built into the app
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _verify(advisories, None if advisories == ADVISORIES else base64.b64encode(raw).decode())


def _verify(advisories: Path, public_key: str | None):
    from fido2tool_core.updates import PUBLIC_KEY_B64, verify as check

    ok = check(advisories.read_bytes(), Path(str(advisories) + ".sig").read_text(encoding="ascii"),
               public_key or PUBLIC_KEY_B64)
    print("Signature valid" if ok else "SIGNATURE INVALID")
    sys.exit(0 if ok else 1)


def verify():
    _verify(Path(_arg(2, ADVISORIES)), _arg(3))


if __name__ == "__main__":
    {"keygen": keygen, "sign": sign, "verify": verify}.get(
        _arg(1, ""), lambda: sys.exit(__doc__))()
