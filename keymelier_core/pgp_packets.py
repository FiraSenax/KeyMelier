"""Minimal OpenPGP (RFC 4880, v4) writer for keys that live on a smart card.

Builds a transferable public key – primary key, user ID, subkeys and their
self-signatures – plus a revocation certificate. The private keys never leave
the card: every signature is made by a `signer` callback that the card
answers. Only what KeyMelier generates is supported: RSA, NIST P-256 and
Ed25519/Cv25519 ("legacy" EdDSA/ECDH, which GnuPG 2.2+ reads).
"""

import base64
import hashlib
import struct
from dataclasses import dataclass

# Public-key algorithm IDs
RSA = 1
ECDH = 18
ECDSA = 19
EDDSA = 22

SHA256 = 8

# Signature types
POSITIVE_CERT = 0x13
SUBKEY_BINDING = 0x18
KEY_REVOCATION = 0x20

# Key flags
FLAG_CERTIFY = 0x01
FLAG_SIGN = 0x02
FLAG_ENCRYPT = 0x04 | 0x08
FLAG_AUTH = 0x20

# Curve OIDs without the DER tag (length-prefixed in key packets)
OID_ED25519 = bytes.fromhex("2b06010401da470f01")
OID_CV25519 = bytes.fromhex("2b060104019755010501")
OID_P256 = bytes.fromhex("2a8648ce3d030107")

KDF_SHA256_AES128 = bytes([1, SHA256, 7])  # reserved, hash, cipher (length-prefixed)


def mpi(value: bytes | int) -> bytes:
    if isinstance(value, int):
        value = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    value = value.lstrip(b"\0") or b"\0"
    bits = (len(value) - 1) * 8 + value[0].bit_length()
    return struct.pack(">H", bits) + value


def packet(tag: int, body: bytes) -> bytes:
    """New-format packet header."""
    n = len(body)
    if n < 192:
        length = bytes([n])
    elif n < 8384:
        n -= 192
        length = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        length = b"\xff" + struct.pack(">I", n)
    return bytes([0xC0 | tag]) + length + body


def subpacket(kind: int, data: bytes) -> bytes:
    n = len(data) + 1
    if n < 192:
        length = bytes([n])
    elif n < 8384:
        n -= 192
        length = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        length = b"\xff" + struct.pack(">I", n)
    return length + bytes([kind]) + data


@dataclass
class PublicKey:
    """Public key material of one card slot in OpenPGP terms."""
    algorithm: int
    material: bytes  # algorithm-specific fields after the algorithm octet
    created: int

    def body(self) -> bytes:
        return bytes([4]) + struct.pack(">I", self.created) + bytes([self.algorithm]) + self.material

    def hashed(self) -> bytes:
        body = self.body()
        return b"\x99" + struct.pack(">H", len(body)) + body

    @property
    def fingerprint(self) -> bytes:
        return hashlib.sha1(self.hashed()).digest()  # noqa: S324 – defined by RFC 4880

    @property
    def key_id(self) -> bytes:
        return self.fingerprint[-8:]


def public_key(crypto_key, created: int, encryption: bool = False) -> PublicKey:
    """OpenPGP public key from a `cryptography` public key read from the card."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if isinstance(crypto_key, rsa.RSAPublicKey):
        n = crypto_key.public_numbers()
        return PublicKey(RSA, mpi(n.n) + mpi(n.e), created)
    if isinstance(crypto_key, ed25519.Ed25519PublicKey):
        raw = crypto_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return PublicKey(EDDSA, bytes([len(OID_ED25519)]) + OID_ED25519 + mpi(b"\x40" + raw), created)
    if isinstance(crypto_key, x25519.X25519PublicKey):
        raw = crypto_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return PublicKey(ECDH, bytes([len(OID_CV25519)]) + OID_CV25519 + mpi(b"\x40" + raw)
                         + bytes([len(KDF_SHA256_AES128)]) + KDF_SHA256_AES128, created)
    if isinstance(crypto_key, ec.EllipticCurvePublicKey) and crypto_key.curve.name == "secp256r1":
        point = crypto_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        head = bytes([len(OID_P256)]) + OID_P256 + mpi(point)
        if encryption:
            return PublicKey(ECDH, head + bytes([len(KDF_SHA256_AES128)]) + KDF_SHA256_AES128, created)
        return PublicKey(ECDSA, head, created)
    raise ValueError(f"Unsupported key type: {type(crypto_key).__name__}")


def signature(primary: PublicKey, sig_type: int, data: bytes, hashed_subpackets: bytes, signer) -> bytes:
    """Signature packet. `signer(digest) -> bytes` returns the algorithm's
    signature MPIs, already encoded."""
    hashed_part = (bytes([4, sig_type, primary.algorithm, SHA256])
                   + struct.pack(">H", len(hashed_subpackets)) + hashed_subpackets)
    trailer = b"\x04\xff" + struct.pack(">I", len(hashed_part))
    digest = hashlib.sha256(data + hashed_part + trailer).digest()
    unhashed = subpacket(16, primary.key_id)
    body = hashed_part + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + signer(digest)
    return packet(2, body)


def _common(primary: PublicKey, created: int) -> bytes:
    return subpacket(2, struct.pack(">I", created)) + subpacket(33, b"\x04" + primary.fingerprint)


def transferable_key(primary: PublicKey, user_id: str, subkeys: list[tuple[PublicKey, int]],
                     signer, created: int, expires_in: int | None = None) -> bytes:
    """Primary key + user ID + subkeys, each with its self-signature."""
    uid = user_id.encode("utf-8")
    expiry = subpacket(9, struct.pack(">I", expires_in)) if expires_in else b""
    cert_subpackets = (
        _common(primary, created)
        + subpacket(27, bytes([FLAG_CERTIFY | FLAG_SIGN]))
        + expiry
        + subpacket(11, bytes([9, 8, 7]))            # AES-256, AES-192, AES-128
        + subpacket(21, bytes([10, 9, 8]))           # SHA-512, SHA-384, SHA-256
        + subpacket(22, bytes([2, 3, 1, 0]))         # ZLIB, BZip2, ZIP, none
        + subpacket(30, bytes([0x01]))               # MDC
        + subpacket(23, bytes([0x80]))               # keyserver: no-modify
    )
    out = packet(6, primary.body()) + packet(13, uid)
    uid_data = primary.hashed() + b"\xb4" + struct.pack(">I", len(uid)) + uid
    out += signature(primary, POSITIVE_CERT, uid_data, cert_subpackets, signer)
    for sub, flags in subkeys:
        out += packet(14, sub.body())
        binding = _common(primary, created) + subpacket(27, bytes([flags])) + expiry
        out += signature(primary, SUBKEY_BINDING, primary.hashed() + sub.hashed(), binding, signer)
    return out


def revocation(primary: PublicKey, signer, created: int) -> bytes:
    reason = subpacket(29, b"\x00" + "Key lost or no longer used".encode())
    return signature(primary, KEY_REVOCATION, primary.hashed(), _common(primary, created) + reason, signer)


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor(data: bytes, kind: str = "PUBLIC KEY BLOCK", comment: str | None = None) -> str:
    b64 = base64.b64encode(data).decode()
    lines = [f"-----BEGIN PGP {kind}-----"]
    if comment:
        lines.append(f"Comment: {comment}")
    lines.append("")
    lines += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    lines.append("=" + base64.b64encode(struct.pack(">I", _crc24(data))[1:]).decode())
    lines.append(f"-----END PGP {kind}-----")
    return "\n".join(lines) + "\n"


def signature_mpis(algorithm: int, raw) -> bytes:
    """Encode what the card returned as signature MPIs."""
    if algorithm == RSA:
        return mpi(raw)
    if algorithm == EDDSA:
        return mpi(raw[:32]) + mpi(raw[32:])
    if algorithm == ECDSA:
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(raw)
        return mpi(r) + mpi(s)
    raise ValueError("Unsupported signature algorithm")
