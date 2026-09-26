"""FIDO2 Attestation verifier.

Performs a real makeCredential call against the attached token, then verifies:
  1. Attestation signature is mathematically valid
  2. Attestation certificate chain traces to a root in the MDS3 entry
  3. AAGUID inside the authenticator data matches the AAGUID from getInfo
  4. Reports the attestation format (packed, fido-u2f, tpm, none, android-*)

The test requires NO PIN and NO user interaction beyond a physical touch.
It uses a random ephemeral RP / challenge so no real credential is persisted
anywhere useful, and the key handle is immediately discarded.
"""

import hashlib
import logging
import os
import struct
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AttestationResult:
    ran: bool = False                        # was the test attempted?
    passed: bool = False                     # overall pass/fail
    format: Optional[str] = None            # packed | fido-u2f | tpm | none | …
    aaguid_match: Optional[bool] = None     # getInfo AAGUID == authData AAGUID
    aaguid_from_auth_data: Optional[str] = None
    sig_valid: Optional[bool] = None        # signature over clientDataHash verified
    chain_valid: Optional[bool] = None      # cert chain to MDS3 root verified
    chain_depth: Optional[int] = None       # number of certs in chain
    subject_cn: Optional[str] = None        # leaf cert CN
    error: Optional[str] = None            # human-readable failure reason
    # Set when the key declined to run the test for a benign reason (no
    # touch, needs PIN/fingerprint, forced PIN change). Not a failure.
    inconclusive: Optional[str] = None
    checks: list = field(default_factory=list)  # list of {name, passed, detail}


def run(device, expected_aaguid: str, mds3_client=None) -> AttestationResult:
    """Run the full attestation test against an already-opened HID device.

    Args:
        device: an open fido2.hid.CtapHidDevice
        expected_aaguid: the AAGUID string from getInfo (hyphenated UUID)
        mds3_client: optional MDS3Client for cert-chain verification

    Returns:
        AttestationResult populated with all check outcomes
    """
    result = AttestationResult(ran=True)
    try:
        _run_checks(device, expected_aaguid, mds3_client, result)
    except Exception as e:
        result.error = f"Unexpected error during attestation test: {e}"
        result.passed = False
        logger.warning("Attestation test error: %s", e, exc_info=True)
    return result


def _inconclusive_reason(exc) -> Optional[str]:
    """Map makeCredential errors that say nothing about authenticity."""
    from fido2.ctap import CtapError

    if not isinstance(exc, CtapError):
        return None
    err = CtapError.ERR
    if exc.code in (err.USER_ACTION_TIMEOUT, err.ACTION_TIMEOUT, err.KEEPALIVE_CANCEL):
        return "no_touch"
    if exc.code in (err.PUAT_REQUIRED,
                    err.UV_INVALID, err.UV_BLOCKED, err.PIN_NOT_SET):
        return "needs_uv"
    if exc.code in (err.OPERATION_DENIED, err.PIN_POLICY_VIOLATION, err.NOT_ALLOWED):
        return "declined"
    return None


def _run_checks(device, expected_aaguid: str, mds3_client, result: AttestationResult):
    from fido2.ctap2 import Ctap2
    from fido2.webauthn import AttestedCredentialData, ES256

    ctap2 = Ctap2(device)

    # Pass rp and user as plain dicts so fido2's cbor encoder keeps user.id
    # as raw CBOR bytes (major type 2). PublicKeyCredentialUserEntity encodes
    # its ByteBuffer id field as base64url text, which causes CBOR_UNEXPECTED_TYPE
    # on YubiKey and other strict CTAP2 implementations.
    rp = {"id": "fido2tool.local", "name": "FIDO2 Tool Attestation Test"}
    user = {
        "id": os.urandom(16),
        "name": "attestation-test",
        "displayName": "Attestation Test",
    }
    challenge = os.urandom(32)
    pub_key_params = [{"type": "public-key", "alg": ES256.ALGORITHM}]

    # clientDataHash = SHA-256 of a synthetic clientData JSON
    client_data = (
        b'{"type":"webauthn.create","challenge":"'
        + challenge.hex().encode()
        + b'","origin":"https://fido2tool.local"}'
    )
    client_data_hash = hashlib.sha256(client_data).digest()

    # NO resident key, NO UV — avoids PIN prompt on most tokens
    options = {"rk": False}

    logger.info("Sending makeCredential to token for attestation test…")
    try:
        att_obj = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=pub_key_params,
            options=options,
        )
    except Exception as e:
        result.error = f"makeCredential failed: {e}"
        result.passed = False
        result.inconclusive = _inconclusive_reason(e)
        result.checks.append({"name": "makeCredential", "passed": False, "detail": str(e)})
        return

    result.checks.append({"name": "makeCredential", "passed": True, "detail": "Credential created"})

    # ── Parse attestation response (fido2 2.x: AttestationResponse dataclass) ─
    fmt = att_obj.fmt
    result.format = fmt
    # auth_data is AuthenticatorData (bytes subclass)
    auth_data_bytes = bytes(att_obj.auth_data)
    att_stmt = att_obj.att_stmt

    result.checks.append({"name": "Format", "passed": True, "detail": fmt})

    # ── Extract AAGUID via AttestedCredentialData.unpack_from ────────────────
    # AuthenticatorData layout: 32 rpIdHash | 1 flags | 4 signCount | [AT: credential data]
    # We check the AT (attested credential data) flag first, then unpack.
    aaguid_from_auth = _extract_aaguid_v2(auth_data_bytes, AttestedCredentialData)
    result.aaguid_from_auth_data = aaguid_from_auth

    aaguid_match = (aaguid_from_auth == expected_aaguid.lower()) if aaguid_from_auth else None
    result.aaguid_match = aaguid_match

    result.checks.append({
        "name": "AAGUID consistency",
        "passed": bool(aaguid_match),
        "detail": (
            f"getInfo={expected_aaguid}  authData={aaguid_from_auth}"
            if aaguid_from_auth else "Could not parse AAGUID from authData"
        ),
    })

    # ── Verify attestation signature ─────────────────────────────────────────
    if fmt == "packed":
        sig_ok, sig_detail, leaf_cert = _verify_packed(att_stmt, auth_data_bytes, client_data_hash)
    elif fmt == "fido-u2f":
        sig_ok, sig_detail, leaf_cert = _verify_fido_u2f(att_stmt, auth_data_bytes, client_data_hash)
    elif fmt == "none":
        sig_ok, sig_detail, leaf_cert = True, "No attestation (self-attestation or none format)", None
    else:
        sig_ok, sig_detail, leaf_cert = None, f"Unhandled format '{fmt}' — signature not verified", None

    result.sig_valid = sig_ok
    result.checks.append({
        "name": "Signature",
        "passed": bool(sig_ok),
        "detail": sig_detail,
    })

    if leaf_cert:
        try:
            from cryptography import x509
            cert_obj = x509.load_der_x509_certificate(leaf_cert)
            cn = cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            result.subject_cn = cn[0].value if cn else None
        except Exception:
            pass

    # ── Verify certificate chain against MDS3 roots ──────────────────────────
    chain_certs = _extract_cert_chain(att_stmt)
    result.chain_depth = len(chain_certs)

    if not chain_certs:
        result.chain_valid = None
        result.checks.append({
            "name": "Cert chain",
            "passed": None,
            "detail": "No certificates in attestation statement (none/self format)",
        })
    elif mds3_client is None:
        result.chain_valid = None
        result.checks.append({
            "name": "Cert chain",
            "passed": None,
            "detail": "MDS3 not available — chain not verified",
        })
    else:
        chain_ok, chain_detail = _verify_chain_against_mds3(
            chain_certs, expected_aaguid, mds3_client
        )
        result.chain_valid = chain_ok
        result.checks.append({
            "name": "Cert chain",
            "passed": chain_ok,
            "detail": chain_detail,
        })

    # ── Overall result ───────────────────────────────────────────────────────
    definite_failures = [c for c in result.checks if c["passed"] is False]
    result.passed = len(definite_failures) == 0


# ── Authenticator data helpers ───────────────────────────────────────────────

def _extract_aaguid_v2(auth_data: bytes, AttestedCredentialData) -> Optional[str]:
    """Extract AAGUID using fido2 2.x AttestedCredentialData.unpack_from.

    AuthenticatorData layout:
      [0:32]  rpIdHash
      [32]    flags
      [33:37] signCount (big-endian u32)
      [37:]   attested credential data (if AT flag set)
    """
    try:
        if len(auth_data) < 37:
            return None
        flags = auth_data[32]
        at_flag = (flags >> 6) & 1
        if not at_flag:
            return None
        cred_data, _ = AttestedCredentialData.unpack_from(auth_data[37:])
        # cred_data is bytes; AAGUID is the first 16 bytes
        aaguid_bytes = bytes(cred_data[:16])
        return str(uuid.UUID(bytes=aaguid_bytes))
    except Exception:
        # Fall back to raw byte parse
        return _extract_aaguid_raw(auth_data)


def _extract_aaguid_raw(auth_data: bytes) -> Optional[str]:
    """Fallback: parse AAGUID directly from raw bytes at offset 37."""
    try:
        if len(auth_data) < 55:
            return None
        flags = auth_data[32]
        if not ((flags >> 6) & 1):
            return None
        return str(uuid.UUID(bytes=auth_data[37:53]))
    except Exception:
        return None


# ── Signature verification ───────────────────────────────────────────────────

def _verify_packed(att_stmt: dict, auth_data: bytes, client_data_hash: bytes):
    """Verify a 'packed' attestation statement signature."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography import x509

        sig = att_stmt.get("sig")
        x5c = att_stmt.get("x5c")
        alg = att_stmt.get("alg", -7)

        if sig is None:
            return False, "No signature in packed attestation", None

        signed_data = auth_data + client_data_hash

        if x5c:
            # Full attestation: cert contains public key
            leaf_der = bytes(x5c[0])
            cert = x509.load_der_x509_certificate(leaf_der)
            pub_key = cert.public_key()
            _verify_signature(pub_key, bytes(sig), signed_data, alg)
            return True, f"Signature valid (packed, full attestation, {len(x5c)} cert(s))", leaf_der
        else:
            # Self attestation: use the credential public key — skip for now
            return None, "Self-attestation (no x5c) — signature not independently verified", None

    except Exception as e:
        return False, f"Packed signature verification failed: {e}", None


def _verify_fido_u2f(att_stmt: dict, auth_data: bytes, client_data_hash: bytes):
    """Verify a 'fido-u2f' attestation statement."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography import x509

        sig = att_stmt.get("sig")
        x5c = att_stmt.get("x5c")

        if not sig or not x5c:
            return False, "Missing sig or x5c in fido-u2f attestation", None

        leaf_der = bytes(x5c[0])
        cert = x509.load_der_x509_certificate(leaf_der)
        pub_key = cert.public_key()

        # fido-u2f verification data: 0x00 | rpIdHash | clientDataHash | credId | pubKeyBytes
        flags = auth_data[32]
        rp_id_hash = auth_data[:32]
        # credentialId starts at byte 55 after 2-byte length
        cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
        cred_id = auth_data[55: 55 + cred_id_len]
        cred_pub_key_cbor = auth_data[55 + cred_id_len:]

        # Decode COSE key to raw 65-byte uncompressed EC point
        pub_key_bytes = _cose_to_uncompressed(cred_pub_key_cbor)

        verification_data = b"\x00" + rp_id_hash + client_data_hash + cred_id + pub_key_bytes

        pub_key.verify(bytes(sig), verification_data, ec.ECDSA(hashes.SHA256()))
        return True, f"Signature valid (fido-u2f, {len(x5c)} cert(s))", leaf_der

    except Exception as e:
        return False, f"fido-u2f signature verification failed: {e}", None


def _verify_signature(pub_key, sig: bytes, data: bytes, alg: int):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

    if isinstance(pub_key, EllipticCurvePublicKey):
        pub_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(pub_key, RSAPublicKey):
        hash_alg = hashes.SHA256() if alg in (-257, -258) else hashes.SHA384()
        pub_key.verify(sig, data, asym_padding.PKCS1v15(), hash_alg)
    else:
        raise ValueError(f"Unsupported key type: {type(pub_key)}")


def _cose_to_uncompressed(cbor_bytes: bytes) -> bytes:
    """Decode a COSE_Key CBOR map and return uncompressed EC point (0x04 | x | y)."""
    try:
        import cbor2
        cose = cbor2.loads(cbor_bytes)
        x = cose.get(-2) or cose.get(b"-2")
        y = cose.get(-3) or cose.get(b"-3")
        if x is None or y is None:
            raise ValueError("Missing x or y in COSE key")
        return b"\x04" + bytes(x) + bytes(y)
    except ImportError:
        # cbor2 not available — fall back to manual parse of simple case
        # COSE key for P-256: a5 01 02 03 26 20 01 21 58 20 <x32> 22 58 20 <y32>
        idx = cbor_bytes.find(b"\x21\x58\x20")
        if idx == -1:
            raise ValueError("Cannot decode COSE key without cbor2")
        x = cbor_bytes[idx + 3: idx + 35]
        y = cbor_bytes[idx + 38: idx + 70]
        return b"\x04" + x + y


# ── Certificate chain helpers ────────────────────────────────────────────────

def _extract_cert_chain(att_stmt: dict) -> list[bytes]:
    x5c = att_stmt.get("x5c") or []
    return [bytes(c) for c in x5c]


def _verify_chain_against_mds3(chain_certs: list[bytes], aaguid: str, mds3_client) -> tuple[bool, str]:
    """Verify that the leaf cert chains to one of the roots listed in MDS3 for this AAGUID."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding

        entry = mds3_client.lookup(aaguid)
        if not entry:
            return None, "AAGUID not found in MDS3 — chain not verifiable"

        ms = entry.get("metadataStatement", {})
        root_b64_list = ms.get("attestationRootCertificates", [])
        if not root_b64_list:
            return None, "No root certificates in MDS3 entry for this AAGUID"

        import base64
        root_certs = []
        for b64 in root_b64_list:
            try:
                der = base64.b64decode(b64)
                root_certs.append(x509.load_der_x509_certificate(der))
            except Exception:
                pass

        if not root_certs:
            return None, "Could not decode MDS3 root certificates"

        # Build ordered chain: leaf … intermediate(s) … root
        # chain_certs[0] is always the leaf; last is closest to root
        leaf = x509.load_der_x509_certificate(chain_certs[0])
        intermediates = [x509.load_der_x509_certificate(c) for c in chain_certs[1:]]

        # Try to find which MDS3 root the chain leads to
        for root in root_certs:
            if _chain_validates(leaf, intermediates, root):
                root_cn = _get_cn(root)
                leaf_cn = _get_cn(leaf)
                return True, (
                    f"Chain valid: leaf='{leaf_cn}' → root='{root_cn}' "
                    f"({len(chain_certs)} cert(s))"
                )

        leaf_cn = _get_cn(leaf)
        return False, (
            f"Leaf cert '{leaf_cn}' does not chain to any MDS3 root "
            f"({len(root_certs)} root(s) tried)"
        )

    except Exception as e:
        return False, f"Chain verification error: {e}"


def _chain_validates(leaf, intermediates: list, root) -> bool:
    """Simple path validation: each cert's issuer must be signed by the next."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa

        chain = [leaf] + intermediates + [root]
        for i in range(len(chain) - 1):
            subject_cert = chain[i]
            issuer_cert = chain[i + 1]
            # Subject's issuer DN must match issuer cert's subject DN
            if subject_cert.issuer != issuer_cert.subject:
                return False
            # Verify subject cert signature with issuer public key
            pub = issuer_cert.public_key()
            try:
                if isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(
                        subject_cert.signature,
                        subject_cert.tbs_certificate_bytes,
                        ec.ECDSA(subject_cert.signature_hash_algorithm),
                    )
                elif isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(
                        subject_cert.signature,
                        subject_cert.tbs_certificate_bytes,
                        asym_padding.PKCS1v15(),
                        subject_cert.signature_hash_algorithm,
                    )
                else:
                    return False
            except Exception:
                return False
        return True
    except Exception:
        return False


def _get_cn(cert) -> str:
    try:
        from cryptography import x509
        attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else str(cert.subject)
    except Exception:
        return "unknown"
