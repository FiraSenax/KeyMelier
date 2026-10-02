"""FIDO2 Attestation verifier.

Performs a real makeCredential call against the attached token, then verifies:
  1. Attestation signature is mathematically valid
  2. Attestation certificate chain traces to a root in the MDS3 entry
  3. AAGUID inside the authenticator data matches the AAGUID from getInfo
  4. Reports the attestation format (packed, fido-u2f, tpm, none, android-*)

The test requires NO PIN and NO user interaction beyond a physical touch.
It uses a dedicated test RP and random challenge so no real credential is persisted
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
    passed: bool = False                     # compatibility: true only for VERIFIED
    status: str = "UNVERIFIED"              # VERIFIED | UNVERIFIED | FAILED
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


def run(device, expected_aaguid: str, mds3_client=None, pin: str | None = None,
        use_uv: bool = False) -> AttestationResult:
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
        _run_checks(device, expected_aaguid, mds3_client, result, pin=pin, use_uv=use_uv)
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
    if exc.code == err.PIN_INVALID:
        return "pin_invalid"
    if exc.code in (err.PIN_BLOCKED, err.PIN_AUTH_BLOCKED):
        return "pin_blocked"
    return None


def _run_checks(device, expected_aaguid: str, mds3_client, result: AttestationResult,
                pin: str | None = None, use_uv: bool = False):
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
        # Keys that require user verification for registrations get a
        # PIN/UV token scoped to this test's RP (PIN is used once, never kept)
        pin_uv_param = pin_uv_protocol = None
        if pin or use_uv:
            from fido2.ctap2.pin import ClientPin
            client_pin = ClientPin(ctap2)
            perm = ClientPin.PERMISSION.MAKE_CREDENTIAL
            token = (client_pin.get_uv_token(perm, rp["id"]) if use_uv
                     else client_pin.get_pin_token(pin, perm, rp["id"]))
            pin_uv_param = client_pin.protocol.authenticate(token, client_data_hash)
            pin_uv_protocol = client_pin.protocol.VERSION
        att_obj = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=pub_key_params,
            options=options,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
        )
    except Exception as e:
        result.error = f"makeCredential failed: {e}"
        result.passed = False
        result.inconclusive = _inconclusive_reason(e)
        result.checks.append({"name": "makeCredential", "passed": None, "detail": str(e)})
        return

    result.checks.append({"name": "makeCredential", "passed": True, "detail": "Credential created"})

    # ── Parse attestation response (fido2 2.x: AttestationResponse dataclass) ─
    fmt = att_obj.fmt
    result.format = fmt
    # auth_data is AuthenticatorData (bytes subclass)
    auth_data_bytes = bytes(att_obj.auth_data)
    att_stmt = att_obj.att_stmt

    result.checks.append({"name": "Format", "passed": True, "detail": fmt})
    result.checks.append({
        "name": "Request binding and user presence",
        "passed": (len(auth_data_bytes) >= 37
                   and auth_data_bytes[:32] == hashlib.sha256(rp["id"].encode()).digest()
                   and bool(auth_data_bytes[32] & 1)),
        "detail": "RP ID hash and user-presence flag must match this test",
    })

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
        sig_ok, sig_detail, leaf_cert = None, "No attestation evidence (none format)", None
    else:
        sig_ok, sig_detail, leaf_cert = None, f"Unhandled format '{fmt}' — signature not verified", None

    result.sig_valid = sig_ok
    result.checks.append({
        "name": "Signature",
        "passed": sig_ok,
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

    # ── Certificate belongs to the claimed model ─────────────────────────────
    # The chain is checked against the roots of the AAGUID the device claims;
    # vendors share roots across products, so the leaf must name the model too.
    if leaf_cert and result.chain_valid is not None:
        bound, detail = _model_binding(fmt, leaf_cert, aaguid_from_auth, expected_aaguid, mds3_client)
        result.checks.append({"name": "Certificate matches model", "passed": bound, "detail": detail})
        if bound is None and result.chain_valid:
            result.chain_valid = None  # chain fine, but model not established

    # ── Overall result ───────────────────────────────────────────────────────
    _finalize(result)


def _finalize(result):
    required = (result.aaguid_match, result.sig_valid, result.chain_valid)
    if any(c["passed"] is False for c in result.checks):
        result.status = "FAILED"
    elif all(v is True for v in required):
        result.status = "VERIFIED"
    else:
        result.status = "UNVERIFIED"
    result.passed = result.status == "VERIFIED"


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
        from fido2.attestation import PackedAttestation
        from fido2.webauthn import AuthenticatorData
        PackedAttestation().verify(att_stmt, AuthenticatorData(auth_data), client_data_hash)
        x5c = att_stmt.get("x5c")
        if x5c:
            return True, "Packed signature and certificate profile verified", bytes(x5c[0])
        return None, "Self-attestation does not establish manufacturer authenticity", None
    except NotImplementedError:
        return None, "Unsupported packed attestation variant", None
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
    from fido2.cose import CoseKey

    # The COSE algorithm controls hash, padding and allowed key type.
    key = CoseKey.for_alg(alg).from_cryptography_key(pub_key)
    key.verify(data, sig)


def _cose_to_uncompressed(cbor_bytes: bytes) -> bytes:
    """Decode a COSE_Key CBOR map and return uncompressed EC point (0x04 | x | y)."""
    from fido2 import cbor
    cose, _ = cbor.decode_from(cbor_bytes)
    if cose.get(1) != 2 or cose.get(-1) != 1 or cose.get(3) != -7:
        raise ValueError("U2F requires an ES256 P-256 credential key")
    x, y = cose.get(-2), cose.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
        raise ValueError("Invalid EC coordinates")
    return b"\x04" + x + y


# ── Certificate chain helpers ────────────────────────────────────────────────

def _extract_cert_chain(att_stmt: dict) -> list[bytes]:
    x5c = att_stmt.get("x5c") or []
    return [bytes(c) for c in x5c]


def _verify_chain_against_mds3(chain_certs: list[bytes], aaguid: str, mds3_client) -> tuple[bool, str]:
    """Verify that the leaf cert chains to one of the roots listed in MDS3 for this AAGUID."""
    try:
        from cryptography import x509

        entry = mds3_client.lookup(aaguid)
        if not entry:
            return None, "AAGUID not found in MDS3 — chain not verifiable"

        if not mds3_client.is_current():
            return None, "MDS3 metadata expired — chain not currently verifiable"

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

        # Signatures chain to a vendor root, but the certificate profile or
        # validity is unusual: not evidence of forgery, but not verified either
        from fido2tool_core.certificates import chains_cryptographically
        for root in root_certs:
            if chains_cryptographically(leaf, intermediates, root):
                return None, (f"Chain to '{_get_cn(root)}' is cryptographically intact but does not meet "
                              "the certificate profile or validity rules – not verified")

        leaf_cn = _get_cn(leaf)
        return False, (
            f"Leaf cert '{leaf_cn}' does not chain to any MDS3 root "
            f"({len(root_certs)} root(s) tried)"
        )

    except Exception as e:
        return False, f"Chain verification error: {e}"


AAGUID_EXTENSION = "1.3.6.1.4.1.45724.1.1.4"


def _model_binding(fmt, leaf_der: bytes, aaguid_auth, expected_aaguid, mds3_client):
    """(True|False|None, detail): does the attestation certificate itself
    identify the model the device claims to be?"""
    import uuid
    from cryptography import x509

    leaf = x509.load_der_x509_certificate(leaf_der)
    if fmt == "packed":
        try:
            ext = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(AAGUID_EXTENSION)).value
        except x509.ExtensionNotFound:
            return None, "Certificate has no AAGUID extension – the model is not bound to it"
        raw = ext.value
        if len(raw) == 18 and raw[:2] == b"\x04\x10":  # DER OCTET STRING wrapper
            raw = raw[2:]
        if len(raw) != 16:
            return None, "Unreadable AAGUID extension"
        cert_aaguid = str(uuid.UUID(bytes=raw))
        if cert_aaguid != expected_aaguid.lower():
            return False, f"Certificate names AAGUID {cert_aaguid}, device claims {expected_aaguid}"
        return True, "Certificate AAGUID matches the device"
    if fmt == "fido-u2f":
        if aaguid_auth and aaguid_auth != "00000000-0000-0000-0000-000000000000":
            return None, "U2F attestation with a non-zero AAGUID – model not bound"
        entry = mds3_client.lookup(expected_aaguid) if mds3_client else None
        kids = [k.lower() for k in (entry or {}).get("attestationCertificateKeyIdentifiers", [])]
        try:
            ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
        except x509.ExtensionNotFound:
            ski = x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()).digest.hex()
        if kids and ski in kids:
            return True, "Certificate key identifier listed for this model"
        return None, "U2F certificate is not listed for this model"
    return None, "Model binding not checked for this format"


def _chain_validates(leaf, intermediates: list, root) -> bool:
    """Validate time, signatures, CA/key usage, path length and critical extensions."""
    from fido2tool_core.certificates import validate_path
    try:
        validate_path(leaf, intermediates, root, strict=False)
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
