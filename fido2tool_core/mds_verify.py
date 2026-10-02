"""Verify the FIDO Alliance MDS3 blob (a JWT) before trusting its contents.

Checks, per the FIDO MDS3 specification:
  - the x5c certificate chain leads to the FIDO MDS root (GlobalSign Root CA - R3)
  - every certificate is currently valid and the leaf is issued for mds.fidoalliance.org
  - the JWT signature verifies with the leaf key
Revocation is checked using current, issuer-signed GlobalSign CRLs; failure is closed.
"""

import base64
import json
from datetime import datetime

# GlobalSign Root CA - R3, the trust anchor for mds.fidoalliance.org.
# SHA-256 fingerprint CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B
MDS_ROOT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
"""

EXPECTED_LEAF_CN = "mds.fidoalliance.org"


class MdsVerificationError(Exception):
    pass


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def verify_jwt(token: str, require_revocation: bool = True) -> dict:
    """Return the verified payload, or raise MdsVerificationError.

    With require_revocation=False a payload whose signature and certificate
    path are valid is returned even when the signer's revocation status cannot
    be established (e.g. offline). It is then marked "_revocation_ok": False
    and "_verified_until": None, so it can name models but never support a
    positive security assessment (see MDS3Client.is_current).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import NameOID

    try:
        header_b64, payload_b64, sig_b64 = token.strip().split(".")
        header = json.loads(_b64url(header_b64))
        chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c", [])]
    except Exception as e:
        raise MdsVerificationError(f"malformed JWT: {e}") from None
    if not chain:
        raise MdsVerificationError("no certificate chain")

    root = x509.load_pem_x509_certificate(MDS_ROOT_PEM)
    # Some blobs include the root itself; drop it, we only trust our own copy
    if chain[-1].fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
        chain = chain[:-1]

    if not chain:
        raise MdsVerificationError("missing signer leaf")
    try:
        from fido2tool_core.certificates import validate_path
        from fido2tool_core.revocation import check_chain_revocation
        verified_chain = validate_path(chain[0], chain[1:], root)
    except Exception as e:
        raise MdsVerificationError(f"certificate path invalid: {e}") from None
    from fido2tool_core.revocation import RevokedError
    try:
        valid_until = check_chain_revocation(verified_chain)
    except RevokedError as e:
        raise MdsVerificationError(f"MDS signer revoked: {e}") from None  # never usable
    except Exception as e:
        if require_revocation:
            raise MdsVerificationError(f"certificate revocation status unavailable: {e}") from None
        valid_until = None  # display only; is_current() stays False

    cns = [a.value for a in chain[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if EXPECTED_LEAF_CN not in cns:
        raise MdsVerificationError(f"unexpected signer {cns}")

    signed = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url(sig_b64)
    key = chain[0].public_key()
    alg = header.get("alg")
    try:
        if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        elif (alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey)
              and isinstance(key.curve, ec.SECP256R1) and len(signature) == 64):
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
        else:
            raise MdsVerificationError(f"unsupported algorithm {alg}")
    except MdsVerificationError:
        raise
    except Exception:
        raise MdsVerificationError("signature invalid") from None

    payload = json.loads(_b64url(payload_b64))
    if (not isinstance(payload, dict) or type(payload.get("no")) is not int
            or payload["no"] < 0 or not isinstance(payload.get("entries"), list)):
        raise MdsVerificationError("malformed metadata payload")
    try:
        datetime.strptime(payload["nextUpdate"], "%Y-%m-%d")
    except (KeyError, ValueError, TypeError):
        raise MdsVerificationError("invalid metadata nextUpdate") from None
    payload["_verified_until"] = valid_until.isoformat() if valid_until else None
    payload["_revocation_ok"] = valid_until is not None
    return payload
