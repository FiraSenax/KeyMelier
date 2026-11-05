"""PKIX path validation using OpenSSL, with explicit application trust anchors."""
from datetime import datetime, timezone


def validation_failure_reason(error: Exception) -> str:
    """Describe only known validation errors, never arbitrary exception contents."""
    from OpenSSL import crypto
    from cryptography import x509

    if isinstance(error, crypto.X509StoreContextError):
        errors = error.errors
        if isinstance(errors, (list, tuple)) and errors:
            code = errors[0]
            reasons = {
                9: "A certificate is not yet valid; check the computer date and certificate validity",
                10: "A certificate has expired; check the computer date and certificate validity",
                24: "An issuer certificate is not a valid certificate authority (CA)",
                25: "The certificate chain exceeds the permitted CA path length",
                26: "A certificate is not permitted for this purpose",
                32: "An issuer certificate is not permitted to sign certificates",
                34: "A certificate contains an unsupported critical extension",
                79: "An issuer certificate is not a valid certificate authority (CA)",
            }
            if type(code) is int and code in reasons:
                return reasons[code]
    if isinstance(error, x509.ExtensionNotFound):
        if error.oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
            return "The trust anchor is missing its CA basic constraints"
    if type(error) is ValueError:
        reasons = {
            "Certificate expired or not yet valid":
                "A certificate is expired or not yet valid; check the computer date and certificate validity",
            "Trust anchor is not a CA": "The trust anchor is not a certificate authority (CA)",
            "Trust anchor cannot sign certificates": "The trust anchor is not permitted to sign certificates",
            "Attestation/signing leaf must not be a CA":
                "The device attestation certificate is marked as a CA instead of an end-entity certificate",
            "Leaf cannot sign": "The device attestation certificate is not permitted to make digital signatures",
        }
        return reasons.get(str(error), "Certificate validation failed; no specific reason is available")
    return "Certificate validation failed; no specific reason is available"


def validate_path(leaf, intermediates, root, strict: bool = True):
    """strict=False for device attestation certificates: RFC 5280 profile
    details (e.g. a missing Authority Key Identifier) are common in older
    vendor certificates and say nothing about authenticity. Signatures,
    validity, explicit CA flags, path length and critical extensions are always
    enforced. Non-strict attestation validation also accepts an explicitly
    trusted, self-signed X.509v1 root without extensions (legacy MDS anchors).
    This exception does not apply to strict MDS JWT validation.
    """
    from OpenSSL import crypto
    from cryptography import x509

    # A trust anchor may terminate the path without being self-signed, but
    # must still be currently valid and have appropriate key usage. Legacy
    # self-signed v1 attestation anchors cannot carry basicConstraints.
    now = datetime.now(timezone.utc)
    for cert in [leaf, *intermediates, root]:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError("Certificate expired or not yet valid")
    try:
        if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Trust anchor is not a CA")
    except x509.ExtensionNotFound:
        if strict or root.version != x509.Version.v1 or len(root.extensions):
            raise
        # The caller supplies an MDS trust anchor, never a device-provided root.
        # Require a genuine self-signature, not merely matching subject/issuer.
        root.verify_directly_issued_by(root)
    try:
        if not root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            raise ValueError("Trust anchor cannot sign certificates")
    except x509.ExtensionNotFound:
        pass
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Attestation/signing leaf must not be a CA")
    except x509.ExtensionNotFound:
        pass  # many U2F-era attestation certificates carry no basicConstraints
    try:
        if not leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ValueError("Leaf cannot sign")
    except x509.ExtensionNotFound:
        pass
    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(root))
    # PARTIAL_CHAIN: MDS may list an intermediate CA as the anchor
    flags = crypto.X509StoreFlags.PARTIAL_CHAIN
    if strict:
        flags |= crypto.X509StoreFlags.X509_STRICT
    store.set_flags(flags)
    store.set_time(now)
    ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(leaf),
                                 [crypto.X509.from_cryptography(c) for c in intermediates if c != root])
    ctx.verify_certificate()
    return [c.to_cryptography() for c in ctx.get_verified_chain()]


def chains_cryptographically(leaf, intermediates, root) -> bool:
    """True if leaf → intermediates → root verify as signatures, ignoring
    profile rules (extensions, strictness). Distinguishes a genuine but
    unusually profiled certificate from a forged one."""
    certs = [leaf, *[c for c in intermediates if c != root]]
    for i, cert in enumerate(certs):
        issuer = certs[i + 1] if i + 1 < len(certs) else root
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception:
            # intermediates may be unordered or the root may issue directly
            if not any(_issued_by(cert, c) for c in [*certs[i + 1:], root]):
                return False
            if _issued_by(cert, root):
                return True
    return True


def _issued_by(cert, issuer) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False
