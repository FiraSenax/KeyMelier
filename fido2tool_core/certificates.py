"""PKIX path validation using OpenSSL, with explicit application trust anchors."""
from datetime import datetime, timezone


def validate_path(leaf, intermediates, root, strict: bool = True):
    """strict=False for device attestation certificates: RFC 5280 profile
    details (e.g. a missing Authority Key Identifier) are common in older
    vendor certificates and say nothing about authenticity. Signatures,
    validity, CA flags, path length and critical extensions are always
    enforced."""
    from OpenSSL import crypto
    from cryptography import x509

    # A trust anchor may terminate the path without being self-signed, but
    # must still be a currently valid CA with appropriate key usage.
    now = datetime.now(timezone.utc)
    for cert in [leaf, *intermediates, root]:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError("Certificate expired or not yet valid")
    if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Trust anchor is not a CA")
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
