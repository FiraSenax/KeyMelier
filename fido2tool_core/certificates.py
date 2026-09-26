"""PKIX path validation using OpenSSL, with explicit application trust anchors."""
from datetime import datetime, timezone


def validate_path(leaf, intermediates, root):
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
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Attestation/signing leaf must not be a CA")
    try:
        if not leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ValueError("Leaf cannot sign")
    except x509.ExtensionNotFound:
        pass
    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(root))
    store.set_flags(crypto.X509StoreFlags.X509_STRICT)
    store.set_time(now)
    ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(leaf),
                                 [crypto.X509.from_cryptography(c) for c in intermediates if c != root])
    ctx.verify_certificate()
    return [c.to_cryptography() for c in ctx.get_verified_chain()]
