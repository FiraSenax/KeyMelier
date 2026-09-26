"""Fail-closed CRL checks for the pinned MDS signer chain.

Only direct, complete CRLs from GlobalSign are supported. Redirects and
arbitrary certificate-provided hosts are never followed.
"""
from datetime import datetime, timezone
from urllib.parse import urlparse
import threading

_CACHE = {}
_LOCK = threading.Lock()
_MAX_SIZE = 8 * 1024 * 1024


def _fetch_crl(url):
    import requests
    from cryptography import x509

    p = urlparse(url)
    if (p.scheme not in {"http", "https"} or p.hostname not in {
        "crl.globalsign.com", "crl2.globalsign.com", "secure.globalsign.com"
    } or p.port not in {None, 80, 443} or p.username or p.password):
        raise ValueError("Unsupported MDS CRL endpoint")
    now = datetime.now(timezone.utc)
    with _LOCK:
        cached = _CACHE.get(url)
        if cached and cached.next_update_utc and now < cached.next_update_utc:
            return cached
    # HTTP CRLs are authenticated by the issuer signature, not the transport.
    with requests.get(url, timeout=15, stream=True, allow_redirects=False) as response:
        if response.status_code != 200:
            raise ValueError("MDS CRL download failed")
        chunks, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > _MAX_SIZE:
                raise ValueError("MDS CRL exceeds size limit")
            chunks.append(chunk)
    crl = x509.load_der_x509_crl(b"".join(chunks))
    # Cache only after validation in check_chain_revocation.
    return crl


def check_chain_revocation(chain):
    from cryptography import x509

    now = datetime.now(timezone.utc)
    deadlines = [c.not_valid_after_utc for c in chain]
    for cert, issuer in zip(chain, chain[1:]):
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls = [n.value for point in points for n in (point.full_name or [])
                if isinstance(n, x509.UniformResourceIdentifier)
                and point.reasons is None and point.crl_issuer is None]
        checked = False
        for url in urls:
            try:
                crl = _fetch_crl(url)
                if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
                    raise ValueError("Invalid CRL signature or issuer")
                usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
                if not usage.crl_sign:
                    raise ValueError("Issuer cannot sign CRLs")
                if crl.next_update_utc is None or not crl.last_update_utc <= now < crl.next_update_utc:
                    raise ValueError("CRL is not current")
                # Reject delta/scoped/indirect CRLs rather than silently interpreting them as complete.
                for ext in crl.extensions:
                    if isinstance(ext.value, (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint)):
                        raise ValueError("Unsupported scoped or delta CRL")
                    if ext.critical:
                        raise ValueError("Unsupported critical CRL extension")
                if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                    raise ValueError("MDS signer certificate revoked")
                with _LOCK:
                    _CACHE[url] = crl
                deadlines.append(crl.next_update_utc)
                checked = True
                break
            except Exception:
                continue
        if not checked:
            raise ValueError("MDS revocation status unavailable or revoked")

    return min(deadlines)
