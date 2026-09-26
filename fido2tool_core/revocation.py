"""Fail-closed CRL checks for the pinned MDS signer chain.

Only direct, complete CRLs from GlobalSign are supported. Redirects and
arbitrary certificate-provided hosts are never followed.

Downloaded CRLs are also kept on disk (~/.keymelier/crl/). That is safe:
a CRL is signed by its issuer and every use re-validates signature, issuer
and validity window in check_chain_revocation. The disk copy only lets the
check succeed offline until the CRL's own nextUpdate.
"""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
import threading

CRL_DIR = Path.home() / ".keymelier" / "crl"


class RevokedError(ValueError):
    """A valid, current CRL lists the certificate as revoked (never soft-fail)."""


def _disk_path(url):
    return CRL_DIR / (sha256(url.encode()).hexdigest()[:32] + ".crl")


def _load_disk(url):
    from cryptography import x509
    from fido2tool_core.storage import stateless

    if stateless():
        return None
    try:
        return x509.load_der_x509_crl(_disk_path(url).read_bytes())
    except (OSError, ValueError):
        return None


def _save_disk(url, crl):
    from cryptography.hazmat.primitives.serialization import Encoding
    from fido2tool_core.storage import atomic_write, stateless

    if stateless():
        return
    try:
        atomic_write(_disk_path(url), crl.public_bytes(Encoding.DER))
    except Exception:
        pass  # the disk copy is only an offline convenience

_CACHE = {}
_LOCK = threading.Lock()
_MAX_SIZE = 8 * 1024 * 1024


def _has_cached(url, now):
    with _LOCK:
        mem = _CACHE.get(url)
    if mem is not None and mem.next_update_utc and now < mem.next_update_utc:
        return True
    disk = _load_disk(url)
    return disk is not None and disk.next_update_utc is not None and now < disk.next_update_utc


def _drop_cached(url):
    with _LOCK:
        _CACHE.pop(url, None)
    try:
        _disk_path(url).unlink()
    except OSError:
        pass


def _fetch_crl(url, allow_cache=True):
    import requests
    from cryptography import x509

    p = urlparse(url)
    if (p.scheme not in {"http", "https"} or p.hostname not in {
        "crl.globalsign.com", "crl2.globalsign.com", "secure.globalsign.com"
    } or p.port not in {None, 80, 443} or p.username or p.password):
        raise ValueError("Unsupported MDS CRL endpoint")
    now = datetime.now(timezone.utc)
    if allow_cache:
        with _LOCK:
            cached = _CACHE.get(url)
            if cached and cached.next_update_utc and now < cached.next_update_utc:
                return cached
        disk = _load_disk(url)
        if disk is not None and disk.next_update_utc and now < disk.next_update_utc:
            return disk  # still validated by the caller like a fresh download
    # HTTP CRLs are authenticated by the issuer signature, not the transport.
    try:
        with requests.get(url, timeout=15, stream=True, allow_redirects=False) as response:
            if response.status_code != 200:
                raise ValueError("MDS CRL download failed")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > _MAX_SIZE:
                    raise ValueError("MDS CRL exceeds size limit")
                chunks.append(chunk)
    except requests.RequestException:
        raise ValueError("MDS CRL download failed") from None
    crl = x509.load_der_x509_crl(b"".join(chunks))
    # Cache only after validation in check_chain_revocation.
    return crl


def _validate_crl(crl, cert, issuer, now):
    from cryptography import x509

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
        raise RevokedError("MDS signer certificate revoked")


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
            # First try the cache; if a cached CRL fails validation (corrupt,
            # forged, wrong issuer), drop it and try one fresh download.
            for allow_cache in (True, False):
                cached = allow_cache and _has_cached(url, now)
                try:
                    crl = _fetch_crl(url, allow_cache=allow_cache)
                    _validate_crl(crl, cert, issuer, now)
                    with _LOCK:
                        _CACHE[url] = crl
                    _save_disk(url, crl)
                    deadlines.append(crl.next_update_utc)
                    checked = True
                    break
                except RevokedError:
                    raise
                except Exception:
                    if not cached:
                        break  # a fresh download failed: nothing better to retry
                    _drop_cached(url)
            if checked:
                break
        if not checked:
            raise ValueError("MDS revocation status unavailable or revoked")

    return min(deadlines)
