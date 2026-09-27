"""Unlocking a key for management operations.

Unlocking with the PIN (or the built-in fingerprint sensor) yields a
pinUvAuthToken carrying every management permission the key supports
(passkeys, fingerprints). Only that token is kept in memory, per key, for a
few minutes so the user can work without re-entering the PIN. The PIN itself
is never stored. Tokens are dropped when the key is unplugged, locked from
the UI, or rejected by the key.
"""

import logging
import threading
import time

from fido2tool_core.pin import PinError, _ctap_error_to_pin_error

logger = logging.getLogger(__name__)

TOKEN_TTL = 300  # seconds; the key may expire it earlier

_tokens: dict[str, tuple[int, bytes, float]] = {}  # token_id -> (protocol, token, expires)
_tokens_lock = threading.Lock()


class AuthError(PinError):
    """User-facing error from a management operation."""


def map_ctap_error(e, client_pin=None) -> AuthError:
    from fido2.ctap import CtapError

    code = e.code
    if code in (CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.PIN_TOKEN_EXPIRED):
        return AuthError("The unlock has expired. Please unlock again.", "locked", status=401)
    if code == CtapError.ERR.UV_INVALID:
        return AuthError("Fingerprint not recognised. Try again or use the PIN.", "uv_invalid")
    if code == CtapError.ERR.UV_BLOCKED:
        return AuthError("Too many unrecognised fingerprints. Please use the PIN.", "uv_blocked")
    if code in (CtapError.ERR.USER_ACTION_TIMEOUT, CtapError.ERR.ACTION_TIMEOUT):
        return AuthError("No finger was detected in time.", "timeout")
    if code == CtapError.ERR.KEEPALIVE_CANCEL:
        return AuthError("Cancelled.", "cancelled")
    if code == CtapError.ERR.OPERATION_DENIED:
        return AuthError("The key denied the request.", "denied")
    if code == CtapError.ERR.NO_CREDENTIALS:
        return AuthError("This entry no longer exists.", "no_credentials", status=404)
    if code == CtapError.ERR.KEY_STORE_FULL:
        return AuthError("The key's storage is full.", "store_full")
    err = _ctap_error_to_pin_error(e, client_pin)
    return AuthError(err.message, err.code, **err.extra)


def forget(token_id: str) -> None:
    with _tokens_lock:
        _tokens.pop(token_id, None)


def is_unlocked(token_id: str) -> bool:
    with _tokens_lock:
        entry = _tokens.get(token_id)
        if entry and entry[2] <= time.monotonic():
            del _tokens[token_id]  # do not keep expired tokens in memory
            return False
        return bool(entry)


def uv_unlock_available(info) -> bool:
    from fido2.ctap2.pin import ClientPin

    return (info.options or {}).get("uv") is True and ClientPin.is_token_supported(info)


def _permissions(info):
    from fido2.ctap2.bio import BioEnrollment
    from fido2.ctap2.config import Config
    from fido2.ctap2.credman import CredentialManagement
    from fido2.ctap2.pin import ClientPin

    perm = ClientPin.PERMISSION(0)
    if CredentialManagement.is_supported(info):
        perm |= ClientPin.PERMISSION.CREDENTIAL_MGMT
    if BioEnrollment.is_supported(info):
        perm |= ClientPin.PERMISSION.BIO_ENROLL
    if Config.is_supported(info):
        perm |= ClientPin.PERMISSION.AUTHENTICATOR_CFG
    return perm


def unlock(token_id: str, ctap2, pin: str | None = None, use_uv: bool = False) -> None:
    """Obtain a management token with the PIN or the fingerprint sensor."""
    from fido2.ctap import CtapError
    from fido2.ctap2.pin import ClientPin

    info = ctap2.info
    if (info.options or {}).get("clientPin") is not True:
        raise AuthError("Set a PIN first – the key only allows management after PIN entry.", "pin_not_set")
    perm = _permissions(info)
    if not perm:
        raise AuthError("This key has nothing to manage.", "unsupported")

    client_pin = ClientPin(ctap2)
    try:
        if use_uv:
            if not uv_unlock_available(info):
                raise AuthError("Fingerprint unlock is not available on this key.", "unsupported")
            token = client_pin.get_uv_token(permissions=perm)
        else:
            if not pin:
                raise AuthError("Please enter the PIN.", "invalid_input")
            token = client_pin.get_pin_token(pin, permissions=perm)
    except CtapError as e:
        if e.code == CtapError.ERR.PIN_POLICY_VIOLATION and getattr(info, "force_pin_change", False):
            raise AuthError(
                "The key requires a PIN change before it can be managed.",
                "force_pin_change",
            ) from None
        raise map_ctap_error(e, client_pin) from None

    with _tokens_lock:
        _tokens[token_id] = (client_pin.protocol.VERSION, token, time.monotonic() + TOKEN_TTL)
    logger.info("Key unlocked for management (%s)", "fingerprint" if use_uv else "PIN")


def get_token(token_id: str):
    """Return (PinProtocol instance, token) or raise AuthError('locked')."""
    from fido2.ctap2.pin import ClientPin

    with _tokens_lock:
        entry = _tokens.get(token_id)
    if not entry or entry[2] <= time.monotonic():
        forget(token_id)
        raise AuthError("Unlock the key first.", "locked", status=401)
    version, token, _ = entry
    protocol = next(p for p in ClientPin.PROTOCOLS if p.VERSION == version)()
    return protocol, token


def call(token_id: str, fn):
    """Run a key operation, translating CTAP errors and dropping expired tokens."""
    from fido2.ctap import CtapError

    try:
        return fn()
    except CtapError as e:
        err = map_ctap_error(e)
        if err.code == "locked":
            forget(token_id)
        raise err from None
