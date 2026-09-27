"""Factory reset of the FIDO application.

Authenticators only accept reset within a few seconds after power-up (CTAP:
10 s) and require a touch. So the UI first *arms* a reset for a specific
model; the user then re-plugs the key, and the scanner hands the freshly
connected key to `perform` instead of starting the attestation test (which
would otherwise hold the key and wait for a touch).
"""

import logging
import threading
import time

from fido2tool_core.auth import AuthError

logger = logging.getLogger(__name__)

ARM_WINDOW = 60  # seconds the user has to re-plug the key

_armed: dict | None = None  # {"aaguid", "product_name", "expires"}
_armed_lock = threading.Lock()


def arm(record) -> dict:
    global _armed
    with _armed_lock:
        _armed = {
            "aaguid": record.aaguid,
            "serial": record.serial_number or None,
            "product_name": record.product_name,
            "expires": time.monotonic() + ARM_WINDOW,
        }
    logger.info("Reset armed for %s", record.product_name)
    return {"window": ARM_WINDOW}


def disarm() -> bool:
    global _armed
    with _armed_lock:
        was = _armed is not None
        _armed = None
    return was


def is_armed() -> bool:
    with _armed_lock:
        return _armed is not None and _armed["expires"] > time.monotonic()


def expired() -> bool:
    """True (once) if an armed reset ran out without the key being re-plugged."""
    global _armed
    with _armed_lock:
        if _armed is not None and _armed["expires"] <= time.monotonic():
            _armed = None
            return True
    return False


def claim(record) -> bool:
    """Called for every newly connected key. Returns True (and disarms) if the
    key matches the armed reset and should be reset now."""
    global _armed
    with _armed_lock:
        if (
            _armed is not None
            and _armed["expires"] > time.monotonic()
            and _armed["aaguid"] == record.aaguid
            # Same model is not enough: a backup key of that model must never
            # be wiped because it happened to be plugged in within the window
            and (_armed["serial"] is None or _armed["serial"] == (record.serial_number or None))
        ):
            _armed = None
            return True
    return False


def perform(ctap2, on_touch) -> None:
    """Reset the FIDO application. Blocks until the user touches the key."""
    from fido2.ctap import STATUS, CtapError

    def keepalive(status):
        if status == STATUS.UPNEEDED:
            on_touch()

    try:
        ctap2.reset(on_keepalive=keepalive)
    except CtapError as e:
        if e.code == CtapError.ERR.NOT_ALLOWED:
            raise AuthError(
                "The key only accepts a reset right after plugging it in. Please try again "
                "and re-plug the key a little faster.",
                "reset_too_late",
            ) from None
        if e.code in (CtapError.ERR.USER_ACTION_TIMEOUT, CtapError.ERR.ACTION_TIMEOUT):
            raise AuthError("The key was not touched in time.", "timeout") from None
        if e.code == CtapError.ERR.OPERATION_DENIED:
            raise AuthError("The reset was denied on the key.", "denied") from None
        if e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
            raise AuthError("The key refuses a reset right now. Re-plug it and try again.", "reset_too_late") from None
        raise AuthError(f"The key reported an error: {e.code}", "ctap_error") from None
    logger.info("FIDO application reset")
