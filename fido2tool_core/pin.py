"""PIN management: status, set, change.

PINs are only ever held in memory for the duration of a single call; they are
never logged or persisted.
"""

import logging

logger = logging.getLogger(__name__)

MAX_PIN_BYTES = 63  # CTAP2: PIN is padded to 64 bytes, must be < 64 bytes UTF-8


class PinError(Exception):
    """User-facing PIN error. `code` is a stable identifier for the UI."""

    def __init__(self, message: str, code: str = "error", status: int = 400, **extra):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.extra = extra


def _ctap_error_to_pin_error(e, client_pin=None) -> PinError:
    from fido2.ctap import CtapError

    code = e.code
    if code == CtapError.ERR.PIN_INVALID:
        retries = None
        if client_pin is not None:
            try:
                retries, _ = client_pin.get_pin_retries()
            except Exception:
                pass
        msg = "Wrong PIN."
        if retries is not None:
            msg += f" {retries} attempt{'s' if retries != 1 else ''} left before the key locks."
        return PinError(msg, "pin_invalid", retries=retries)
    if code == CtapError.ERR.PIN_AUTH_BLOCKED:
        return PinError(
            "Too many wrong attempts in a row. Unplug the key and plug it back in to try again.",
            "pin_auth_blocked",
        )
    if code == CtapError.ERR.PIN_BLOCKED:
        return PinError(
            "The PIN is blocked. Only a factory reset can make the key usable again "
            "(this deletes all passkeys on it).",
            "pin_blocked",
        )
    if code == CtapError.ERR.PIN_POLICY_VIOLATION:
        return PinError(
            "The key rejected the new PIN (too short, too simple, or equal to the old PIN).",
            "pin_policy_violation",
        )
    if code == CtapError.ERR.PIN_NOT_SET:
        return PinError("No PIN is set on this key.", "pin_not_set")
    if code == CtapError.ERR.NOT_ALLOWED:
        return PinError("The key does not allow this operation right now.", "not_allowed")
    return PinError(f"The key reported an error: {code.name if hasattr(code, 'name') else code}", "ctap_error")


def status(ctap2) -> dict:
    """Return the PIN/UV status of a token. No PIN or touch required."""
    from fido2.ctap2.pin import ClientPin

    info = ctap2.info
    options = info.options or {}
    supported = ClientPin.is_supported(info)
    is_set = options.get("clientPin") is True

    result = {
        "supported": supported,
        "is_set": is_set,
        "retries": None,
        "power_cycle_required": False,
        "min_length": getattr(info, "min_pin_length", 4) or 4,
        "max_bytes": MAX_PIN_BYTES,
        "force_change": bool(getattr(info, "force_pin_change", False)),
        # Built-in user verification (fingerprint): None = not present,
        # False = present but nothing enrolled, True = enrolled
        "uv": options.get("uv"),
        "uv_retries": None,
    }
    if not supported:
        return result

    client_pin = ClientPin(ctap2)
    if is_set:
        try:
            retries, power_cycle = client_pin.get_pin_retries()
            result["retries"] = retries
            result["power_cycle_required"] = bool(power_cycle)
        except Exception as e:
            logger.debug("get_pin_retries failed: %s", e)
    if options.get("uv") is True and ClientPin.is_token_supported(info):
        try:
            result["uv_retries"] = client_pin.get_uv_retries()
        except Exception as e:
            logger.debug("get_uv_retries failed: %s", e)
    return result


def _validate_new_pin(new_pin: str, min_length: int):
    if not isinstance(new_pin, str) or not new_pin:
        raise PinError("Please enter a new PIN.", "invalid_input")
    if len(new_pin) < min_length:
        raise PinError(f"The PIN must be at least {min_length} characters long.", "too_short")
    if len(new_pin.encode("utf-8")) > MAX_PIN_BYTES:
        raise PinError(f"The PIN must be at most {MAX_PIN_BYTES} bytes long.", "too_long")


def set_or_change(ctap2, new_pin: str, current_pin: str | None = None) -> str:
    """Set a PIN (if none is set) or change it. Returns 'set' or 'changed'."""
    from fido2.ctap import CtapError
    from fido2.ctap2.pin import ClientPin

    info = ctap2.info
    if not ClientPin.is_supported(info):
        raise PinError("This key does not support a PIN.", "unsupported", reason="pin")

    _validate_new_pin(new_pin, getattr(info, "min_pin_length", 4) or 4)
    client_pin = ClientPin(ctap2)
    is_set = (info.options or {}).get("clientPin") is True

    try:
        if is_set:
            if not current_pin:
                raise PinError("Please enter the current PIN.", "invalid_input")
            client_pin.change_pin(current_pin, new_pin)
            logger.info("PIN changed")
            return "changed"
        client_pin.set_pin(new_pin)
        logger.info("PIN set")
        return "set"
    except CtapError as e:
        raise _ctap_error_to_pin_error(e, client_pin) from None
