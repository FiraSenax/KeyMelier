"""Authenticator configuration (CTAP 2.1 authenticatorConfig).

- minimum PIN length (can only be raised; lowering needs a factory reset)
- force a PIN change before the next use
- alwaysUv: require PIN/fingerprint for every use, also for U2F-style logins

Requires the key to be unlocked (see fido2tool_core.auth).
"""

import logging

from fido2tool_core import auth
from fido2tool_core.auth import AuthError

logger = logging.getLogger(__name__)

MAX_PIN_LENGTH = 63


def capabilities(ctap2) -> dict:
    from fido2.ctap2.config import Config

    info = ctap2.info
    options = info.options or {}
    return {
        "supported": Config.is_supported(info),
        "pin_set": options.get("clientPin") is True,
        "uv_unlock": auth.uv_unlock_available(info),
        "min_pin_length": getattr(info, "min_pin_length", 4) or 4,
        "can_set_min_pin": options.get("setMinPINLength") is True,
        "force_pin_change": bool(getattr(info, "force_pin_change", False)),
        # None = the key has no alwaysUv option, True/False = current state
        "always_uv": options.get("alwaysUv"),
    }


def _config(token_id: str, ctap2):
    from fido2.ctap2.config import Config

    if not Config.is_supported(ctap2.info):
        raise AuthError("This key has no configurable settings.", "unsupported", reason="no_config")
    protocol, token = auth.get_token(token_id)
    return Config(ctap2, protocol, token)


def set_min_pin_length(token_id: str, ctap2, length: int) -> None:
    caps = capabilities(ctap2)
    if not caps["can_set_min_pin"]:
        raise AuthError("This key does not allow changing the minimum PIN length.", "unsupported", reason="min_pin_length")
    try:
        length = int(length)
    except (TypeError, ValueError):
        raise AuthError("Please enter a number.", "invalid_input") from None
    if length <= caps["min_pin_length"]:
        raise AuthError("The minimum PIN length can only be increased.", "min_pin_not_higher",
                        current=caps["min_pin_length"])
    if length > MAX_PIN_LENGTH:
        raise AuthError(f"At most {MAX_PIN_LENGTH} characters.", "too_long")
    cfg = _config(token_id, ctap2)
    auth.call(token_id, lambda: cfg.set_min_pin_length(min_pin_length=length))
    logger.info("Minimum PIN length set to %d", length)


def force_pin_change(token_id: str, ctap2) -> None:
    if not capabilities(ctap2)["can_set_min_pin"]:
        raise AuthError("This key does not support forcing a PIN change.", "unsupported", reason="force_pin_change")
    cfg = _config(token_id, ctap2)
    auth.call(token_id, lambda: cfg.set_min_pin_length(force_change_pin=True))
    logger.info("PIN change forced")


def set_always_uv(token_id: str, ctap2, enabled: bool) -> None:
    current = capabilities(ctap2)["always_uv"]
    if current is None:
        raise AuthError("This key does not support this setting.", "unsupported", reason="setting")
    if bool(current) == bool(enabled):
        return
    cfg = _config(token_id, ctap2)
    auth.call(token_id, cfg.toggle_always_uv)
    logger.info("alwaysUv %s", "enabled" if enabled else "disabled")
