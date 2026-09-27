"""YubiKey-only extras: OTP slots (short/long touch) and enabled applications
per USB/NFC.

OTP slots are reached through the key's keyboard (HID OTP) interface. On macOS
that needs the "Input Monitoring" permission for KeyMelier; without it opening
the device fails with kIOReturnNotPermitted.
"""

import logging
import sys

from fido2tool_core.cards import CardError, map_card_error

logger = logging.getLogger(__name__)

NOT_PERMITTED = -536870174  # kIOReturnNotPermitted


# ── OTP slots ────────────────────────────────────────────────────────────────

def _otp_error(e) -> CardError:
    text = str(e)
    if str(NOT_PERMITTED) in text or "not permitted" in text.lower():
        return CardError("macOS blocks access to the key's keyboard interface. Allow KeyMelier under "
                         "System Settings › Privacy & Security › Input Monitoring, then restart KeyMelier.",
                         "otp_permission")
    return CardError(f"OTP interface error: {text}", "card_error")


def _otp_device(serial: str | None):
    """(device, connection) of the HID OTP interface belonging to a YubiKey."""
    from ykman.hid import list_otp_devices
    from yubikit.core.otp import OtpConnection
    from yubikit.management import ManagementSession

    devices = list_otp_devices()
    if not devices:
        raise CardError("The key's OTP interface is not available (disabled or not a YubiKey).", "no_otp",
                        status=404)
    errors = []
    for dev in devices:
        try:
            conn = dev.open_connection(OtpConnection)
        except Exception as e:
            errors.append(e)
            continue
        try:
            info = ManagementSession(conn).read_device_info()
            if serial is None or str(info.serial) == str(serial):
                return conn
        except Exception as e:
            errors.append(e)
        conn.close()
    if errors:
        raise _otp_error(errors[0])
    raise CardError("The key's OTP interface is not available.", "no_otp", status=404)


def otp_status(serial: str | None) -> dict:
    from yubikit.yubiotp import YubiOtpSession

    conn = _otp_device(serial)
    try:
        session = YubiOtpSession(conn)
        state = session.get_config_state()
        return {
            "slots": [
                {"slot": n, "configured": bool(state.is_configured(n)),
                 "touch": bool(state.is_touch_triggered(n)) if state.is_configured(n) else None}
                for n in (1, 2)
            ],
            "led_inverted": bool(state.is_led_inverted()),
        }
    except CardError:
        raise
    except Exception as e:
        raise _otp_error(e) from None
    finally:
        conn.close()


def _access_code(code: str | None) -> bytes | None:
    if not code:
        return None
    try:
        raw = bytes.fromhex(code.strip())
    except ValueError:
        raise CardError("The access code must be 12 hexadecimal digits.", "otp_access_invalid") from None
    if len(raw) != 6:
        raise CardError("The access code must be 12 hexadecimal digits.", "otp_access_invalid")
    return raw


def otp_swap(serial: str | None) -> None:
    from yubikit.yubiotp import YubiOtpSession
    conn = _otp_device(serial)
    try:
        YubiOtpSession(conn).swap_slots()
    except Exception as e:
        raise _otp_access_error(e) from None
    finally:
        conn.close()


def otp_delete(serial: str | None, slot: int, access_code: str | None = None) -> None:
    from yubikit.yubiotp import SLOT, YubiOtpSession
    if slot not in (1, 2):
        raise CardError("Invalid slot.", "invalid_input")
    code = _access_code(access_code)
    conn = _otp_device(serial)
    try:
        YubiOtpSession(conn).delete_slot(SLOT(slot), code)
    except Exception as e:
        raise _otp_access_error(e) from None
    finally:
        conn.close()


def otp_static_password(serial: str | None, slot: int, password: str, access_code: str | None = None) -> None:
    """Program a static password (typed by the key on touch). Only characters
    that exist on the US keyboard layout are accepted."""
    from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession
    from ykman.scancodes import KEYBOARD_LAYOUT, encode

    if slot not in (1, 2):
        raise CardError("Invalid slot.", "invalid_input")
    if not password or len(password) > 38:
        raise CardError("1–38 characters.", "otp_password_length")
    try:
        scan_codes = encode(password, KEYBOARD_LAYOUT.US)
    except Exception:
        raise CardError("Use only letters, digits and common symbols (US keyboard layout).",
                        "otp_password_chars") from None
    code = _access_code(access_code)
    conn = _otp_device(serial)
    try:
        YubiOtpSession(conn).put_configuration(SLOT(slot), StaticPasswordSlotConfiguration(scan_codes), code, code)
    except Exception as e:
        raise _otp_access_error(e) from None
    finally:
        conn.close()


def otp_challenge_response(serial: str | None, slot: int, secret: str | None = None,
                           touch: bool = False, access_code: str | None = None) -> str:
    """HMAC-SHA1 challenge-response (KeePassXC, LUKS, …). Returns the secret
    (hex) so the user can keep a backup; a random one is generated if empty."""
    import os
    from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession

    if slot not in (1, 2):
        raise CardError("Invalid slot.", "invalid_input")
    if secret:
        try:
            key = bytes.fromhex(secret.replace(" ", ""))
        except ValueError:
            raise CardError("The secret must be hexadecimal.", "invalid_input") from None
        if not 1 <= len(key) <= 64:
            raise CardError("The secret must be at most 64 bytes.", "invalid_input")
    else:
        key = os.urandom(20)
    code = _access_code(access_code)
    conn = _otp_device(serial)
    try:
        config = HmacSha1SlotConfiguration(key).require_touch(bool(touch))
        YubiOtpSession(conn).put_configuration(SLOT(slot), config, code, code)
    except Exception as e:
        raise _otp_access_error(e) from None
    finally:
        conn.close()
    return key.hex()


def _otp_access_error(e) -> CardError:
    from yubikit.core import CommandError
    if isinstance(e, CardError):
        return e
    if isinstance(e, CommandError) or "not written" in str(e).lower():
        return CardError("The slot is protected by an access code (or the code is wrong).", "otp_access_required")
    return _otp_error(e)


# ── Applications per USB/NFC ─────────────────────────────────────────────────

APPS = ("OTP", "U2F", "FIDO2", "OATH", "PIV", "OPENPGP", "HSMAUTH")


def interfaces(conn) -> dict:
    from yubikit.management import CAPABILITY, TRANSPORT, ManagementSession
    try:
        info = ManagementSession(conn).read_device_info()
    except Exception as e:
        raise map_card_error(e) from None
    result = {"locked": bool(info.is_locked), "transports": {}}
    for transport in (TRANSPORT.USB, TRANSPORT.NFC):
        supported = info.supported_capabilities.get(transport)
        if not supported:
            continue
        enabled = info.config.enabled_capabilities.get(transport, CAPABILITY(0))
        result["transports"][transport.value] = {
            app: bool(enabled & CAPABILITY[app]) for app in APPS if supported & CAPABILITY[app]
        }
    return result


def set_interfaces(conn, transport: str, apps: dict) -> None:
    """Enable/disable applications on one transport. The key restarts."""
    from yubikit.management import CAPABILITY, TRANSPORT, DeviceConfig, ManagementSession

    try:
        tr = TRANSPORT(transport)
    except ValueError:
        raise CardError("Invalid interface.", "invalid_input") from None
    try:
        session = ManagementSession(conn)
        info = session.read_device_info()
    except Exception as e:
        raise map_card_error(e) from None
    if info.is_locked:
        raise CardError("The key's configuration is locked with a lock code.", "config_locked")
    supported = info.supported_capabilities.get(tr) or CAPABILITY(0)
    enabled = info.config.enabled_capabilities.get(tr, CAPABILITY(0))
    new = enabled
    for app, on in (apps or {}).items():
        if app not in APPS or not supported & CAPABILITY[app]:
            continue
        new = (new | CAPABILITY[app]) if on else (new & ~CAPABILITY[app])
    if tr == TRANSPORT.USB:
        # KeyMelier finds keys through FIDO2 and talks to them over the smart
        # card interface – keep what it needs to undo this
        if supported & CAPABILITY.FIDO2 and not new & CAPABILITY.FIDO2:
            raise CardError("FIDO2 over USB stays on – without it KeyMelier could no longer find this key.",
                            "usb_fido2_required")
    if new == enabled:
        return
    try:
        session.write_device_config(DeviceConfig({tr: new}, None, None, None), reboot=True)
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("Applications on %s changed", tr.value)


def platform_needs_input_monitoring() -> bool:
    return sys.platform == "darwin"
