"""Vendor-specific device details that FIDO itself does not expose.

YubiKeys report neither serial number nor (on many models) firmware over
CTAP2 getInfo. Yubico's yubikit reads both – plus form factor and FIPS/NFC
flags – through the management application over the same FIDO HID
connection KeyMelier already uses, so no extra drivers are needed.
"""

import logging

logger = logging.getLogger(__name__)

YUBICO_VID = 0x1050

# yubikit FORM_FACTOR names → KeyMelier form factor ids (used for illustrations)
_FORM_FACTORS = {
    "USB_A_KEYCHAIN": "usb-a-keychain",
    "USB_A_NANO": "usb-a-nano",
    "USB_C_KEYCHAIN": "usb-c-keychain",
    "USB_C_NANO": "usb-c-nano",
    "USB_C_LIGHTNING": "usb-c-lightning",
    "USB_A_BIO": "usb-a-bio",
    "USB_C_BIO": "usb-c-bio",
}


def read(device, vid: int, pid: int) -> dict | None:
    """Return {serial, version, form_factor, fips, nfc} or None if unavailable.

    Uses the management application directly. yubikit's read_info() is
    avoided on purpose: when the key does not answer it synthesises
    placeholder values (e.g. firmware 3.0.0) instead of failing.
    """
    if vid != YUBICO_VID:
        return None
    try:
        from yubikit.core import TRANSPORT
        from yubikit.management import ManagementSession

        info = ManagementSession(device).read_device_info()
    except Exception as e:
        logger.debug("YubiKey management read failed: %s", e)
        return None

    version = tuple(info.version) if info.version else None
    if not version or version < (5, 0, 0):
        return None  # every FIDO2 YubiKey is 5.x or newer; anything else is not trustworthy
    return {
        "serial": str(info.serial) if info.serial else None,
        "version": version,
        "form_factor": _FORM_FACTORS.get(getattr(info.form_factor, "name", ""), None),
        "fips": bool(getattr(info, "is_fips", False)),
        "nfc": TRANSPORT.NFC in info.supported_capabilities,
    }
