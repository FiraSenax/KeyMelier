"""Vendor-specific device details that FIDO itself does not expose.

YubiKeys report neither serial number nor (on many models) firmware over
CTAP2 getInfo. Yubico's yubikit reads both – plus form factor and FIPS/NFC
flags – through the management application over the same FIDO HID
connection KeyMelier already uses, so no extra drivers are needed. Additional
read-only identity commands cover Token2's CTAPHID OTP channel and the Trussed
admin UUID on explicitly listed Solo/Nitrokey products. No applet is modified.
"""

import logging
import re
from contextlib import contextmanager
from threading import Event, Timer

logger = logging.getLogger(__name__)

YUBICO_VID = 0x1050
TOKEN2_VID = 0x349E
# The read-only Trussed admin UUID command. Never send it to a bootloader
# or infer support from a product name alone.
TRUSSED_IDS = {(0x1209, 0xBEEE), (0x20A0, 0x42B2), (0x20A0, 0x42F3)}


@contextmanager
def _identity_timeout():
    event = Event()
    timer = Timer(1.5, event.set)
    timer.daemon = True
    timer.start()
    try:
        yield event
        if event.is_set():
            raise TimeoutError()
    finally:
        timer.cancel()


def has_identity_reader(vid: int, pid: int) -> bool:
    return vid in (YUBICO_VID, TOKEN2_VID) or (vid, pid) in TRUSSED_IDS


def _read_identity(device, vid: int, pid: int) -> dict | None:
    """Read identity on this exact HID connection; no PC/SC reader guessing.

    Protocol references (no implementation copied): Token2 GET_INFO §6.10,
    keyroost-token2otp/read_serial_request and Nitrokey SDK AdminCommand.UUID.
    Unsupported/invalid responses leave the identity unavailable.
    """
    with _identity_timeout() as event:
        def keepalive(status):
            if int(status) == 2:  # UPNEEDED: an identity read must not ask for touch
                event.set()

        if (vid, pid) in TRUSSED_IDS:
            reply = device.call(0x62, b"", event=event, on_keepalive=keepalive)
            if len(reply) == 16 and reply not in (bytes(16), b"\xff" * 16):
                return {"serial": reply.hex(), "serial_source": "trussed"}
        elif vid == TOKEN2_VID:
            # CTAPHID vendor command 0x41 carries a short GET_INFO APDU.
            # D1 10 requests the serial; no PIN, seed or settings are touched.
            request = bytes.fromhex("8033000012d110") + bytes(16)
            reply = device.call(0x41, request, event=event, on_keepalive=keepalive)
            if len(reply) < 6 or reply[-2:] != b"\x90\x00" or reply[0] != 0xD1:
                return None
            size = reply[1]
            if not 2 <= size <= 32 or size % 2 or len(reply) != size + 4:
                return None
            value = reply[2:-2]
            if not re.fullmatch(b"[0-9a-fA-F]+", value):
                return None
            serial = bytes.fromhex(value.decode("ascii"))
            if serial not in (bytes(len(serial)), b"\xff" * len(serial)):
                return {"serial": serial.hex(), "serial_source": "token2"}
    return None

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
        if not has_identity_reader(vid, pid):
            return None
        try:
            return _read_identity(device, vid, pid)
        except Exception as e:
            logger.debug("Vendor identity unavailable (%s)", type(e).__name__)
            return None
    try:
        from yubikit.core import TRANSPORT
        from yubikit.management import ManagementSession

        info = ManagementSession(device).read_device_info()
    except Exception as e:
        logger.debug("YubiKey management read failed: %s", type(e).__name__)
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
