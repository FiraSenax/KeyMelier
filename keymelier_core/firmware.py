"""Vendor-aware CTAP2 firmware_version integer decoding."""

from typing import Optional


# Manufacturers known to use the packed-byte layout: 0xMMmmpp → MM.mm.pp
PACKED_BYTE_VENDORS = {
    "yubico", "feitian", "token2", "solokeys",
    "nitrokey", "google", "thetis", "hid global",
}


def decode_firmware(raw: Optional[int], manufacturer: str = "") -> str:
    """Decode the opaque CTAP2 firmware_version integer.

    Layout overview (CTAP2 spec leaves encoding vendor-defined):
      packed-byte    0x050403  → 5.4.3   (Yubico, Feitian, Token2, SoloKey, Nitrokey, most)
      packed-decimal 50403     → 5.4.3   (some obscure devices)
      word-split     0x00050004 → 5.4    (rare: upper 16-bit major, lower 16-bit minor)
    """
    if raw is None:
        return "unknown"

    mfr = manufacturer.lower()

    if mfr in PACKED_BYTE_VENDORS:
        return _packed_byte(raw)

    # Unknown vendor: try packed-byte and validate plausibility
    pb = _packed_byte(raw)
    parts = [int(x) for x in pb.split(".")]
    if parts[0] <= 50 and parts[1] <= 99 and parts[2] <= 99:
        return pb

    pd = _packed_decimal(raw)
    if pd:
        return pd

    ws_major = (raw >> 16) & 0xFFFF
    ws_minor = raw & 0xFFFF
    if ws_major <= 999 and ws_minor <= 999:
        return f"{ws_major}.{ws_minor}"

    return f"0x{raw:08X}"


def parse_firmware_str(version_str: str) -> Optional[tuple]:
    """Parse 'major.minor.patch' (or 'major.minor') into a comparable int tuple."""
    if not version_str or version_str in ("unknown",) or version_str.startswith("0x"):
        return None
    try:
        parts = [int(p) for p in version_str.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except ValueError:
        return None


def firmware_from_raw(raw: Optional[int], manufacturer: str = "") -> str:
    """Convenience alias — returns the decoded string or 'unknown'."""
    return decode_firmware(raw, manufacturer)


def _packed_byte(raw: int) -> str:
    major = (raw >> 16) & 0xFF
    minor = (raw >> 8) & 0xFF
    patch = raw & 0xFF
    return f"{major}.{minor}.{patch}"


def _packed_decimal(raw: int) -> Optional[str]:
    """Decode a decimal-encoded version like 50403 → 5.4.3."""
    s = str(raw)
    if len(s) < 3:
        return None
    patch = int(s[-2:])
    minor = int(s[-4:-2]) if len(s) >= 4 else 0
    major = int(s[:-4]) if len(s) > 4 else (int(s[:-2]) if len(s) <= 4 else 0)
    if minor > 99 or patch > 99:
        return None
    return f"{major}.{minor}.{patch}"
