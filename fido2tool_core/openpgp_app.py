"""OpenPGP card application (GnuPG keys on the security key).

Works with YubiKeys and other OpenPGP 3.x cards (e.g. Token2). PINs are only
passed through to the card for the one operation that needs them and never
kept.
"""

import logging
from datetime import datetime, timezone

from fido2tool_core.cards import CardError, map_card_error

logger = logging.getLogger(__name__)

SLOTS = {"sig": 1, "dec": 2, "aut": 3}  # KEY_REF values
MIN_USER_PIN = 6
MIN_ADMIN_PIN = 8
MAX_PIN = 127

CURVE_NAMES = {
    "SECP256R1": "NIST P-256", "SECP384R1": "NIST P-384", "SECP521R1": "NIST P-521",
    "BrainpoolP256R1": "Brainpool P-256", "BrainpoolP384R1": "Brainpool P-384",
    "BrainpoolP512R1": "Brainpool P-512", "X25519": "Curve25519", "Ed25519": "Ed25519",
    "SECP256K1": "secp256k1",
}


def _session(conn):
    from yubikit.core import Version
    from yubikit.core.smartcard import ApduError
    from yubikit.openpgp import OpenPgpSession

    class _Session(OpenPgpSession):
        # Non-YubiKey cards don't know Yubico's GET VERSION instruction; treat
        # them as a plain OpenPGP card without YubiKey extras (touch policies).
        def _read_version(self):
            try:
                return super()._read_version()
            except ApduError:
                self._generic = True
                return Version(1, 0, 6)

    try:
        session = _Session(conn)
    except CardError:
        raise
    except Exception as e:
        raise map_card_error(e) from None
    session._generic = getattr(session, "_generic", False)
    return session


def _pin_error(e, which="user"):
    from yubikit.core.smartcard import ApduError
    from yubikit.openpgp import InvalidPinError

    if isinstance(e, InvalidPinError):
        n = e.attempts_remaining
        if n == 0:
            return CardError("The PIN is blocked.", f"pgp_{which}_blocked")
        return CardError(f"Wrong PIN ({n} attempts left).", f"pgp_{which}_invalid", retries=n)
    if isinstance(e, ApduError) and e.sw == 0x6983:
        return CardError("The PIN is blocked.", f"pgp_{which}_blocked")
    if isinstance(e, ApduError) and e.sw == 0x6982:
        return CardError("Wrong PIN.", f"pgp_{which}_invalid")
    return map_card_error(e)


def _algorithm(attrs) -> str:
    from yubikit.openpgp import EcAttributes, RsaAttributes
    if isinstance(attrs, RsaAttributes):
        return f"RSA {attrs.n_len}"
    if isinstance(attrs, EcAttributes):
        name = getattr(attrs.oid, "name", None) or str(attrs.oid)
        return CURVE_NAMES.get(name, name)
    return "?"


def _fingerprint(fp: bytes) -> str:
    h = fp.hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def info(conn) -> dict:
    from yubikit.openpgp import DO, KEY_REF, KEY_STATUS, PIN_POLICY, UIF

    session = _session(conn)
    try:
        data = session.get_application_related_data()
        disc = data.discretionary
        pw = disc.pw_status
        fingerprints = disc.fingerprints
        times = disc.generation_times
        try:
            key_info = session.get_key_information()
        except Exception:
            key_info = {}
        keys = []
        for slot, ref in SLOTS.items():
            ref = KEY_REF(ref)
            fp = fingerprints.get(ref, b"")
            present = bool(fp and any(fp))
            status = key_info.get(ref)
            entry = {"slot": slot, "present": present}
            try:
                entry["algorithm"] = _algorithm(disc.attributes_sig if slot == "sig" else
                                                disc.attributes_dec if slot == "dec" else disc.attributes_aut)
            except Exception:
                entry["algorithm"] = None
            if present:
                entry["fingerprint"] = _fingerprint(fp)
                created = times.get(ref) or 0
                entry["created"] = (datetime.fromtimestamp(created, timezone.utc).isoformat()
                                    if created else None)
                entry["origin"] = ("generated" if status == KEY_STATUS.GENERATED else
                                   "imported" if status == KEY_STATUS.IMPORTED else None)
            touch = None
            if not session._generic:
                try:
                    touch = {UIF.OFF: "off", UIF.ON: "on", UIF.FIXED: "fixed",
                             UIF.CACHED: "cached", UIF.CACHED_FIXED: "cached_fixed"}.get(session.get_uif(ref))
                except Exception:
                    touch = None
            entry["touch"] = touch
            keys.append(entry)
        try:
            counter = session.get_signature_counter()
        except Exception:
            counter = None
        name = url = ""
        try:
            holder = session.get_data(DO.CARDHOLDER_RELATED_DATA)
            name = _cardholder_name(holder)
        except Exception:
            pass
        try:
            url = session.get_data(DO.URL).decode("utf-8", "replace")
        except Exception:
            pass
    except CardError:
        raise
    except Exception as e:
        raise map_card_error(e) from None
    aid = session.aid
    return {
        "spec": f"{aid.version[0]}.{aid.version[1]}",
        "serial": str(aid.serial) if aid.serial else None,
        "yubikey": not session._generic,
        "keys": keys,
        "signature_counter": counter,
        "pin": {
            "user": pw.attempts_user, "admin": pw.attempts_admin, "reset": pw.attempts_reset,
            "sign_every_time": pw.pin_policy_user == PIN_POLICY.ALWAYS,
        },
        "name": name,
        "url": url,
        "can_touch": not session._generic,
    }


def _cardholder_name(holder: bytes) -> str:
    """Name (tag 5B) from the cardholder related data (tag 65); "Last<<First" format."""
    from yubikit.core import Tlv
    try:
        inner = Tlv.unpack(0x65, holder)
    except Exception:
        inner = holder
    for tlv in Tlv.parse_list(inner):
        if tlv.tag == 0x5B:
            raw = tlv.value.decode("latin-1", "replace")
            if "<<" in raw:
                last, _, first = raw.partition("<<")
                return f"{first.replace('<', ' ')} {last.replace('<', ' ')}".strip()
            return raw.replace("<", " ").strip()
    return ""


def _check_pin(pin: str, minimum: int, code: str):
    if not isinstance(pin, str) or len(pin.encode()) < minimum:
        raise CardError(f"At least {minimum} characters.", code, min=minimum)
    if len(pin.encode()) > MAX_PIN:
        raise CardError("Too long.", "too_long")


def _verify_admin(session, admin_pin: str):
    try:
        session.verify_admin(admin_pin or "")
    except Exception as e:
        raise _pin_error(e, "admin") from None


def change_pin(conn, which: str, current: str, new: str) -> None:
    session = _session(conn)
    if which == "admin":
        _check_pin(new, MIN_ADMIN_PIN, "pgp_admin_short")
        try:
            session.change_admin(current or "", new)
        except Exception as e:
            raise _pin_error(e, "admin") from None
    else:
        _check_pin(new, MIN_USER_PIN, "pgp_user_short")
        try:
            session.change_pin(current or "", new)
        except Exception as e:
            raise _pin_error(e, "user") from None


def unblock_pin(conn, admin_pin: str, new_pin: str) -> None:
    """Set a new user PIN with the admin PIN (also clears a blocked PIN)."""
    session = _session(conn)
    _check_pin(new_pin, MIN_USER_PIN, "pgp_user_short")
    _verify_admin(session, admin_pin)
    try:
        session.reset_pin(new_pin)
    except Exception as e:
        raise map_card_error(e) from None


def set_touch(conn, slot: str, policy: str, admin_pin: str) -> None:
    """YubiKey only. 'fixed' variants are deliberately not offered (irreversible)."""
    from yubikit.openpgp import KEY_REF, UIF

    if slot not in SLOTS or policy not in ("off", "on", "cached"):
        raise CardError("Invalid setting.", "invalid_input")
    session = _session(conn)
    if session._generic:
        raise CardError("This key has no touch policy.", "unsupported")
    current = session.get_uif(KEY_REF(SLOTS[slot]))
    if current in (UIF.FIXED, UIF.CACHED_FIXED):
        raise CardError("The touch policy of this key is fixed.", "pgp_touch_fixed")
    _verify_admin(session, admin_pin)
    try:
        session.set_uif(KEY_REF(SLOTS[slot]), {"off": UIF.OFF, "on": UIF.ON, "cached": UIF.CACHED}[policy])
    except Exception as e:
        raise map_card_error(e) from None


def set_signature_pin(conn, every_time: bool, admin_pin: str) -> None:
    from yubikit.openpgp import PIN_POLICY
    session = _session(conn)
    _verify_admin(session, admin_pin)
    try:
        session.set_signature_pin_policy(PIN_POLICY.ALWAYS if every_time else PIN_POLICY.ONCE)
    except Exception as e:
        raise map_card_error(e) from None


def set_cardholder(conn, name: str, url: str, admin_pin: str) -> None:
    from yubikit.openpgp import DO
    name = (name or "").strip()
    url = (url or "").strip()
    if len(name) > 39 or len(url) > 254:
        raise CardError("Too long.", "too_long")
    try:
        encoded_name = name.encode("latin-1")
    except UnicodeEncodeError:
        raise CardError("The name may only contain Latin letters.", "pgp_name_charset") from None
    if url and not url.lower().startswith(("https://", "http://")):
        raise CardError("The URL must start with https://.", "invalid_input")
    # OpenPGP stores "Last<<First"; take the last word as the surname
    if " " in name:
        first, _, last = name.rpartition(" ")
        encoded_name = f"{last}<<{first}".replace(" ", "<").encode("latin-1")
    session = _session(conn)
    _verify_admin(session, admin_pin)
    try:
        session.put_data(DO.NAME, encoded_name)
        session.put_data(DO.URL, url.encode())
    except Exception as e:
        raise map_card_error(e) from None


def reset(conn) -> None:
    session = _session(conn)
    try:
        session.reset()
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("OpenPGP application reset")
