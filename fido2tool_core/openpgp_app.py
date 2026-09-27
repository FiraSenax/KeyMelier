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
        "algorithms": algorithms_for(session),
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
        raise CardError("This key has no touch policy.", "unsupported", reason="touch_policy")
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
    if url and not url.lower().startswith("https://"):
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


# ── Key generation ───────────────────────────────────────────────────────────

SHA256_DIGEST_INFO = bytes.fromhex("3031300D060960864801650304020105000420")

ALGORITHMS = {
    # name: (primary/auth, encryption) – "ed25519" means Ed25519 + Cv25519
    "ed25519": ("Ed25519", "X25519"),
    "p256": ("SECP256R1", "SECP256R1"),
    "rsa2048": (2048, 2048),
    "rsa4096": (4096, 4096),
}


def algorithms_for(session) -> list[str]:
    if session._generic:
        return ["rsa2048"]  # other cards: keep their default attributes
    if session.version >= (5, 2, 0):
        return ["ed25519", "p256", "rsa2048", "rsa4096"]
    return ["rsa2048", "rsa4096"]


def _check_user_id(name: str, email: str) -> str:
    import re
    name = (name or "").strip()
    email = (email or "").strip()
    if not name or len(name) > 100:
        raise CardError("Please enter a name.", "invalid_input")
    if any(c in name for c in "<>\n\r"):
        raise CardError("The name must not contain < or >.", "invalid_input")
    if email and not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", email):
        raise CardError("The e-mail address is not valid.", "pgp_email_invalid")
    return f"{name} <{email}>" if email else name


def generate_keys(conn, algorithm: str, name: str, email: str, expire_days: int,
                  admin_pin: str, user_pin: str) -> dict:
    """Generate signature, encryption and authentication keys on the card and
    return the OpenPGP public key and a revocation certificate (armored).

    Existing OpenPGP keys on the card are replaced.
    """
    import time

    from cryptography.hazmat.primitives import hashes
    from yubikit.core.smartcard import ApduError
    from yubikit.openpgp import KEY_REF, OID, RSA_SIZE, Prehashed

    from fido2tool_core import pgp_packets as P

    user_id = _check_user_id(name, email)
    session = _session(conn)
    if algorithm not in algorithms_for(session):
        raise CardError("This key does not support that algorithm.", "unsupported", reason="algorithm")
    expire_days = int(expire_days or 0)
    if expire_days < 0 or expire_days > 3650 * 2:
        raise CardError("Invalid validity.", "invalid_input")
    try:
        session.verify_pin(user_pin or "")  # check early: nothing is changed yet
    except Exception as e:
        raise _pin_error(e, "user") from None
    _verify_admin(session, admin_pin)

    main, enc = ALGORITHMS[algorithm]
    created = int(time.time())

    def gen(ref, spec):
        if isinstance(spec, int):
            return session.generate_rsa_key(ref, RSA_SIZE(spec))
        return session.generate_ec_key(ref, OID[spec])

    try:
        keys = {}
        for ref, spec, encryption in ((KEY_REF.SIG, main, False), (KEY_REF.DEC, enc, True), (KEY_REF.AUT, main, False)):
            keys[ref] = P.public_key(gen(ref, spec), created, encryption=encryption)
        for ref, key in keys.items():
            session.set_fingerprint(ref, key.fingerprint)
            session.set_generation_time(ref, created)
    except CardError:
        raise
    except ApduError as e:
        raise map_card_error(e) from None
    except Exception as e:
        raise CardError(f"Key generation failed: {e}", "card_error") from None

    primary = keys[KEY_REF.SIG]

    def signer(digest: bytes) -> bytes:
        # Re-verify: the signature PIN may be valid for a single signature only
        try:
            session.verify_pin(user_pin)
        except Exception as e:
            raise _pin_error(e, "user") from None
        if primary.algorithm == P.RSA:
            # yubikit's sign() cannot take a precomputed hash for RSA: send
            # PSO:COMPUTE DIGITAL SIGNATURE with the SHA-256 DigestInfo ourselves
            raw = session.protocol.send_apdu(0, 0x2A, 0x9E, 0x9A, SHA256_DIGEST_INFO + digest)
        else:
            raw = session.sign(digest, Prehashed(hashes.SHA256()))
        return P.signature_mpis(primary.algorithm, raw)

    try:
        body = P.transferable_key(
            primary, user_id,
            [(keys[KEY_REF.DEC], P.FLAG_ENCRYPT), (keys[KEY_REF.AUT], P.FLAG_AUTH)],
            signer, created, expire_days * 86400 if expire_days else None)
        revocation = P.revocation(primary, signer, created)
    except CardError:
        raise
    except Exception as e:
        raise CardError(f"Signing on the key failed: {e}", "card_error") from None
    fingerprint = primary.fingerprint.hex().upper()
    logger.info("OpenPGP keys generated on the card")
    return {
        "fingerprint": _fingerprint(primary.fingerprint),
        "user_id": user_id,
        "public_key": P.armor(body, comment=f"{fingerprint[-16:]} – created on a security key with KeyMelier"),
        "revocation": P.armor(revocation, comment="Revocation certificate – import it only if the key is lost"),
        "filename": f"{fingerprint[-16:]}",
    }
