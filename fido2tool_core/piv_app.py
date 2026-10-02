"""PIV smart card application (certificates for Windows/macOS login, VPN, S/MIME).

YubiKey PIV. PINs, the PUK and management keys are only passed through to the
key for the one operation that needs them and never kept.

Management key handling, in this order:
1. PIN-protected (ykman "protected" mode, stored on the key): derived after
   verifying the PIN.
2. The factory default key.
3. A key the user types in (hex).
"""

import logging
from datetime import datetime, timedelta, timezone

from fido2tool_core.cards import CardError, map_card_error

logger = logging.getLogger(__name__)

# Slots shown by default; retired slots only when they hold something
MAIN_SLOTS = ("9a", "9c", "9d", "9e")
KEY_TYPES = ("ECCP256", "ECCP384", "RSA2048", "RSA3072", "RSA4096", "ED25519")
MIN_PIN = 6
MAX_PIN = 8


def _session(conn):
    from yubikit.piv import PivSession
    try:
        return PivSession(conn)
    except Exception as e:
        raise map_card_error(e) from None


def _slot(name: str):
    from yubikit.piv import SLOT
    try:
        return SLOT(int(name, 16))
    except (TypeError, ValueError):
        raise CardError("Invalid slot.", "invalid_input") from None


def normalize_slot(name: str) -> str:
    """Canonical application-key slot; the attestation key is never a target."""
    from yubikit.piv import SLOT
    slot = _slot(name)
    if slot == SLOT.ATTESTATION:
        raise CardError("The attestation slot cannot hold an application key.", "invalid_input")
    return f"{int(slot):02x}"


def _has(session, version) -> bool:
    return session.version >= version


def _pin_error(e, which="pin"):
    from yubikit.core.smartcard import ApduError
    from yubikit.piv import InvalidPinError

    if isinstance(e, InvalidPinError):
        n = e.attempts_remaining
        if n == 0:
            return CardError("Blocked.", f"piv_{which}_blocked")
        return CardError(f"Wrong {which.upper()} ({n} attempts left).", f"piv_{which}_invalid", retries=n)
    if isinstance(e, ApduError) and e.sw == 0x6983:
        return CardError("Blocked.", f"piv_{which}_blocked")
    return map_card_error(e)


def _cert_info(cert) -> dict:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algo = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algo = {"secp256r1": "ECC P-256", "secp384r1": "ECC P-384"}.get(key.curve.name, key.curve.name)
    elif isinstance(key, ed25519.Ed25519PublicKey):
        algo = "Ed25519"
    else:
        algo = type(key).__name__
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after < now,
        "expires_soon": now <= not_after < now + timedelta(days=30),
        "algorithm": algo,
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
    }


def info(conn) -> dict:
    from yubikit.core.smartcard import ApduError, SW
    from yubikit.piv import PIN_POLICY, SLOT, TOUCH_POLICY
    from ykman.piv import get_pivman_data

    session = _session(conn)
    metadata = _has(session, (5, 3, 0))
    try:
        pin = {"attempts": None, "default": None, "puk_attempts": None, "puk_default": None}
        if metadata:
            pm, pk = session.get_pin_metadata(), session.get_puk_metadata()
            pin.update(attempts=pm.attempts_remaining, default=pm.default_value,
                       puk_attempts=pk.attempts_remaining, puk_default=pk.default_value)
        else:
            pin["attempts"] = session.get_pin_attempts()
        pivman = get_pivman_data(session)
        mgmt = {"protected": pivman.has_protected_key, "type": session.management_key_type.name,
                "default": None, "touch": None}
        if metadata:
            mm = session.get_management_key_metadata()
            mgmt.update(default=mm.default_value, touch=mm.touch_policy != TOUCH_POLICY.NEVER)
        elif not pivman.has_protected_key:
            mgmt["default"] = _is_default_mgmt(session)
        slots = []
        for slot in SLOT:
            if slot == SLOT.ATTESTATION:
                continue
            name = f"{int(slot):02x}"
            entry = {"slot": name, "cert": None, "key": None}
            try:
                entry["cert"] = _cert_info(session.get_certificate(slot))
            except ApduError as e:
                if e.sw != SW.FILE_NOT_FOUND:
                    raise
            except ValueError:
                # Data is there but is no certificate we can parse: the slot is
                # occupied (the overwrite guard must see that), it just cannot be
                # shown – one odd object must not hide the whole PIV page.
                entry["cert"] = {"unreadable": True}
            if metadata:
                try:
                    sm = session.get_slot_metadata(slot)
                    entry["key"] = {
                        "type": sm.key_type.name,
                        "generated": sm.generated,
                        "pin_policy": PIN_POLICY(sm.pin_policy).name.lower(),
                        "touch_policy": TOUCH_POLICY(sm.touch_policy).name.lower(),
                    }
                except ApduError as e:
                    if e.sw != SW.REFERENCE_DATA_NOT_FOUND:
                        raise
            if name in MAIN_SLOTS or entry["cert"] or entry["key"]:
                slots.append(entry)
    except CardError:
        raise
    except Exception as e:
        raise map_card_error(e) from None
    return {
        "version": str(session.version),
        "pin": pin,
        "management_key": mgmt,
        "slots": slots,
        "can_delete_key": _has(session, (5, 7, 0)),
        "key_types": [k for k in KEY_TYPES
                      if k not in ("ED25519", "RSA3072", "RSA4096") or _has(session, (5, 7, 0))],
        "metadata": metadata,
    }


def _is_default_mgmt(session) -> bool:
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY
    try:
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        return True
    except Exception:
        return False


def _check_pin(pin: str, code: str):
    if not isinstance(pin, str) or not (MIN_PIN <= len(pin.encode()) <= MAX_PIN):
        raise CardError(f"{MIN_PIN}–{MAX_PIN} characters.", code, min=MIN_PIN, max=MAX_PIN)


def change_pin(conn, which: str, current: str, new: str) -> None:
    from ykman.piv import pivman_change_pin
    session = _session(conn)
    if which == "puk":
        _check_pin(new, "piv_puk_length")
        try:
            session.change_puk(current or "", new)
        except Exception as e:
            raise _pin_error(e, "puk") from None
    else:
        _check_pin(new, "piv_pin_length")
        try:
            # Keeps a PIN-protected management key in sync
            pivman_change_pin(session, current or "", new)
        except Exception as e:
            raise _pin_error(e, "pin") from None


def unblock_pin(conn, puk: str, new_pin: str) -> None:
    session = _session(conn)
    _check_pin(new_pin, "piv_pin_length")
    try:
        session.unblock_pin(puk or "", new_pin)
    except Exception as e:
        raise _pin_error(e, "puk") from None


def _authenticate(session, pin: str | None, management_key: str | None):
    """Authenticate with the management key (see module docstring)."""
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY
    from ykman.piv import get_pivman_data, get_pivman_protected_data

    pivman = get_pivman_data(session)
    if pivman.has_protected_key:
        _verify_pin(session, pin)
        try:
            key = get_pivman_protected_data(session).key
            session.authenticate(key)
            return
        except Exception as e:
            raise map_card_error(e) from None
    if management_key:
        try:
            key = bytes.fromhex(management_key.replace(" ", ""))
        except ValueError:
            raise CardError("The management key must be hexadecimal.", "piv_mgmt_invalid") from None
        try:
            session.authenticate(key)
            return
        except Exception:
            raise CardError("Wrong management key.", "piv_mgmt_invalid") from None
    try:
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
    except Exception:
        raise CardError("This key uses a custom management key. Enter it to continue.",
                        "piv_mgmt_required") from None


def _verify_pin(session, pin):
    try:
        session.verify_pin(pin or "")
    except Exception as e:
        raise _pin_error(e, "pin") from None


def generate(conn, slot: str, key_type: str, subject: str, days: int, pin: str,
             management_key: str | None = None, pin_policy: str = "default",
             touch_policy: str = "default") -> None:
    """New key pair in the slot with a self-signed certificate."""
    from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY
    from ykman.piv import generate_self_signed_certificate, parse_rfc4514_string

    if key_type not in KEY_TYPES:
        raise CardError("Unsupported key type.", "invalid_input")
    subject = (subject or "").strip()
    if not subject:
        raise CardError("Please enter a name.", "invalid_input")
    if "=" not in subject:
        subject = f"CN={subject}"
    try:
        parse_rfc4514_string(subject)
    except Exception:
        raise CardError("The name is not a valid certificate subject.", "piv_subject_invalid") from None
    days = max(1, min(int(days or 365), 3650))
    try:
        pin_p = PIN_POLICY[pin_policy.upper()]
        touch_p = TOUCH_POLICY[touch_policy.upper()]
    except KeyError:
        raise CardError("Invalid setting.", "invalid_input") from None
    session = _session(conn)
    target = _slot(slot)
    # Check the PIN before anything is changed: a wrong PIN must not leave
    # the slot with a new key and an old, non-matching certificate
    _verify_pin(session, pin)
    _authenticate(session, pin, management_key)
    try:
        public_key = session.generate_key(target, KEY_TYPE[key_type], pin_p, touch_p)
    except Exception as e:
        raise map_card_error(e) from None
    _verify_pin(session, pin)
    now = datetime.now(timezone.utc)
    try:
        cert = generate_self_signed_certificate(session, target, public_key, subject, now, now + timedelta(days=days))
        session.put_certificate(target, cert)
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("PIV key generated in slot %s", slot)


def import_certificate(conn, slot: str, pem: str, pin: str | None = None,
                       management_key: str | None = None) -> None:
    from cryptography import x509
    try:
        data = (pem or "").strip().encode()
        cert = (x509.load_pem_x509_certificate(data) if data.startswith(b"-----")
                else x509.load_der_x509_certificate(bytes.fromhex(pem)))
    except Exception:
        raise CardError("This is not a valid certificate (PEM).", "piv_cert_invalid") from None
    session = _session(conn)
    target = _slot(slot)
    _authenticate(session, pin, management_key)
    try:
        session.put_certificate(target, cert)
    except Exception as e:
        raise map_card_error(e) from None


def export_certificate(conn, slot: str) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding
    session = _session(conn)
    try:
        cert = session.get_certificate(_slot(slot))
    except Exception:
        raise CardError("This slot holds no certificate.", "not_found", status=404) from None
    return cert.public_bytes(Encoding.PEM).decode()


def delete(conn, slot: str, pin: str | None = None, management_key: str | None = None,
           key: bool = False) -> None:
    session = _session(conn)
    target = _slot(slot)
    _authenticate(session, pin, management_key)
    try:
        try:
            session.delete_certificate(target)
        except Exception:
            pass  # no certificate is fine when deleting the key
        if key and _has(session, (5, 7, 0)):
            session.delete_key(target)
    except Exception as e:
        raise map_card_error(e) from None


def protect_management_key(conn, pin: str, management_key: str | None = None) -> None:
    """Replace the (default) management key by a random one stored PIN-protected
    on the key – as `ykman piv access change-management-key --protect` does."""
    from yubikit.piv import MANAGEMENT_KEY_TYPE
    from ykman.piv import generate_random_management_key, pivman_set_mgm_key

    session = _session(conn)
    _authenticate(session, pin, management_key)
    _verify_pin(session, pin)
    algorithm = (MANAGEMENT_KEY_TYPE.AES192 if _has(session, (5, 4, 0)) else MANAGEMENT_KEY_TYPE.TDES)
    try:
        pivman_set_mgm_key(session, generate_random_management_key(algorithm), algorithm, store_on_device=True)
    except Exception as e:
        raise map_card_error(e) from None


def reset(conn) -> None:
    session = _session(conn)
    try:
        session.reset()
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("PIV application reset")
