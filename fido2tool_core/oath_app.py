"""OATH authenticator (TOTP/HOTP codes) on the key's smart card interface.

A password-protected OATH application is unlocked with the password; only the
derived access key is kept in memory for a few minutes, never the password.
"""

import logging
import threading
import time

from fido2tool_core.cards import CardError, map_card_error

logger = logging.getLogger(__name__)

KEY_TTL = 300
_keys: dict[str, tuple[bytes, float]] = {}  # OATH device id -> (access key, expires)
_keys_lock = threading.Lock()


def _remember_key(device_id: str, key: bytes):
    with _keys_lock:
        _keys[device_id] = (key, time.monotonic() + KEY_TTL)


def forget_all():
    with _keys_lock:
        _keys.clear()


def purge_expired():
    now = time.monotonic()
    with _keys_lock:
        for device_id in [d for d, (_, exp) in _keys.items() if exp <= now]:
            del _keys[device_id]


def _session(conn, need_unlock=True):
    from yubikit.oath import OathSession
    try:
        session = OathSession(conn)
    except Exception as e:
        raise map_card_error(e) from None
    if need_unlock and session.locked:
        with _keys_lock:
            entry = _keys.get(session.device_id)
        if not entry or entry[1] <= time.monotonic():
            purge_expired()
            raise CardError("Enter the authenticator password.", "oath_locked", status=401)
        try:
            session.validate(entry[0])
        except Exception:
            with _keys_lock:
                _keys.pop(session.device_id, None)
            raise CardError("Enter the authenticator password.", "oath_locked", status=401) from None
    return session


def status(conn) -> dict:
    session = _session(conn, need_unlock=False)
    with _keys_lock:
        entry = _keys.get(session.device_id)
    unlocked = not session.locked or bool(entry and entry[1] > time.monotonic())
    return {"password": session.has_key, "unlocked": unlocked, "version": str(session.version)}


def unlock(conn, password: str):
    session = _session(conn, need_unlock=False)
    if not session.locked:
        return
    key = session.derive_key(password or "")
    try:
        session.validate(key)
    except Exception:
        raise CardError("Wrong authenticator password.", "oath_wrong_password") from None
    _remember_key(session.device_id, key)


def _account(cred, code=None) -> dict:
    from yubikit.oath import OATH_TYPE
    totp = cred.oath_type == OATH_TYPE.TOTP
    return {
        "id": cred.id.hex(),
        "issuer": cred.issuer or "",
        "name": cred.name,
        "type": "TOTP" if totp else "HOTP",
        "period": cred.period if totp else None,
        "touch": bool(cred.touch_required),
        "code": code.value if code else None,
        "valid_to": code.valid_to if code else None,
    }


def list_accounts(conn) -> list[dict]:
    session = _session(conn)
    try:
        codes = session.calculate_all()
    except Exception as e:
        raise map_card_error(e) from None
    accounts = [_account(cred, code) for cred, code in codes.items()]
    accounts.sort(key=lambda a: ((a["issuer"] or a["name"]).lower(), a["name"].lower()))
    return accounts


def _find(session, account_id: str):
    try:
        wanted = bytes.fromhex(account_id or "")
    except ValueError:
        raise CardError("Invalid account.", "invalid_input") from None
    for cred in session.list_credentials():
        if cred.id == wanted:
            return cred
    raise CardError("This account no longer exists.", "not_found", status=404)


def calculate(conn, account_id: str) -> dict:
    """Code for one account (touch accounts block until the key is touched)."""
    session = _session(conn)
    cred = _find(session, account_id)
    try:
        code = session.calculate_code(cred)
    except Exception as e:
        if "timeout" in str(e).lower() or "6985" in str(e):
            raise CardError("The key was not touched in time.", "timeout") from None
        raise map_card_error(e) from None
    return _account(cred, code)


def add(conn, uri: str | None = None, issuer: str = "", name: str = "", secret: str = "",
        oath_type: str = "TOTP", digits: int = 6, period: int = 30, algorithm: str = "SHA1",
        touch: bool = False) -> dict:
    from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, parse_b32_key

    try:
        if uri:
            data = CredentialData.parse_uri(uri.strip())
        else:
            if not name.strip() or not secret.strip():
                raise CardError("Account name and secret are required.", "invalid_input")
            data = CredentialData(
                name=name.strip(),
                oath_type=OATH_TYPE[oath_type],
                hash_algorithm=HASH_ALGORITHM[algorithm],
                secret=parse_b32_key(secret),
                digits=int(digits),
                period=int(period),
                issuer=issuer.strip() or None,
            )
    except CardError:
        raise
    except Exception:
        raise CardError("The account data is invalid (check the secret or the otpauth:// link).",
                        "invalid_input") from None
    if data.digits not in (6, 7, 8) or not (1 <= data.period <= 300):
        raise CardError("Unsupported digits or period.", "invalid_input")
    if len(data.get_id()) > 64:
        raise CardError("Issuer and account name are too long.", "name_too_long", max=64)

    session = _session(conn)
    if any(c.id == data.get_id() for c in session.list_credentials()):
        raise CardError("An account with this name already exists.", "exists")
    try:
        cred = session.put_credential(data, touch_required=bool(touch))
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("OATH account added")
    return _account(cred)


def rename(conn, account_id: str, issuer: str, name: str) -> None:
    session = _session(conn)
    cred = _find(session, account_id)
    if not (name or "").strip():
        raise CardError("Please enter a name.", "invalid_input")
    try:
        session.rename_credential(cred.id, name.strip(), (issuer or "").strip() or None)
    except Exception as e:
        raise CardError(f"This key cannot rename accounts ({e}).", "unsupported") from None


def delete(conn, account_id: str) -> None:
    session = _session(conn)
    cred = _find(session, account_id)
    try:
        session.delete_credential(cred.id)
    except Exception as e:
        raise map_card_error(e) from None
    logger.info("OATH account deleted")


def set_password(conn, password: str | None) -> None:
    """Set/change the password; an empty password removes it."""
    session = _session(conn)
    try:
        if password:
            key = session.derive_key(password)
            session.set_key(key)
            _remember_key(session.device_id, key)
        else:
            session.unset_key()
    except Exception as e:
        raise map_card_error(e) from None


def reset(conn) -> None:
    session = _session(conn, need_unlock=False)
    try:
        session.reset()
    except Exception as e:
        raise map_card_error(e) from None
    with _keys_lock:
        _keys.pop(session.device_id, None)
    logger.info("OATH application reset")
