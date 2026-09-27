"""Passkey (discoverable credential) management: list and delete.

Requires the key to be unlocked first (see fido2tool_core.auth).
"""

import base64
import logging

from fido2tool_core import auth
from fido2tool_core.auth import AuthError

logger = logging.getLogger(__name__)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        raise AuthError("Invalid credential id.", "invalid_input") from None


def capabilities(ctap2) -> dict:
    from fido2.ctap2.credman import CredentialManagement

    info = ctap2.info
    return {
        "supported": CredentialManagement.is_supported(info),
        "pin_set": (info.options or {}).get("clientPin") is True,
        "uv_unlock": auth.uv_unlock_available(info),
        "rename": CredentialManagement.is_update_supported(info),
    }


def _credman(token_id: str, ctap2):
    from fido2.ctap2.credman import CredentialManagement

    if not CredentialManagement.is_supported(ctap2.info):
        raise AuthError("This key does not support passkey management.", "unsupported", reason="passkey_management")
    protocol, token = auth.get_token(token_id)
    return CredentialManagement(ctap2, protocol, token)


def list_passkeys(token_id: str, ctap2) -> dict:
    from fido2.ctap2.credman import CredentialManagement as CM

    cm = _credman(token_id, ctap2)
    meta = auth.call(token_id, cm.get_metadata)
    rps_raw = auth.call(token_id, cm.enumerate_rps)

    rps = []
    for rp_entry in rps_raw:
        rp = dict(rp_entry.get(CM.RESULT.RP) or {})
        rp_hash = rp_entry[CM.RESULT.RP_ID_HASH]
        creds = []
        for c in auth.call(token_id, lambda: cm.enumerate_creds(rp_hash)):
            user = dict(c.get(CM.RESULT.USER) or {})
            cred_id = dict(c.get(CM.RESULT.CREDENTIAL_ID) or {})
            creds.append({
                "credential_id": _b64(cred_id.get("id", b"")),
                "user_id": _b64(user.get("id", b"")),
                "user_name": user.get("name") or "",
                "display_name": user.get("displayName") or "",
                "cred_protect": c.get(CM.RESULT.CRED_PROTECT),
                "large_blob": CM.RESULT.LARGE_BLOB_KEY in c,
            })
        rps.append({
            "rp_id": rp.get("id") or "",
            "rp_name": rp.get("name") or "",
            "rp_id_hash": bytes(rp_hash).hex(),
            "credentials": creds,
        })
    rps.sort(key=lambda r: (r["rp_id"] or r["rp_id_hash"]).lower())

    return {
        "existing": meta.get(CM.RESULT.EXISTING_CRED_COUNT, 0),
        "remaining": meta.get(CM.RESULT.MAX_REMAINING_COUNT),
        "rps": rps,
    }


def rename_passkey(token_id: str, ctap2, credential_id: str, user_id: str, name: str, display_name: str) -> None:
    """Change the stored account name / display name (CTAP 2.1 only)."""
    from fido2.ctap2.credman import CredentialManagement

    if not CredentialManagement.is_update_supported(ctap2.info):
        raise AuthError("This key cannot rename passkeys.", "unsupported", reason="passkey_rename")
    name = (name or "").strip()
    display_name = (display_name or "").strip()
    if not name and not display_name:
        raise AuthError("Please enter a name.", "invalid_input")
    if len(name.encode()) > 64 or len(display_name.encode()) > 64:
        raise AuthError("The name is too long (max. 64 bytes).", "name_too_long", max=64)
    cm = _credman(token_id, ctap2)
    descriptor = {"type": "public-key", "id": _unb64(credential_id)}
    user = {"id": _unb64(user_id), "name": name or display_name, "displayName": display_name or name}
    auth.call(token_id, lambda: cm.update_user_info(descriptor, user))
    logger.info("Passkey renamed")


def delete_passkey(token_id: str, ctap2, credential_id: str) -> None:
    if not credential_id:
        raise AuthError("Missing credential id.", "invalid_input")
    cm = _credman(token_id, ctap2)
    descriptor = {"type": "public-key", "id": _unb64(credential_id)}
    auth.call(token_id, lambda: cm.delete_cred(descriptor))
    logger.info("Passkey deleted")
