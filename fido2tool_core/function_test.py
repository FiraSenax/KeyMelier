"""End-to-end function test: register, sign in, verify the signature.

Uses a non-discoverable credential for a fake relying party, so nothing is
stored on the key (the credential lives only in this test's memory). Needs
up to two touches; keys that always require user verification also need the
PIN (or a fingerprint via the key's built-in sensor).
"""

import hashlib
import logging
import os
import time

from fido2tool_core.auth import AuthError, map_ctap_error

logger = logging.getLogger(__name__)

RP = {"id": "test.keymelier.app", "name": "KeyMelier function test"}


def _bound_response(data, require_uv: bool) -> bool:
    """A valid signature is insufficient without request binding and presence."""
    return (data.rp_id_hash == hashlib.sha256(RP["id"].encode()).digest()
            and data.is_user_present()
            and (not require_uv or data.is_user_verified())
            and (not data.is_backed_up() or data.is_backup_eligible()))


def needs_pin(ctap2) -> bool:
    """True if the key will refuse a registration without PIN/UV."""
    options = ctap2.info.options or {}
    if options.get("alwaysUv"):
        return True
    # CTAP 2.1: without makeCredUvNotRqd a PIN-protected key wants UV for MC
    return options.get("clientPin") is True and options.get("makeCredUvNotRqd") is False


def run(ctap2, pin: str | None = None, on_touch=None) -> dict:
    from fido2.ctap import STATUS, CtapError
    from fido2.ctap2.pin import ClientPin
    from fido2.webauthn import ES256

    steps: list[dict] = []
    started = time.monotonic()

    def result(user_verified=False):
        return {"ok": len(steps) == 3 and all(s["ok"] for s in steps),
                "steps": steps, "user_verified": user_verified,
                "seconds": round(time.monotonic() - started, 1)}

    def keepalive(status):
        if status == STATUS.UPNEEDED and on_touch:
            on_touch()

    def uv_param(cdh: bytes, permission):
        if not pin:
            return None, None
        client_pin = ClientPin(ctap2)
        token = client_pin.get_pin_token(pin, permission, RP["id"])
        return client_pin.protocol.authenticate(token, cdh), client_pin.protocol.VERSION

    try:
        # 1. Register
        cdh = hashlib.sha256(os.urandom(32)).digest()
        param, proto = uv_param(cdh, ClientPin.PERMISSION.MAKE_CREDENTIAL)
        user = {"id": os.urandom(16), "name": "function-test", "displayName": "Function test"}
        att = ctap2.make_credential(
            cdh, RP, user, [{"type": "public-key", "alg": ES256.ALGORITHM}],
            options={"rk": False}, pin_uv_param=param, pin_uv_protocol=proto, on_keepalive=keepalive,
        )
        cred = att.auth_data.credential_data
        require_uv = bool(pin) or bool((ctap2.info.options or {}).get("alwaysUv"))
        registration_ok = bool(cred and cred.credential_id and _bound_response(att.auth_data, require_uv))
        steps.append({"step": "register", "ok": registration_ok})
        if not registration_ok:
            return result()

        # 2. Sign in with the new credential
        cdh2 = hashlib.sha256(os.urandom(32)).digest()
        param, proto = uv_param(cdh2, ClientPin.PERMISSION.GET_ASSERTION)
        assertion = ctap2.get_assertion(
            RP["id"], cdh2, allow_list=[{"type": "public-key", "id": cred.credential_id}],
            pin_uv_param=param, pin_uv_protocol=proto, on_keepalive=keepalive,
        )
        descriptor = assertion.credential
        sign_in_ok = (_bound_response(assertion.auth_data, require_uv)
                      and descriptor.get("id") == cred.credential_id
                      and descriptor.get("type") == "public-key")
        steps.append({"step": "sign_in", "ok": sign_in_ok})
        if not sign_in_ok:
            return result()

        # 3. Verify the signature with the registered public key
        try:
            cred.public_key.verify(bytes(assertion.auth_data) + cdh2, assertion.signature)
            steps.append({"step": "signature", "ok": True})
        except Exception:
            steps.append({"step": "signature", "ok": False})

        return result(assertion.auth_data.is_user_verified())
    except CtapError as e:
        err = map_ctap_error(e)
        if e.code == CtapError.ERR.PUAT_REQUIRED:
            err = AuthError("This key requires the PIN for this test.", "pin_required")
        return {"ok": False, "steps": steps, "error": err.message, "code": err.code,
                "seconds": round(time.monotonic() - started, 1)}
