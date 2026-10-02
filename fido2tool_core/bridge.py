"""GUI-independent allow-listed service boundary and stable error envelopes.

No arbitrary attribute traversal, request arguments in logs, or exception text
from unexpected failures in UI responses. Domain errors retain actionable text.
"""

import inspect
import os
import traceback
import logging

from fido2tool_core.pin import PinError
from fido2tool_core.scanner import DeviceBusy, DeviceNotFound

logger = logging.getLogger(__name__)

# Service methods the UI may call. Everything else is unreachable from JS.
ALLOWED = {
    "tokens", "mds_status", "data_status", "check_updates",
    "history_list", "history_get", "history_rename", "history_forget",
    "history_set_lost", "history_lost_done", "history_replace", "history_replace_done",
    "sync_status", "sync_enable", "sync_disable", "sync_now",
    "get_settings", "set_settings", "diagnostics",
    "pin_status", "pin_update", "attestation_rerun",
    "unlock", "unlock_cancel", "lock",
    "passkeys", "passkey_delete", "passkey_rename",
    "fingerprints", "fingerprint_rename", "fingerprint_delete",
    "fingerprint_enroll", "fingerprint_enroll_cancel",
    "reset_arm", "reset_disarm", "config", "config_update",
    "function_test", "function_test_info",
    "card_apps", "oath", "oath_unlock", "oath_code", "oath_add", "oath_rename", "oath_delete",
    "oath_password", "oath_reset",
    "openpgp", "openpgp_change_pin", "openpgp_unblock_pin", "openpgp_touch", "openpgp_signature_pin",
    "openpgp_cardholder", "openpgp_reset", "openpgp_generate",
    "piv", "piv_change_pin", "piv_unblock_pin", "piv_generate", "piv_import", "piv_export", "piv_delete",
    "piv_protect_management_key", "piv_reset",
    "otp", "otp_swap", "otp_delete", "otp_static", "otp_hmac", "interfaces", "interfaces_set",
    "open_privacy_settings",
    "export_all", "history_export", "history_import", "update_download", "update_open", "read_contents", "passkeys_probe", "passkeys_probe_cancel",
}



def _failure(service, method, code, message, status):
    service.error_log.record(method, code)
    return {"ok": False, "error": message, "code": code, "status": status}


def dispatch(service, method, kwargs=None):
    if not isinstance(method, str) or method not in ALLOWED:
        return {"ok": False, "error": "Unknown method.", "code": "unknown_method", "status": 400}
    if kwargs is None:
        kwargs = {}
    if not isinstance(kwargs, dict) or not all(isinstance(k, str) for k in kwargs):
        return _failure(service, method, "invalid_input", "Invalid request.", 400)
    if "token_id" in kwargs and (not isinstance(kwargs["token_id"], str)
                                 or not 0 < len(kwargs["token_id"]) <= 256):
        return _failure(service, method, "invalid_input", "Invalid request.", 400)
    handler = getattr(service, method)
    try:
        inspect.signature(handler).bind(**kwargs)
    except TypeError:
        return _failure(service, method, "invalid_input", "Invalid request.", 400)
    try:
        return {"ok": True, "data": handler(**kwargs)}
    except PinError as e:
        logger.warning("%s -> %s", method, e.code)
        service.error_log.record(method, e.code, e.extra.get("reason"))
        return {"ok": False, "error": e.message, "code": e.code, "status": e.status, **e.extra}
    except DeviceBusy:
        return _failure(service, method, "busy", "The key is busy.", 409)
    except DeviceNotFound:
        return _failure(service, method, "not_found", "The key is no longer connected.", 404)
    except Exception as e:
        # Exception strings can contain PINs, URLs or private device data.
        # Keep the operation/type for debugging, never arguments or messages.
        # Where it happened (file name, line, function) keeps field reports
        # diagnosable; no source lines (literals) and no full paths (user name).
        where = " < ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}"
                           for f in reversed(traceback.extract_tb(e.__traceback__)))
        logger.error("%s failed (%s) at %s", method, type(e).__name__, where)
        return _failure(service, method, "error", "The operation could not be completed.", 500)
