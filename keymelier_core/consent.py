"""Single-request native consent; no renderer-provided approval token or text."""
import hashlib
import json
import locale
import threading
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from keymelier_core.pin import PinError

# UI labels are read from a bundled, generated subset of our translations.
OPERATIONS = {
    "pin_update": ("FIDO2", "pin.form.change"),
    "passkey_delete": ("Passkey", "pk.delete.do"),
    "fingerprint_delete": ("Fingerprint", "pk.delete.do"),
    "fingerprint_enroll": ("Fingerprint", "fp.enroll.title"),
    "reset_arm": ("FIDO2", "rs.title"),
    "config_update": ("FIDO2", "cfg.title"),
    "oath_add": ("OATH", "oath.add"),
    "oath_delete": ("OATH", "pk.delete.do"),
    "oath_password": ("OATH", "oath.protect.title"),
    "oath_reset": ("OATH", "oath.reset.title"),
    "openpgp_change_pin": ("OpenPGP", "pgp.pin.change"),
    "openpgp_unblock_pin": ("OpenPGP", "pgp.unblock"),
    "openpgp_touch": ("OpenPGP", "pgp.touch.title"),
    "openpgp_signature_pin": ("OpenPGP", "pgp.sigpin.title"),
    "openpgp_cardholder": ("OpenPGP", "pgp.name"),
    "openpgp_generate": ("OpenPGP", "pgp.gen.title"),
    "openpgp_reset": ("OpenPGP", "pgp.reset.title"),
    "piv_change_pin": ("PIV", "piv.pin.change"),
    "piv_unblock_pin": ("PIV", "pgp.unblock"),
    "piv_generate": ("PIV", "piv.gen.title"),
    "piv_import": ("PIV", "piv.import.title"),
    "piv_delete": ("PIV", "piv.delete.title"),
    "piv_protect_management_key": ("PIV", "piv.mgmt.protect"),
    "piv_reset": ("PIV", "piv.reset.title"),
    "otp_swap": ("OTP", "otp.swap"),
    "otp_delete": ("OTP", "otp.delete.title"),
    "otp_static": ("OTP", "otp.static.title"),
    "otp_hmac": ("OTP", "otp.hmac.title"),
    "interfaces_set": ("USB / NFC", "if.title"),
    "history_forget": ("KeyMelier", "hist.forget.title"),
    "sync_disable": ("KeyMelier", "sync.removeFile"),
}


def _text(value):
    # Device strings are data even in a plain-text native dialog: no new lines,
    # control characters or bidi overrides that can impersonate dialog text.
    value = "".join(c for c in str(value) if not unicodedata.category(c).startswith("C"))
    return json.dumps(value[:120], ensure_ascii=False)


def _identity(record):
    return tuple(getattr(record, key, None) for key in
                 ("id", "path", "serial_number", "aaguid", "vendor_id", "product_id"))


class NativeConsent:
    def __init__(self, service, confirm, texts: Path):
        self.service, self.confirm = service, confirm
        self.texts = json.loads(texts.read_text(encoding="utf-8"))
        self._lock = threading.Lock()

    @contextmanager
    def authorize(self, method, args):
        if method not in OPERATIONS or (method == "sync_disable" and args.get("remove_file") is not True):
            yield
            return
        if not self._lock.acquire(blocking=False):
            raise PinError("Another confirmation or operation is in progress.", "busy", status=409)
        try:
            token_id = args.get("token_id")
            record = self.service._scanner.get(token_id) if token_id else None
            identity = _identity(record) if record is not None else None
            lang = self.service._stored_settings().get("lang") or locale.getlocale()[0] or "en"
            words = self.texts.get(lang.lower().replace("_", "-").split("-")[0], self.texts['en'])
            applet, label = OPERATIONS[method]
            action = words[label].replace("{slot}", _text(args.get("slot", "")))
            if record is not None:
                target = _text(record.product_name) + " / " + _text(record.serial_number or record.id)
            else:
                target = _text(args.get("kid", "KeyMelier"))
            # Only public identifiers/settings, never PINs, passwords or key material.
            details = [_text(args[k]) for k in ("credential_id", "template_id", "account_id", "which", "transport", "policy")
                       if k in args]
            for key in ("key", "replace", "every_time", "min_pin_length", "always_uv", "force_pin_change"):
                if key in args:
                    details.append(f"{key}: {_text(args[key])}")
            if method == "piv_import":
                details.append("SHA-256: " + hashlib.sha256(str(args.get("pem", "")).encode()).hexdigest())
            message = f"{applet}: {action}\n\n{words['native.target']}: {target}"
            if details:
                message += "\n" + "\n".join(details)
            message += "\n\n" + words['native.warning']
            if self.confirm(words['native.confirm'], message) is not True:
                raise PinError("The operation was cancelled.", "cancelled", status=409)
            if record is not None:
                current = self.service._scanner.get(token_id)
                if current is not record or _identity(current) != identity:
                    raise PinError("The key changed during confirmation. Try again.", "not_found", status=404)
            yield
        finally:
            self._lock.release()
