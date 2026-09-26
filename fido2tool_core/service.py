"""KeyMelier application service: everything the UI can ask for or do.

UI-agnostic. Methods return plain JSON-serialisable dicts and raise PinError
(or subclasses), DeviceBusy or DeviceNotFound on failure. Live changes are
pushed through `emit(event_name, payload)`.
"""

import dataclasses
import json
import logging
import threading
from pathlib import Path

from fido2tool_core import auth
from fido2tool_core import fingerprints as fingerprints_mod
from fido2tool_core import passkeys as passkeys_mod
from fido2tool_core import pin as pin_mod
from fido2tool_core import reset as reset_mod
from fido2tool_core.history import History, key_id
from fido2tool_core.pin import PinError
from fido2tool_core.scanner import DeviceBusy, DeviceNotFound

logger = logging.getLogger(__name__)

SETTINGS_FILE = Path.home() / "keymelier" / "settings.json"

# Unlocking may wait for a fingerprint or for the plug-in attestation test to
# finish (it holds the device while waiting for a touch), so it gets a longer
# lock timeout.
UNLOCK_WAIT = 35.0


def system_languages() -> list[str]:
    """Preferred UI languages of the OS, most preferred first (e.g. ["de-DE", "en-US"])."""
    import sys

    langs: list[str] = []
    try:
        if sys.platform == "darwin":
            from Foundation import NSLocale
            langs = [str(x) for x in NSLocale.preferredLanguages()]
        elif sys.platform == "win32":
            import ctypes
            import locale
            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            name = locale.windows_locale.get(lang_id)
            if name:
                langs = [name.replace("_", "-")]
    except Exception as e:
        logger.debug("Could not read system languages: %s", e)
    if not langs:
        import locale
        loc = locale.getlocale()[0]
        if loc:
            langs = [loc.replace("_", "-")]
    return langs


class KeyService:
    def __init__(self, scanner, exporter, mds3_client=None, history: History | None = None,
                 advisories=None):
        self._scanner = scanner
        self._advisories = advisories
        self._last_update_check = None
        self._exporter = exporter
        self._mds3 = mds3_client
        self.history = history or History()
        self.emit = lambda name, payload: None
        self._attestation_logged: set[str] = set()

        scanner.set_callbacks(
            on_connect=self._on_connect,
            on_disconnect=self._on_disconnect,
            on_update=self._on_update,
        )
        scanner.intercept_connect = self._intercept_for_reset

    # ── Serialisation & history ──────────────────────────────────────────────

    @staticmethod
    def _record_dict(record) -> dict:
        d = dataclasses.asdict(record)
        d["history_id"] = key_id(record)
        return d

    def _log(self, record, kind, **detail):
        summary = self.history.add_event(record, kind, **detail)
        self.emit("history_updated", summary)

    # ── Scanner callbacks ────────────────────────────────────────────────────

    def _on_connect(self, record):
        try:
            self._exporter.export(record)
        except Exception as e:
            logger.error("Export failed: %s", e)
        logger.info("Token connected: %s", record.product_name)
        self.history.update_snapshot(record)
        self._log(record, "connected")
        self.emit("token_connected", self._record_dict(record))

    def _on_disconnect(self, record):
        auth.forget(record.id)
        fingerprints_mod.cancel_enrollment(record.id)
        self._attestation_logged.discard(record.id)
        logger.info("Token disconnected: %s", record.product_name)
        self._log(record, "disconnected")
        self.emit("token_disconnected", {"id": record.id, "product_name": record.product_name})

    def _on_update(self, record):
        try:
            self._exporter.export(record)
        except Exception as e:
            logger.error("Re-export failed: %s", e)
        self.history.update_snapshot(record)
        att = record.attestation
        if att is None:
            self._attestation_logged.discard(record.id)
        elif att.get("ran") and record.id not in self._attestation_logged:
            self._attestation_logged.add(record.id)
            if att.get("inconclusive"):
                self._log(record, "attestation_skipped", reason=att["inconclusive"])
            else:
                self._log(record, "attestation", passed=bool(att.get("passed")))
        self.emit("token_updated", self._record_dict(record))

    # ── Queries ──────────────────────────────────────────────────────────────

    def tokens(self) -> dict:
        return {"tokens": [self._record_dict(r) for r in self._scanner.get_all()]}

    UPDATE_INTERVAL = 6 * 3600  # seconds between update checks

    def run_update_loop(self):
        """Background thread: keep metadata and advisories current."""
        while True:
            self.check_updates()
            threading.Event().wait(self.UPDATE_INTERVAL)

    def check_updates(self) -> dict:
        from fido2tool_core.updates import now_iso

        changed = False
        if self._mds3 and self._mds3.refresh_if_stale():
            changed = True
        if self._advisories and self._advisories.check_for_update():
            changed = True
        self._last_update_check = now_iso()
        if changed:
            self._scanner.reevaluate_all()
        status = self.data_status()
        self.emit("data_status", status)
        return status

    def data_status(self) -> dict:
        return {
            "advisories": self._advisories.info() if self._advisories else None,
            "mds": self.mds_status(),
            "last_check": self._last_update_check,
        }

    def mds_status(self) -> dict:
        if self._mds3:
            return self._mds3.get_cache_info()
        return {"cached": False, "fetched_at": None, "entry_count": 0}

    def history_list(self) -> dict:
        return {"keys": self.history.list()}

    def history_get(self, kid: str) -> dict:
        entry = self.history.get(kid)
        if entry is None:
            raise PinError("Unknown history entry.", "not_found", status=404)
        return entry

    def history_rename(self, kid: str, label: str) -> dict:
        summary = self.history.rename(kid, label)
        if summary is None:
            raise PinError("Unknown history entry.", "not_found", status=404)
        self.emit("history_updated", summary)
        return summary

    def history_forget(self, kid: str) -> dict:
        return {"removed": self.history.forget(kid)}

    # ── Settings ─────────────────────────────────────────────────────────────

    def _stored_settings(self) -> dict:
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def get_settings(self) -> dict:
        # lang: the user's explicit choice (absent = follow the system)
        return {**self._stored_settings(), "system_languages": system_languages()}

    def set_settings(self, values: dict) -> dict:
        settings = self._stored_settings()
        for key, value in (values or {}).items():
            if key != "lang":
                continue
            if value:
                settings["lang"] = str(value)[:10]
            else:
                settings.pop("lang", None)
        try:
            SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps(settings), encoding="utf-8")
        except Exception as e:
            logger.error("Could not save settings: %s", e)
        return {**settings, "system_languages": system_languages()}

    # ── PIN ──────────────────────────────────────────────────────────────────

    def pin_status(self, token_id: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return pin_mod.status(ctap2)

    def pin_update(self, token_id: str, new_pin: str, current_pin: str | None = None) -> dict:
        with self._scanner.session(token_id) as (record, ctap2):
            action = pin_mod.set_or_change(ctap2, new_pin=new_pin, current_pin=current_pin)
        self._log(record, "pin_set" if action == "set" else "pin_changed")
        # A forced PIN change (e.g. pre-registered keys) blocks makeCredential, so
        # the attestation test on plug-in failed. Now it can succeed: run it again.
        if record.attestation and not record.attestation.get("passed"):
            record.attestation = None
            self._on_update(record)
            self._scanner.start_attestation(record)
        return {"result": action}

    def attestation_rerun(self, token_id: str) -> dict:
        record = self._scanner.get(token_id)
        record.attestation = None
        self._on_update(record)
        self._scanner.start_attestation(record)
        return {"started": True}

    # ── Unlock ───────────────────────────────────────────────────────────────

    def unlock(self, token_id: str, pin: str | None = None, method: str | None = None) -> dict:
        with self._scanner.session(token_id, timeout=UNLOCK_WAIT, refresh=False) as (_record, ctap2):
            auth.unlock(token_id, ctap2, pin=pin, use_uv=method == "uv")
        return {"unlocked": True}

    def lock(self, token_id: str) -> dict:
        auth.forget(token_id)
        return {"unlocked": False}

    # ── Passkeys ─────────────────────────────────────────────────────────────

    def _passkeys(self, token_id, ctap2) -> dict:
        caps = passkeys_mod.capabilities(ctap2)
        if not caps["supported"] or not auth.is_unlocked(token_id):
            return {**caps, "unlocked": False}
        return {**caps, "unlocked": True, **passkeys_mod.list_passkeys(token_id, ctap2)}

    def passkeys(self, token_id: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return self._passkeys(token_id, ctap2)

    def passkey_delete(self, token_id: str, credential_id: str, site: str = "", user: str = "") -> dict:
        with self._scanner.session(token_id) as (record, ctap2):
            passkeys_mod.delete_passkey(token_id, ctap2, credential_id)
            data = self._passkeys(token_id, ctap2)
        self._log(record, "passkey_deleted", site=str(site)[:120], user=str(user)[:120])
        return data

    # ── Fingerprints ─────────────────────────────────────────────────────────

    def _fingerprints(self, token_id, ctap2) -> dict:
        caps = fingerprints_mod.capabilities(ctap2)
        caps["enrolling"] = fingerprints_mod.is_enrolling(token_id)
        if not caps["supported"] or not auth.is_unlocked(token_id):
            return {**caps, "unlocked": False}
        return {**caps, "unlocked": True, "fingerprints": fingerprints_mod.list_fingerprints(token_id, ctap2)}

    def fingerprints(self, token_id: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return self._fingerprints(token_id, ctap2)

    def fingerprint_rename(self, token_id: str, template_id: str, name: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (record, ctap2):
            fingerprints_mod.rename(token_id, ctap2, template_id, name)
            data = self._fingerprints(token_id, ctap2)
        self._log(record, "fingerprint_renamed", name=str(name)[:60])
        return data

    def fingerprint_delete(self, token_id: str, template_id: str, name: str = "") -> dict:
        with self._scanner.session(token_id) as (record, ctap2):
            fingerprints_mod.remove(token_id, ctap2, template_id)
            data = self._fingerprints(token_id, ctap2)
        self._log(record, "fingerprint_removed", name=str(name)[:60])
        return data

    def fingerprint_enroll(self, token_id: str, name: str = "") -> dict:
        """Start an enrollment. Progress arrives as `enroll_progress` events,
        the outcome as `enroll_done`."""
        record = self._scanner.get(token_id)  # DeviceNotFound early if the key is gone
        auth.get_token(token_id)  # 'locked' early
        cancel = fingerprints_mod.begin_enrollment(token_id)

        def progress(payload):
            self.emit("enroll_progress", {"id": token_id, **payload})

        def run():
            result = {"id": token_id, "ok": False}
            try:
                with self._scanner.session(token_id, timeout=UNLOCK_WAIT) as (_record, ctap2):
                    result["template_id"] = fingerprints_mod.enroll(token_id, ctap2, name, cancel, progress)
                    result["ok"] = True
            except PinError as e:
                result.update(error=e.message, code=e.code, **e.extra)
            except DeviceBusy:
                result.update(error="The key is busy.", code="busy")
            except DeviceNotFound:
                result.update(error="The key is no longer connected.", code="not_found")
            except Exception as e:
                logger.exception("Enrollment failed")
                result.update(error=str(e), code="error")
            finally:
                fingerprints_mod.end_enrollment(token_id)
            if result["ok"]:
                self._log(record, "fingerprint_enrolled", name=str(name)[:60])
            else:
                logger.warning("Enrollment ended: %s", result.get("code"))
            self.emit("enroll_done", result)

        threading.Thread(target=run, daemon=True, name=f"enroll-{token_id}").start()
        return {"started": True}

    def fingerprint_enroll_cancel(self, token_id: str) -> dict:
        return {"cancelled": fingerprints_mod.cancel_enrollment(token_id)}

    # ── Factory reset ────────────────────────────────────────────────────────

    def _intercept_for_reset(self, record) -> bool:
        if not reset_mod.claim(record):
            return False
        threading.Thread(target=self._run_reset, args=(record,), daemon=True, name=f"reset-{record.id}").start()
        return True

    def _run_reset(self, record):
        result = {"id": record.id, "ok": False}
        self.emit("reset_progress", {"id": record.id, "stage": "running"})
        try:
            with self._scanner.session(record.id, timeout=5.0) as (_record, ctap2):
                reset_mod.perform(ctap2, lambda: self.emit("reset_progress", {"id": record.id, "stage": "touch"}))
            result["ok"] = True
            auth.forget(record.id)
            record.attestation = {"ran": False, "passed": False, "error": "Skipped after factory reset", "checks": []}
            self._attestation_logged.add(record.id)
            self._log(record, "reset")
            self._on_update(record)
        except PinError as e:
            result.update(error=e.message, code=e.code)
        except (DeviceBusy, DeviceNotFound):
            result.update(error="The key could not be reached.", code="not_found")
        except Exception as e:
            logger.exception("Reset failed")
            result.update(error=str(e), code="error")
        if not result["ok"]:
            logger.warning("Reset ended: %s", result.get("code"))
            # The attestation test was skipped for this connection; run it now
            self._scanner.start_attestation(record)
        self.emit("reset_done", result)

    def reset_arm(self, token_id: str, confirm: bool = False) -> dict:
        if confirm is not True:
            raise PinError("Please confirm the reset.", "invalid_input")
        info = reset_mod.arm(self._scanner.get(token_id))

        def check_expired():
            if reset_mod.expired():
                self.emit("reset_done", {"ok": False, "code": "expired", "error": "Time is up."})

        threading.Timer(reset_mod.ARM_WINDOW + 0.5, check_expired).start()
        return info

    def reset_disarm(self) -> dict:
        return {"disarmed": reset_mod.disarm()}

    # ── Export ───────────────────────────────────────────────────────────────

    def export_all(self) -> dict:
        results = []
        for record in self._scanner.get_all():
            try:
                path = self._exporter.export(record)
                results.append({"serial": record.serial_number, "file": str(path)})
            except Exception as e:
                results.append({"serial": record.serial_number, "error": str(e)})
        return {"exports": results}
