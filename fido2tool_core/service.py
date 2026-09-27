"""KeyMelier application service: everything the UI can ask for or do.

UI-agnostic. Methods return plain JSON-serialisable dicts and raise PinError
(or subclasses), DeviceBusy or DeviceNotFound on failure. Live changes are
pushed through `emit(event_name, payload)`.
"""

import dataclasses
import json
import logging
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from fido2tool_core.storage import atomic_write, secret_delete, secret_get, secret_set, stateless
from fido2tool_core import sync as sync_mod

from fido2tool_core import auth
from fido2tool_core import fingerprints as fingerprints_mod
from fido2tool_core import key_config
from fido2tool_core import oath_app
from fido2tool_core import openpgp_app
from fido2tool_core import piv_app
from fido2tool_core import yubikey_apps
from fido2tool_core.cards import Cards, CardError
from fido2tool_core import passkeys as passkeys_mod
from fido2tool_core import pin as pin_mod
from fido2tool_core import reset as reset_mod
from fido2tool_core.history import History, key_id
from fido2tool_core.pin import PinError
from fido2tool_core.scanner import DeviceBusy, DeviceNotFound
from fido2tool_core.version import __version__

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


def _is_yubikey(record) -> bool:
    return record.vendor_id == 0x1050 or "yubi" in (record.product_name or "").lower()


class KeyService:
    def __init__(self, scanner, exporter, mds3_client=None, history: History | None = None,
                 advisories=None):
        self._scanner = scanner
        self._advisories = advisories
        self._last_update_check = None
        self._cards = Cards()
        self._reader_tokens: dict[str, str] = {}  # PC/SC reader -> FIDO token id
        self._cards.hold = self._hold_reader
        self._otp_lock = threading.Lock()
        self._probe_cancel: set[str] = set()
        self._app_update = None
        self._exporter = exporter
        self._mds3 = mds3_client
        self._session_settings = {}
        # History is on unless the user switched it off (websites stay opt-in)
        self.history = history or History(enabled=self._stored_settings().get("history_enabled") is not False)
        if not self._remember_contents():
            self.history.clear_sites()
        self.emit = lambda name, payload: None
        self._attestation_logged: set[str] = set()
        # Sync between the user's computers through a folder (off unless set up)
        self._syncer = sync_mod.Syncer(self.history, lambda n, p: self.emit(n, p), self._remember_contents,
                                       on_new_device=self._sync_new_device)
        self._sync_problem = None
        self._sync_configure()

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
        if not self._remember_contents():
            detail = {k: v for k, v in detail.items() if k not in {"site", "user", "rp_id"}}
        summary = self.history.add_event(record, kind, **detail)
        self.emit("history_updated", summary)

    # ── Scanner callbacks ────────────────────────────────────────────────────

    def _on_connect(self, record):
        logger.info("Token connected: %s", record.product_name)
        self.history.update_snapshot(record)
        self._log(record, "connected")
        self.emit("token_connected", self._record_dict(record))

    def _on_disconnect(self, record):
        auth.forget(record.id)
        # OATH access keys are per application, not per FIDO token: a key
        # that leaves takes every unlocked authenticator with it
        oath_app.forget_all()
        fingerprints_mod.cancel_enrollment(record.id)
        self._attestation_logged.discard(record.id)
        logger.info("Token disconnected: %s", record.product_name)
        self._log(record, "disconnected")
        self.emit("token_disconnected", {"id": record.id, "product_name": record.product_name})

    def _on_update(self, record):
        self.history.update_snapshot(record)
        att = record.attestation
        if att is None:
            self._attestation_logged.discard(record.id)
        elif att.get("ran") and record.id not in self._attestation_logged:
            self._attestation_logged.add(record.id)
            if att.get("status") != "FAILED" and not att.get("passed"):
                self._log(record, "attestation_skipped", reason=att.get("inconclusive") or "unverified")
            else:
                self._log(record, "attestation", passed=bool(att.get("passed")), status=att.get("status", "UNVERIFIED"))
        self.emit("token_updated", self._record_dict(record))

    # ── Queries ──────────────────────────────────────────────────────────────

    def tokens(self) -> dict:
        return {"tokens": [self._record_dict(r) for r in self._scanner.get_all()]}

    UPDATE_INTERVAL = 6 * 3600  # seconds between update checks
    RETRY_INTERVAL = 15 * 60    # while metadata lacks current revocation evidence

    def run_update_loop(self):
        """Background thread: keep metadata and advisories current."""
        while True:
            self.check_updates()
            current = self._mds3 is None or self._mds3.is_current()
            threading.Event().wait(self.UPDATE_INTERVAL if current else self.RETRY_INTERVAL)

    def update_download(self) -> dict:
        """Download and verify the newer release for this platform (in the
        background; progress via update_progress events)."""
        from fido2tool_core import app_update
        info = self._app_update or {}
        if not info.get("newer") or not info.get("asset"):
            raise PinError("No update available for download.", "no_update")
        if getattr(self, "_update_running", False):
            return {"started": False}
        self._update_running = True

        def run():
            try:
                path = app_update.download(info["asset"], lambda pct: self.emit("update_progress", {"pct": pct}))
                self._update_path = path
                self.emit("update_ready", {"name": path.name, "platform": sys.platform})
            except app_update.UpdateError as e:
                code = "update_checksum" if str(e) == "checksum" else "update_failed"
                self.emit("update_failed", {"code": code, "error": str(e)})
            finally:
                self._update_running = False

        threading.Thread(target=run, daemon=True, name="update-download").start()
        return {"started": True}

    def update_open(self) -> dict:
        from fido2tool_core import app_update
        path = getattr(self, "_update_path", None)
        if not path or not path.exists():
            raise PinError("The update file is no longer there.", "no_update")
        app_update.open_download(path)
        return {"opened": True}

    def check_updates(self) -> dict:
        from fido2tool_core.updates import now_iso

        changed = False
        if self._mds3 and self._mds3.refresh_if_stale():
            changed = True
        if self._advisories and self._advisories.check_for_update():
            changed = True
        self._last_update_check = now_iso()
        from fido2tool_core import app_update
        self._app_update = app_update.check()
        if self._app_update.get("newer"):
            self.emit("app_update", self._app_update)
        # Expiry can change the assessment even when no new blob arrives.
        self._scanner.reevaluate_all()
        status = self.data_status()
        self.emit("data_status", status)
        return status

    def data_status(self) -> dict:
        return {
            "advisories": self._advisories.info() if self._advisories else None,
            "mds": self.mds_status(),
            "last_check": self._last_update_check,
            "app": self._app_update or {"current": __version__},
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

    def history_export(self) -> dict:
        from datetime import date
        return {"text": json.dumps(self.history.export(), indent=1, ensure_ascii=False),
                "filename": f"keymelier-history-{date.today().isoformat()}.json"}

    def history_import(self, text: str) -> dict:
        if not isinstance(text, str) or len(text) > 20_000_000:
            raise PinError("The file is too large.", "invalid_input")
        try:
            result = self.history.import_(json.loads(text))
        except (ValueError, TypeError):
            raise PinError("This is not a KeyMelier history export.", "history_invalid") from None
        self.emit("history_reloaded", {})
        return {**result, "saved": self.history.enabled}

    def history_forget(self, kid: str) -> dict:
        return {"removed": self.history.forget(kid)}

    # ── Settings ─────────────────────────────────────────────────────────────

    def _remember_contents(self) -> bool:
        """Record what is on each key (site names, account labels, ...)? On unless turned off."""
        return not stateless() and self._stored_settings().get("remember_sites") is not False

    def _stored_settings(self) -> dict:
        if stateless():
            return self._session_settings
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def get_settings(self) -> dict:
        # lang: the user's explicit choice (absent = follow the system)
        return {"history_enabled": not stateless(), "remember_sites": not stateless(), "personal_mode": True,
                **self._stored_settings(),
                "stateless": stateless(), "system_languages": system_languages()}

    def set_settings(self, values: dict) -> dict:
        settings = self._stored_settings()
        for key, value in (values or {}).items():
            if key == "lang":
                if value:
                    settings["lang"] = str(value)[:10]
                else:
                    settings.pop("lang", None)
            elif key == "history_enabled":
                if not isinstance(value, bool):
                    raise PinError("Expected a boolean", "invalid_input")
                settings[key] = value and not stateless()
                self.history.set_enabled(settings[key])
                if settings.get("remember_sites") is False:
                    self.history.clear_sites()
            elif key == "personal_mode":
                # All keys belong to one person: cross-key overviews make sense
                if not isinstance(value, bool):
                    raise PinError("Expected a boolean", "invalid_input")
                settings["personal_mode"] = value
            elif key == "remember_sites":
                settings["remember_sites"] = value is True and not stateless()
                if not value:
                    self.history.clear_sites()
        self._write_settings(settings)
        if "history_enabled" in (values or {}):
            self._sync_configure()   # sync needs the history
        return self.get_settings()

    def _write_settings(self, settings: dict) -> None:
        try:
            if stateless():
                self._session_settings = settings
            else:
                atomic_write(SETTINGS_FILE, json.dumps(settings))
        except Exception as e:
            logger.error("Could not save settings: %s", e)

    # ── Sync between computers ───────────────────────────────────────────────

    def _sync_configure(self) -> None:
        st = self._stored_settings()
        folder, device = st.get("sync_folder"), st.get("sync_device")
        self._sync_problem = None
        if stateless() or not self.history.enabled or not folder or not device:
            self._syncer.configure(None, None, None)
            return
        try:
            passphrase = secret_get(sync_mod.KEYRING_NAME)
        except Exception as e:
            logger.warning("Sync passphrase unavailable: %s", e)
            passphrase = None
        if not passphrase:
            self._sync_problem = "sync_keychain"
            self._syncer.configure(None, None, None)
            return
        self._syncer.configure(Path(folder), device, passphrase)

    def _sync_new_device(self, device: str) -> None:
        settings = self._stored_settings()
        settings["sync_device"] = device
        self._write_settings(settings)

    def sync_status(self) -> dict:
        st = self._stored_settings()
        return {**self._syncer.status(), "available": not stateless() and self.history.enabled,
                "configured": bool(st.get("sync_folder")), "configured_folder": st.get("sync_folder"),
                "problem": self._sync_problem, "min_passphrase": sync_mod.MIN_PASSPHRASE}

    def sync_enable(self, folder: str, passphrase: str) -> dict:
        if stateless() or not self.history.enabled:
            raise PinError("Sync needs the history to be switched on.", "sync_unavailable", status=409)
        if not isinstance(folder, str) or not isinstance(passphrase, str) or len(folder) > 1000 or len(passphrase) > 1000:
            raise PinError("Invalid input.", "invalid_input")
        settings = self._stored_settings()
        device = settings.get("sync_device") or sync_mod.new_device_id()
        try:
            sync_mod.probe_folder(Path(folder), passphrase, device)
            secret_set(sync_mod.KEYRING_NAME, passphrase)
        except sync_mod.SyncError as e:
            raise PinError(str(e), e.code, status=400) from None
        except RuntimeError as e:   # no native credential store
            raise PinError(str(e), "sync_keychain", status=409) from None
        settings.update(sync_folder=str(Path(folder)), sync_device=device)
        self._write_settings(settings)
        self._sync_configure()
        self._syncer.run_once(full=True)
        return self.sync_status()

    def sync_disable(self, remove_file: bool = False) -> dict:
        status = self._syncer.status()
        self._syncer.configure(None, None, None)
        if remove_file and status["folder"] and status["device"]:
            own = Path(status["folder"]) / f"KeyMelier-{status['device']}.kmsync"
            if own.is_file() and not own.is_symlink():
                own.unlink()
        try:
            secret_delete(sync_mod.KEYRING_NAME)
        except Exception as e:
            logger.info("Could not remove sync passphrase: %s", e)
        settings = self._stored_settings()
        settings.pop("sync_folder", None)
        self._write_settings(settings)
        self.history.stop_tracking_forgotten()
        self._sync_problem = None
        return self.sync_status()

    def sync_now(self) -> dict:
        self._syncer.run_once(full=True)
        return self.sync_status()

    def sync_flush(self) -> None:
        """On quit: write the latest state for the other computers."""
        if self._syncer.active:
            try:
                self._syncer.run_once()
            except Exception as e:
                logger.info("Final sync failed: %s", e)

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

    def attestation_rerun(self, token_id: str, pin: str | None = None, method: str | None = None) -> dict:
        record = self._scanner.get(token_id)
        record.attestation = None
        self._on_update(record)
        self._scanner.start_attestation(record, pin=pin or None, use_uv=method == "uv")
        return {"started": True}

    # ── Unlock ───────────────────────────────────────────────────────────────

    def unlock(self, token_id: str, pin: str | None = None, method: str | None = None) -> dict:
        with self._scanner.session(token_id, timeout=UNLOCK_WAIT, refresh=False) as (_record, ctap2):
            auth.unlock(token_id, ctap2, pin=pin, use_uv=method == "uv")
        return {"unlocked": True, "ttl": auth.TOKEN_TTL}

    def read_contents(self, token_id: str) -> dict:
        """After an unlock: read what is on the key in one go (passkeys, and
        authenticator/OpenPGP/PIV where present) so the history and the
        account overview are current. Best effort – each part may fail."""
        result = {"sites": None, "oath": None, "openpgp": None, "piv": None}
        try:
            data = self.passkeys(token_id)
            if data.get("unlocked"):
                result["sites"] = len(data.get("rps", []))
        except Exception as e:
            logger.debug("read_contents passkeys: %s", e)
        apps = self.card_apps(token_id).get("apps", {})
        for app, reader in (("oath", self.oath), ("openpgp", self.openpgp), ("piv", self.piv)):
            if not apps.get(app):
                continue
            try:
                data = reader(token_id)
                if app == "oath":
                    result["oath"] = len(data["accounts"]) if data.get("unlocked") else None
                elif app == "openpgp":
                    result["openpgp"] = sum(1 for k in data["keys"] if k["present"])
                else:
                    result["piv"] = sum(1 for s in data["slots"] if s["cert"])
            except Exception as e:
                logger.debug("read_contents %s: %s", app, e)
        return result

    def lock(self, token_id: str) -> dict:
        auth.forget(token_id)
        oath_app.forget_all()
        return {"unlocked": False}

    # ── Passkeys ─────────────────────────────────────────────────────────────

    def _passkeys(self, token_id, ctap2) -> dict:
        caps = passkeys_mod.capabilities(ctap2)
        if not caps["supported"] or not auth.is_unlocked(token_id):
            return {**caps, "unlocked": False}
        data = passkeys_mod.list_passkeys(token_id, ctap2)
        self._remember_sites(token_id, data["rps"])
        return {**caps, "unlocked": True, **data}

    def _remember_sites(self, token_id, rps):
        """Store the website names for the backup check (unless disabled)."""
        if not self._remember_contents():
            return
        try:
            record = self._scanner.get(token_id)
        except DeviceNotFound:
            return
        sites = [{"rp_id": rp["rp_id"] or rp["rp_id_hash"][:16], "name": rp["rp_name"],
                  "count": len(rp["credentials"]),
                  "users": [{"name": c.get("user_name", ""), "display": c.get("display_name", "")}
                            for c in rp["credentials"]]} for rp in rps]
        self.emit("history_updated", self.history.set_sites(record, sites))

    def history_set_lost(self, kid: str, lost: bool) -> dict:
        summary = self.history.set_lost(kid, bool(lost))
        if summary is None:
            raise PinError("Unknown history entry.", "not_found", status=404)
        self.emit("history_updated", summary)
        return summary

    def history_lost_done(self, kid: str, rp_id: str, done: bool) -> dict:
        summary = self.history.set_lost_done(kid, str(rp_id), bool(done))
        if summary is None:
            raise PinError("Unknown history entry.", "not_found", status=404)
        self.emit("history_updated", summary)
        return summary

    def history_replace(self, kid: str, new_kid: str | None) -> dict:
        summary = self.history.set_replace(str(kid), str(new_kid) if new_kid else None)
        if summary is None:
            raise PinError("Choose two different known keys.", "not_found", status=404)
        self.emit("history_updated", summary)
        return summary

    def history_replace_done(self, kid: str, item: str, done: bool) -> dict:
        # item names services/accounts: only kept when contents may be remembered
        if not self._remember_contents():
            raise PinError("Remembering key contents is turned off.", "not_allowed", status=409)
        summary = self.history.set_replace_done(str(kid), str(item), bool(done))
        if summary is None:
            raise PinError("Unknown history entry.", "not_found", status=404)
        self.emit("history_updated", summary)
        return summary

    def passkeys(self, token_id: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return self._passkeys(token_id, ctap2)

    def passkeys_probe(self, token_id: str, pin: str | None = None, extra: list | None = None) -> dict:
        """Keys without credential management: ask site by site (see passkey_probe)."""
        from fido2tool_core import passkey_probe
        record = self._scanner.get(token_id)
        known = [s["rp_id"] for e in self.history.list() for s in (e.get("sites") or [])]
        extra = [str(x) for x in (extra or [])][:50]
        rp_ids = passkey_probe.candidates(known, extra)
        self._probe_cancel.discard(token_id)
        with self._scanner.session(token_id, timeout=10.0, refresh=False) as (_record, ctap2):
            scan = passkey_probe.probe(
                ctap2, rp_ids, pin=pin or None,
                progress=lambda i, n: self.emit("probe_progress", {"id": token_id, "done": i, "total": n}),
                cancelled=lambda: token_id in self._probe_cancel)
        self._probe_cancel.discard(token_id)
        if self._remember_contents():
            self.emit("history_updated",
                      self.history.merge_probe(record, scan["results"], scan["complete"], len(rp_ids)))
        counts: dict[str, int] = {}
        for r in scan["results"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return {"found": [r for r in scan["results"] if r["status"] == "found"], "counts": counts,
                "complete": scan["complete"], "asked": len(scan["results"]), "candidates": len(rp_ids),
                "names": bool(pin)}

    def passkeys_probe_cancel(self, token_id: str) -> dict:
        self._probe_cancel.add(str(token_id))
        return {"cancelling": True}

    def passkey_rename(self, token_id: str, credential_id: str, user_id: str, name: str = "",
                       display_name: str = "", site: str = "") -> dict:
        with self._scanner.session(token_id, refresh=False) as (record, ctap2):
            passkeys_mod.rename_passkey(token_id, ctap2, credential_id, user_id, name, display_name)
            data = self._passkeys(token_id, ctap2)
        self._log(record, "passkey_renamed", site=str(site)[:120], user=str(display_name or name)[:120])
        return data

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

    # ── Function test ────────────────────────────────────────────────────────

    def function_test_info(self, token_id: str) -> dict:
        from fido2tool_core import function_test
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return {"needs_pin": function_test.needs_pin(ctap2)}

    def function_test(self, token_id: str, pin: str | None = None) -> dict:
        from fido2tool_core import function_test
        with self._scanner.session(token_id, timeout=UNLOCK_WAIT, refresh=False) as (record, ctap2):
            result = function_test.run(ctap2, pin=pin or None,
                                       on_touch=lambda: self.emit("test_touch", {"id": token_id}))
        self._log(record, "function_test", passed=bool(result["ok"]))
        return result

    # ── Smart card applications ──────────────────────────────────────────────

    def _card(self, token_id: str):
        record = self._scanner.get(token_id)
        reader = self._cards.find_reader(record)
        if reader:
            self._reader_tokens[reader] = token_id
        if not reader:
            raise CardError("KeyMelier cannot reach this key's smart card interface.", "no_card", status=404)
        return record, reader

    @contextmanager
    def _hold_reader(self, reader: str):
        token_id = self._reader_tokens.get(reader)
        if token_id is None:
            yield
            return
        try:
            cm = self._scanner.hold(token_id)
            cm.__enter__()
        except DeviceNotFound:
            yield  # FIDO side already gone; the card call reports it
            return
        except DeviceBusy:
            raise CardError("The key is busy. Try again in a moment.", "busy", status=409) from None
        try:
            yield
        finally:
            cm.__exit__(None, None, None)

    def card_apps(self, token_id: str) -> dict:
        """Which non-FIDO applications (OATH, PIV, OpenPGP) the key offers."""
        try:
            record, reader = self._card(token_id)
            apps = self._cards.applets(reader)
            if _is_yubikey(record):
                # OTP lives on the keyboard interface, not the smart card
                apps["otp"] = True
                apps["interfaces"] = True
            return {"reader": True, "apps": apps}
        except CardError as e:
            return {"reader": e.code not in ("no_card", "not_found"), "apps": {}, "code": e.code}

    def _remember_inventory(self, record, section, items):
        if self._remember_contents():
            self.emit("history_updated", self.history.set_inventory(record, section, items))

    # ── OATH (authenticator codes) ───────────────────────────────────────────

    def oath(self, token_id: str) -> dict:
        record, reader = self._card(token_id)

        def read(conn):
            st = oath_app.status(conn)
            major, minor, patch = (list(map(int, st["version"].split("."))) + [0, 0, 0])[:3]
            st["can_rename"] = (major, minor, patch) >= (5, 3, 1)
            return st, (oath_app.list_accounts(conn) if st["unlocked"] else None)

        st, accounts = self._cards.read(reader, read)
        if accounts is None:
            return st
        self._remember_inventory(record, "oath", [{"issuer": a["issuer"], "name": a["name"]} for a in accounts])
        return {**st, "accounts": accounts}

    def oath_unlock(self, token_id: str, password: str) -> dict:
        _record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            oath_app.unlock(conn, password)
        return self.oath(token_id)

    def oath_code(self, token_id: str, account_id: str) -> dict:
        _record, reader = self._card(token_id)
        with self._cards.connect(reader, timeout=30.0) as conn:
            return oath_app.calculate(conn, account_id)

    def oath_add(self, token_id: str, **fields) -> dict:
        record, reader = self._card(token_id)
        allowed = {"uri", "issuer", "name", "secret", "oath_type", "digits", "period", "algorithm", "touch"}
        with self._cards.connect(reader) as conn:
            account = oath_app.add(conn, **{k: v for k, v in fields.items() if k in allowed})
        self._log(record, "oath_added", site=account["issuer"], user=account["name"])
        return self.oath(token_id)

    def oath_rename(self, token_id: str, account_id: str, issuer: str = "", name: str = "") -> dict:
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            oath_app.rename(conn, account_id, issuer, name)
        self._log(record, "oath_renamed", site=issuer, user=name)
        return self.oath(token_id)

    def oath_delete(self, token_id: str, account_id: str, label: str = "") -> dict:
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            oath_app.delete(conn, account_id)
        self._log(record, "oath_deleted", site=str(label)[:120])
        return self.oath(token_id)

    def oath_password(self, token_id: str, password: str | None = None) -> dict:
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            oath_app.set_password(conn, password or None)
        self._log(record, "oath_password_set" if password else "oath_password_removed")
        return self.oath(token_id)

    def oath_reset(self, token_id: str, confirm: bool = False) -> dict:
        if confirm is not True:
            raise CardError("Please confirm the reset.", "invalid_input")
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            oath_app.reset(conn)
        self._log(record, "oath_reset")
        return self.oath(token_id)

    # ── OpenPGP ──────────────────────────────────────────────────────────────

    def openpgp(self, token_id: str) -> dict:
        record, reader = self._card(token_id)
        data = self._cards.read(reader, openpgp_app.info)
        self._remember_inventory(record, "openpgp", [
            {"slot": k["slot"], "algorithm": k["algorithm"], "fingerprint": k["fingerprint"]}
            for k in data["keys"] if k["present"]])
        return data

    def _openpgp_do(self, token_id, fn, *args, event=None, **detail) -> dict:
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            fn(conn, *args)
        if event:
            self._log(record, event, **detail)
        return self.openpgp(token_id)

    def openpgp_change_pin(self, token_id: str, which: str, current: str, new: str) -> dict:
        which = "admin" if which == "admin" else "user"
        return self._openpgp_do(token_id, openpgp_app.change_pin, which, current, new,
                                event=f"pgp_{which}_pin_changed")

    def openpgp_unblock_pin(self, token_id: str, admin_pin: str, new_pin: str) -> dict:
        return self._openpgp_do(token_id, openpgp_app.unblock_pin, admin_pin, new_pin, event="pgp_pin_unblocked")

    def openpgp_touch(self, token_id: str, slot: str, policy: str, admin_pin: str) -> dict:
        return self._openpgp_do(token_id, openpgp_app.set_touch, slot, policy, admin_pin,
                                event="pgp_touch_changed", slot=slot, policy=policy)

    def openpgp_signature_pin(self, token_id: str, every_time: bool, admin_pin: str) -> dict:
        return self._openpgp_do(token_id, openpgp_app.set_signature_pin, every_time is True, admin_pin)

    def openpgp_cardholder(self, token_id: str, name: str, url: str, admin_pin: str) -> dict:
        return self._openpgp_do(token_id, openpgp_app.set_cardholder, name, url, admin_pin)

    def openpgp_generate(self, token_id: str, algorithm: str, name: str, email: str = "",
                         expire_days: int = 0, admin_pin: str = "", user_pin: str = "",
                         replace: bool = False) -> dict:
        record, reader = self._card(token_id)
        if replace is not True and any(k["present"] for k in self._cards.read(reader, openpgp_app.info)["keys"]):
            raise CardError("This key already holds OpenPGP keys. Confirm replacing them.", "confirm_replace")
        with self._cards.connect(reader, timeout=30.0) as conn:
            result = openpgp_app.generate_keys(conn, algorithm, name, email, expire_days, admin_pin, user_pin)
        self._log(record, "pgp_generated", site=result["user_id"] if self._remember_contents() else None)
        return {**result, "state": self.openpgp(token_id)}

    def openpgp_reset(self, token_id: str, confirm: bool = False) -> dict:
        if confirm is not True:
            raise CardError("Please confirm the reset.", "invalid_input")
        return self._openpgp_do(token_id, openpgp_app.reset, event="pgp_reset")

    # ── PIV ──────────────────────────────────────────────────────────────────

    def piv(self, token_id: str) -> dict:
        record, reader = self._card(token_id)
        data = self._cards.read(reader, piv_app.info)
        self._remember_inventory(record, "piv", [
            {"slot": s["slot"], "label": f'{s["slot"].upper()}: {s["cert"]["subject"]}'}
            for s in data["slots"] if s["cert"]])
        return data

    def _piv_do(self, token_id, fn, *args, event=None, detail=None, **kwargs):
        record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            result = fn(conn, *args, **kwargs)
        if event:
            self._log(record, event, **(detail or {}))
        return result

    def piv_change_pin(self, token_id: str, which: str, current: str, new: str) -> dict:
        which = "puk" if which == "puk" else "pin"
        self._piv_do(token_id, piv_app.change_pin, which, current, new, event=f"piv_{which}_changed")
        return self.piv(token_id)

    def piv_unblock_pin(self, token_id: str, puk: str, new_pin: str) -> dict:
        self._piv_do(token_id, piv_app.unblock_pin, puk, new_pin, event="piv_pin_unblocked")
        return self.piv(token_id)

    def _piv_slot_used(self, token_id, slot) -> bool:
        data = self.piv(token_id)
        return any(s["slot"] == str(slot).lower() and (s["cert"] or s["key"]) for s in data["slots"])

    def piv_generate(self, token_id: str, slot: str, key_type: str, subject: str, days: int, pin: str,
                     management_key: str | None = None, pin_policy: str = "default",
                     touch_policy: str = "default", replace: bool = False) -> dict:
        if replace is not True and self._piv_slot_used(token_id, slot):
            raise CardError("This slot is in use. Confirm replacing it.", "confirm_replace")
        self._piv_do(token_id, piv_app.generate, slot, key_type, subject, days, pin, management_key,
                     pin_policy, touch_policy, event="piv_generated", detail={"slot": slot})
        return self.piv(token_id)

    def piv_import(self, token_id: str, slot: str, pem: str, pin: str | None = None,
                   management_key: str | None = None) -> dict:
        self._piv_do(token_id, piv_app.import_certificate, slot, pem, pin, management_key,
                     event="piv_imported", detail={"slot": slot})
        return self.piv(token_id)

    def piv_export(self, token_id: str, slot: str) -> dict:
        return {"pem": self._piv_do(token_id, piv_app.export_certificate, slot)}

    def piv_delete(self, token_id: str, slot: str, pin: str | None = None,
                   management_key: str | None = None, key: bool = False, confirm: bool = False) -> dict:
        if confirm is not True:
            raise CardError("Please confirm deleting.", "invalid_input")
        self._piv_do(token_id, piv_app.delete, slot, pin, management_key, key is True,
                     event="piv_deleted", detail={"slot": slot})
        return self.piv(token_id)

    def piv_protect_management_key(self, token_id: str, pin: str, management_key: str | None = None) -> dict:
        self._piv_do(token_id, piv_app.protect_management_key, pin, management_key, event="piv_mgmt_protected")
        return self.piv(token_id)

    def piv_reset(self, token_id: str, confirm: bool = False) -> dict:
        if confirm is not True:
            raise CardError("Please confirm the reset.", "invalid_input")
        self._piv_do(token_id, piv_app.reset, event="piv_reset")
        return self.piv(token_id)

    # ── YubiKey OTP slots and interfaces ─────────────────────────────────────

    def _yubikey(self, token_id):
        record = self._scanner.get(token_id)
        if not _is_yubikey(record):
            raise CardError("Only available for YubiKeys.", "unsupported")
        return record

    @contextmanager
    def _otp_hold(self, token_id):
        """Pause FIDO polling: the YubiKey answers only one interface at a time."""
        try:
            with self._scanner.hold(token_id):
                yield
        except DeviceBusy:
            raise CardError("The key is busy. Try again in a moment.", "busy", status=409) from None

    def otp(self, token_id: str) -> dict:
        record = self._yubikey(token_id)
        with self._otp_lock, self._otp_hold(token_id):
            data = yubikey_apps.otp_status(record.serial_number)
        data["input_monitoring"] = yubikey_apps.platform_needs_input_monitoring()
        self._remember_inventory(record, "otp", [
            {"otp_slot": s["slot"]} for s in data["slots"] if s["configured"]])
        return data

    def otp_swap(self, token_id: str) -> dict:
        record = self._yubikey(token_id)
        with self._otp_lock, self._otp_hold(token_id):
            yubikey_apps.otp_swap(record.serial_number)
        self._log(record, "otp_swapped")
        return self.otp(token_id)

    def otp_delete(self, token_id: str, slot: int, access_code: str | None = None) -> dict:
        record = self._yubikey(token_id)
        with self._otp_lock, self._otp_hold(token_id):
            yubikey_apps.otp_delete(record.serial_number, int(slot), access_code)
        self._log(record, "otp_deleted", slot=int(slot))
        return self.otp(token_id)

    def _otp_guard(self, token_id, slot, replace):
        if replace is not True and any(s["slot"] == int(slot) and s["configured"]
                                       for s in self.otp(token_id)["slots"]):
            raise CardError("This slot is in use. Confirm replacing it.", "confirm_replace")

    def otp_static(self, token_id: str, slot: int, password: str, access_code: str | None = None,
                   replace: bool = False) -> dict:
        self._otp_guard(token_id, slot, replace)
        record = self._yubikey(token_id)
        with self._otp_lock, self._otp_hold(token_id):
            yubikey_apps.otp_static_password(record.serial_number, int(slot), password, access_code)
        self._log(record, "otp_programmed", slot=int(slot))
        return self.otp(token_id)

    def otp_hmac(self, token_id: str, slot: int, secret: str | None = None, touch: bool = False,
                 access_code: str | None = None, replace: bool = False) -> dict:
        self._otp_guard(token_id, slot, replace)
        record = self._yubikey(token_id)
        with self._otp_lock, self._otp_hold(token_id):
            key = yubikey_apps.otp_challenge_response(record.serial_number, int(slot), secret,
                                                     touch is True, access_code)
        self._log(record, "otp_programmed", slot=int(slot))
        return {**self.otp(token_id), "secret": key}

    def open_privacy_settings(self) -> dict:
        """macOS: open Privacy & Security › Input Monitoring (for the OTP slots)."""
        import subprocess
        import sys
        if sys.platform == "darwin":
            subprocess.Popen(["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent"])
        return {}

    def interfaces(self, token_id: str) -> dict:
        self._yubikey(token_id)
        _record, reader = self._card(token_id)
        return self._cards.read(reader, yubikey_apps.interfaces)

    def interfaces_set(self, token_id: str, transport: str, apps: dict) -> dict:
        record = self._yubikey(token_id)
        _record, reader = self._card(token_id)
        with self._cards.connect(reader) as conn:
            yubikey_apps.set_interfaces(conn, transport, apps)
        self._log(record, "interfaces_changed", transport=str(transport))
        return {"restarting": True}

    # ── Key settings (authenticatorConfig) ───────────────────────────────────

    def _config(self, token_id, ctap2) -> dict:
        caps = key_config.capabilities(ctap2)
        return {**caps, "unlocked": auth.is_unlocked(token_id)}

    def config(self, token_id: str) -> dict:
        with self._scanner.session(token_id, refresh=False) as (_record, ctap2):
            return self._config(token_id, ctap2)

    def config_update(self, token_id: str, min_pin_length: int | None = None,
                      always_uv: bool | None = None, force_pin_change: bool = False) -> dict:
        with self._scanner.session(token_id) as (record, ctap2):
            if min_pin_length is not None:
                key_config.set_min_pin_length(token_id, ctap2, min_pin_length)
                self._log(record, "config_min_pin", value=int(min_pin_length))
            if always_uv is not None:
                before = key_config.capabilities(ctap2)["always_uv"]
                key_config.set_always_uv(token_id, ctap2, always_uv)
                if bool(before) != bool(always_uv):
                    self._log(record, "config_always_uv", value=bool(always_uv))
            if force_pin_change:
                key_config.force_pin_change(token_id, ctap2)
                self._log(record, "config_force_pin")
            ctap2._info = ctap2.get_info()  # re-read the changed options
            return self._config(token_id, ctap2)

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
        record = self._scanner.get(token_id)
        if not record.serial_number and any(
                r.aaguid == record.aaguid and r.id != record.id for r in self._scanner.get_all()):
            # Without a serial the re-plugged key can only be recognised by
            # its model – with a second key of that model present, refuse.
            raise PinError("Another key of this model is connected. Unplug it before resetting.",
                           "ambiguous_key")
        info = reset_mod.arm(record)

        def check_expired():
            if reset_mod.expired():
                self.emit("reset_done", {"ok": False, "code": "expired", "error": "Time is up."})

        threading.Timer(reset_mod.ARM_WINDOW + 0.5, check_expired).start()
        return info

    def reset_disarm(self) -> dict:
        return {"disarmed": reset_mod.disarm()}

    # ── Export ───────────────────────────────────────────────────────────────

    def export_all(self) -> dict:
        if stateless():
            raise PinError("Exports are disabled in stateless mode.", "disabled")
        results = []
        for record in self._scanner.get_all():
            try:
                path = self._exporter.export(record)
                results.append({"serial": record.serial_number, "file": str(path)})
            except Exception as e:
                results.append({"serial": record.serial_number, "error": str(e)})
        return {"exports": results}
