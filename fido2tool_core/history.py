"""Persistent history of keys seen by KeyMelier and what happened to them.

Stored as JSON in ~/keymelier/history.json. FIDO keys expose no unique serial
over the FIDO interface, so a key is identified by AAGUID (model/firmware
batch) plus the USB serial when one is reported. Two keys of the same model
without a serial therefore share one history entry.

Never stores PINs or secrets: only the last getInfo snapshot and an event log.
"""

import dataclasses
import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from fido2tool_core.storage import atomic_write, stateless, history_cipher

logger = logging.getLogger(__name__)

HISTORY_FILE = Path.home() / "keymelier" / "history.json"
MAX_EVENTS = 200

# Fields that describe the physical connection, not the key
_VOLATILE = {"id", "path", "first_seen"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def key_id(record) -> str:
    raw = f"{record.aaguid}|{record.serial_number or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class History:
    def __init__(self, path: Path = HISTORY_FILE, enabled: bool = False):
        self.enabled = enabled and not stateless()
        self._encrypted = os.environ.get("KEYMELIER_ENCRYPT_HISTORY") == "1"
        self._path = path.with_suffix(".encrypted") if self._encrypted else path
        self._cipher = None
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self):
        if not self.enabled:
            return
        try:
            raw = self._path.read_bytes()
            if self._encrypted:
                self._cipher = history_cipher(create=False)
                raw = self._cipher.decrypt(raw)
            data = json.loads(raw)
            self._entries = {e["key_id"]: e for e in data.get("keys", [])}
            for entry in self._entries.values():
                snap = entry.get("snapshot", {})
                snap["security_status"] = "UNKNOWN"
                att = snap.get("attestation")
                if att and "status" not in att:
                    att.update(status="UNVERIFIED", passed=False)
                for ev in entry.get("events", []):
                    if ev.get("type") == "attestation" and "status" not in ev:
                        ev["type"] = "attestation_skipped"
        except FileNotFoundError:
            pass
        except Exception as e:
            if self._encrypted:
                self.enabled = False
                raise RuntimeError("Encrypted history could not be opened; existing file preserved") from e
            logger.warning("Could not read history (%s); starting fresh", e)

    def _save(self):
        if not self.enabled:
            return
        try:
            raw = json.dumps({"version": 1, "keys": list(self._entries.values())}, indent=1).encode()
            if self._encrypted:
                self._cipher = self._cipher or history_cipher()
                raw = self._cipher.encrypt(raw)
            atomic_write(self._path, raw)
        except Exception as e:
            logger.error("Could not save history: %s", e)

    def set_enabled(self, enabled):
        with self._lock:
            was_enabled = self.enabled
            self.enabled = bool(enabled) and not stateless()
            # Turning persistence off does not delete existing user files.
            if self.enabled and not was_enabled and self._path.exists():
                session_entries = self._entries
                self._load()
                for kid, current in session_entries.items():
                    previous = self._entries.get(kid)
                    if previous is None:
                        self._entries[kid] = current
                    else:
                        previous["snapshot"] = current["snapshot"]
                        previous["last_seen"] = current["last_seen"]
                        previous["connect_count"] += current["connect_count"]
                        previous["events"] = (previous["events"] + current["events"])[-MAX_EVENTS:]
            if self.enabled:
                self._save()

    @staticmethod
    def _summary(entry: dict) -> dict:
        summary = {k: v for k, v in entry.items() if k != "events"}
        entry.pop("replaces", None)  # reported once, then forgotten
        return summary

    def _entry_for(self, record) -> dict:
        kid = key_id(record)
        entry = self._entries.get(kid)
        if entry is None and record.serial_number:
            # Seen before without a serial (older KeyMelier or no vendor info):
            # continue that entry instead of starting a new one
            legacy_kid = hashlib.sha256(f"{record.aaguid}|".encode()).hexdigest()[:16]
            legacy = self._entries.get(legacy_kid)
            if legacy is not None and not legacy.get("snapshot", {}).get("serial_number"):
                entry = self._entries.pop(legacy_kid)
                entry["key_id"] = kid
                entry["replaces"] = legacy_kid
                self._entries[kid] = entry
        if entry is None:
            entry = {
                "key_id": kid,
                "first_seen": _now(),
                "last_seen": _now(),
                "connect_count": 0,
                "label": "",
                "snapshot": {},
                "events": [],
            }
            self._entries[kid] = entry
        return entry

    def update_snapshot(self, record) -> dict:
        """Store the latest known state of a key. Returns the entry summary."""
        with self._lock:
            entry = self._entry_for(record)
            snap = dataclasses.asdict(record)
            entry["snapshot"] = {k: v for k, v in snap.items() if k not in _VOLATILE}
            entry["last_seen"] = _now()
            self._save()
            return self._summary(entry)

    def add_event(self, record, kind: str, **detail) -> dict:
        """Append an event (connected, pin_changed, passkey_deleted, ...)."""
        with self._lock:
            entry = self._entry_for(record)
            if kind == "connected":
                entry["connect_count"] += 1
            entry["last_seen"] = _now()
            entry["events"].append({"ts": _now(), "type": kind, **detail})
            del entry["events"][:-MAX_EVENTS]
            self._save()
            return self._summary(entry)

    def set_sites(self, record, sites: list[dict]) -> dict:
        """Remember which websites have passkeys on this key (names only)."""
        with self._lock:
            entry = self._entry_for(record)
            entry["sites"] = sorted(
                ({"rp_id": s["rp_id"], "name": s.get("name", ""), "count": int(s.get("count", 1))} for s in sites),
                key=lambda s: s["rp_id"],
            )
            entry["sites_updated"] = _now()
            self._save()
            return self._summary(entry)

    def clear_sites(self) -> None:
        with self._lock:
            for entry in self._entries.values():
                entry.pop("sites", None)
                entry.pop("sites_updated", None)
                entry.pop("lost_done", None)
                for event in entry.get("events", []):
                    for field in ("site", "user", "rp_id"):
                        event.pop(field, None)
            self._save()

    def set_lost(self, kid: str, lost: bool) -> dict | None:
        with self._lock:
            entry = self._entries.get(kid)
            if not entry:
                return None
            if lost:
                entry["lost_since"] = entry.get("lost_since") or _now()
            else:
                entry.pop("lost_since", None)
                entry.pop("lost_done", None)
            self._save()
            return self._summary(entry)

    def set_lost_done(self, kid: str, rp_id: str, done: bool) -> dict | None:
        with self._lock:
            entry = self._entries.get(kid)
            if not entry:
                return None
            items = set(entry.get("lost_done", []))
            (items.add if done else items.discard)(rp_id)
            entry["lost_done"] = sorted(items)
            self._save()
            return self._summary(entry)

    def list(self) -> list[dict]:
        with self._lock:
            items = [self._summary(e) for e in self._entries.values()]
        return sorted(items, key=lambda e: e["last_seen"], reverse=True)

    def get(self, kid: str) -> dict | None:
        with self._lock:
            entry = self._entries.get(kid)
            return json.loads(json.dumps(entry)) if entry else None

    def rename(self, kid: str, label: str) -> dict | None:
        with self._lock:
            entry = self._entries.get(kid)
            if not entry:
                return None
            entry["label"] = (label or "").strip()[:60]
            self._save()
            return self._summary(entry)

    def forget(self, kid: str) -> bool:
        with self._lock:
            removed = self._entries.pop(kid, None) is not None
            if removed:
                self._save()
            return removed
