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
import threading
from datetime import datetime, timezone
from pathlib import Path

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
    def __init__(self, path: Path = HISTORY_FILE):
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self):
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._entries = {e["key_id"]: e for e in data.get("keys", [])}
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Could not read history (%s); starting fresh", e)

    def _save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"version": 1, "keys": list(self._entries.values())}, indent=1),
                encoding="utf-8",
            )
            tmp.replace(self._path)
        except Exception as e:
            logger.error("Could not save history: %s", e)

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
