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
from fido2tool_core.storage import atomic_write, set_aside, stateless, history_cipher

logger = logging.getLogger(__name__)

HISTORY_FILE = Path.home() / "keymelier" / "history.json"
MAX_EVENTS = 200
FORGET_KEEP_DAYS = 400   # how long "this key was removed" is remembered for sync

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
        # key_id -> when it was removed; tells other computers (sync) to drop it
        # too. Only kept while sync is on – otherwise forgetting leaves no trace.
        self._forgotten: dict[str, str] = {}
        self.track_forgotten = False
        self.revision = 0   # bumped on every change (sync writes only when it moved)
        self.load_problem: dict | None = None   # history file could not be read (kept aside)
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
            self._forgotten = {k: v for k, v in (data.get("forgotten") or {}).items()
                               if isinstance(k, str) and isinstance(v, str)}
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
            # Never overwrite what we could not read: keep it under another name
            self._entries, self._forgotten = {}, {}
            kept = set_aside(self._path)
            self.load_problem = {"code": "history_unreadable", "file": kept or ""}
            logger.warning("Could not read history (%s); kept as %s, starting fresh", e, kept)

    def _save(self):
        self.revision += 1
        if not self.enabled:
            return
        try:
            raw = json.dumps({"version": 1, "keys": list(self._entries.values()),
                              "forgotten": self._forgotten}, indent=1).encode()
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

    @staticmethod
    def _site(s: dict, source: str, checked: str) -> dict:
        site = {"rp_id": s["rp_id"], "name": s.get("name", ""), "count": int(s.get("count", 1)),
                "users": [{"name": str(u.get("name", ""))[:200], "display": str(u.get("display", ""))[:200]}
                          for u in (s.get("users") or [])][:100],
                "source": source, "checked": checked}
        if s.get("partial"):
            site["partial"] = True
        return site

    def set_sites(self, record, sites: list[dict]) -> dict:
        """Remember which websites (and account names) have passkeys on this
        key, from the key's complete list (credential management)."""
        with self._lock:
            entry = self._entry_for(record)
            now = _now()
            entry["sites"] = sorted((self._site(s, "list", now) for s in sites), key=lambda s: s["rp_id"])
            entry["sites_updated"] = now
            entry.pop("sites_probed", None)
            entry.pop("probe", None)
            entry.pop("probe_rp", None)
            self._save()
            return self._summary(entry)

    def merge_probe(self, record, results: list[dict], complete: bool, checked: int) -> dict:
        """Merge a passkey search (keys that cannot list passkeys). Only an
        explicit "no credentials" answer removes a known site; errors,
        unsupported queries and sites not asked (cancelled scan) keep what
        was known before.

        probe_rp records per rpId what the search found out and when – a
        search only covers the sites it asked, so only those can ever be
        "not there". A definite answer (found/none) is not overwritten by a
        later error, unsupported or PIN-required answer."""
        with self._lock:
            entry = self._entry_for(record)
            now = _now()
            sites = {s["rp_id"]: s for s in entry.get("sites") or [] if isinstance(s, dict) and s.get("rp_id")}
            counts: dict[str, int] = {}
            per_rp = dict(entry.get("probe_rp") or {})
            for r in results:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
                if r["status"] in ("found", "none") or r["rp_id"] not in per_rp:
                    per_rp[r["rp_id"]] = {"status": r["status"], "checked": now}
                    if r.get("partial"):
                        per_rp[r["rp_id"]]["partial"] = True
                if r["status"] == "found":
                    sites[r["rp_id"]] = self._site(r, "probe", now)
                elif r["status"] == "none":
                    sites.pop(r["rp_id"], None)
            entry["sites"] = sorted(sites.values(), key=lambda s: s["rp_id"])
            entry["sites_updated"] = now
            entry["sites_probed"] = checked
            entry["probe_rp"] = per_rp
            entry["probe"] = {"at": now, "complete": bool(complete), "asked": len(results), "counts": counts}
            self._save()
            return self._summary(entry)

    def set_inventory(self, record, section: str, items: list[dict]) -> dict:
        """Remember what a key holds in one area (e.g. "oath", "piv", "openpgp").

        Only descriptive labels are stored (account names, certificate
        subjects, key fingerprints) – never secrets or codes.
        """
        with self._lock:
            entry = self._entry_for(record)
            inventory = entry.setdefault("inventory", {})
            inventory[section] = {"items": items, "updated": _now()}
            self._save()
            return self._summary(entry)

    def clear_sites(self) -> None:
        with self._lock:
            for entry in self._entries.values():
                entry.pop("sites", None)
                entry.pop("sites_updated", None)
                entry.pop("sites_probed", None)
                entry.pop("probe", None)
                entry.pop("probe_rp", None)
                entry.pop("inventory", None)
                entry.pop("lost_done", None)
                entry.pop("replace", None)
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
            entry["lost_at"] = _now()
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
            entry["lost_at"] = _now()
            self._save()
            return self._summary(entry)

    def set_replace(self, kid: str, new_kid: str | None) -> dict | None:
        """Start (or stop, new_kid=None) replacing key kid by new_kid. Choosing
        another new key starts over; nothing is ever done to either key."""
        with self._lock:
            entry = self._entries.get(kid)
            if not entry or (new_kid and (new_kid == kid or new_kid not in self._entries)):
                return None
            current = entry.get("replace") or {}
            if not new_kid:
                entry.pop("replace", None)
            elif current.get("new") != new_kid:
                entry["replace"] = {"new": new_kid, "since": _now(), "done": []}
            entry["replace_at"] = _now()
            self._save()
            return self._summary(entry)

    def set_replace_done(self, kid: str, item: str, done: bool) -> dict | None:
        """The user confirms (or un-confirms) that one item was moved."""
        with self._lock:
            entry = self._entries.get(kid)
            if not entry or not entry.get("replace"):
                return None
            items = set(entry["replace"].get("done", []))
            (items.add if done else items.discard)(item[:600])
            entry["replace"]["done"] = sorted(items)[:5000]
            entry["replace_at"] = _now()
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
            entry["label_at"] = _now()
            self._save()
            return self._summary(entry)

    # ── Export / import ──────────────────────────────────────────────────────

    def export(self) -> dict:
        """Everything KeyMelier knows about the keys (for backup or another
        computer). Contains website/account names – the caller warns."""
        with self._lock:
            return json.loads(json.dumps({
                "format": "keymelier-history", "version": 1, "exported": _now(),
                "keys": list(self._entries.values()),
            }))

    def import_(self, data: dict) -> dict:
        """Merge an export into this history. Existing keys keep their data
        and gain missing events/contents; unknown keys are added."""
        if not isinstance(data, dict) or data.get("format") != "keymelier-history" \
                or not isinstance(data.get("keys"), list):
            raise ValueError("not a KeyMelier history export")
        added = merged = 0
        with self._lock:
            for raw in data["keys"][:500]:
                entry = _clean_entry(raw)
                if entry is None:
                    continue
                current = self._entries.get(entry["key_id"])
                if current is None:
                    self._entries[entry["key_id"]] = entry
                    added += 1
                    continue
                candidate = json.loads(json.dumps(current))
                _merge_entry(candidate, entry)
                self._entries[entry["key_id"]] = candidate
                merged += 1
            self._save()
        return {"added": added, "merged": merged}

    # ── Sync between the user's computers (fido2tool_core/sync.py) ─────────

    def stop_tracking_forgotten(self) -> None:
        """Sync turned off: drop the removal marks (they only serve sync)."""
        with self._lock:
            self.track_forgotten = False
            if self._forgotten:
                self._forgotten = {}
                self._save()

    def sync_state(self) -> dict:
        """Everything to share with the other computers."""
        with self._lock:
            return json.loads(json.dumps({"keys": list(self._entries.values()), "forgotten": self._forgotten}))

    def merge_sync(self, state: dict, keep_contents: bool = True) -> bool:
        """Merge another computer's state. Every field group follows its
        newest change (label, lost, replacement, websites, contents); a key
        removed there is removed here unless it was seen here afterwards.
        Security verdicts are never taken over. Returns True if anything changed."""
        if not isinstance(state, dict):
            return False
        cutoff = datetime.now(timezone.utc).timestamp() - FORGET_KEEP_DAYS * 86400
        with self._lock:
            before = json.dumps([self._entries, self._forgotten], sort_keys=True)
            for kid, when in (state.get("forgotten") or {}).items():
                if isinstance(kid, str) and _ID.match(kid) and isinstance(when, str) and when > self._forgotten.get(kid, ""):
                    self._forgotten[kid] = when[:40]
            for raw in (state.get("keys") or [])[:500] if isinstance(state.get("keys"), list) else []:
                entry = _clean_entry(raw, source="sync")
                if entry is None:
                    continue
                if not keep_contents:
                    for field in _CONTENT_FIELDS:
                        entry.pop(field, None)
                current = self._entries.get(entry["key_id"])
                if current is None:
                    self._entries[entry["key_id"]] = entry
                else:
                    candidate = json.loads(json.dumps(current))
                    _merge_entry(candidate, entry)
                    self._entries[entry["key_id"]] = candidate
            for kid, when in list(self._forgotten.items()):
                entry = self._entries.get(kid)
                if entry is not None and _last_change(entry) <= when:
                    del self._entries[kid]
                elif entry is not None:
                    del self._forgotten[kid]   # seen again after it was removed
                elif _ts(when) < cutoff:
                    del self._forgotten[kid]
            changed = json.dumps([self._entries, self._forgotten], sort_keys=True) != before
            if changed:
                self._save()
            return changed

    def forget(self, kid: str) -> bool:
        with self._lock:
            removed = self._entries.pop(kid, None) is not None
            if removed:
                if self.track_forgotten:
                    self._forgotten[kid] = _now()
                # no trace left: drop replacements that pointed to this key
                for entry in self._entries.values():
                    if (entry.get("replace") or {}).get("new") == kid:
                        entry.pop("replace", None)
                self._save()
            return removed


# ── Import helpers ───────────────────────────────────────────────────────────

_ID = __import__("re").compile(r"^[0-9a-f]{16}$")


# Snapshot fields an import may carry: descriptive only. Security verdicts
# (attestation, advisories, MDS status) are never imported – they are
# re-established when the real key is plugged in.
_SNAPSHOT_TEXT = {"product_name": 120, "serial_number": 40, "manufacturer": 80, "aaguid": 36,
                  "firmware_version_str": 40, "form_factor": 40, "mds_description": 200}
_SNAPSHOT_INT = ("vendor_id", "product_id", "firmware_version_raw", "max_cred_count", "min_pin_length")


# Everything that names websites, accounts or contents ("remember contents")
_CONTENT_FIELDS = ("sites", "sites_updated", "sites_probed", "probe", "probe_rp", "inventory",
                   "lost_done", "replace", "replace_at")


def _ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _last_change(entry: dict) -> str:
    """Newest time anything happened to this key (to compare with its removal)."""
    stamps = [entry.get("last_seen", ""), entry.get("label_at", ""), entry.get("lost_at", ""),
              entry.get("replace_at", ""), entry.get("sites_updated", "")]
    stamps += [str(v.get("updated", "")) for v in (entry.get("inventory") or {}).values() if isinstance(v, dict)]
    return max(s for s in stamps if isinstance(s, str))


_PROBE_STATUS = ("found", "none", "unsupported", "uv_required", "error")


def _text(v, n=200):
    return v[:n] if isinstance(v, str) else ""


def _clean_snapshot(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    snap = {k: _text(raw.get(k), n) for k, n in _SNAPSHOT_TEXT.items() if isinstance(raw.get(k), str)}
    for k in _SNAPSHOT_INT:
        if isinstance(raw.get(k), int) and not isinstance(raw.get(k), bool):
            snap[k] = raw[k]
    for k in ("fido2_versions", "extensions"):
        if isinstance(raw.get(k), list):
            snap[k] = [_text(x, 40) for x in raw[k][:20] if isinstance(x, str)]
    if isinstance(raw.get("options"), dict):
        snap["options"] = {_text(k, 40): v for k, v in list(raw["options"].items())[:40] if isinstance(v, bool)}
    if isinstance(raw.get("algorithms"), list):
        snap["algorithms"] = [a for a in raw["algorithms"][:20] if isinstance(a, int) and not isinstance(a, bool)]
    snap["security_status"] = "UNKNOWN"
    snap["imported"] = True
    return snap


def _clean_event(e) -> dict | None:
    if not isinstance(e, dict) or not isinstance(e.get("type"), str) or not isinstance(e.get("ts"), str):
        return None
    out = {"ts": _text(e["ts"], 40), "type": _text(e["type"], 40)}
    for k, v in e.items():
        if k in out or not isinstance(k, str) or len(k) > 20 or len(out) > 12:
            continue
        if isinstance(v, str):
            out[k] = v[:200]
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
    return out


def _clean_items(items) -> list:
    out = []
    for item in (items if isinstance(items, list) else [])[:500]:
        if isinstance(item, dict):
            clean = {_text(k, 20): (v[:300] if isinstance(v, str) else v) for k, v in list(item.items())[:8]
                     if isinstance(k, str) and (isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool)))}
            if clean:
                out.append(clean)
    return out


def _clean_entry(raw, source: str = "import") -> dict | None:
    """Validate an imported entry; keep only known fields of the right type."""
    if not isinstance(raw, dict) or not isinstance(raw.get("key_id"), str) or not _ID.match(raw["key_id"]):
        return None
    events = [e for e in map(_clean_event, raw.get("events") or [] if isinstance(raw.get("events"), list) else [])
              if e][-MAX_EVENTS:]
    entry = {
        "key_id": raw["key_id"],
        "first_seen": _text(raw.get("first_seen"), 40) or _now(),
        "last_seen": _text(raw.get("last_seen"), 40) or _now(),
        "connect_count": raw.get("connect_count") if isinstance(raw.get("connect_count"), int)
        and not isinstance(raw.get("connect_count"), bool) and raw.get("connect_count") >= 0 else 0,
        "label": _text(raw.get("label"), 60),
        "snapshot": _clean_snapshot(raw.get("snapshot")),
        "events": events,
    }
    if isinstance(raw.get("sites"), list):
        entry["sites"] = [{"source": source, "checked": _text(s.get("checked"), 40),
                           "rp_id": _text(s.get("rp_id"), 253), "name": _text(s.get("name")),
                           "count": s["count"] if isinstance(s.get("count"), int) and not isinstance(s.get("count"), bool) else 1,
                           "users": [{"name": _text(u.get("name")), "display": _text(u.get("display"))}
                                     for u in (s.get("users") if isinstance(s.get("users"), list) else [])[:100]
                                     if isinstance(u, dict)]}
                          for s in raw["sites"][:2000] if isinstance(s, dict) and isinstance(s.get("rp_id"), str) and s["rp_id"]]
    if isinstance(raw.get("inventory"), dict):
        inv = {}
        for section in ("oath", "openpgp", "piv", "otp"):
            value = raw["inventory"].get(section)
            if isinstance(value, dict):
                inv[section] = {"items": _clean_items(value.get("items")), "updated": _text(value.get("updated"), 40)}
        if inv:
            entry["inventory"] = inv
    if isinstance(raw.get("lost_done"), list):
        entry["lost_done"] = [_text(x, 300) for x in raw["lost_done"][:2000] if isinstance(x, str)]
    if isinstance(raw.get("replace"), dict) and isinstance(raw["replace"].get("new"), str) \
            and _ID.match(raw["replace"]["new"]) and raw["replace"]["new"] != raw["key_id"]:
        done = raw["replace"].get("done")
        entry["replace"] = {"new": raw["replace"]["new"], "since": _text(raw["replace"].get("since"), 40),
                            "done": [_text(x, 600) for x in (done if isinstance(done, list) else [])[:5000] if isinstance(x, str)]}
    for field in ("sites_updated", "lost_since", "label_at", "lost_at", "replace_at"):
        if isinstance(raw.get(field), str):
            entry[field] = raw[field][:40]
    if isinstance(raw.get("sites_probed"), int) and not isinstance(raw.get("sites_probed"), bool):
        entry["sites_probed"] = raw["sites_probed"]
    if isinstance(raw.get("probe_rp"), dict):
        entry["probe_rp"] = {rp[:253]: {"status": v["status"], "checked": _text(v.get("checked"), 40),
                                        **({"partial": True} if v.get("partial") is True else {})}
                             for rp, v in list(raw["probe_rp"].items())[:1000]
                             if isinstance(rp, str) and rp and isinstance(v, dict) and v.get("status") in _PROBE_STATUS}
    return entry


def _merge_entry(current: dict, other: dict) -> None:
    current["first_seen"] = min(current.get("first_seen", other["first_seen"]), other["first_seen"])
    if other["last_seen"] > current.get("last_seen", ""):
        current["last_seen"] = other["last_seen"]
        if other.get("snapshot"):
            # only fill descriptive gaps; never take verdicts from an import
            filled = _clean_snapshot(other["snapshot"])
            filled.pop("imported", None)
            filled.pop("security_status", None)
            current["snapshot"] = {**filled, **current.get("snapshot", {})}
    current["connect_count"] = max(current.get("connect_count", 0), other.get("connect_count", 0))
    if other.get("label_at") or current.get("label_at"):
        if other.get("label_at", "") > current.get("label_at", ""):
            current["label"], current["label_at"] = other.get("label", ""), other["label_at"]
    elif not current.get("label") and other.get("label"):
        current["label"] = other["label"]
    seen = {(e.get("ts"), e.get("type")) for e in current.get("events", [])}
    events = current.get("events", []) + [e for e in other["events"] if (e["ts"], e["type"]) not in seen]
    current["events"] = sorted(events, key=lambda e: e.get("ts", ""))[-MAX_EVENTS:]
    if other.get("sites") is not None and other.get("sites_updated", "") > current.get("sites_updated", ""):
        current["sites"], current["sites_updated"] = other["sites"], other["sites_updated"]
        # coverage belongs to the site list it describes
        for field in ("sites_probed", "probe_rp", "probe"):
            if field in other:
                current[field] = other[field]
            else:
                current.pop(field, None)
    for section, inv in (other.get("inventory") or {}).items():
        mine = current.setdefault("inventory", {}).get(section)
        if not isinstance(mine, dict):
            mine = None
        if isinstance(inv, dict) and (not mine or inv.get("updated", "") > str(mine.get("updated", ""))):
            current["inventory"][section] = inv
    if other.get("lost_at") or current.get("lost_at"):
        # the newest decision wins – also "no longer lost"
        if other.get("lost_at", "") > current.get("lost_at", ""):
            for field in ("lost_since", "lost_done"):
                if field in other:
                    current[field] = other[field]
                else:
                    current.pop(field, None)
            current["lost_at"] = other["lost_at"]
    else:
        if other.get("lost_since") and not current.get("lost_since"):
            current["lost_since"] = other["lost_since"]
        if other.get("lost_done"):
            mine = [x for x in current.get("lost_done", []) if isinstance(x, str)]
            current["lost_done"] = sorted(set(mine) | set(other["lost_done"]))
    if other.get("replace_at", "") > current.get("replace_at", ""):
        if "replace" in other:
            current["replace"] = other["replace"]
        else:
            current.pop("replace", None)
        current["replace_at"] = other["replace_at"]
