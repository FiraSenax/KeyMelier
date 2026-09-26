import base64
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

MDS3_URL = "https://mds.fidoalliance.org/"
CACHE_PATH = Path.home() / ".keymelier" / "mds3_cache.json"
CACHE_MAX_AGE_HOURS = 24

# Higher index = higher priority (most severe first)
STATUS_PRIORITY = [
    "NOT_FIDO_CERTIFIED",
    "SELF_ASSERTION_SUBMITTED",
    "FIDO_CERTIFIED",
    "FIDO_CERTIFIED_L1",
    "FIDO_CERTIFIED_L1plus",
    "FIDO_CERTIFIED_L2",
    "FIDO_CERTIFIED_L2plus",
    "FIDO_CERTIFIED_L3",
    "FIDO_CERTIFIED_L3plus",
    "UPDATE_AVAILABLE",
    "USER_VERIFICATION_BYPASS",
    "USER_KEY_PHYSICAL_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "ATTESTATION_KEY_COMPROMISE",
    "REVOKED",
]


class MDS3Client:
    def __init__(self):
        self._entries: list[dict] = []
        self._by_aaguid: dict[str, dict] = {}
        self._fetched_at: Optional[datetime] = None
        self._serial: Optional[int] = None
        self._loaded = False

    def _read_cache(self) -> dict | None:
        """Return the cached, signature-verified blob, or None.

        The raw JWT is cached and re-verified on every load, so editing the
        cache file cannot inject metadata. Old unverified caches are ignored.
        """
        from fido2tool_core.mds_verify import MdsVerificationError, verify_jwt

        try:
            data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            payload = verify_jwt(data["jwt"])
            return {"fetched_at": datetime.fromisoformat(data["fetched_at"]), "payload": payload}
        except FileNotFoundError:
            return None
        except (MdsVerificationError, KeyError, ValueError) as e:
            logger.warning("Ignoring MDS3 cache: %s", e)
            return None

    def _is_cache_fresh(self) -> bool:
        cache = self._read_cache()
        return bool(cache and datetime.now(timezone.utc) - cache["fetched_at"] < timedelta(hours=CACHE_MAX_AGE_HOURS))

    def _fetch_from_network(self) -> list[dict]:
        from fido2tool_core.mds_verify import verify_jwt

        logger.info("Fetching MDS3 from %s", MDS3_URL)
        resp = requests.get(MDS3_URL, timeout=20)
        resp.raise_for_status()
        payload = verify_jwt(resp.text)  # raises MdsVerificationError
        cached = self._read_cache()
        if cached and payload.get("no", 0) < cached["payload"].get("no", 0):
            raise ValueError(f"MDS3 blob #{payload.get('no')} is older than cached #{cached['payload'].get('no')}")
        self._serial = payload.get("no")
        self._save_cache(resp.text)
        entries = payload.get("entries", [])
        logger.info("MDS3 fetched and verified: blob #%s, %d entries", payload.get("no"), len(entries))
        return entries

    def _save_cache(self, jwt: str):
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        cache = {"fetched_at": datetime.now(timezone.utc).isoformat(), "jwt": jwt}
        CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")

    def _load_cache(self) -> list[dict]:
        cache = self._read_cache()
        if cache is None:
            raise ValueError("no valid MDS3 cache")
        self._fetched_at = cache["fetched_at"]
        self._serial = cache["payload"].get("no")
        return cache["payload"].get("entries", [])

    def _index(self, entries: list[dict]):
        self._entries = entries
        self._by_aaguid = {}
        for entry in entries:
            aaguid = (entry.get("aaguid") or "").lower().strip()
            if aaguid:
                self._by_aaguid[aaguid] = entry

    def ensure_loaded(self):
        if self._loaded:
            return
        try:
            if self._is_cache_fresh():
                entries = self._load_cache()
                logger.info("MDS3 loaded from cache (%d entries)", len(entries))
            else:
                entries = self._fetch_from_network()
                self._fetched_at = datetime.now(timezone.utc)
            self._index(entries)
        except Exception as e:
            logger.warning("MDS3 load failed (%s); using empty metadata", e)
            # Fall back to stale cache if available
            if CACHE_PATH.exists():
                try:
                    entries = self._load_cache()
                    self._index(entries)
                    logger.info("Using stale MDS3 cache (%d entries)", len(entries))
                except Exception:
                    self._entries = []
                    self._by_aaguid = {}
            else:
                self._entries = []
                self._by_aaguid = {}
        self._loaded = True

    def refresh_if_stale(self) -> bool:
        """Re-download the metadata if the cache is older than the max age.
        Returns True if new metadata was loaded."""
        if self._is_cache_fresh():
            return False
        try:
            entries = self._fetch_from_network()
        except Exception as e:
            logger.info("MDS3 refresh failed: %s", e)
            return False
        self._fetched_at = datetime.now(timezone.utc)
        self._index(entries)
        return True

    def lookup(self, aaguid: str) -> Optional[dict]:
        return self._by_aaguid.get(aaguid.lower().strip())

    def get_description(self, aaguid: str) -> Optional[str]:
        entry = self.lookup(aaguid)
        if not entry:
            return None
        return entry.get("metadataStatement", {}).get("description")

    def get_highest_security_status(self, aaguid: str) -> Optional[str]:
        entry = self.lookup(aaguid)
        if not entry:
            return None
        reports = entry.get("statusReports", [])
        statuses = [r.get("status", "") for r in reports]
        best = None
        best_priority = -1
        for s in statuses:
            try:
                p = STATUS_PRIORITY.index(s)
                if p > best_priority:
                    best_priority = p
                    best = s
            except ValueError:
                pass
        return best

    def get_cache_info(self) -> dict:
        return {
            "cached": self._loaded and bool(self._entries),
            "fetched_at": self._fetched_at.isoformat() if self._fetched_at else None,
            "entry_count": len(self._entries),
            "serial": self._serial,
            "verified": bool(self._entries),  # only verified blobs are ever loaded
        }
