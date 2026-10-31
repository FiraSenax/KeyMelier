import base64
import binascii
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_to_bytes
from keymelier_core.network import bounded_get, read_limited
from keymelier_core.storage import atomic_write, stateless

logger = logging.getLogger(__name__)

MDS3_URL = "https://mds.fidoalliance.org/"
CACHE_PATH = Path.home() / ".keymelier" / "mds3_cache.json"
CACHE_MAX_AGE_HOURS = 24


def display_icon(value):
    """Return a bounded, passive MDS PNG/SVG as an inline image, or None.

    The original artwork is retained. Render only through an HTML img element;
    never insert supplier SVG markup into the document or fetch external images.
    """
    if not isinstance(value, str) or len(value) > 200_000:
        return None
    match = re.fullmatch(r"data:(image/(?:png|svg\+xml))(;base64)?,(.*)", value, re.S)
    if not match:
        return None
    mime, encoded, content = match.groups()
    try:
        if encoded:
            content = re.sub(rb"\s+", b"", unquote_to_bytes(content))
            raw = base64.b64decode(content + b"=" * (-len(content) % 4), validate=True)
        else:
            raw = unquote_to_bytes(content)
        if mime == "image/png":
            # Some vendor statements label JPEG data as PNG. Preserve the
            # passive raster image and correct its MIME type for the browser.
            if raw.startswith(b"\xff\xd8\xff"):
                mime = "image/jpeg"
            elif not raw.startswith(b"\x89PNG\r\n\x1a\n"):
                return None
        else:
            text = raw.decode("utf-8")
            if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
                return None
            # defusedxml would add a dependency without replacing the SVG/CSS
            # allowlist below. This UTF-8-only, size-bounded path rejects DTDs
            # and entities before stdlib parsing (including expansion payloads).
            # Reject NULs too: Expat otherwise auto-detects UTF-16 without a
            # BOM, bypassing a textual DOCTYPE check even after UTF-8 decoding.
            # Keep those gates if the parser changes; never parse raw bytes.
            svg = ET.fromstring(text)
            if svg.tag != "{http://www.w3.org/2000/svg}svg":
                return None
            allowed = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
                       "title", "desc", "metadata", "defs", "clipPath", "mask", "linearGradient", "radialGradient",
                       "stop", "use", "style", "text", "tspan"}
            for el in svg.iter():
                if el.tag not in {"{http://www.w3.org/2000/svg}" + tag for tag in allowed}:
                    return None
                for key, val in el.attrib.items():
                    local = key.rsplit("}", 1)[-1].lower()
                    if local.startswith("on") or local == "base" or (local == "href" and not val.startswith("#")):
                        return None
            # Inspect decoded XML values too: character references must not
            # hide external CSS URLs. CSS escapes are deliberately unsupported.
            styles = " ".join(part for el in svg.iter() for part in [el.text or "", *el.attrib.values()])
            if re.search(r"@import|@font-face|\\|/\*", styles, re.I):
                return None
            if any(not url.strip(" \t\r\n\"'").startswith("#") for url in re.findall(r"url\s*\((.*?)\)", styles, re.I | re.S)):
                return None
    except (ValueError, binascii.Error, ET.ParseError):
        return None
    return "data:" + mime + ";base64," + base64.b64encode(raw).decode("ascii")

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
        self._next_update = None
        self._verified_until = None
        self._legal_header = None

    def _read_cache(self) -> dict | None:
        """Return the cached, signature-verified blob, or None.

        The raw JWT is cached and re-verified on every load, so editing the
        cache file cannot inject metadata. Old unverified caches are ignored.
        """
        from keymelier_core.mds_verify import MdsVerificationError, verify_jwt

        if stateless():
            return None
        try:
            data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            payload = verify_jwt(data["jwt"], require_revocation=True)
            fetched = datetime.fromisoformat(data["fetched_at"])
            if fetched.tzinfo is None:
                raise ValueError("cache timestamp lacks timezone")
            return {"fetched_at": fetched, "payload": payload}
        except FileNotFoundError:
            return None
        except (MdsVerificationError, KeyError, ValueError, TypeError, OSError) as e:
            logger.warning("Ignoring MDS3 cache: %s", type(e).__name__)
            return None

    def _is_cache_fresh(self) -> bool:
        cache = self._read_cache()
        return bool(cache and timedelta(0) <= datetime.now(timezone.utc) - cache["fetched_at"] < timedelta(hours=CACHE_MAX_AGE_HOURS)
                    and self._payload_current(cache["payload"]))

    def _fetch_from_network(self) -> list[dict]:
        from keymelier_core.mds_verify import verify_jwt

        logger.info("Fetching MDS3 from %s", MDS3_URL)
        with bounded_get(MDS3_URL, timeout=20, stream=True) as resp:
            jwt = read_limited(resp, 16 * 1024 * 1024).decode("utf-8")
        payload = verify_jwt(jwt, require_revocation=True)  # raises MdsVerificationError
        cached = self._read_cache()
        if cached and payload.get("no", 0) < cached["payload"].get("no", 0):
            raise ValueError(f"MDS3 blob #{payload.get('no')} is older than cached #{cached['payload'].get('no')}")
        if not self._payload_current(payload):
            raise ValueError("MDS3 metadata has expired")
        if self._serial is not None and payload["no"] < self._serial:
            raise ValueError("MDS3 metadata rollback")
        self._next_update = payload["nextUpdate"]
        self._verified_until = payload["_verified_until"]
        self._serial = payload.get("no")
        self._legal_header = payload.get("legalHeader")
        self._save_cache(jwt)
        entries = payload.get("entries", [])
        logger.info("MDS3 fetched and verified: blob #%s, %d entries", payload.get("no"), len(entries))
        return entries

    def _save_cache(self, jwt: str):
        if stateless():
            return
        cache = {"fetched_at": datetime.now(timezone.utc).isoformat(), "jwt": jwt}
        atomic_write(CACHE_PATH, json.dumps(cache))

    def _load_cache(self) -> list[dict]:
        cache = self._read_cache()
        if cache is None or not self._payload_current(cache["payload"]):
            raise ValueError("no valid MDS3 cache")
        self._fetched_at = cache["fetched_at"]
        self._serial = cache["payload"].get("no")
        self._next_update = cache["payload"].get("nextUpdate")
        self._verified_until = cache["payload"].get("_verified_until")
        self._legal_header = cache["payload"].get("legalHeader")
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
            logger.warning("MDS3 load failed (%s); using empty metadata", type(e).__name__)
            # A cache older than the refresh interval may still be valid.
            # Never use an expired BLOB or one without valid revocation evidence.
            if CACHE_PATH.exists():
                try:
                    entries = self._load_cache()
                    self._index(entries)
                    logger.info("Using still-valid MDS3 cache (%d entries)", len(entries))
                except Exception:
                    self._entries = []
                    self._by_aaguid = {}
            else:
                self._entries = []
                self._by_aaguid = {}
        self._loaded = True

    def refresh_if_stale(self) -> bool:
        """Re-download the metadata if the cache is older than the max age, or
        re-verify a fresh cache whose revocation evidence is missing/expired
        (e.g. after an offline start). Returns True if the state changed."""
        if self._is_cache_fresh():
            if self._entries and self.is_current():
                return False
            try:
                entries = self._load_cache()  # re-runs signature, path and revocation checks
            except Exception as e:
                logger.info("MDS3 re-verification failed: %s", type(e).__name__)
                return False
            self._index(entries)
            return self.is_current()
        try:
            entries = self._fetch_from_network()
        except Exception as e:
            logger.info("MDS3 refresh failed: %s", type(e).__name__)
            return False
        self._fetched_at = datetime.now(timezone.utc)
        self._index(entries)
        return True

    @staticmethod
    def _payload_current(payload):
        try:
            deadline = datetime.strptime(payload["nextUpdate"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < deadline
        except (KeyError, ValueError, TypeError):
            return False

    def is_current(self):
        try:
            return (bool(self._entries) and self._payload_current({"nextUpdate": self._next_update})
                    and self._verified_until is not None
                    and datetime.now(timezone.utc) < datetime.fromisoformat(self._verified_until))
        except (TypeError, ValueError):
            return False

    def seconds_until_expiry(self):
        """Wake the updater when the displayed statement's evidence expires."""
        try:
            deadline = min(datetime.strptime(self._next_update, "%Y-%m-%d").replace(tzinfo=timezone.utc),
                           datetime.fromisoformat(self._verified_until))
            return max(0, (deadline - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            return None

    def lookup(self, aaguid: str) -> Optional[dict]:
        # Check on every use: an already loaded BLOB can expire during a session.
        if not self.is_current():
            return None
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
        statuses = [r.get("status", "") if isinstance(r, dict) else "" for r in reports]
        best = None
        best_priority = -1
        unknown = False
        for s in statuses:
            try:
                p = STATUS_PRIORITY.index(s)
                if p > best_priority:
                    best_priority = p
                    best = s
            except ValueError:
                unknown = True
        if best_priority >= STATUS_PRIORITY.index("UPDATE_AVAILABLE"):
            return best  # never hide a compromise/bypass report behind later certification
        if unknown:
            return "UNKNOWN"
        certifications = []
        for report in reports:
            status = report.get("status", "") if isinstance(report, dict) else ""
            if status not in STATUS_PRIORITY[:STATUS_PRIORITY.index("UPDATE_AVAILABLE")]:
                continue
            effective = report.get("effectiveDate")
            if not effective and status in {"NOT_FIDO_CERTIFIED", "SELF_ASSERTION_SUBMITTED"}:
                return status  # an undated negative status is effective while present
            try:
                date = datetime.fromisoformat(effective.replace("Z", "+00:00")) if effective else datetime.min
                date = date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)
            except (ValueError, TypeError, AttributeError, OverflowError):
                return "UNKNOWN"
            if date <= datetime.now(timezone.utc):
                certifications.append((date, -STATUS_PRIORITY.index(status), status))
        # A later NOT_FIDO_CERTIFIED supersedes earlier certification. At an
        # ambiguous equal date, prefer the less reassuring status.
        return max(certifications)[2] if certifications else None

    def get_cache_info(self) -> dict:
        return {
            "cached": self._loaded and self.is_current(),
            "fetched_at": self._fetched_at.isoformat() if self._fetched_at else None,
            "entry_count": len(self._entries),
            "serial": self._serial,
            "current": self.is_current(),
            "next_update": self._next_update,
            "revocation_checked": bool(self._entries) and self._verified_until is not None,
            "verified": bool(self._entries),  # only verified blobs are ever loaded
            "legal_header": self._legal_header,
        }
