import json
import logging
import re
from pathlib import Path
from typing import Optional

from fido2tool_core.firmware import firmware_from_raw as _firmware_from_raw, parse_firmware_str as _parse_firmware

logger = logging.getLogger(__name__)


MAX_SOURCE_BYTES = 2_000_000
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _read_source(location: str) -> tuple[bytes, str]:
    """Document and signature of a managed source (https URL or local file)."""
    if location.startswith("https://"):
        import requests

        def get(url):
            r = requests.get(url, timeout=15, stream=True)
            r.raise_for_status()
            data = r.raw.read(MAX_SOURCE_BYTES + 1, decode_content=True)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("too large")
            return data
        return get(location), get(location + ".sig").decode("ascii")
    path = Path(location)
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("too large")
    return path.read_bytes(), Path(location + ".sig").read_text(encoding="ascii")


# Company advisories (policy sources) are checked field by field against a
# whitelist; anything not listed is dropped, anything malformed drops the
# whole entry. The UI escapes every value and runs only hashed scripts (CSP),
# so this is a second line of defence – and it keeps a broken source from
# matching more keys than intended.
MAX_ADVISORIES = 1000
MAX_AAGUIDS = 200
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_AAGUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}")
_FIRMWARE = re.compile(r"\d{1,5}(\.\d{1,5}){0,3}")
_CVSS = re.compile(r"(10(\.0)?|\d(\.\d)?)")
_URL = re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~!$&()*+,;=:@%/?#-]*)?")


def clean_text(value, limit: int) -> Optional[str]:
    """Plain text without control characters, or None."""
    if not isinstance(value, str):
        return None
    text = _CONTROL.sub(" ", value).strip()
    return text[:limit] or None


def _clean_entry(adv, origin: str) -> Optional[dict]:
    """A managed advisory in the official shape, or None if unusable."""
    if not isinstance(adv, dict) or not isinstance(adv.get("id"), str) or not _ID.fullmatch(adv["id"]):
        return None
    aaguids = adv.get("affected_aaguids")
    if not isinstance(aaguids, list) or not 0 < len(aaguids) <= MAX_AAGUIDS \
            or not all(isinstance(a, str) and _AAGUID.fullmatch(a) for a in aaguids):
        return None
    entry = {"id": adv["id"], "affected_aaguids": [a.lower() for a in aaguids],
             "severity": adv.get("severity") if adv.get("severity") in SEVERITIES else "MEDIUM",
             "origin": origin}
    for key in ("firmware_min_inclusive", "firmware_max_exclusive"):
        if key in adv:   # a bound that cannot be read would widen the match to every firmware
            if not isinstance(adv[key], str) or not _FIRMWARE.fullmatch(adv[key]):
                return None
            entry[key] = adv[key]
    for key, limit in (("title", 200), ("note", 2000)):
        text = clean_text(adv.get(key), limit)
        if text:
            entry[key] = text
    cvss = adv.get("cvss")
    if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and 0 <= cvss <= 10:
        entry["cvss"] = round(float(cvss), 1)
    elif isinstance(cvss, str) and _CVSS.fullmatch(cvss):
        entry["cvss"] = cvss
    # Only plain https links; the app may open exactly these (in the browser)
    refs = adv.get("references") if isinstance(adv.get("references"), list) else []
    entry["references"] = [u for u in refs if isinstance(u, str) and len(u) <= 2000 and _URL.fullmatch(u)][:10]
    return entry


class AdvisoryChecker:
    def __init__(self, data_path: Path, policy_sources: Optional[list[dict]] = None, defer_policy: bool = False):
        """defer_policy: load the company sources only in check_for_update (the app's background
        update thread), so a slow or unreachable network path never delays the start."""
        from fido2tool_core import policy, updates

        self._data_path = Path(data_path)
        self._advisories: list[dict] = []
        self._official: list[dict] = []
        self.document: Optional[dict] = None
        self.source = "none"
        # Managed sources (company policy): name -> state; they only ever add findings
        self._sources = policy.advisory_sources() if policy_sources is None else policy_sources
        self._extra: dict[str, dict] = {s["name"]: {"status": "pending", "document": None} for s in self._sources}
        doc, source = updates.load_best(self._data_path)
        if doc is not None:
            self.use(doc, source)
        else:
            logger.warning("No advisory database available")
        if not defer_policy:
            self.load_policy_sources(network=False)

    def use(self, document: dict, source: str):
        self.document = document
        self.source = source
        self._official = [a for a in document.get("advisories", []) if isinstance(a, dict) and "origin" not in a]
        self._merge()
        logger.info("Loaded %d advisories (%s, updated %s)", len(self._official), source, document.get("updated"))

    def load_policy_sources(self, network: bool = True) -> bool:
        """(Re)load the managed sources; file sources always, URLs only with network.

        Returns True if the findings changed. A source that fails keeps its
        last good document (no rollback to an older one either).
        """
        from fido2tool_core import updates

        changed = False
        for src in self._sources:
            if src["location"].startswith("https://") and not network:
                continue
            state = self._extra[src["name"]]
            try:
                data, sig = _read_source(src["location"])
            except Exception as e:
                logger.warning("Advisory source %s not readable: %s", src["name"], e)
                state["status"] = "unreachable"
                continue
            if not updates.verify(data, sig, src["public_key"]):
                logger.warning("Advisory source %s ignored: signature invalid", src["name"])
                state["status"] = "invalid"
                continue
            doc = updates.parse(data)
            if doc is None:
                logger.warning("Advisory source %s ignored: malformed", src["name"])
                state["status"] = "invalid"
                continue
            old = state["document"]
            state["status"] = "ok"
            try:
                if old is not None and updates._updated(doc) <= updates._updated(old):
                    continue
            except (TypeError, ValueError) as e:
                logger.warning("Advisory source %s: dates not comparable (%s); keeping the loaded one", src["name"], e)
                continue
            state["document"] = doc
            changed = True
        if changed:
            self._merge()
        return changed

    def _merge(self):
        """Official advisories first and unchanged; managed ones only add new ids."""
        official_ids = {a.get("id") for a in self._official}
        merged = list(self._official)
        for src in self._sources:
            state = self._extra[src["name"]]
            state["count"] = state["dropped"] = 0
            advisories = (state["document"] or {}).get("advisories", [])
            if len(advisories) > MAX_ADVISORIES:
                logger.warning("Advisory source %s: only the first %d entries are used", src["name"], MAX_ADVISORIES)
            for adv in advisories[:MAX_ADVISORIES]:
                entry = _clean_entry(adv, src["name"])
                if entry is None or entry["id"] in official_ids:
                    state["dropped"] += 1   # malformed, or would shadow an official entry
                    continue
                merged.append(entry)
                state["count"] += 1
            if state["dropped"]:
                logger.warning("Advisory source %s: %d entries skipped (malformed or official id)",
                               src["name"], state["dropped"])
        self._advisories = merged

    def policy_links(self) -> set[str]:
        """Reference URLs (https) of the loaded company advisories – the app may open exactly these."""
        return {u for a in self._advisories if a.get("origin") for u in a.get("references", [])}

    def check_for_update(self) -> bool:
        """Fetch a newer signed advisory file and reload managed sources.

        Returns True if anything changed.
        """
        from fido2tool_core import updates

        changed = self.load_policy_sources(network=True) if self._sources else False
        doc = updates.fetch(self.document)
        if doc is None:
            return changed
        self.use(doc, "downloaded")
        return True

    def info(self) -> dict:
        return {
            "source": self.source,
            "updated": (self.document or {}).get("updated"),
            "count": len(self._official),
            "policy": [{"name": s["name"], "status": self._extra[s["name"]]["status"],
                        "count": self._extra[s["name"]].get("count", 0),
                        "updated": (self._extra[s["name"]]["document"] or {}).get("updated")}
                       for s in self._sources],
        }

    def _firmware_in_range(self, firmware_str: str, adv: dict) -> bool:
        fw = _parse_firmware(firmware_str)
        if fw is None:
            # Unknown firmware — conservatively flag as affected if advisory has no lower bound
            return True

        max_excl = _parse_firmware(adv.get("firmware_max_exclusive"))
        min_incl = _parse_firmware(adv.get("firmware_min_inclusive"))

        if max_excl is not None and fw >= max_excl:
            return False
        if min_incl is not None and fw < min_incl:
            return False
        return True

    def check(self, aaguid: str, firmware_version_raw: Optional[int], manufacturer: str = "") -> list[dict]:
        aaguid_norm = (aaguid or "").lower().strip()
        fw_str = _firmware_from_raw(firmware_version_raw, manufacturer)
        matches = []
        seen_ids = set()
        for adv in self._advisories:
            affected = [a.lower().strip() for a in adv.get("affected_aaguids", [])]
            if aaguid_norm not in affected:
                continue
            if not self._firmware_in_range(fw_str, adv):
                continue
            # One CVE can be split into several entries (different fixed versions)
            if adv["id"] in seen_ids:
                continue
            seen_ids.add(adv["id"])
            matches.append(adv)
        return matches

    def get_cve_ids(self, aaguid: str, firmware_version_raw: Optional[int], manufacturer: str = "") -> list[str]:
        return [a["id"] for a in self.check(aaguid, firmware_version_raw, manufacturer=manufacturer)]
