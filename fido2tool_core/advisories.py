import json
import logging
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


def _clean_entry(adv, origin: str) -> Optional[dict]:
    """A managed advisory in the official shape, or None if unusable."""
    if not isinstance(adv, dict) or not isinstance(adv.get("id"), str) or not adv["id"].strip():
        return None
    aaguids = adv.get("affected_aaguids")
    if not isinstance(aaguids, list) or not all(isinstance(a, str) for a in aaguids):
        return None
    entry = {"id": adv["id"].strip()[:100], "affected_aaguids": aaguids,
             "severity": adv.get("severity") if adv.get("severity") in SEVERITIES else "MEDIUM",
             "origin": origin}
    for key in ("title", "note", "firmware_min_inclusive", "firmware_max_exclusive"):
        if isinstance(adv.get(key), str):
            entry[key] = adv[key][:2000]
    if isinstance(adv.get("cvss"), (int, float, str)) and not isinstance(adv.get("cvss"), bool):
        entry["cvss"] = adv["cvss"]
    entry["references"] = [u for u in adv.get("references") or [] if isinstance(u, str) and u.startswith("https://")][:10]
    return entry


class AdvisoryChecker:
    def __init__(self, data_path: Path, policy_sources: Optional[list[dict]] = None):
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
            if old is not None and updates._updated(doc) <= updates._updated(old):
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
            for adv in (state["document"] or {}).get("advisories", []):
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
