import json
import logging
from pathlib import Path
from typing import Optional

from fido2tool_core.firmware import firmware_from_raw as _firmware_from_raw, parse_firmware_str as _parse_firmware

logger = logging.getLogger(__name__)


class AdvisoryChecker:
    def __init__(self, data_path: Path):
        from fido2tool_core import updates

        self._data_path = Path(data_path)
        self._advisories: list[dict] = []
        self.document: Optional[dict] = None
        self.source = "none"
        doc, source = updates.load_best(self._data_path)
        if doc is not None:
            self.use(doc, source)
        else:
            logger.warning("No advisory database available")

    def use(self, document: dict, source: str):
        self.document = document
        self.source = source
        self._advisories = document.get("advisories", [])
        logger.info("Loaded %d advisories (%s, updated %s)", len(self._advisories), source, document.get("updated"))

    def check_for_update(self) -> bool:
        """Fetch a newer signed advisory file. Returns True if one was applied."""
        from fido2tool_core import updates

        doc = updates.fetch(self.document)
        if doc is None:
            return False
        self.use(doc, "downloaded")
        return True

    def info(self) -> dict:
        return {
            "source": self.source,
            "updated": (self.document or {}).get("updated"),
            "count": len(self._advisories),
        }

    def _firmware_in_range(self, firmware_str: str, adv: dict) -> bool:
        fw = _parse_firmware(firmware_str)
        if fw is None:
            # Unknown firmware — conservatively flag as affected if advisory has no lower bound
            return adv.get("firmware_min_inclusive") is None

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
