import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

EXPORT_DIR = Path.home() / "keymelier" / "exports"


class CSVExporter:
    HEADERS = [
        "timestamp",
        "manufacturer",
        "model",
        "serial_number",
        "firmware_version",
        "aaguid",
        "fido2_versions",
        "extensions",
        "options",
        "pin_protocols",
        "max_cred_count",
        "security_status",
        "cve_ids",
        "mds_description",
        "mds_status",
        "attestation_ran",
        "attestation_passed",
        "attestation_format",
        "attestation_sig_valid",
        "attestation_chain_valid",
        "attestation_aaguid_match",
        "attestation_subject_cn",
        "attestation_error",
    ]

    def export(self, record) -> Path:
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_serial = (record.serial_number or "noserial").replace("/", "_").replace("\\", "_")
        filename = EXPORT_DIR / f"{ts}_{safe_serial}.csv"

        options_str = "|".join(
            f"{k}:{v}" for k, v in sorted((record.options or {}).items())
        )

        att = record.attestation or {}
        row = [
            datetime.now(timezone.utc).isoformat(),
            record.manufacturer,
            record.product_name,
            record.serial_number or "",
            record.firmware_version_str,
            record.aaguid,
            "|".join(record.fido2_versions or []),
            "|".join(record.extensions or []),
            options_str,
            "|".join(str(p) for p in (record.pin_protocols or [])),
            str(record.max_cred_count) if record.max_cred_count is not None else "",
            record.security_status,
            "|".join(record.cve_ids or []),
            record.mds_description or "",
            record.mds_status or "",
            str(att.get("ran", "")),
            str(att.get("passed", "")),
            att.get("format") or "",
            str(att.get("sig_valid", "")),
            str(att.get("chain_valid", "")),
            str(att.get("aaguid_match", "")),
            att.get("subject_cn") or "",
            att.get("error") or "",
        ]

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.HEADERS)
            writer.writerow(row)

        logger.info("CSV exported: %s", filename)
        return filename
