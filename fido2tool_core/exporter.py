import csv
import io
import uuid
from fido2tool_core.storage import atomic_write, stateless
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
        "attestation_status",
        "attestation_format",
        "attestation_sig_valid",
        "attestation_chain_valid",
        "attestation_aaguid_match",
        "attestation_subject_cn",
        "attestation_error",
    ]

    def export(self, record) -> Path:
        if stateless():
            raise ValueError("Exports are disabled in stateless mode")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = EXPORT_DIR / f"{ts}_{uuid.uuid4().hex}.csv"

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
            att.get("status", "UNVERIFIED"),
            att.get("format") or "",
            str(att.get("sig_valid", "")),
            str(att.get("chain_valid", "")),
            str(att.get("aaguid_match", "")),
            att.get("subject_cn") or "",
            att.get("error") or "",
        ]

        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(self.HEADERS)
        # CSV quoting alone does not prevent spreadsheet formula execution.
        writer.writerow([_safe_cell(value) for value in row])
        atomic_write(filename, buffer.getvalue())

        logger.info("CSV exported: %s", filename)
        return filename


def _safe_cell(value):
    value = str(value)
    stripped = value.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@", "|", "\uff1d", "\uff0b", "\uff0d", "\uff20")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value
