"""Runtime metadata stays current, attributed and outside persistent exports."""
import base64
import csv
import dataclasses
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from keymelier_core import mds3
from keymelier_core.history import History
from keymelier_core.scanner import TokenRecord, TokenScanner
from keymelier_core.service import KeyService
from keymelier_core.exporter import CSVExporter


ICON = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\nfixture").decode()
ENTRY = {"aaguid": "example", "metadataStatement": {
    "description": "Example authenticator", "icon": ICON, "legalHeader": "Vendor notice"},
    "statusReports": [{"status": "FIDO_CERTIFIED"}]}


def client():
    m = mds3.MDS3Client()
    m._index([ENTRY])
    m._loaded = True
    m._next_update = "2999-01-01"
    m._verified_until = "2999-01-01T00:00:00+00:00"
    return m


def record():
    return TokenRecord("id", "test", "Key", None, "Unknown", "example",
                       [], [], {}, [], None, None, "", "now")


class MdsDisplayTests(unittest.TestCase):
    def test_runtime_icon_and_legal_header_follow_current_statement(self):
        m, r = client(), record()
        scanner = TokenScanner(mds3_client=m)
        scanner._enrich_record(r)
        self.assertEqual(r.mds_icon, ICON)
        self.assertEqual(r.mds_legal_header, "Vendor notice")
        m._next_update = "2000-01-01"
        self.assertIsNone(m.lookup("example"))
        scanner._enrich_record(r)
        self.assertIsNone(r.mds_icon)
        self.assertIsNone(r.mds_description)
        self.assertIsNone(r.mds_legal_header)

    def test_new_blob_removes_withdrawn_statement(self):
        m, r = client(), record()
        scanner = TokenScanner(mds3_client=m)
        scanner._enrich_record(r)
        m._index([{"aaguid": "replacement"}])
        scanner._enrich_record(r)
        self.assertIsNone(r.mds_icon)
        self.assertIsNone(m.lookup("example"))

    def test_update_deadline_uses_earliest_verification_expiry(self):
        m = client()
        m._verified_until = (datetime.now(timezone.utc) + timedelta(seconds=20)).isoformat()
        self.assertTrue(0 < m.seconds_until_expiry() <= 20)
        m._next_update = "2000-01-01"
        self.assertEqual(m.seconds_until_expiry(), 0)

    def test_missing_or_invalid_deadline_uses_retry_interval(self):
        m = client()
        for value in (None, "broken", "2999-01-01T00:00:00"):
            m._verified_until = value
            self.assertIsNone(m.seconds_until_expiry())
        service = KeyService.__new__(KeyService)
        service._mds3 = Mock()
        service._mds3.is_current.return_value = True
        service._mds3.seconds_until_expiry.return_value = None
        service.check_updates = Mock()
        with patch("keymelier_core.service.threading.Event") as event:
            event.return_value.wait.side_effect = StopIteration
            with self.assertRaises(StopIteration):
                service._run_update_loop()
            event.return_value.wait.assert_called_once_with(service.RETRY_INTERVAL)

    def test_bridge_distinguishes_absent_aaguid_and_unverified_metadata(self):
        service = KeyService.__new__(KeyService)
        m, r = client(), record()
        service._mds3 = m
        TokenScanner(mds3_client=m)._enrich_record(r)
        self.assertEqual(service._record_dict(r)["mds_state"], "current")
        m._index([{"aaguid": "other"}])
        absent = service._record_dict(r)
        self.assertEqual(absent["mds_state"], "not_found")
        self.assertIsNone(absent["mds_description"])
        m._verified_until = None
        unavailable = service._record_dict(r)
        self.assertEqual(unavailable["mds_state"], "unverified")
        self.assertIsNone(unavailable["mds_status"])

    def test_csv_preserves_main_header_and_leaves_mds_columns_empty(self):
        # Exact header from main before this remediation, including order.
        expected = ["timestamp", "manufacturer", "model", "serial_number", "firmware_version", "aaguid",
                    "fido2_versions", "extensions", "options", "pin_protocols", "max_cred_count",
                    "security_status", "cve_ids", "mds_description", "mds_status", "attestation_ran",
                    "attestation_passed", "attestation_status", "attestation_format", "attestation_sig_valid",
                    "attestation_chain_valid", "attestation_aaguid_match", "attestation_subject_cn", "attestation_error"]
        r = record()
        TokenScanner(mds3_client=client())._enrich_record(r)
        self.assertTrue(r.mds_description and r.mds_status)
        with tempfile.TemporaryDirectory() as tmp, patch("keymelier_core.exporter.EXPORT_DIR", Path(tmp)):
            with CSVExporter().export(r).open(newline="") as stream:
                header, row = list(csv.reader(stream))
        self.assertEqual(header, expected)
        self.assertEqual(len(row), len(header))
        exported = dict(zip(header, row))
        self.assertEqual(exported["mds_description"], "")
        self.assertEqual(exported["mds_status"], "")

    def test_expired_cache_not_used_when_offline(self):
        m = mds3.MDS3Client()
        cached = {"fetched_at": datetime.now(timezone.utc) - timedelta(days=2), "payload": {
            "entries": [ENTRY], "nextUpdate": "2000-01-01", "_verified_until": "2999-01-01T00:00:00+00:00"}}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            cache.write_text("{}")
            with patch.object(mds3, "CACHE_PATH", cache), patch.object(m, "_read_cache", return_value=cached), \
                    patch.object(m, "_fetch_from_network", side_effect=OSError("offline")):
                m.ensure_loaded()
        self.assertIsNone(m.lookup("example"))
        self.assertEqual(m._entries, [])

    def test_still_valid_cache_remains_usable_when_refresh_is_offline(self):
        m = mds3.MDS3Client()
        cached = {"fetched_at": datetime.now(timezone.utc) - timedelta(days=2), "payload": {
            "entries": [ENTRY], "nextUpdate": "2999-01-01", "_verified_until": "2999-01-01T00:00:00+00:00"}}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            cache.write_text("{}")
            with patch.object(mds3, "CACHE_PATH", cache), patch.object(m, "_read_cache", return_value=cached), \
                    patch.object(m, "_fetch_from_network", side_effect=OSError("offline")):
                m.ensure_loaded()
        self.assertTrue(m.is_current())
        self.assertEqual(m.lookup("example"), ENTRY)

    def test_icon_accepts_passive_data_and_rejects_active_or_remote_content(self):
        self.assertEqual(mds3.display_icon(ICON), ICON)
        declaration = ('<!DOCTYPE svg [<!ENTITY fixture "expanded">]>'
                       '<svg xmlns="http://www.w3.org/2000/svg"><text>&fixture;</text></svg>')
        for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            value = "data:image/svg+xml;base64," + base64.b64encode(declaration.encode(encoding)).decode()
            self.assertIsNone(mds3.display_icon(value), encoding)
        for body in ('<metadata/><path d="M0 0L1 1"/>', '<defs><path id="x"/></defs><use href="#x"/>'):
            svg = '<svg xmlns="http://www.w3.org/2000/svg">' + body + '</svg>'
            self.assertIsNotNone(mds3.display_icon("data:image/svg+xml," + svg))
        self.assertEqual(mds3.display_icon(ICON.rstrip("=")), ICON)
        jpeg = "data:image/png;base64," + base64.b64encode(b"\xff\xd8\xfffixture").decode()
        self.assertTrue(mds3.display_icon(jpeg).startswith("data:image/jpeg;base64,"))
        for value in ("https://example.com/logo.png", "data:image/png;base64,bad!", "data:text/html,<script/>",
                      "data:image/svg+xml,<!DOCTYPE svg [<!ENTITY x 'expanded'>]><svg xmlns='http://www.w3.org/2000/svg'>&x;</svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'>" + "X" * 200_000 + "</svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><use href='https://example.com'/></svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><style>@import 'https://example.com';</style></svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' style='fill:u&#114;l(https://example.com)'/>",
                      r"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' style='fill:u\72l(https://example.com)'/>"):
            self.assertIsNone(mds3.display_icon(value), value)

    def test_history_migration_and_new_snapshots_exclude_mds_copies(self):
        r = record()
        TokenScanner(mds3_client=client())._enrich_record(r)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            history = History(path, enabled=True, encrypted=False)
            history.update_snapshot(r)
            raw = json.loads(path.read_text())
            self.assertFalse(any(k.startswith("mds_") for k in raw["keys"][0]["snapshot"]))
            raw["keys"][0]["snapshot"].update(dataclasses.asdict(r))
            path.write_text(json.dumps(raw))
            History(path, enabled=True, encrypted=False)
            migrated = json.loads(path.read_text())
            self.assertFalse(any(k.startswith("mds_") for k in migrated["keys"][0]["snapshot"]))


if __name__ == "__main__":
    unittest.main()
