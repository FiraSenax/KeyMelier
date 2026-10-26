"""Runtime metadata stays current, attributed and outside persistent exports."""
import base64
import dataclasses
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from keymelier_core import mds3
from keymelier_core.history import History
from keymelier_core.scanner import TokenRecord, TokenScanner


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

    def test_icon_accepts_passive_data_and_rejects_active_or_remote_content(self):
        self.assertEqual(mds3.display_icon(ICON), ICON)
        for body in ('<metadata/><path d="M0 0L1 1"/>', '<defs><path id="x"/></defs><use href="#x"/>'):
            svg = '<svg xmlns="http://www.w3.org/2000/svg">' + body + '</svg>'
            self.assertIsNotNone(mds3.display_icon("data:image/svg+xml," + svg))
        self.assertEqual(mds3.display_icon(ICON.rstrip("=")), ICON)
        jpeg = "data:image/png;base64," + base64.b64encode(b"\xff\xd8\xfffixture").decode()
        self.assertTrue(mds3.display_icon(jpeg).startswith("data:image/jpeg;base64,"))
        for value in ("https://example.com/logo.png", "data:image/png;base64,bad!", "data:text/html,<script/>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><use href='https://example.com'/></svg>",
                      "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><style>@import 'https://example.com';</style></svg>"):
            self.assertIsNone(mds3.display_icon(value), value)

    def test_history_migration_and_new_snapshots_exclude_mds_copies(self):
        r = record()
        TokenScanner(mds3_client=client())._enrich_record(r)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            history = History(path, enabled=True)
            history.update_snapshot(r)
            raw = json.loads(path.read_text())
            self.assertFalse(any(k.startswith("mds_") for k in raw["keys"][0]["snapshot"]))
            raw["keys"][0]["snapshot"].update(dataclasses.asdict(r))
            path.write_text(json.dumps(raw))
            History(path, enabled=True)
            migrated = json.loads(path.read_text())
            self.assertFalse(any(k.startswith("mds_") for k in migrated["keys"][0]["snapshot"]))


if __name__ == "__main__":
    unittest.main()
