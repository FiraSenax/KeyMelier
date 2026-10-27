import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from keymelier_core.licenses import documents


class LicenseReaderTests(unittest.TestCase):
    def test_complete_local_documents_and_missing_bundle_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            texts = {"LICENSE": "MIT original", "THIRD_PARTY_LICENSES.txt": "Copyright <script>\n" * 60000,
                     "THIRD_PARTY_SOURCES.json": '{"sources": []}'}
            for name, text in texts.items():
                (root / name).write_text(text, encoding="utf-8")
            with patch.dict(os.environ, KEYMELIER_STATELESS="1"):
                result = documents(root, bundled=True)
                self.assertEqual({d["filename"]: d["text"] for d in result["documents"]}, texts)
            (root / "THIRD_PARTY_LICENSES.txt").unlink()
            with self.assertRaises(FileNotFoundError):
                documents(root, bundled=True)

    def test_large_license_export_and_unknown_ids(self):
        import app
        api = app.Api(Mock())
        text = "Original notice\n" * 100000
        with patch.object(api, "get_licenses", return_value={"documents": [
                {"id": "notices", "filename": "THIRD_PARTY_LICENSES.txt", "text": text}]}), \
             patch.object(api, "_save_document") as save:
            api.save_license("notices")
            save.assert_called_once_with("THIRD_PARTY_LICENSES.txt", text)
            with self.assertRaises(ValueError):
                api.save_license("../../private")
            self.assertIsNone(api.save_text("input.txt", text))
            self.assertEqual(save.call_count, 1, "large arbitrary bridge inputs remain blocked")
