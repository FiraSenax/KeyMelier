import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from keymelier_core.licenses import _documents, document, documents


class LicenseReaderTests(unittest.TestCase):
    def setUp(self):
        _documents.cache_clear()

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
            _documents.cache_clear()  # simulate a new application process
            with self.assertRaises(FileNotFoundError):
                documents(root, bundled=True)

    def test_large_license_export_and_unknown_ids(self):
        import app
        api = app.Api(Mock())
        text = "Original notice\n" * 100000
        with tempfile.TemporaryDirectory() as tmp, patch.object(app, "ROOT_DIR", Path(tmp)), \
             patch.object(api, "get_licenses", side_effect=AssertionError("Do not rebuild the document list")), \
             patch.object(api, "_save_document") as save:
            (Path(tmp) / "THIRD_PARTY_LICENSES.txt").write_text(text)
            (Path(tmp) / "LICENSE").write_text("MIT")
            api.save_license("notices")
            save.assert_called_once_with("THIRD_PARTY_LICENSES.txt", text)
            with self.assertRaises(ValueError):
                api.save_license("../../private")
            self.assertIsNone(api.save_text("input.txt", text))
            self.assertEqual(save.call_count, 1, "large arbitrary bridge inputs remain blocked")

    def test_development_notices_cached_without_changing_import_path(self):
        import sys
        from tools import third_party_licenses
        with tempfile.TemporaryDirectory() as tmp, patch.object(third_party_licenses, "build", return_value="original") as build:
            root = Path(tmp)
            (root / "LICENSE").write_text("MIT")
            before = list(sys.path)
            first = documents(root, bundled=False)
            first["documents"][0]["text"] = "mutated by caller"
            self.assertEqual(documents(root, bundled=False)["documents"][0]["text"], "original")
            self.assertEqual(document(root, "notices", bundled=False), ("THIRD_PARTY_LICENSES.txt", "original"))
            self.assertEqual(sys.path, before)
            build.assert_called_once_with()
