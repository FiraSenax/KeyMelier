"""Source/notice collection must reject drift and retain nested license texts."""
import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import corresponding_sources as sources  # noqa: E402
import bundle_inventory  # noqa: E402
import third_party_licenses as licenses  # noqa: E402


class LicenseSourceTests(unittest.TestCase):
    def test_conflicting_proxy_metadata_does_not_relabel_bsd_source_as_mit(self):
        dist = SimpleNamespace(metadata={"Name": "proxy_tools", "License": "MIT"})
        self.assertIn("BSD-3-Clause", licenses.license_label(dist))

    def test_matching_cache_and_corrupt_download(self):
        raw = b"unmodified upstream source"
        item = {"filename": "library.tar.gz", "url": "https://example.com/library.tar.gz",
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        with tempfile.TemporaryDirectory() as tmp, patch.object(sources, "CACHE", Path(tmp)):
            cached = Path(tmp) / (item["sha256"][:16] + "-" + item["filename"])
            cached.write_bytes(raw)
            with patch.object(sources.requests, "get") as get:
                self.assertEqual(sources.fetch(item), cached)
                get.assert_not_called()
            cached.write_bytes(b"corrupt cache")
            with patch.object(sources.requests, "get") as get:
                get.return_value.__enter__.return_value.iter_content.return_value = [b"X" * len(raw)]
                with self.assertRaisesRegex(ValueError, "checksum/size"):
                    sources.fetch(item)
            self.assertFalse(list(Path(tmp).glob("*.partial")))
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                sources.fetch({**item, "filename": "../escape"})

    def test_original_nested_notices_and_spdx_license_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for name, raw in {"qt/LICENSES/MIT.txt": b"Original copyright",
                                  "fuse/LGPL2.txt": b"Original LGPL",
                                  "qt/chromium/third_party/example/README.chromium": b"Chromium origin",
                                  "qt/src/code.cpp": b"not a license"}.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(raw)
                    archive.addfile(entry, io.BytesIO(raw))
            text = sources.archive_notices(path)
            for expected in ("Original copyright", "Original LGPL", "Chromium origin"):
                self.assertIn(expected, text)
            self.assertNotIn("not a license", text)

    def test_debian_source_mapping_requires_strong_hash_and_complete_files(self):
        package = {"source_package": "example", "source_version": "1.2-3"}
        line = "'http://azure.archive.ubuntu.com/ubuntu/pool/example_1.2-3.dsc' example_1.2-3.dsc 42 SHA256:" + "1" * 64
        with patch.object(sources.subprocess, "run", return_value=SimpleNamespace(stdout=line)) as run:
            found = sources.debian_sources([package, package])
            self.assertIn("Acquire::ForceHash=sha256", run.call_args.args[0])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["version"], "1.2-3")
            self.assertEqual(found[0]["url"], "https://archive.ubuntu.com/ubuntu/pool/example_1.2-3.dsc")
        with patch.object(sources.subprocess, "run", return_value=SimpleNamespace(stdout=line.replace("SHA256", "MD5Sum"))):
            with self.assertRaisesRegex(ValueError, "No SHA-256"):
                sources.debian_sources([package])

    def test_collected_files_determine_inventory_and_nested_notices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = [Path("library/core.py"), Path("library/_vendor/vendor.dist-info/LICENSE")]
            for file in files:
                (root / file).parent.mkdir(parents=True, exist_ok=True)
                (root / file).write_text("Original upstream notice" if file.name == "LICENSE" else "# source")
            dist = SimpleNamespace(metadata={"Name": "library"}, files=files, version="1.0", locate_file=lambda f: root / f)
            with patch.object(bundle_inventory, "distributions", return_value=[dist]):
                self.assertEqual(bundle_inventory.collected_packages([("library.core", str(root / files[0]), "PYMODULE")]), ["library"])
                self.assertEqual(bundle_inventory.collected_packages([]), [])
            self.assertEqual(licenses.license_texts(dist), [(files[1].as_posix(), "Original upstream notice")])


if __name__ == "__main__":
    unittest.main()
