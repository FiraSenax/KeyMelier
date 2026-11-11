"""Source/notice collection must reject drift and retain nested license texts."""
import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

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

    def test_inline_c_notices_are_retained_without_copying_implementation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.tar.gz"
            raw = b"/* Copyright Original Author.\nRedistribution permitted. */\nint private_implementation;\n// Copyright Another Author\n// SPDX-License-Identifier: MIT\nint code;"
            with tarfile.open(path, "w:gz") as archive:
                entry = tarfile.TarInfo("zint/backend/qr.c")
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
            self.assertEqual(sources.archive_notices(path), "")
            text = sources.archive_notices(path, inline=True)
            self.assertIn("Redistribution permitted.", text)
            self.assertIn("SPDX-License-Identifier: MIT", text)
            self.assertNotIn("int private_implementation", text)
            self.assertNotIn("int code", text)

    def test_debian_source_mapping_requires_strong_hash_and_complete_files(self):
        package = {"source_package": "example", "source_version": "1.2-3"}
        line = "'http://azure.archive.ubuntu.com/ubuntu/pool/example_1.2-3.dsc' example_1.2-3.dsc 42 SHA256:" + "1" * 64
        with patch.object(sources.subprocess, "run", return_value=SimpleNamespace(stdout=line, returncode=0)) as run:
            found = sources.debian_sources([package, package])
            self.assertIn("Acquire::ForceHash=sha256", run.call_args.args[0])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["version"], "1.2-3")
            self.assertEqual(found[0]["url"], "https://archive.ubuntu.com/ubuntu/pool/example_1.2-3.dsc")
        with patch.object(sources.subprocess, "run", return_value=SimpleNamespace(stdout=line.replace("SHA256", "MD5Sum"), returncode=0)):
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


class SourceDownloadRetryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        cache = patch.object(sources, "CACHE", self.folder)
        cache.start()
        self.addCleanup(cache.stop)
        self.raw = b"verified upstream source"
        self.item = {"filename": "source.tar.gz", "url": "https://example.com/source.tar.gz",
                     "sha256": hashlib.sha256(self.raw).hexdigest(), "size": len(self.raw)}
        self.target = self.folder / (self.item["sha256"][:16] + "-" + self.item["filename"])
        self.previous = b"X" * len(self.raw)
        self.target.write_bytes(self.previous)

    def response(self, chunks=None, error=None):
        response = Mock()
        response.raise_for_status.side_effect = error
        response.iter_content.return_value = iter([self.raw] if chunks is None else chunks)
        return nullcontext(response)

    def test_interrupted_download_restarts_without_appending_or_weakening_tls(self):
        def interrupted():
            yield self.raw[:5]
            raise sources.requests.ConnectionError("Synthetic closed connection")

        replies = iter([sources.requests.ConnectTimeout("Synthetic timeout"),
                        self.response(interrupted()), self.response()])

        def request(*args, **kwargs):
            self.assertFalse(list(self.folder.glob("*.partial")))
            self.assertEqual(self.target.read_bytes(), self.previous)
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        with patch.object(sources.requests, "get", side_effect=request) as get, \
                patch.object(sources.time, "sleep") as sleep:
            result = sources.fetch(self.item)
        self.assertEqual(result.read_bytes(), self.raw)
        self.assertEqual(get.call_args_list, [call(self.item["url"], stream=True, timeout=(20, 90))] * 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])
        self.assertFalse(list(self.folder.glob("*.partial")))

    def test_transport_failures_stop_after_three_attempts_and_preserve_cache(self):
        errors = [sources.requests.ReadTimeout("Synthetic timeout"),
                  sources.requests.exceptions.ChunkedEncodingError("Synthetic truncated transfer"),
                  sources.requests.ConnectionError("Synthetic closed connection")]
        with patch.object(sources.requests, "get", side_effect=errors) as get, \
                patch.object(sources.time, "sleep") as sleep:
            with self.assertRaises(sources.requests.ConnectionError) as caught:
                sources.fetch(self.item)
        self.assertIs(caught.exception, errors[-1])
        self.assertEqual(get.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(list(self.folder.glob("*.partial")))

    def test_certificate_http_and_integrity_failures_are_not_retried(self):
        cases = [
            ("certificate", sources.requests.exceptions.SSLError("Synthetic certificate failure")),
            ("http404", sources.requests.HTTPError("Synthetic missing source")),
            ("http503", sources.requests.HTTPError("Synthetic service failure")),
            ("checksum", None), ("oversize", None), ("incomplete", None),
        ]
        for name, error in cases:
            with self.subTest(name=name):
                if name == "checksum":
                    reply = self.response([self.previous])
                elif name == "oversize":
                    reply = self.response([self.raw + b"X"])
                elif name == "incomplete":
                    reply = self.response([self.raw[:5]])
                else:
                    reply = self.response(error=error)
                request = {"side_effect": error} if name == "certificate" else {"return_value": reply}
                with patch.object(sources.requests, "get", **request) as get, \
                        patch.object(sources.time, "sleep") as sleep:
                    with self.assertRaises(type(error) if error is not None else ValueError):
                        sources.fetch(self.item)
                self.assertEqual(get.call_count, 1)
                sleep.assert_not_called()
                self.assertEqual(self.target.read_bytes(), self.previous)
                self.assertFalse(list(self.folder.glob("*.partial")))

    def test_partial_file_access_failure_does_not_retry_or_replace_cache(self):
        original_open = Path.open

        def open_file(path, *args, **kwargs):
            if path.name.endswith(".partial"):
                raise PermissionError("Synthetic access denied")
            return original_open(path, *args, **kwargs)

        with patch.object(sources.requests, "get", return_value=self.response()) as get, \
                patch.object(Path, "open", open_file), patch.object(sources.time, "sleep") as sleep:
            with self.assertRaises(PermissionError):
                sources.fetch(self.item)
        self.assertEqual(get.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.previous)
        self.assertFalse(list(self.folder.glob("*.partial")))


if __name__ == "__main__":
    unittest.main()
