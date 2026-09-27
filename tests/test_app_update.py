import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fido2tool_core import app_update

PREFIX = app_update.DOWNLOAD_PREFIX + "v9.9.9/"
ASSET = {"name": "KeyMelier-macOS.dmg", "url": PREFIX + "KeyMelier-macOS.dmg", "sums": PREFIX + "SHA256SUMS.txt"}
PAYLOAD = b"disk image bytes" * 1000


def fake_get(sums_digest):
    def get(url, **kwargs):
        resp = MagicMock()
        if url.endswith("SHA256SUMS.txt"):
            resp.text = f"{sums_digest}  KeyMelier-macOS.dmg\n{'0' * 64}  KeyMelier-Windows-Setup.exe\n"
            return resp
        resp.__enter__.return_value = resp
        resp.headers = {"Content-Length": str(len(PAYLOAD))}
        resp.iter_content.return_value = [PAYLOAD[:5000], PAYLOAD[5000:]]
        return resp
    return get


class AppUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = patch.object(app_update, "_download_dir", return_value=Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_verified_download(self):
        with patch("requests.get", side_effect=fake_get(hashlib.sha256(PAYLOAD).hexdigest())):
            path = app_update.download(ASSET)
        self.assertEqual(path.read_bytes(), PAYLOAD)
        self.assertEqual(path.name, "KeyMelier-macOS.dmg")

    def test_checksum_mismatch_deletes_file(self):
        with patch("requests.get", side_effect=fake_get("f" * 64)):
            with self.assertRaises(app_update.UpdateError) as e:
                app_update.download(ASSET)
        self.assertEqual(str(e.exception), "checksum")
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_only_project_release_urls(self):
        for bad in ({**ASSET, "url": "https://evil.example/KeyMelier-macOS.dmg"},
                    {**ASSET, "sums": "https://github.com/other/repo/releases/download/x/SHA256SUMS.txt"},
                    {**ASSET, "name": "../../evil.dmg"}):
            with self.assertRaises(app_update.UpdateError):
                app_update.download(bad)


if __name__ == "__main__":
    unittest.main()
