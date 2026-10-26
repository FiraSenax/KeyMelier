import base64
import hashlib
import json
import sys
import tempfile
import unittest
from importlib.metadata import PackagePath
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import wheel_evidence
from check_library_replacement import modify_pyscard, modify_qt, PROBE


class WheelEvidenceTests(unittest.TestCase):
    def test_upstream_record_hash_is_verified_and_optional_gpl_not_flattened(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.json"
            raw = json.dumps({"bomFormat": "CycloneDX", "components": [
                {"name": "optional-gpl-codec", "scope": "optional"}]}).encode()
            path.write_bytes(raw)
            file = PackagePath("example.dist-info/sboms/original.json")
            file.hash = SimpleNamespace(mode="sha256", value=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="))
            dist = SimpleNamespace(version="1", files=[file], locate_file=lambda _: path)
            with patch.object(wheel_evidence, "EXPECTED", {"example": ("1", 1)}), patch.object(wheel_evidence, "distribution", return_value=dist):
                evidence, pillow, datas = wheel_evidence.collect(["example"], [])
                self.assertEqual(evidence[0]["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(Path(datas[0][1]).read_bytes(), raw)
                self.assertEqual(pillow, {})
                path.write_bytes(raw + b" ")
                with self.assertRaisesRegex(ValueError, "RECORD hash mismatch"):
                    wheel_evidence.collect(["example"], [])

    def test_replacement_probes_change_behavior_and_reject_version_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "System.py"
            path.write_text("value = 1\n")
            proof = modify_pyscard(path)
            namespace = {}
            exec(path.read_text(), namespace)
            self.assertEqual(namespace["__keymelier_replacement_probe__"], PROBE)
            self.assertNotEqual(proof["before"], proof["after"])
            path.write_bytes(b"prefix\0" + b"6.11.2\0" + b"suffix")
            modify_qt(path)
            self.assertEqual(path.read_bytes(), b"prefix\0" + b"6.11.3\0" + b"suffix")
            with self.assertRaisesRegex(ValueError, "Review"):
                modify_qt(path)
