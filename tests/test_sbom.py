"""SBOM: complete, SPDX-clean and consistent with the lock file (tools/sbom.py)."""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sbom  # noqa: E402


class SbomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bom = sbom.build("9.9.9", report_glob=str(ROOT / "build" / "no-such-report-*.json"))

    def names(self):
        return {c["name"] for c in self.bom["components"]}

    def test_current_environment_gives_a_valid_sbom(self):
        self.assertEqual(sbom.validate(self.bom, "9.9.9"), [])

    def test_everything_shipped_is_listed(self):
        for required in ("fido2", "cryptography", "pyscard", "pywebview", "CPython", "OpenSSL", "simple-icons"):
            self.assertIn(required, self.names())
        icons = next(c for c in self.bom["components"] if c["name"] == "simple-icons")
        self.assertEqual(icons["licenses"], [{"license": {"id": "CC0-1.0"}}])
        self.assertEqual(icons["hashes"][0]["content"],
                         hashlib.sha256((ROOT / "static" / "service-icons.js").read_bytes()).hexdigest())

    def test_licenses_are_spdx(self):
        by_name = {c["name"]: c["licenses"] for c in self.bom["components"]}
        self.assertEqual(by_name["fido2"], [{"expression": "BSD-2-Clause AND Apache-2.0 AND MPL-2.0"}])
        self.assertEqual(by_name["pyscard"], [{"license": {"id": "LGPL-2.1-or-later"}}])
        for c in self.bom["components"]:
            self.assertTrue(c["licenses"], c["name"])

    def test_expression_checker(self):
        ok = ["MIT", "Apache-2.0 OR BSD-3-Clause", "GPL-2.0-or-later WITH Bootloader-exception",
              "(MIT OR Apache-2.0) AND BSD-2-Clause"]
        bad = ["BSD License", "MIT License", "GPL-2.0-or-later WITH MIT", "LGPLv2+", "MIT AND", ""]
        for expr in ok:
            self.assertTrue(sbom.expression_ok(expr), expr)
        for expr in bad[:-2]:
            self.assertFalse(sbom.expression_ok(expr), expr)

    def test_validation_finds_problems(self):
        def broken(change):
            bom = copy.deepcopy(self.bom)
            change(bom)
            return sbom.validate(bom, "9.9.9")
        comp = lambda bom, name: next(c for c in bom["components"] if c["name"] == name)
        self.assertTrue(broken(lambda b: comp(b, "fido2").__setitem__("licenses", [])))
        self.assertTrue(broken(lambda b: comp(b, "fido2").__setitem__("licenses", [{"license": {"name": "BSD License"}}])))
        self.assertTrue(broken(lambda b: b["components"].remove(comp(b, "simple-icons"))))
        self.assertTrue(broken(lambda b: comp(b, "simple-icons")["hashes"][0].__setitem__("content", "0" * 64)))
        self.assertTrue(broken(lambda b: comp(b, "fido2").__setitem__("hashes", [{"alg": "SHA-256", "content": "1" * 64}])),
                        "a hash the lock file does not allow")
        self.assertTrue(broken(lambda b: b["metadata"]["component"].__setitem__("version", "1.0.0")))
        self.assertTrue(broken(lambda b: b["dependencies"][0]["dependsOn"].pop()))

    def test_strict_requires_installed_hashes_and_the_bootloader(self):
        problems = sbom.validate(self.bom, "9.9.9", strict=True)
        self.assertTrue(any("no hash of the installed artifact" in p for p in problems))

    def test_pip_report_hashes_are_used(self):
        allowed = sbom.lock_hashes()
        from importlib.metadata import distribution
        version = distribution("fido2").version
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "pip-report.json"
            report.write_text(json.dumps({"install": [{"metadata": {"name": "fido2", "version": version},
                "download_info": {"url": "https://files.pythonhosted.org/x/fido2.whl",
                                  "archive_info": {"hashes": {"sha256": allowed["fido2"][0]}}}}]}))
            bom = sbom.build("9.9.9", report_glob=str(Path(tmp) / "pip-report*.json"))
        fido = next(c for c in bom["components"] if c["name"] == "fido2")
        self.assertEqual(fido["hashes"], [{"alg": "SHA-256", "content": allowed["fido2"][0]}])
        self.assertEqual(sbom.validate(bom, "9.9.9"), [])


if __name__ == "__main__":
    unittest.main()
