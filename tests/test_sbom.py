"""SBOM: complete, SPDX-clean and consistent with the lock file (tools/sbom.py)."""

import copy
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        for required in ("fido2", "cryptography", "pyscard", "pywebview", "CPython", "OpenSSL", "Lucide", "Feather", "brand:github"):
            self.assertIn(required, self.names())
        icons = next(c for c in self.bom["components"] if c["name"] == "brand:github")
        self.assertEqual(icons["licenses"][0]["license"]["name"], "Brand usage terms")
        self.assertEqual(icons["hashes"][0]["content"],
                         hashlib.sha256((ROOT / "packaging/brands/github.svg").read_bytes()).hexdigest())

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
        self.assertTrue(broken(lambda b: b["components"].remove(comp(b, "brand:github"))))
        self.assertTrue(broken(lambda b: comp(b, "brand:github")["hashes"][0].__setitem__("content", "0" * 64)))
        self.assertTrue(broken(lambda b: comp(b, "fido2").__setitem__("hashes", [{"alg": "SHA-256", "content": "1" * 64}])),
                        "a hash the lock file does not allow")
        self.assertTrue(broken(lambda b: b["metadata"]["component"].__setitem__("version", "1.0.0")))
        self.assertTrue(broken(lambda b: b["dependencies"][0]["dependsOn"].pop()))

    def test_strict_requires_installed_hashes_and_the_bootloader(self):
        problems = sbom.validate(self.bom, "9.9.9", strict=True)
        self.assertTrue(any("no hash of the installed artifact" in p for p in problems))

    def test_known_spdx_license_still_requires_component_review(self):
        bom = copy.deepcopy(self.bom)
        package = next(c for c in bom['components'] if c['name'] == 'requests')
        package['version'] = '999.0'
        self.assertTrue(any('new or changed license needs review' in p for p in sbom.validate(bom)))
        package['version'] = next(c['version'] for c in self.bom['components'] if c['name'] == 'requests')
        package['licenses'] = [{'license': {'id': 'GPL-3.0-only'}}]
        self.assertTrue(any('new or changed license needs review' in p for p in sbom.validate(bom)))
        package['name'] = 'new-package'
        package['purl'] = 'pkg:pypi/new-package@1.0'
        package['licenses'] = [{'license': {'id': 'MIT'}}]
        self.assertTrue(any('new or changed license needs review' in p for p in sbom.validate(bom)))

    def test_nested_vendor_uses_its_own_reviewed_version(self):
        from importlib.metadata import distribution, distributions
        vendors = distributions(path=[str(distribution('setuptools').locate_file('setuptools/_vendor'))])
        vendor = next(d for d in vendors if d.metadata['Name'] == 'packaging')
        bom = copy.deepcopy(self.bom)
        package = next(c for c in bom['components'] if c['name'] == 'packaging')
        package['version'] = vendor.version
        package['licenses'] = sbom._licenses(sbom.spdx_expression(vendor))
        package['properties'] = [{'name': 'keymelier:bundled-in', 'value': 'setuptools wheel; see parent artifact hash'}]
        self.assertEqual(sbom.validate(bom), [])
        package['version'] = '999.0'
        self.assertTrue(any('new or changed license needs review' in p for p in sbom.validate(bom)))

    def test_cli_checks_default_file_without_treating_strict_as_a_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build").mkdir()
            path = root / "build" / "keymelier-sbom.cdx.json"
            path.write_text(json.dumps(self.bom))
            with patch.object(sbom, "ROOT", root), patch.object(sbom, "_version", return_value="9.9.9"), \
                 patch.object(sbom, "validate", return_value=[]) as validate, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(sbom.main(["--check", "--strict"]), 0)
                validate.assert_called_once_with(self.bom, "9.9.9", strict=True)
                validate.return_value = ["missing installed hash"]
                self.assertEqual(sbom.main(["--check", str(path), "--strict"]), 1)

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
