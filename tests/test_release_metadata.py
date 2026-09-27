"""Release metadata: one version everywhere, and a changelog entry for it."""

import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def app_version() -> str:
    ns: dict = {}
    exec((ROOT / "fido2tool_core" / "version.py").read_text(), ns)
    return ns["__version__"]


class ReleaseMetadataTests(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(app_version(), r"^\d+\.\d+\.\d+$")

    def test_package_configuration_matches(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(pyproject["project"]["version"], app_version())
        lock = (ROOT / "uv.lock").read_text()
        m = re.search(r'\[\[package\]\]\nname = "keymelier"\nversion = "([^"]+)"', lock)
        self.assertIsNotNone(m, "keymelier entry in uv.lock")
        self.assertEqual(m.group(1), app_version())

    def test_app_bundle_and_installer_take_the_version_from_version_py(self):
        spec = (ROOT / "fido2tool.spec").read_text()
        self.assertIn("fido2tool_core/version.py", spec)
        self.assertIn("'CFBundleShortVersionString': APP_VERSION", spec)
        self.assertIn("'CFBundleVersion': APP_VERSION", spec)
        iss = (ROOT / "packaging" / "keymelier.iss").read_text()
        for field in ("AppVersion={#AppVersion}", "VersionInfoVersion={#AppVersion}", "VersionInfoProductVersion={#AppVersion}"):
            self.assertIn(field, iss)
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text()
        self.assertIn("from fido2tool_core.version import __version__", workflow)
        self.assertIn('"/DAppVersion=$version"', workflow)

    def test_public_hardware_page_matches_the_matrix(self):
        import subprocess
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "make_hardware_page.py"), "--check"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_workflows_are_valid_yaml(self):
        """A plain `run:` value must not contain ": " (YAML reads it as a mapping and
        GitHub rejects the whole workflow); use a block (`run: |`) instead."""
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
                m = re.match(r"\s*(?:- )?run: (?![|>'\"])(.*)$", line)
                with self.subTest(f"{wf.name}:{n}"):
                    self.assertFalse(m and (": " in m.group(1) or m.group(1).rstrip().endswith(":")), line.strip())
            try:
                import yaml
            except ImportError:
                continue
            with self.subTest(wf.name):
                self.assertIn("jobs", yaml.safe_load(wf.read_text(encoding="utf-8")))

    def test_changelog_has_an_entry_for_this_version(self):
        headings = re.findall(r"^## (.+)$", (ROOT / "CHANGELOG.md").read_text(), re.M)
        versions = [h.split(" ")[0] for h in headings if h != "Unreleased"]
        self.assertEqual(len(versions), len(set(versions)), "no version twice")
        first = headings[0]
        self.assertTrue(first == "Unreleased" or first.split(" ")[0] == app_version(),
                        f"top entry '{first}' is neither Unreleased nor {app_version()}")
        self.assertIn(app_version(), versions, f"CHANGELOG.md has no section for {app_version()}")
        self.assertRegex(next(h for h in headings if h.startswith(app_version())), r"^\d+\.\d+\.\d+ — \d{4}-\d{2}-\d{2}$")


if __name__ == "__main__":
    unittest.main()
