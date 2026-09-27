"""Release metadata: one version everywhere, and a changelog entry for it."""

import re
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
