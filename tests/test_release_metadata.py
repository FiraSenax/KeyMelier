"""Release metadata: one version everywhere, and a changelog entry for it."""

import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def app_version() -> str:
    ns: dict = {}
    exec((ROOT / "fido2tool_core" / "version.py").read_text(encoding="utf-8"), ns)
    return ns["__version__"]


class ReleaseMetadataTests(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(app_version(), r"^\d+\.\d+\.\d+$")

    def test_package_configuration_matches(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], app_version())
        lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
        m = re.search(r'\[\[package\]\]\nname = "keymelier"\nversion = "([^"]+)"', lock)
        self.assertIsNotNone(m, "keymelier entry in uv.lock")
        self.assertEqual(m.group(1), app_version())

    def test_app_bundle_and_installer_take_the_version_from_version_py(self):
        spec = (ROOT / "fido2tool.spec").read_text(encoding="utf-8")
        self.assertIn("fido2tool_core/version.py", spec)
        self.assertIn("'CFBundleShortVersionString': APP_VERSION", spec)
        self.assertIn("'CFBundleVersion': APP_VERSION", spec)
        iss = (ROOT / "packaging" / "keymelier.iss").read_text(encoding="utf-8")
        for field in ("AppVersion={#AppVersion}", "VersionInfoVersion={#AppVersion}", "VersionInfoProductVersion={#AppVersion}"):
            self.assertIn(field, iss)
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
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

    def test_signing_keychain_outlives_every_signing_step(self):
        """1.8.1 failed in CI: the keychain was removed after notarizing the app,
        before the disk image was signed. Only the release run signs, so the
        rehearsal could not catch it – this checks the step order instead."""
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        job = workflow.split("\n  build-macos:\n", 1)[1].split("\n  build-", 1)[0]
        steps = re.split(r"\n      - ", job)
        removal = next(i for i, step in enumerate(steps) if "security delete-keychain" in step)
        users = [i for i, step in enumerate(steps)
                 if re.search(r"MACOS_SIGN_IDENTITY|notarytool|make-dmg\.sh|sign-macos\.sh", step)]
        self.assertTrue(users)
        self.assertGreater(removal, max(users), "the signing keychain is removed before a step that signs")
        self.assertIn("always()", steps[removal])

    def test_signed_rc_uses_signing_but_never_the_publish_job(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        trigger = workflow.get('on', workflow.get(True))
        self.assertFalse(trigger['workflow_dispatch']['inputs']['signed_rc']['default'])
        mac = workflow['jobs']['build-macos']
        self.assertIn('inputs.signed_rc', mac['environment'])
        self.assertIn('release-signing', mac['environment'])
        self.assertIn('inputs.signed_rc', mac['env']['SIGN_MAC'])
        required = next(s for s in mac['steps'] if s.get('name') == 'Require signing and notarization for a signed RC')
        self.assertIn('exit 1', required['run'])
        for secret in ('MACOS_CERTIFICATE_P12', 'MACOS_SIGN_IDENTITY', 'APPLE_ID', 'APPLE_TEAM_ID', 'APPLE_APP_PASSWORD'):
            self.assertIn(secret, required['env'])
        release = workflow['jobs']['release']
        self.assertIn("github.event_name == 'push'", release['if'])
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", release['if'])
        self.assertNotIn('signed_rc', release['if'])
        self.assertIn("!contains(github.ref_name, '-rc.')", release['if'])
        rc = workflow['jobs']['release-rehearsal']
        self.assertEqual(rc['permissions'], {'contents':'read'})
        self.assertTrue(any(s.get('uses') == './.github/actions/prepare-release' for s in rc['steps']))
        self.assertFalse(any('action-gh-release' in s.get('uses', '') for s in rc['steps']))
        self.assertTrue(any(s.get('name') == 'Verify signed RC result' for s in rc['steps']))

    def test_shipped_files_have_the_same_bytes_on_every_platform(self):
        """Git must not convert line endings on Windows: the SBOM hashes the shipped files."""
        import shutil
        import subprocess
        if not shutil.which("git") or not (ROOT / ".git").exists():
            self.skipTest("no git checkout")
        files = ["static/service-icons.js", "static/app.js", "static/index.html", "fido2tool_core/page.py"]
        out = subprocess.run(["git", "check-attr", "eol", "--", *files, "build-windows.bat"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
        eol = {path: value for path, _attr, value in (line.split(": ") for line in out.splitlines())}
        for f in files:
            self.assertEqual(eol[f], "lf", f)
        self.assertEqual(eol["build-windows.bat"], "crlf")
        binary = subprocess.run(["git", "check-attr", "text", "--", "data/advisories.json", "data/advisories.json.sig"],
                                cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertEqual(binary.count(": text: unset"), 2, "signed files are never converted")

    def test_requirement_exports_match_the_lock(self):
        """CI installs requirements*.txt; they must be the current export of uv.lock.
        Dependabot updates only uv.lock – this fails its PR until the exports are regenerated:
            uv export --frozen --no-dev --no-emit-project -o requirements.txt
            uv export --frozen --only-group build --no-emit-project -o requirements-build.txt"""
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()
        locked = {}
        for pkg in lock["package"]:
            hashes = {pkg["sdist"]["hash"]} if "sdist" in pkg and "hash" in pkg["sdist"] else set()
            hashes |= {w["hash"] for w in pkg.get("wheels", []) if "hash" in w}
            locked[norm(pkg["name"])] = (pkg["version"], hashes)
        exported = {}
        for name in ("requirements.txt", "requirements-build.txt"):
            text = (ROOT / name).read_text(encoding="utf-8").replace("\\\n", " ")
            for line in text.splitlines():
                m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", line)
                if m:
                    exported[norm(m.group(1))] = (m.group(2), set(re.findall(r"--hash=(sha256:[0-9a-f]{64})", line)), name)
        for pkg, (version, hashes, source) in exported.items():
            with self.subTest(pkg):
                self.assertIn(pkg, locked, f"{source} pins {pkg}, uv.lock does not have it")
                self.assertEqual(version, locked[pkg][0], f"{source} pins {pkg}=={version}, uv.lock has {locked[pkg][0]}")
                self.assertTrue(hashes and hashes <= locked[pkg][1], f"{source}: hashes of {pkg} are not the lock's")
        missing = set(locked) - set(exported) - {"keymelier"}
        self.assertEqual(missing, set(), "packages in uv.lock that no export installs – regenerate the exports")

    def test_changelog_has_an_entry_for_this_version(self):
        headings = re.findall(r"^## (.+)$", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
        versions = [h.split(" ")[0] for h in headings if h != "Unreleased"]
        self.assertEqual(len(versions), len(set(versions)), "no version twice")
        first = headings[0]
        self.assertTrue(first == "Unreleased" or first.split(" ")[0] == app_version(),
                        f"top entry '{first}' is neither Unreleased nor {app_version()}")
        self.assertIn(app_version(), versions, f"CHANGELOG.md has no section for {app_version()}")
        self.assertRegex(next(h for h in headings if h.startswith(app_version())), r"^\d+\.\d+\.\d+ — \d{4}-\d{2}-\d{2}$")


if __name__ == "__main__":
    unittest.main()
