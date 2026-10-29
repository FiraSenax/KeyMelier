"""Release metadata: one version everywhere, and a changelog entry for it."""

import re
import sys
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def app_version() -> str:
    ns: dict = {}
    exec((ROOT / "keymelier_core" / "version.py").read_text(encoding="utf-8"), ns)
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
        spec = (ROOT / "keymelier.spec").read_text(encoding="utf-8")
        self.assertIn("keymelier_core/version.py", spec)
        self.assertIn("'CFBundleShortVersionString': APP_VERSION", spec)
        self.assertIn("'CFBundleVersion': APP_VERSION", spec)
        iss = (ROOT / "packaging" / "keymelier.iss").read_text(encoding="utf-8")
        for field in ("AppVersion={#AppVersion}", "VersionInfoVersion={#AppVersion}", "VersionInfoProductVersion={#AppVersion}"):
            self.assertIn(field, iss)
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        self.assertIn("from keymelier_core.version import __version__", workflow)
        installer = (ROOT / 'tools/build-windows-installer.ps1').read_text()
        self.assertIn('-AppVersion $version', workflow)
        self.assertIn('"/DAppVersion=$AppVersion"', installer)

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

    def test_signed_rc_uses_signing_but_never_the_stable_publish_job(self):
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

    def test_production_jobs_wait_for_the_main_source_gate_before_secrets(self):
        from types import SimpleNamespace

        jobs = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())['jobs']
        gate = jobs['release-source']
        self.assertNotIn('environment', gate)
        self.assertEqual(gate['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', str(gate))
        checkout = gate['steps'][0]['with']
        self.assertEqual(checkout['fetch-depth'], 0)
        self.assertFalse(checkout['persist-credentials'])
        step = gate['steps'][1]
        self.assertIn('git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main', step['run'])
        self.assertLess(step['run'].index('git fetch'), step['run'].index('tools/check_release_source.py'))
        self.assertNotIn('continue-on-error', step)
        self.assertEqual(step['env'], {'RELEASE_REF': '${{ github.ref }}', 'RELEASE_SHA': '${{ github.sha }}'})
        for name, job in jobs.items():
            if 'release-signing' in str(job.get('environment', '')):
                with self.subTest(job=name):
                    self.assertIn('release-source', job['needs'])
                    self.assertNotIn('always()', job.get('if', ''))
        expression = step['if'].replace('&&', ' and ').replace('||', ' or ')
        for event, ref, signed, required in (
            ('push', 'refs/tags/v1.2.3-rc.1', False, True),
            ('push', 'refs/tags/v1.2.3', False, True),
            ('workflow_dispatch', 'refs/tags/v1.2.3-rc.1', False, True),
            ('workflow_dispatch', 'refs/heads/codex/test', True, True),
            ('workflow_dispatch', 'refs/heads/codex/test', False, False),
            ('push', 'refs/heads/main', False, False),
            ('pull_request', 'refs/pull/1/merge', False, False),
        ):
            with self.subTest(event=event, ref=ref, signed=signed):
                context = {'__builtins__': {}, 'startsWith': str.startswith,
                           'github': SimpleNamespace(event_name=event, ref=ref),
                           'inputs': SimpleNamespace(signed_rc=signed)}
                self.assertEqual(eval(expression, context), required)

    def test_rc_publication_trigger_preserves_manual_rehearsals_and_stable_channel(self):
        from types import SimpleNamespace

        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        expression = workflow['jobs']['release-candidate']['if']
        expression = expression.replace('&&', ' and ').replace('||', ' or ')
        cases = (
            ('push', 'refs/tags/v1.8.7-rc.9', False, False, True),
            ('push', 'refs/tags/v1.8.7', False, False, False),
            ('push', 'refs/heads/v1.8.7-rc.9', False, False, False),
            ('push', 'refs/heads/main', False, False, False),
            ('pull_request', 'refs/pull/1/merge', True, True, False),
            ('workflow_dispatch', 'refs/tags/v1.8.7-rc.9', True, True, True),
            ('workflow_dispatch', 'refs/tags/v1.8.7-rc.9', True, False, False),
            ('workflow_dispatch', 'refs/tags/v1.8.7-rc.9', False, True, False),
            ('workflow_dispatch', 'refs/tags/v1.8.7-rc.9', False, False, False),
            ('workflow_dispatch', 'refs/tags/v1.8.7', True, True, False),
            ('workflow_dispatch', 'refs/heads/v1.8.7-rc.9', True, True, False),
        )
        for event, ref, signed, publish, allowed in cases:
            with self.subTest(event=event, ref=ref, signed=signed, publish=publish):
                # These expressions only use boolean operators, string predicates
                # and the explicit event/input context. Evaluate the real YAML gate.
                context = {'__builtins__': {}, 'startsWith': str.startswith,
                           'contains': lambda value, part: part in value,
                           'github': SimpleNamespace(event_name=event, ref=ref, ref_name=ref.rsplit('/', 1)[-1]),
                           'inputs': SimpleNamespace(signed_rc=signed, publish_rc=publish)}
                self.assertEqual(eval(expression, context), allowed)

    def test_rc_publication_requires_green_rehearsal_and_signatures(self):
        import os
        import subprocess
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        trigger = workflow.get('on', workflow.get(True))
        self.assertFalse(trigger['workflow_dispatch']['inputs']['publish_rc']['default'])
        job = workflow['jobs']['release-candidate']
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.signed_rc && inputs.publish_rc', job['if'])
        self.assertIn('release-rehearsal', job['needs'])
        self.assertNotIn('always()', job['if'])
        self.assertEqual(job['environment'], 'release-signing')
        gate = next(s for s in job['steps'] if s.get('name') == 'Require an RC tag and both verified signatures')
        bash = str(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe') if sys.platform == 'win32' else 'bash'
        for ref, mac, win, allowed in ((f'v{app_version()}-rc.3', 'true', 'true', True),
                                       (f'v{app_version()}', 'true', 'true', False),
                                       ('main', 'true', 'true', False),
                                       ('v0.0.0-rc.1', 'true', 'true', False),
                                       (f'v{app_version()}-rc.3', 'false', 'true', False),
                                       (f'v{app_version()}-rc.3', 'true', 'false', False)):
            with self.subTest(ref=ref, mac=mac, win=win):
                script = gate['run'].replace('python3', '"' + sys.executable.replace('\\', '/') + '"')
                result = subprocess.run([bash, '-e', '-c', script], cwd=ROOT, capture_output=True, text=True,
                                        env={**os.environ, 'GITHUB_REF_NAME':ref, 'MAC_SIGNED':mac, 'WIN_SIGNED':win})
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
        publish = job['steps'][-1]['run']
        self.assertLess(publish.index('sha256sum --check'), publish.index('gh release create'))
        self.assertIn('--verify-tag --draft --prerelease --latest=false', publish)
        self.assertIn('--draft=false --prerelease --latest=false', publish)

    def test_shipped_files_have_the_same_bytes_on_every_platform(self):
        """Git must not convert line endings on Windows: the SBOM hashes the shipped files."""
        import shutil
        import subprocess
        if not shutil.which("git") or not (ROOT / ".git").exists():
            self.skipTest("no git checkout")
        files = ["static/service-icons.js", "static/app.js", "static/index.html", "keymelier_core/page.py"]
        out = subprocess.run(["git", "check-attr", "eol", "--", *files, "build-windows.bat"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
        eol = {path: value for path, _attr, value in (line.split(": ") for line in out.splitlines())}
        for f in files:
            self.assertEqual(eol[f], "lf", f)
        self.assertEqual(eol["build-windows.bat"], "crlf")
        binary = subprocess.run(["git", "check-attr", "text", "--", "data/advisories.json", "data/advisories.json.sig"],
                                cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertEqual(binary.count(": text: unset"), 2, "signed files are never converted")

    def test_stable_publication_requires_both_verified_signatures(self):
        import os
        import subprocess
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        steps = workflow['jobs']['release']['steps']
        gate = next(s for s in steps if s.get('name') == 'Require completed production signing')
        publish = next(s for s in steps if 'action-gh-release' in s.get('uses', ''))
        self.assertLess(steps.index(gate), steps.index(publish))
        self.assertEqual(gate['env']['WIN_SIGNED'], '${{ needs.build-windows.outputs.signed }}')
        self.assertEqual(gate['env']['MAC_SIGNED'], '${{ needs.build-macos.outputs.signed }}')
        # Windows' PATH can resolve bash.exe to the WSL launcher. Actions uses
        # Git Bash; choose that interpreter explicitly for the portable test.
        bash = str(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe') if sys.platform == 'win32' else 'bash'
        for mac, win in (('true', 'true'), ('false', 'true'), ('true', 'false'), ('true', ''), ('', '')):
            with self.subTest(mac=mac, win=win):
                result = subprocess.run([bash, '-e', '-c', gate['run']], capture_output=True, text=True,
                                        env={**os.environ, 'MAC_SIGNED': mac, 'WIN_SIGNED': win})
                self.assertEqual(result.returncode == 0, mac == win == 'true', result.stderr)

    def test_certum_cleanup_precedes_execution_and_artifact_upload(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        job = workflow['jobs']['build-windows']
        # Configured signing must not fall back simply because a secret is absent.
        self.assertNotIn('secrets.', job['env']['SIGN_WIN'])
        steps = job['steps']
        cleanup = next(s for s in steps if 'disconnect-simplysign.ps1' in s.get('run', ''))
        self.assertIn('always()', cleanup['if'])
        smoke = next(s for s in steps if 'smoke_packaged.py' in s.get('run', ''))
        self.assertLess(steps.index(cleanup), steps.index(smoke))
        upload = next(s for s in steps if s.get('with', {}).get('name') == 'KeyMelier-Windows')
        self.assertLess(steps.index(cleanup), steps.index(upload))

    def test_requirement_exports_match_the_lock(self):
        """CI installs requirements*.txt; they must be the current export of uv.lock.
        Includes isolated quality tools; all exports come from one lock:
            python tools/export_requirements.py"""
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()
        locked = {}
        for pkg in lock["package"]:
            hashes = {pkg["sdist"]["hash"]} if "sdist" in pkg and "hash" in pkg["sdist"] else set()
            hashes |= {w["hash"] for w in pkg.get("wheels", []) if "hash" in w}
            locked[norm(pkg["name"])] = (pkg["version"], hashes)
        exported = {}
        for name in ("requirements.txt", "requirements-build.txt", "requirements-quality.txt"):
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

    def test_quality_tools_stay_out_of_runtime_and_build_exports(self):
        for name in ("requirements.txt", "requirements-build.txt"):
            packages = set(re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", (ROOT / name).read_text()))
            self.assertFalse(packages & {"ruff", "pyyaml", "uv"}, name)

    def test_dependabot_does_not_update_generated_exports_independently(self):
        config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
        update = next(item for item in config["updates"] if item["package-ecosystem"] == "uv")
        self.assertTrue({"requirements.txt", "requirements-build.txt", "requirements-quality.txt"}
                        <= set(update["exclude-paths"]))

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
