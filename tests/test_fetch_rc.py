"""tools/fetch_rc.py: a release candidate only from one checked CI run, verified, never overwritten.
Synthetic packages and a simulated `gh`; no network."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import check_artifacts as ca  # noqa: E402
import fetch_rc  # noqa: E402
from test_check_artifacts import COMMIT, VERSION, fake_squashfs, make_release  # noqa: E402

RUN = "123456"


class FetchRCTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dist = self.tmp / "dist"
        self.dist.mkdir()
        (self.dist / "KeyMelier-macOS.dmg").write_bytes(b"an old local package")   # must stay untouched
        self.rehearsal = self.tmp / "rehearsal"
        (self.rehearsal / "artifacts").mkdir(parents=True)
        notes = make_release(self.rehearsal / "artifacts")
        shutil.copy(notes, self.rehearsal / "release-notes.md")
        with patch.object(ca, "check_sbom", lambda r, path, version, strict: r.check(True, "sbom")), \
                patch.object(ca, "squashfs_contents", fake_squashfs()):
            r = ca.run(["release", str(self.rehearsal / "artifacts"), "--commit", COMMIT, "--notes", str(notes),
                        "--mac-signed", "false", "--win-signed", "false"])
        self.assertEqual(r.problems, [])
        ca.write_report(self.rehearsal / "release-check.md", r, self.rehearsal / "artifacts", COMMIT, "test=success")

    def fetch(self, run=None):
        info = run or {"headSha": COMMIT, "status": "completed", "conclusion": "success"}

        def run_info(run_id):
            if info["conclusion"] != "success":
                raise fetch_rc.RCError("not a successful run")
            return info
        with patch.object(fetch_rc, "run_info", run_info), \
                patch.object(fetch_rc, "download", lambda run_id, target: shutil.copytree(self.rehearsal, target, dirs_exist_ok=True)):
            return fetch_rc.main([RUN, "--dest", str(self.dist)])

    def target(self):
        return self.dist / f"rc-{VERSION}-{COMMIT[:12]}"

    def test_a_checked_run_becomes_its_own_candidate(self):
        self.assertEqual(self.fetch(), 0)
        manifest = json.loads((self.target() / "RC-MANIFEST.json").read_text())
        self.assertEqual((manifest["version"], manifest["commit"], manifest["run_id"]), (VERSION, COMMIT, RUN))
        self.assertIn(f"/actions/runs/{RUN}", manifest["run_url"])
        self.assertEqual(set(manifest["files"]), set(ca.RELEASE_FILES))
        for name, digest in manifest["files"].items():
            self.assertEqual(fetch_rc.sha256(self.target() / name), digest)
        self.assertTrue((self.target() / "release-check.md").exists())
        self.assertEqual((self.dist / "KeyMelier-macOS.dmg").read_bytes(), b"an old local package")
        self.assertEqual([p.name for p in self.dist.iterdir() if p.name.startswith(".rc-")], [], "no staging left")

    def test_missing_package_fails(self):
        (self.rehearsal / "artifacts" / "KeyMelier-Linux-aarch64.AppImage").unlink()
        self.assertEqual(self.fetch(), 1)
        self.assertFalse(self.target().exists())

    def test_changed_package_fails(self):
        (self.rehearsal / "artifacts" / "KeyMelier-Windows.zip").write_bytes(b"tampered")
        self.assertEqual(self.fetch(), 1)
        self.assertFalse(self.target().exists())

    def test_report_for_another_commit_fails(self):
        self.assertEqual(self.fetch({"headSha": "b" * 40, "status": "completed", "conclusion": "success"}), 1)

    def test_failed_run_is_not_a_candidate(self):
        self.assertEqual(self.fetch({"headSha": COMMIT, "status": "completed", "conclusion": "failure"}), 1)

    def test_a_second_run_changes_nothing(self):
        self.assertEqual(self.fetch(), 0)
        before = {p.name: p.stat().st_mtime_ns for p in self.target().iterdir()}
        self.assertEqual(self.fetch(), 0)
        self.assertEqual({p.name: p.stat().st_mtime_ns for p in self.target().iterdir()}, before)

    def test_an_existing_candidate_is_never_overwritten(self):
        self.assertEqual(self.fetch(), 0)
        (self.target() / "KeyMelier-macOS.zip").write_bytes(b"edited by hand")
        self.assertEqual(self.fetch(), 1)
        self.assertEqual((self.target() / "KeyMelier-macOS.zip").read_bytes(), b"edited by hand", "left as it is")


if __name__ == "__main__":
    unittest.main()
