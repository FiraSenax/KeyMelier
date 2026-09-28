"""tools/write_build_info.py: the source commit and whether the tree differs from it,
checked in a temporary Git repository (no network, the real repository is not touched)."""

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("write_build_info", ROOT / "tools" / "write_build_info.py")
wbi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wbi)


@unittest.skipIf(shutil.which("git") is None, "needs git")
class ModifiedStateTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / ".gitignore").write_text("build/\ndist/\n__pycache__/\ndata/build.json\n", encoding="utf-8")
        (self.repo / "data").mkdir()
        (self.repo / "app.py").write_text("print('app')\n", encoding="utf-8")
        (self.repo / "static.js").write_text("// ui\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "initial")
        self.head = self.git("rev-parse", "HEAD")
        env = patch.dict(os.environ, {"GITHUB_SHA": ""})   # the runner's value must not leak in
        env.start()
        self.addCleanup(env.stop)

    def git(self, *args) -> str:
        return subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()

    def info(self, ci=False):
        return wbi.build_info(False, False, ci, root=self.repo)

    def test_1_clean_checkout(self):
        self.assertEqual((self.info()["commit"], self.info()["modified"]), (self.head, False))

    def test_2_edited_tracked_file(self):
        (self.repo / "app.py").write_text("print('changed')\n", encoding="utf-8")
        self.assertIs(self.info()["modified"], True)

    def test_3_new_untracked_source_file_regression(self):
        """The original bug: --untracked-files=no reported a tree with a new source file as unmodified."""
        (self.repo / "extra_module.py").write_text("SECRET_FEATURE = True\n", encoding="utf-8")
        self.assertIs(self.info()["modified"], True)
        self.assertEqual(self.info()["commit"], self.head, "the commit stays the checked-out one")

    def test_4_new_staged_file(self):
        (self.repo / "staged.py").write_text("x = 1\n", encoding="utf-8")
        self.git("add", "staged.py")
        self.assertIs(self.info()["modified"], True)

    def test_5_deleted_or_renamed_tracked_file(self):
        (self.repo / "static.js").unlink()
        self.assertIs(self.info()["modified"], True, "deleted")
        self.git("checkout", "--", "static.js")
        self.git("mv", "static.js", "renamed.js")
        self.assertIs(self.info()["modified"], True, "renamed")

    def test_6_only_ignored_build_output(self):
        for rel in ("build/work/x.o", "dist/KeyMelier.app/Contents/Info.plist", "__pycache__/app.cpython-312.pyc",
                    "data/build.json"):
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("generated", encoding="utf-8")
        self.assertIs(self.info()["modified"], False)

    def test_7_failing_status_is_never_unmodified(self):
        real = wbi.git

        def failing(*args, cwd=None):
            return None if args[0] == "status" else real(*args, cwd=cwd)
        with patch.object(wbi, "git", failing):
            info = self.info()
            self.assertEqual(info["commit"], self.head)
            self.assertIsNone(info["modified"], "unknown – not false")
            with self.assertRaises(SystemExit):
                self.info(ci=True)                   # a CI build stops instead
        # and the app reads "unknown" as not proven unmodified
        from fido2tool_core import build_info
        path = self.repo / "b.json"
        path.write_text(__import__("json").dumps(info), encoding="utf-8")
        self.assertIs(build_info.load(path)["modified"], True)

    def test_8_no_git_repository(self):
        plain = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, plain, True)
        info = wbi.build_info(False, False, False, root=plain)
        self.assertEqual((info["commit"], info["modified"]), (None, None))

    def test_ci_must_build_the_commit_it_was_asked_for(self):
        with patch.dict(os.environ, {"GITHUB_SHA": self.head}):
            self.assertEqual(self.info(ci=True)["commit"], self.head)
        with patch.dict(os.environ, {"GITHUB_SHA": "f" * 40}), self.assertRaises(SystemExit):
            self.info(ci=True)


class RealCheckoutTests(unittest.TestCase):
    @unittest.skipIf(shutil.which("git") is None or not (ROOT / ".git").exists(), "no git checkout")
    def test_this_checkout(self):
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        with patch.dict(os.environ, {"GITHUB_SHA": ""}):
            info = wbi.build_info(False, False, False)
        self.assertEqual(info["commit"], head)
        self.assertIn(info["modified"], (True, False))


if __name__ == "__main__":
    unittest.main()
