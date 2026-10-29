import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.check_release_source import MAIN_REF, validate


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release source test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        self.git("commit", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-m", "main advances")
        self.main = self.git("rev-parse", "HEAD")
        self.git("update-ref", MAIN_REF, self.main)
        self.git("checkout", "-b", "codex/unmerged", self.base)
        self.git("commit", "--allow-empty", "-m", "unmerged change")
        self.unmerged = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       stderr=subprocess.PIPE, text=True).strip()

    def tag_at(self, commit, name="v1.2.3-rc.1", annotated=False):
        self.git("checkout", "--detach", commit)
        if annotated:
            self.git("tag", "-a", name, "-m", "release")
        else:
            self.git("tag", name)
        return "refs/tags/" + name

    def test_main_commit_and_ancestor_are_accepted(self):
        for index, commit in enumerate((self.base, self.main), 1):
            with self.subTest(commit=commit):
                ref = self.tag_at(commit, f"v1.2.3-rc.{index}")
                self.assertEqual(validate(ref, commit, self.repo), commit)

    def test_annotated_and_stable_tags_resolve_to_the_exact_commit(self):
        ref = self.tag_at(self.main, "v1.2.3", annotated=True)
        self.assertEqual(validate(ref, self.main, self.repo), self.main)

    def test_unmerged_branch_tag_is_rejected(self):
        ref = self.tag_at(self.unmerged)
        with self.assertRaisesRegex(ValueError, "contained in origin/main"):
            validate(ref, self.unmerged, self.repo)

    def test_checkout_and_tag_must_match(self):
        ref = self.tag_at(self.base)
        self.git("checkout", "--detach", self.main)
        with self.assertRaisesRegex(ValueError, "do not match"):
            validate(ref, self.main, self.repo)

    def test_workflow_sha_must_match_the_checkout(self):
        ref = self.tag_at(self.main)
        with self.assertRaisesRegex(ValueError, "do not match"):
            validate(ref, self.base, self.repo)

    def test_missing_main_or_missing_tag_fails_closed(self):
        ref = self.tag_at(self.main)
        with self.assertRaises(ValueError):
            validate("refs/tags/v9.9.9", self.main, self.repo)
        self.git("update-ref", "-d", MAIN_REF)
        with self.assertRaises(ValueError):
            validate(ref, self.main, self.repo)

    def test_branches_invalid_tags_and_nonliteral_object_ids_are_rejected(self):
        for ref in ("refs/heads/main", "refs/heads/v1.2.3-rc.1", "refs/tags/v1.2.3-rc.0",
                    "refs/tags/v1.2.3-rc.01", "refs/tags/v1.2.3-rc.x", "refs/tags/vsigncheck-test"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                validate(ref, self.main, self.repo)
        ref = self.tag_at(self.main)
        for sha in ("HEAD", self.main[:7], self.main + "^", "--all"):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                validate(ref, sha, self.repo)

    def test_commit_becomes_eligible_only_after_merge_into_main(self):
        ref = self.tag_at(self.unmerged)
        with self.assertRaises(ValueError):
            validate(ref, self.unmerged, self.repo)
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "codex/unmerged", "-m", "reviewed merge")
        self.git("update-ref", MAIN_REF, "HEAD")
        self.git("checkout", "--detach", self.unmerged)
        self.assertEqual(validate(ref, self.unmerged, self.repo), self.unmerged)
