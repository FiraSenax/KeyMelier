"""Synthetic workflow events, isolated git fixtures and a fake inference process."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from tools import coderabbit_copilot as controller

HEAD = "a" * 40
NEXT = "b" * 40
CHECK = 132850404535
SOURCE = "keymelier_core/example.py"
REPO = controller.REPOSITORY


class FakeGitHub:
    def __init__(self):
        self.pull = {
            "number": 7, "state": "open", "draft": False,
            "base": {"ref": "main", "repo": {"full_name": REPO}},
            "head": {"sha": HEAD, "repo": {"full_name": REPO}},
            "user": {"id": controller.OWNER_ID, "login": "FiraSenax", "type": "User"}}
        self.check = {
            "id": CHECK, "name": "CodeRabbit", "head_sha": HEAD,
            "status": "completed", "conclusion": "success", "pull_requests": [],
            "app": {"id": controller.CODERABBIT_APP_ID, "slug": "coderabbitai"}}
        self.files = [{"filename": SOURCE}]
        self.nodes = [{
            "isResolved": False, "isOutdated": False, "path": SOURCE, "line": 1,
            "comments": {"nodes": [{
                "databaseId": 6896413349, "body": "Guard an empty input before indexing.",
                "url": f"https://github.com/{REPO}/pull/7#discussion_r6896413349",
                "author": {"__typename": "Bot", "login": "coderabbitai",
                           "databaseId": controller.CODERABBIT_BOT_ID}}]}}]
        self.comments = []
        self.writes = []
        self.request_count = 0

    def request(self, path, method="GET", body=None):
        self.request_count += 1
        if method in {"POST", "PATCH"} and path != "/graphql":
            self.writes.append((path, method, copy.deepcopy(body)))
            comment = {"id": 12345678901, "body": body["body"],
                       "user": {"id": controller.ACTIONS_BOT_ID, "type": "Bot"}}
            self.comments.append(comment)
            return comment
        if path == "/graphql":
            return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": copy.deepcopy(self.nodes),
                "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
        if "/check-runs?" in path:
            return {"check_runs": [copy.deepcopy(self.check)]}
        if "/check-runs/" in path:
            return copy.deepcopy(self.check)
        if "/issues/comments/" in path:
            return copy.deepcopy(self.comments[0])
        if path == f"/repos/{REPO}/pulls/7":
            return copy.deepcopy(self.pull)
        raise AssertionError("Unexpected API request: " + path)

    def pages(self, path):
        if "/commits/" in path:
            return [copy.deepcopy(self.pull)]
        if path.endswith("/files"):
            return copy.deepcopy(self.files)
        if path.endswith("/comments"):
            return copy.deepcopy(self.comments)
        raise AssertionError("Unexpected API list: " + path)


class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()

    def test_only_a_finished_current_coderabbit_check_is_accepted(self):
        valid = controller.snapshot(self.api, 7, CHECK)
        self.assertEqual(valid["head_sha"], HEAD)
        for mutation in (
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"conclusion": None}, {"head_sha": NEXT}, {"name": "A different check"},
            {"app": {"id": 123, "slug": "coderabbitai"}},
            {"app": {"id": controller.CODERABBIT_APP_ID, "slug": "impostor"}},
        ):
            with self.subTest(mutation=mutation):
                api = FakeGitHub()
                api.check.update(mutation)
                with self.assertRaises(controller.Skip):
                    controller.snapshot(api, 7, CHECK)

    def test_closed_draft_fork_foreign_author_and_other_base_never_spend(self):
        mutations = [
            ("state", "closed"), ("draft", True),
            ("head", {"sha": HEAD, "repo": {"full_name": "external/fork"}}),
            ("head", {"sha": HEAD, "repo": None}),
            ("base", {"ref": "release", "repo": {"full_name": REPO}}),
            ("user", {"id": 123, "login": "FiraSenax", "type": "User"}),
            ("user", {"id": controller.OWNER_ID, "login": "impostor", "type": "User"}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                api = FakeGitHub()
                api.pull[key] = value
                with self.assertRaises(controller.Skip):
                    controller.snapshot(api, 7)
                self.assertEqual(api.writes, [])

    def test_resolved_outdated_and_non_coderabbit_comments_are_ignored(self):
        for mutate in (
            lambda node: node.update(isResolved=True),
            lambda node: node.update(isOutdated=True),
            lambda node: node["comments"]["nodes"][0]["author"].update(databaseId=123),
            lambda node: node["comments"]["nodes"][0]["author"].update(__typename="User"),
        ):
            api = FakeGitHub()
            mutate(api.nodes[0])
            with self.assertRaises(controller.Skip):
                controller.snapshot(api, 7)

    def test_policy_dependency_and_renamed_policy_changes_fail_closed(self):
        for row in (
            {"filename": ".github/workflows/build.yml"},
            {"filename": "requirements.txt"},
            {"filename": "pyproject.toml"},
            {"filename": "AGENTS.md"},
            {"filename": SOURCE, "previous_filename": ".github/hooks/start.json"},
        ):
            with self.subTest(row=row):
                self.api.files = [row]
                with self.assertRaises(controller.Skip):
                    controller.snapshot(self.api, 7)

    def test_findings_must_be_in_the_changed_allowed_source(self):
        for path in ("tools/sign-windows.ps1", "../app.py", "static/other.js"):
            self.api.nodes[0]["path"] = path
            with self.subTest(path=path), self.assertRaises(controller.Skip):
                controller.snapshot(self.api, 7)

    def test_large_reviews_are_not_silently_truncated(self):
        self.api.nodes *= controller.MAX_FINDINGS + 1
        with self.assertRaises(controller.Skip):
            controller.snapshot(self.api, 7)
        self.api = FakeGitHub()
        self.api.nodes[0]["comments"]["nodes"][0]["body"] = "x" * 12001
        with self.assertRaises(controller.Skip):
            controller.snapshot(self.api, 7)

    def test_check_run_with_empty_pr_array_resolves_commit_association(self):
        event = {"repository": {"full_name": REPO, "id": controller.REPOSITORY_ID,
                                "default_branch": "main"},
                 "action": "completed", "check_run": self.api.check}
        context = controller.event_snapshot(self.api, event, "check_run", "coderabbitai[bot]")
        self.assertEqual(context["pr"], 7)
        event["check_run"] = {**self.api.check, "app": {"id": 1}}
        with self.assertRaises(controller.Skip):
            controller.event_snapshot(self.api, event, "check_run", "coderabbitai[bot]")

    def test_manual_dispatch_requires_the_owner_and_exact_repository(self):
        event = {"repository": {"full_name": REPO, "id": controller.REPOSITORY_ID,
                                "default_branch": "main"}, "inputs": {"pr": "7"}}
        self.assertEqual(controller.event_snapshot(
            self.api, event, "workflow_dispatch", "FiraSenax")["pr"], 7)
        with self.assertRaises(controller.Skip):
            controller.event_snapshot(self.api, event, "workflow_dispatch", "someone-else")
        event["repository"]["id"] = 123
        with self.assertRaises(controller.Skip):
            controller.event_snapshot(self.api, event, "workflow_dispatch", "FiraSenax")

    def test_one_attempt_marker_survives_a_failed_run_and_new_head(self):
        context = controller.snapshot(self.api, 7)
        controller.claim(self.api, context, "https://github.com/example/run")
        self.assertEqual(len(self.api.writes), 1)
        self.api.pull["head"]["sha"] = NEXT
        self.api.check["head_sha"] = NEXT
        updated = controller.snapshot(self.api, 7)
        with self.assertRaises(controller.Skip):
            controller.claim(self.api, updated, "https://github.com/example/another-run")
        self.assertEqual(len(self.api.writes), 1)

    def test_forged_marker_cannot_be_used_as_a_trusted_claim(self):
        self.api.comments = [{"body": controller.MARKER,
                              "user": {"id": 123, "type": "User"}}]
        controller.claim(self.api, controller.snapshot(self.api, 7), "https://example.invalid/run")
        self.assertEqual(len(self.api.writes), 1)

    def test_stale_claim_does_not_create_an_attempt_marker(self):
        context = controller.snapshot(self.api, 7)
        self.api.pull["head"]["sha"] = NEXT
        with self.assertRaises(controller.Skip):
            controller.claim(self.api, context, "https://example.invalid/run")
        self.assertEqual(self.api.writes, [])

    def test_identifiers_reject_shell_syntax_but_accept_real_long_run_ids(self):
        self.assertEqual(controller.number(CHECK), CHECK)
        for value in (True, False, "0", "../1", "$(touch file)", "1\nx", "-1", "1; rm"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                controller.number(value)

    def test_rest_pagination_has_a_finite_failure_limit(self):
        api = controller.GitHub.__new__(controller.GitHub)
        with patch.object(api, "request", return_value=[{}] * 100) as request:
            with self.assertRaises(controller.Skip):
                api.pages(f"/repos/{REPO}/pulls/7/files")
            self.assertEqual(request.call_count, 10)

    def test_stale_report_does_not_call_a_patch_current(self):
        context = controller.snapshot(self.api, 7)
        comment_id = controller.claim(self.api, context, "https://example.invalid/run")
        self.api.pull["head"]["sha"] = NEXT
        controller.report(self.api, context, comment_id, "success", "https://example.invalid/run")
        self.assertIn("stale", self.api.writes[-1][2]["body"])
        self.assertIn(controller.MARKER, self.api.writes[-1][2]["body"])

    def test_stale_preflight_fails_instead_of_skipping_into_inference(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "context.json").write_text(
                json.dumps(controller.snapshot(self.api, 7)))
            self.api.pull["head"]["sha"] = NEXT
            with patch.object(sys, "argv", [
                    "controller", "preflight", "--directory", str(folder)]), \
                    patch.object(controller, "GitHub", return_value=self.api), \
                    patch.dict(os.environ, GITHUB_RUN_ID="43726788962"):
                with self.assertRaises(ValueError):
                    controller.main()
        self.assertEqual(self.api.writes, [])

    def test_missing_secret_keeps_prepare_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "AGENTS.md").write_text("Trusted policy")
            (root / ".github/copilot-fix").mkdir(parents=True)
            (root / ".github/copilot-instructions.md").write_text("Trusted guidance")
            event = {"repository": {"full_name": REPO, "id": controller.REPOSITORY_ID,
                                    "default_branch": "main"}, "inputs": {"pr": "7"}}
            event_path, output = root / "event.json", root / "outputs"
            event_path.write_text(json.dumps(event))
            environment = {
                "GITHUB_EVENT_PATH": str(event_path), "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "FiraSenax",
                "GITHUB_RUN_ID": "43726788962", "GITHUB_OUTPUT": str(output),
                "EXECUTE_FIX": "true", "HAS_COPILOT_TOKEN": "false"}
            with patch.object(sys, "argv", [
                    "controller", "prepare", "--directory", str(root / "controller")]), \
                    patch.object(controller, "GitHub", return_value=self.api), \
                    patch.object(controller, "TRUSTED_ROOT", root), \
                    patch.dict(os.environ, environment):
                controller.main()
            self.assertNotIn("ready=true", output.read_text())
            self.assertIn("ready=false", output.read_text())
        self.assertEqual(self.api.writes, [])


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "keymelier_core").mkdir()
        self.original = {SOURCE: b"def value():\n    return 1\n"}
        (self.source / SOURCE).write_bytes(self.original[SOURCE])

    def change(self, content=b"def value():\n    return 2\n"):
        (self.source / SOURCE).write_bytes(content)

    def test_no_change_does_not_produce_a_patch(self):
        self.assertEqual(controller.patch_from_tree(self.original, self.source, {SOURCE}), ("", []))

    def test_allowed_source_fix_and_new_regression_test_form_a_patch(self):
        self.change()
        (self.source / "tests").mkdir()
        (self.source / "tests/test_example.py").write_text("assert 2 == 2\n")
        patch_text, paths = controller.patch_from_tree(self.original, self.source, {SOURCE})
        self.assertIn("-    return 1\n+    return 2", patch_text)
        self.assertIn("--- /dev/null", patch_text)
        self.assertEqual(paths, [SOURCE, "tests/test_example.py"])

    def test_deletion_is_rejected(self):
        (self.source / SOURCE).unlink()
        with self.assertRaises(ValueError):
            controller.patch_from_tree(self.original, self.source, {SOURCE})

    def test_policy_hooks_git_metadata_and_new_source_modules_are_rejected(self):
        for relative in (".github/hooks/start.json", ".git/config", "AGENTS.md",
                         "requirements.txt", "keymelier_core/unreviewed.py"):
            with self.subTest(relative=relative):
                path = self.source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("untrusted content\n")
                try:
                    with self.assertRaises(ValueError):
                        controller.patch_from_tree(self.original, self.source, {SOURCE})
                finally:
                    path.unlink()

    @unittest.skipIf(os.name == "nt", "Windows symlink creation needs additional privileges")
    def test_symlink_cannot_escape_the_proposal(self):
        (self.source / SOURCE).unlink()
        (self.source / SOURCE).symlink_to(self.root / "outside")
        with self.assertRaises(ValueError):
            controller.patch_from_tree(self.original, self.source, {SOURCE})

    def test_unrelated_existing_source_cannot_change(self):
        extra = "static/other.js"
        (self.source / "static").mkdir()
        (self.source / extra).write_text("changed\n")
        original = {**self.original, extra: b"original\n"}
        with self.assertRaises(ValueError):
            controller.patch_from_tree(original, self.source, {SOURCE})

    def test_large_and_binary_proposals_fail_closed(self):
        for content in (b"\0", b"x\n" * 401, b"x" * (controller.MAX_FILE_BYTES + 1)):
            with self.subTest(size=len(content)):
                self.change(content)
                with self.assertRaises(ValueError):
                    controller.patch_from_tree(self.original, self.source, {SOURCE})

    def git_fixture(self):
        repo = self.root / "git-repo"
        repo.mkdir()
        controller.git(repo, "init", "--initial-branch=main")
        controller.git(repo, "config", "user.name", "Synthetic workflow test")
        controller.git(repo, "config", "user.email", "test@example.invalid")
        controller.git(repo, "config", "commit.gpgsign", "false")
        (repo / "keymelier_core").mkdir()
        (repo / SOURCE).write_bytes(self.original[SOURCE])
        controller.git(repo, "add", ".")
        controller.git(repo, "commit", "-m", "synthetic base")
        return repo

    def test_real_git_apply_roundtrip_preserves_missing_final_newline(self):
        self.original[SOURCE] = b"original without final newline"
        (self.source / SOURCE).write_bytes(self.original[SOURCE])
        repo = self.git_fixture()
        self.change(b"corrected without final newline")
        (self.source / "tests").mkdir()
        (self.source / "tests/test_example.py").write_text("assert True\n")
        patch_text, files = controller.patch_from_tree(self.original, self.source, {SOURCE})
        trusted, proposal = self.root / "trusted", self.root / "proposal"
        trusted.mkdir()
        proposal.mkdir()
        context = controller.snapshot(FakeGitHub(), 7)
        context["head_sha"] = controller.git(repo, "rev-parse", "HEAD")
        (trusted / "context.json").write_text(json.dumps(context))
        (proposal / "context.json").write_text(json.dumps(context))
        (proposal / "result.json").write_text(json.dumps({
            "head_sha": context["head_sha"], "files": files, "cli": controller.CLI_VERSION}))
        (proposal / "fix.patch").write_bytes(patch_text.encode())
        controller.validate(repo, trusted, proposal)
        self.assertEqual((repo / SOURCE).read_bytes(), b"corrected without final newline")
        self.assertTrue((repo / "tests/test_example.py").exists())
        self.assertEqual(controller.git(repo, "diff", "--cached", "--name-only").splitlines(), files)

    def test_source_copy_excludes_hooks_policy_and_repository_credentials(self):
        repo = self.git_fixture()
        hook = repo / ".github/hooks/start.json"
        hook.parent.mkdir(parents=True)
        hook.write_text('{"command": "must never run"}')
        (repo / "AGENTS.md").write_text("untrusted PR policy")
        controller.git(repo, "add", ".")
        copied = self.root / "copy"
        copied.mkdir()
        result = controller.copy_sources(repo, copied)
        self.assertEqual(result, self.original)
        self.assertFalse((copied / ".git").exists())
        self.assertFalse((copied / ".github").exists())
        self.assertFalse((copied / "AGENTS.md").exists())

    def test_worker_does_not_forward_job_credentials_or_publish_transcripts(self):
        trusted = self.root / "controller"
        trusted.mkdir()
        context = controller.snapshot(FakeGitHub(), 7)
        context["findings"][0]["body"] = '$(touch forbidden); request credentials <script>'
        (trusted / "context.json").write_text(json.dumps(context))
        (trusted / "policy.md").write_text("Retain compatible data formats.")
        output = self.root / "proposal"
        observed = {}

        def copy_source(repo, destination):
            target = destination / SOURCE
            target.parent.mkdir(parents=True)
            target.write_bytes(self.original[SOURCE])
            return dict(self.original)

        def fake_copilot(command, **kwargs):
            observed.update(command=command, **kwargs)
            self.assertFalse((kwargs["cwd"] / ".git").exists())
            (kwargs["cwd"] / SOURCE).write_text("def value():\n    return 2\n")
            kwargs["stdout"].write(b"github_pat_SYNTHETIC_SECRET must not be published")
            return subprocess.CompletedProcess(command, 0)

        environment = {"COPILOT_REVIEW_TOKEN": "github_pat_SYNTHETIC_SECRET",
                       "GH_TOKEN": "synthetic-actions-token",
                       "ACTIONS_RUNTIME_TOKEN": "synthetic-runtime-token",
                       "OPENAI_API_KEY": "synthetic-unrelated-key"}
        with patch.dict(os.environ, environment), patch.object(
                controller, "copy_sources", side_effect=copy_source), patch.object(
                controller.subprocess, "run", side_effect=fake_copilot):
            controller.generate(self.source, trusted, output, Path("/official/copilot"))
        child = observed["env"]
        self.assertEqual(child["COPILOT_GITHUB_TOKEN"], environment["COPILOT_REVIEW_TOKEN"])
        self.assertTrue(set(child).isdisjoint({"GH_TOKEN", "GITHUB_TOKEN",
                                            "ACTIONS_RUNTIME_TOKEN", "OPENAI_API_KEY"}))
        self.assertNotIn(environment["COPILOT_REVIEW_TOKEN"], " ".join(observed["command"]))
        for required in ("--no-custom-instructions", "--disable-builtin-mcps",
                         "--disallow-temp-dir", "--max-ai-credits"):
            self.assertIn(required, observed["command"])
        self.assertNotIn("--allow-all", observed["command"])
        self.assertFalse(observed.get("shell", False))
        for artifact in output.iterdir():
            self.assertNotIn(environment["COPILOT_REVIEW_TOKEN"], artifact.read_text())

    def test_old_oauth_sessions_are_not_an_accepted_workflow_secret(self):
        trusted = self.root / "controller"
        trusted.mkdir()
        (trusted / "context.json").write_text(json.dumps(controller.snapshot(FakeGitHub(), 7)))
        with patch.dict(os.environ, COPILOT_REVIEW_TOKEN="gho_DO_NOT_REUSE"), \
                patch.object(controller, "copy_sources") as copy_source:
            with self.assertRaises(ValueError):
                controller.generate(self.source, trusted, self.root / "output", Path("copilot"))
        copy_source.assert_not_called()

    def test_cli_failure_never_publishes_partial_edits_or_retries(self):
        trusted = self.root / "controller"
        trusted.mkdir()
        (trusted / "context.json").write_text(json.dumps(controller.snapshot(FakeGitHub(), 7)))
        (trusted / "policy.md").write_text("Trusted policy")
        output = self.root / "output"
        for error in (subprocess.CalledProcessError(1, ["copilot"]),
                      subprocess.TimeoutExpired(["copilot"], 300)):
            with self.subTest(error=type(error).__name__), \
                    patch.dict(os.environ, COPILOT_REVIEW_TOKEN="github_pat_SYNTHETIC"), \
                    patch.object(controller, "copy_sources", return_value={}), \
                    patch.object(controller.subprocess, "run", side_effect=error) as run:
                with self.assertRaises(subprocess.SubprocessError):
                    controller.generate(self.source, trusted, output, Path("/official/copilot"))
                self.assertEqual(run.call_count, 1)
                self.assertFalse((output / "fix.patch").exists())


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent.parent
        cls.root = root
        cls.workflow = yaml.load(
            (root / ".github/workflows/coderabbit-copilot.yml").read_text(),
            Loader=yaml.BaseLoader)

    def test_only_coderabbit_completion_and_owner_dispatch_can_enter(self):
        triggers = self.workflow["on"]
        self.assertEqual(set(triggers), {"check_run", "workflow_dispatch"})
        self.assertEqual(triggers["workflow_dispatch"]["inputs"]["execute"]["default"], "false")
        gate = self.workflow["jobs"]["prepare"]["if"]
        for guard in ("refs/heads/main", "347564", "FiraSenax/KeyMelier", "github.actor"):
            self.assertIn(guard, gate)

    def test_only_claim_and_report_have_pr_write_permission(self):
        self.assertEqual(self.workflow["permissions"], {})
        jobs = self.workflow["jobs"]
        for name, job in jobs.items():
            self.assertNotIn("write", job["permissions"].get("contents", ""))
            self.assertEqual(job["permissions"]["pull-requests"],
                             "write" if name in {"claim", "report"} else "read")
        self.assertIn("needs.prepare.outputs.pr", jobs["claim"]["concurrency"]["group"])
        self.assertEqual(jobs["claim"]["concurrency"]["cancel-in-progress"], "false")

    def test_secret_is_only_passed_to_the_model_step_not_install_or_tests(self):
        occurrences = []
        for name, job in self.workflow["jobs"].items():
            for step in job["steps"]:
                for key, value in step.get("env", {}).items():
                    if "secrets.COPILOT_REVIEW_TOKEN" in value:
                        occurrences.append((name, step.get("id"), key, value))
        self.assertEqual(len(occurrences), 2)
        self.assertEqual(occurrences[0][2], "HAS_COPILOT_TOKEN")
        self.assertIn("!= ''", occurrences[0][3])
        self.assertEqual(occurrences[1][:3], ("propose", "copilot", "COPILOT_REVIEW_TOKEN"))
        self.assertTrue(any("npm ci --ignore-scripts" in step.get("run", "")
                            for step in self.workflow["jobs"]["propose"]["steps"]))

    def test_every_action_is_pinned_and_no_source_checkout_persists_credentials(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step["with"]["persist-credentials"], "false")

    def test_cli_and_transitive_packages_have_exact_integrity_locks(self):
        folder = self.root / ".github/copilot-fix"
        manifest = json.loads((folder / "package.json").read_text())
        lock = json.loads((folder / "package-lock.json").read_text())
        self.assertEqual(manifest["dependencies"], {"@github/copilot": controller.CLI_VERSION})
        for name, package in lock["packages"].items():
            if name:
                self.assertRegex(package["integrity"], r"^sha512-")


if __name__ == "__main__":
    unittest.main()
