"""Exercise the real offline export gate against broken dependency metadata."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ("requirements.txt", "requirements-build.txt", "requirements-quality.txt")


class DependencyExportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("uv"), "install requirements-quality.txt first")
        folder = tempfile.TemporaryDirectory(prefix="keymelier-export-test-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / "tools").mkdir()
        for name in ("pyproject.toml", "uv.lock", *EXPORTS, "tools/export_requirements.py"):
            shutil.copyfile(ROOT / name, self.root / name)
        self.env = dict(os.environ, UV_CACHE_DIR=str(self.root / "empty-cache"),
                        UV_PYTHON=sys.executable, UV_OFFLINE="1")

    def run_export(self, *args):
        return subprocess.run([sys.executable, str(self.root / "tools/export_requirements.py"), *args],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)

    def snapshot(self):
        return {name: (self.root / name).read_bytes() for name in ("uv.lock", *EXPORTS)}

    def test_check_rejects_each_stale_export_without_rewriting_it(self):
        baseline = self.snapshot()
        result = self.run_export("--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in EXPORTS:
            with self.subTest(name):
                path = self.root / name
                path.write_bytes(baseline[name] + b"# Unexpected manual change\n")
                changed = self.snapshot()
                result = self.run_export("--check")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(name, result.stdout)
                self.assertEqual(self.snapshot(), changed)
                result = self.run_export()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.snapshot(), baseline)

    def test_stale_manifest_cannot_rewrite_the_lock_or_exports(self):
        path = self.root / "pyproject.toml"
        path.write_text(path.read_text(encoding="utf-8") + '\n[project.optional-dependencies]\nexport-test = ["requests==0.0.0"]\n',
                        encoding="utf-8")
        baseline = self.snapshot()
        for args in ((), ("--check",)):
            with self.subTest(args):
                result = self.run_export(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.snapshot(), baseline)


if __name__ == "__main__":
    unittest.main()
