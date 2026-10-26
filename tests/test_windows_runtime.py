import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import windows_runtime


class WindowsRuntimeTests(unittest.TestCase):
    def test_jdk_copies_are_replaced_and_companions_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            roots = {name: Path(tmp) / name for name in ("vc", "ucrt")}
            for path in roots.values():
                path.mkdir()
            for name in ("MSVCP140.dll", "VCRUNTIME140.dll", "VCRUNTIME140_1.dll"):
                (roots["vc"] / name).write_bytes(b"official redist")
            for name in ("ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll"):
                (roots["ucrt"] / name).write_bytes(b"sdk redist")
            entries = [("MSVCP140.dll", "JDK/bin/MSVCP140.dll", "BINARY"),
                       ("ucrtbase.dll", "JDK/bin/ucrtbase.dll", "BINARY"),
                       ("python312.dll", "Python/python312.dll", "BINARY")]
            selected = windows_runtime.select(entries, roots)
            self.assertFalse(any("JDK" in src for _, src, _ in selected))
            self.assertIn(entries[-1], selected)
            self.assertEqual(len(selected), 6)
            (roots["vc"] / "MSVCP140.dll").unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                windows_runtime.select(entries, roots)

    def test_numeric_version_selection_and_no_unreviewed_fallback(self):
        paths = [Path(f"/VS/{version}/x64/Microsoft.VC143.CRT") for version in ("14.9.1", "14.44.1", "debug_nonredist")]
        self.assertEqual(windows_runtime.latest(paths, -3), paths[1])
        with self.assertRaisesRegex(ValueError, "Install"):
            windows_runtime.latest(paths[-1:], -3)
