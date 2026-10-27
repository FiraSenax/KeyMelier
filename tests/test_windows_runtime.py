import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import windows_runtime


class WindowsRuntimeTests(unittest.TestCase):
    def test_runtime_copies_are_removed_even_from_nested_wheels(self):
        excluded = ["MSVCP140.dll", "VCRUNTIME140.dll", "vcruntime140_1.dll", "ucrtbase.dll",
                    "api-ms-win-crt-runtime-l1-1-0.dll", "concrt140.dll", "mfc140u.dll",
                    "win32\\msvcp140_atomic_wait.dll", "wheel/lib/vcruntime140.dll"]
        kept = ["python312.dll", "webview/lib/Microsoft.Web.WebView2.Core.dll", "libcrypto-3.dll"]
        entries = [(n, "some/origin/" + n, "BINARY") for n in excluded + kept]
        self.assertEqual([e[0] for e in windows_runtime.select(entries)], kept)
