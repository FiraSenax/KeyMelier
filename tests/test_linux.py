"""Linux support that can be checked on every system: keyring choice, languages,
page file, host programs without the AppImage's libraries, update asset per CPU."""

import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from fido2tool_core import app_update, desktop, storage
from fido2tool_core import service as service_mod
from fido2tool_core.history import History
from fido2tool_core.pin import PinError


def backend(module):
    """An object whose type lives in `module`, like a keyring backend."""
    return type("Backend", (), {"__module__": module})()


class KeyringTests(unittest.TestCase):
    def use(self, chosen):
        return patch("keyring.get_keyring", return_value=chosen)

    def test_secret_service_is_accepted(self):
        with self.use(backend("keyring.backends.SecretService")):
            self.assertEqual(type(storage._native_keyring()).__module__, "keyring.backends.SecretService")

    def test_native_store_is_taken_out_of_a_chain(self):
        chain = backend("keyring.backends.chainer")
        chain.backends = [backend("keyrings.alt.file"), backend("keyring.backends.SecretService")]
        with self.use(chain):
            self.assertEqual(type(storage._native_keyring()).__module__, "keyring.backends.SecretService")

    def test_plaintext_and_fail_backends_are_refused(self):
        for module in ("keyring.backends.fail", "keyrings.alt.file", "keyring.backends.null"):
            with self.subTest(module), self.use(backend(module)), self.assertRaises(RuntimeError):
                storage._native_keyring()

    def test_sync_without_keyring_says_so(self):
        tmp = Path(tempfile.mkdtemp())
        with patch.object(service_mod, "SETTINGS_FILE", tmp / "settings.json"), \
                self.use(backend("keyring.backends.fail")):
            svc = service_mod.KeyService(types.SimpleNamespace(set_callbacks=lambda **kw: None), None,
                                         history=History(tmp / "h.json", enabled=True))
            (tmp / "sync").mkdir()
            with self.assertRaises(PinError) as ctx:
                svc.sync_enable(str(tmp / "sync"), "a long enough passphrase")
            self.assertEqual(ctx.exception.code, "sync_no_keyring")


class ReplaceFileTests(unittest.TestCase):
    """Windows refuses to replace a file another process has open for a moment."""

    def test_retries_a_sharing_violation_on_windows(self):
        calls = []

        def replace(src, dst):
            calls.append(src)
            if len(calls) < 3:
                raise PermissionError(13, "The process cannot access the file")
        with patch.object(storage.os, "name", "nt"), patch.object(storage.os, "replace", replace), \
                patch("time.sleep"):
            storage.replace_file("a", "b")
        self.assertEqual(len(calls), 3)

    def test_gives_up_after_the_limit_and_never_retries_on_posix(self):
        def always(src, dst):
            raise PermissionError(13, "denied")
        with patch.object(storage.os, "name", "nt"), patch.object(storage.os, "replace", always), \
                patch("time.sleep") as sleep, self.assertRaises(PermissionError):
            storage.replace_file("a", "b", attempts=5)
        self.assertEqual(sleep.call_count, 4)
        with patch.object(storage.os, "name", "posix"), patch.object(storage.os, "replace", always), \
                patch("time.sleep") as sleep, self.assertRaises(PermissionError):
            storage.replace_file("a", "b")
        sleep.assert_not_called()


class LanguageTests(unittest.TestCase):
    def test_posix_language_order(self):
        langs = service_mod._posix_languages
        self.assertEqual(langs({"LANGUAGE": "de_DE:en", "LANG": "de_DE.UTF-8"}), ["de-DE", "en"])
        self.assertEqual(langs({"LC_ALL": "ja_JP.UTF-8", "LANG": "en_US.UTF-8"}), ["ja-JP", "en-US"])
        self.assertEqual(langs({"LANG": "C.UTF-8"}), [])
        self.assertEqual(langs({"LANG": "sr_RS@latin"}), ["sr-RS"])


class DesktopTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_page_file_is_private_and_removed(self):
        with tempfile.TemporaryDirectory() as runtime, patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}):
            path, cleanup = desktop.private_page_file("<html>ä</html>")
            self.assertTrue(str(path).startswith(runtime))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(path.read_text(encoding="utf-8"), "<html>ä</html>")
            cleanup()
            self.assertFalse(path.parent.exists())

    def test_host_programs_do_not_get_the_bundled_libraries(self):
        env = {"LD_LIBRARY_PATH": "/tmp/.mount_Key/usr/lib", "LD_LIBRARY_PATH_ORIG": "/opt/lib",
               "QT_PLUGIN_PATH": "/tmp/.mount_Key/plugins", "PATH": "/usr/bin"}
        with patch.object(sys, "platform", "linux"), patch.object(sys, "frozen", True, create=True), \
                patch.dict(os.environ, env, clear=True):
            host = desktop.host_env()
        self.assertEqual(host["LD_LIBRARY_PATH"], "/opt/lib")
        self.assertNotIn("QT_PLUGIN_PATH", host)
        self.assertEqual(host["PATH"], "/usr/bin")
        with patch.object(sys, "platform", "linux"):
            self.assertIsNone(desktop.host_env(), "running from source: inherit unchanged")

    def test_clipboard_uses_the_first_available_tool(self):
        ran = []
        with patch.dict(os.environ, {"WAYLAND_DISPLAY": ""}, clear=False), \
                patch.object(desktop.shutil, "which", lambda name: name == "xsel"), \
                patch.object(desktop.subprocess, "run", lambda cmd, **kw: ran.append(cmd)):
            self.assertTrue(desktop.linux_copy("code"))
        self.assertEqual(ran, [["xsel", "--clipboard", "--input"]])
        with patch.object(desktop.shutil, "which", lambda name: False):
            self.assertFalse(desktop.linux_copy("code"))


class NavigationLockTests(unittest.TestCase):
    """Linux loads the page from a file: that file (as Qt reports it) stays, anything else is reverted."""

    class Window:
        def __init__(self, url):
            self.url, self.loaded = url, []
            self.events = types.SimpleNamespace(loaded=self)

        def __iadd__(self, handler):
            self.handler = handler
            return self

        def get_current_url(self):
            return self.url

        def load_url(self, url):
            self.loaded.append(url)

        def load_html(self, html):
            self.loaded.append("inline")

    def visit(self, current, page_url):
        import app
        window = self.Window(current)
        app._lock_navigation(window, page_url)
        window.events.loaded.handler()
        return window.loaded

    def test_own_page_file_is_kept_even_as_qt_reports_it(self):
        page = PurePosixPath("/run/user/1000/keymelier-a b/keymelier.html").as_uri()
        self.assertEqual(self.visit("file:///run/user/1000/keymelier-a b/keymelier.html", page), [])
        self.assertEqual(self.visit(page + "#section", page), [])

    def test_other_documents_are_reverted(self):
        page = PurePosixPath("/run/user/1000/keymelier-x/keymelier.html").as_uri()
        for url in ("file:///etc/passwd", "https://example.com/", "file:///run/user/1000/keymelier-x/other.html"):
            with self.subTest(url):
                self.assertEqual(self.visit(url, page), [page])
        self.assertEqual(self.visit("https://example.com/", None), ["inline"], "macOS/Windows: inline page")


class UpdateAssetTests(unittest.TestCase):
    RELEASE = {"tag_name": "v99.0.0", "html_url": "https://github.com/x", "assets": [
        {"name": n, "browser_download_url": app_update.DOWNLOAD_PREFIX + "v99.0.0/" + n}
        for n in ("KeyMelier-Linux-x86_64.AppImage", "KeyMelier-Linux-aarch64.AppImage", "SHA256SUMS.txt")]}

    def check(self, machine):
        response = types.SimpleNamespace(status_code=200, raise_for_status=lambda: None, json=lambda: self.RELEASE)
        with patch.object(sys, "platform", "linux"), patch("platform.machine", return_value=machine), \
                patch("requests.get", return_value=response):
            return app_update.check().get("asset", {}).get("name")

    def test_asset_matches_the_processor(self):
        self.assertEqual(self.check("x86_64"), "KeyMelier-Linux-x86_64.AppImage")
        self.assertEqual(self.check("aarch64"), "KeyMelier-Linux-aarch64.AppImage")
        self.assertIsNone(self.check("riscv64"), "no build for this processor: no download offered")


if __name__ == "__main__":
    unittest.main()


class CompatReportTests(unittest.TestCase):
    """tools/linux_compat.py report: every combination listed; one failure or no result blocks."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("linux_compat", Path(__file__).resolve().parent.parent / "tools" / "linux_compat.py")
        self.compat = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.compat)
        self.dir = Path(tempfile.mkdtemp())

    def result(self, name, **fields):
        (self.dir / name).mkdir()
        base = {"image": name, "distribution": name, "arch": "x86_64", "mode": "native", "glibc": "ldd 2.39",
                "status": "passed", "checks": 46, "passed_checks": 46, "sha256": "ab" * 32, "missing_required": []}
        (self.dir / name / "result.json").write_text(json.dumps({**base, **fields}), encoding="utf-8")

    def test_all_passed(self):
        self.result("ubuntu-24.04")
        self.result("debian-13", mode="emulated")
        text, ok = self.compat.report([self.dir])
        self.assertTrue(ok)
        self.assertIn("emulated", text)
        self.assertIn("ab" * 32, text)
        self.assertIn("no USB/key access, no Wayland", text)

    def test_a_failure_or_no_result_blocks(self):
        self.result("ubuntu-24.04")
        self.result("fedora-43", status="failed", missing_required=["libfoo.so.1 (needed by x)"])
        text, ok = self.compat.report([self.dir])
        self.assertFalse(ok)
        self.assertIn("libfoo.so.1", text)
        self.assertFalse(self.compat.report([Path(tempfile.mkdtemp())])[1], "no results at all is not a pass")

    def test_matrix_matches_the_workflow(self):
        wf = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        for image in set(self.compat.MATRIX["x86_64"]) | set(self.compat.MATRIX["aarch64"]):
            self.assertIn(f"'{image}'", wf)
