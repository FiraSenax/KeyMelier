"""App settings that the UI relies on: introduction flag, platform and build info."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fido2tool_core import build_info
from fido2tool_core import service as service_mod
from fido2tool_core.history import History
from fido2tool_core.pin import PinError


class Scanner:
    def set_callbacks(self, **kw):
        pass


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.settings = patch.object(service_mod, "SETTINGS_FILE", self.tmp / "settings.json")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.svc = service_mod.KeyService(Scanner(), None, history=History(self.tmp / "h.json", enabled=True))

    def test_introduction_flag_is_stored(self):
        self.assertFalse(self.svc.get_settings().get("onboarding_done", False), "shown on a first start")
        self.svc.set_settings({"onboarding_done": True})
        self.assertTrue(json.loads((self.tmp / "settings.json").read_text())["onboarding_done"])
        with self.assertRaises(PinError):
            self.svc.set_settings({"onboarding_done": "yes"})

    def test_platform_and_build_are_reported(self):
        st = self.svc.get_settings()
        self.assertEqual(st["platform"], sys.platform)
        self.assertEqual(set(st["build"]), {"signed", "notarized", "ci", "commit", "modified"})

    def test_commit_is_validated_and_modified_is_never_assumed_clean(self):
        full = "0123456789abcdef0123456789abcdef01234567"
        cases = [({"commit": full, "modified": False}, (full, False)),
                 ({"commit": full}, (full, True)),                       # not stated: counts as modified
                 ({"commit": full, "modified": "no"}, (full, True)),
                 ({"commit": full.upper()}, (None, None)),
                 ({"commit": full[:12]}, (None, None)),
                 ({"commit": "../../etc/passwd"}, (None, None)),
                 ({"commit": full + "\nevil"}, (None, None)),
                 ({"commit": "a" * 64, "modified": False}, ("a" * 64, False)),   # SHA-256 repositories
                 ([], (None, None))]
        for data, expected in cases:
            with self.subTest(data=data):
                (self.tmp / "c.json").write_text(json.dumps(data))
                info = build_info.load(self.tmp / "c.json")
                self.assertEqual((info["commit"], info["modified"]), expected)

    def test_build_info_writer_uses_the_checkout(self):
        import importlib.util
        import subprocess
        spec = importlib.util.spec_from_file_location("wbi", Path(__file__).resolve().parent.parent / "tools" / "write_build_info.py")
        wbi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wbi)
        full = "0123456789abcdef0123456789abcdef01234567"
        answers = {("rev-parse", "HEAD"): full, ("status", "--porcelain", "--untracked-files=no"): ""}
        # in CI the runner sets GITHUB_SHA; here it is the commit the fake Git reports
        with patch.object(wbi, "git", lambda *a: answers[a]), patch.dict("os.environ", {"GITHUB_SHA": full}):
            self.assertEqual(wbi.build_info(False, False, True)["commit"], full)
            self.assertIs(wbi.build_info(False, False, True)["modified"], False)
            answers[("status", "--porcelain", "--untracked-files=no")] = " M static/app.js"
            self.assertIs(wbi.build_info(False, False, False)["modified"], True, "local changes are declared")
            with patch.dict("os.environ", {"GITHUB_SHA": "f" * 40}), self.assertRaises(SystemExit):
                wbi.build_info(False, False, True)          # CI: must be the commit that was checked out
        with patch.object(wbi, "git", lambda *a: None), patch.dict("os.environ", {"GITHUB_SHA": ""}):
            self.assertEqual((wbi.build_info(False, False, False)["commit"], wbi.build_info(False, False, False)["modified"]),
                             (None, None), "no Git: unknown, nothing invented")
        if (Path(__file__).resolve().parent.parent / ".git").exists():
            head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                  cwd=Path(__file__).resolve().parent.parent).stdout.strip()
            self.assertEqual(wbi.build_info(False, False, False)["commit"], head)

    def test_build_info_is_honest_by_default(self):
        self.assertEqual(build_info.load(self.tmp / "missing.json"),
                         {"signed": False, "notarized": False, "ci": False, "commit": None, "modified": None})
        (self.tmp / "b.json").write_text('{"signed": true, "notarized": true, "ci": true}')
        self.assertEqual(build_info.load(self.tmp / "b.json"),
                         {"signed": True, "notarized": True, "ci": True, "commit": None, "modified": None})
        (self.tmp / "c.json").write_text('{"signed": "true"}')           # only a real boolean counts
        self.assertFalse(build_info.load(self.tmp / "c.json")["signed"])
        (self.tmp / "d.json").write_text("not json")
        self.assertFalse(build_info.load(self.tmp / "d.json")["signed"])


if __name__ == "__main__":
    unittest.main()
