"""App settings that the UI relies on: introduction flag, platform and build info."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keymelier_core import build_info
from keymelier_core import service as service_mod
from keymelier_core.history import History
from keymelier_core.pin import PinError


class Scanner:
    def set_callbacks(self, **kw):
        pass

    def reevaluate_all(self):
        pass


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.settings = patch.object(service_mod, "SETTINGS_FILE", self.tmp / "settings.json")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.svc = service_mod.KeyService(Scanner(), None, history=History(self.tmp / "h.json", enabled=True, encrypted=False))

    def test_introduction_flag_is_stored(self):
        self.assertFalse(self.svc.get_settings().get("onboarding_done", False), "shown on a first start")
        self.svc.set_settings({"onboarding_done": True})
        self.assertTrue(json.loads((self.tmp / "settings.json").read_text())["onboarding_done"])
        with self.assertRaises(PinError):
            self.svc.set_settings({"onboarding_done": "yes"})

    def test_platform_and_build_are_reported(self):
        st = self.svc.get_settings()
        self.assertEqual(st["platform"], sys.platform)
        self.assertEqual(set(st["build"]), {"signed", "notarized", "ci", "commit", "modified", "release_tag"})

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

    def test_build_info_is_honest_by_default(self):
        self.assertEqual(build_info.load(self.tmp / "missing.json"),
                         {"signed": False, "notarized": False, "ci": False, "commit": None, "modified": None, "release_tag": None})
        (self.tmp / "b.json").write_text('{"signed": true, "notarized": true, "ci": true}')
        self.assertEqual(build_info.load(self.tmp / "b.json"),
                         {"signed": True, "notarized": True, "ci": True, "commit": None, "modified": None, "release_tag": None})
        (self.tmp / "c.json").write_text('{"signed": "true"}')           # only a real boolean counts
        self.assertFalse(build_info.load(self.tmp / "c.json")["signed"])
        (self.tmp / "d.json").write_text("not json")
        self.assertFalse(build_info.load(self.tmp / "d.json")["signed"])

    def test_rc_channel_is_off_by_default_persisted_and_strictly_boolean(self):
        self.assertFalse(self.svc.get_settings()['include_rc_updates'])
        self.svc.set_settings({'include_rc_updates': True})
        restarted = service_mod.KeyService(Scanner(), None, history=self.svc.history)
        self.assertTrue(restarted.get_settings()['include_rc_updates'])
        self.svc._app_update = {'newer': True, 'latest': '1.8.7-rc.3'}
        self.svc._update_path = Path('/not/a/real/download')
        self.svc.set_settings({'include_rc_updates': False})
        self.assertIsNone(self.svc._app_update)
        self.assertIsNone(self.svc._update_path)
        for bad in ('true', 1, [], None):
            with self.subTest(bad=bad), self.assertRaises(PinError):
                self.svc.set_settings({'include_rc_updates': bad})

    def test_old_check_cannot_restore_rc_offer_after_channel_switch(self):
        from keymelier_core import app_update
        self.svc.set_settings({'include_rc_updates': True})
        def stale_check(*, include_rc):
            self.assertTrue(include_rc)
            self.svc.set_settings({'include_rc_updates': False})
            return {'newer': True, 'latest': '1.8.7-rc.3'}
        with patch.object(app_update, 'check', side_effect=stale_check):
            self.assertFalse(self.svc.check_updates()['app'].get('newer'))

    def test_channel_cannot_change_during_requested_download(self):
        self.svc._update_running = True
        with self.assertRaises(PinError):
            self.svc.set_settings({'include_rc_updates': True})
        self.assertFalse(self.svc.get_settings()['include_rc_updates'])

    def test_rc_tag_must_match_the_base_version_and_clean_build(self):
        tag = 'v' + build_info.__version__ + '-rc.3'
        base = {'commit':'a' * 40, 'modified':False, 'release_tag':tag}
        for data, expected in ((base, tag), ({**base, 'modified':True}, None),
                               ({**base, 'release_tag':'v0.0.0-rc.3'}, None),
                               ({**base, 'release_tag':tag + '\n'}, None),
                               ({**base, 'release_tag':tag.replace('-rc.3', '-rc.03')}, None)):
            with self.subTest(data=data):
                path = self.tmp / 'build.json'
                path.write_text(json.dumps(data))
                self.assertEqual(build_info.load(path)['release_tag'], expected)


if __name__ == "__main__":
    unittest.main()
