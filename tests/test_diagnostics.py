"""Diagnostic report: built from a fixed list of fields, so injected sensitive
values (names, serials, paths, internal URLs, sync ids, messages) never appear."""

import json
import socket
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from fido2tool_core import diagnostics
from fido2tool_core import service as service_mod
from fido2tool_core.history import History
from fido2tool_core.pin import PinError
from fido2tool_core.scanner import TokenRecord

SECRETS = {
    "serial": "SN-98765432",
    "key label": "Alice Private YubiKey",
    "account": "alice@example.com",
    "site": "intranet-hr.contoso.example",
    "home path": "/Users/alice",
    "windows path": "C:\\\\Users\\\\alice",
    "sync folder": "Dropbox/KeyMelier-alice",
    "sync device": "0123456789abcdef",
    "passphrase": "correct horse battery staple",
    "internal url": "https://wiki.contoso.example/keys",
    "company source": "Contoso Internal Security",
    "pin": "271828",
    "error message": "TOPSECRET-TRACE",
    "unknown field": "SHOULD-NOT-BE-COPIED",
}


def record():
    return TokenRecord("tok-1", "/dev/hidraw7", "YubiKey 5 NFC", SECRETS["serial"], "Yubico",
                       "cb69481e-8ff7-4039-93ec-0a2729a154a8", [], [], {}, [], None, None, "", "now")


class FakeScanner:
    def __init__(self, records):
        self.records = records

    def set_callbacks(self, **kw):
        pass

    def get_all(self):
        return self.records

    def get(self, token_id):
        return self.records[0]


class FakeAdvisories:
    def info(self):
        return {"source": "downloaded", "updated": "2026-09-26T18:09:57+00:00", "count": 2,
                "secret": SECRETS["unknown field"],
                "policy": [{"name": SECRETS["company source"], "status": "ok", "count": 3,
                            "location": SECRETS["internal url"]},
                           {"name": "Lab", "status": "invalid", "count": 0}]}

    def policy_links(self):
        return set()


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        settings = {"lang": "de", "history_enabled": True, "remember_sites": True,
                    "sync_folder": f"{SECRETS['home path']}/{SECRETS['sync folder']}",
                    "sync_device": SECRETS["sync device"], "passphrase": SECRETS["passphrase"],
                    "extra": SECRETS["unknown field"]}
        (self.tmp / "settings.json").write_text(json.dumps(settings))
        p = patch.object(service_mod, "SETTINGS_FILE", self.tmp / "settings.json")
        p.start()
        self.addCleanup(p.stop)

    def service(self, records):
        history = History(self.tmp / "history.json", enabled=True)
        svc = service_mod.KeyService(FakeScanner(records), None, history=history, advisories=FakeAdvisories())
        if records:
            entry = history.update_snapshot(records[0])
            history.rename(entry["key_id"], SECRETS["key label"])
            history.set_sites(records[0], [{"rp_id": SECRETS["site"], "users": [{"name": SECRETS["account"], "display": SECRETS["account"]}]}])
        return svc

    def text(self, svc):
        return json.dumps(svc.diagnostics(), indent=2)

    def assert_clean(self, text):
        for what, value in SECRETS.items():
            with self.subTest(what):
                self.assertNotIn(value.replace("\\\\", "\\"), text)
                self.assertNotIn(value, text)
        host = socket.gethostname()
        if len(host) > 3:
            self.assertNotIn(host, text)
        self.assertNotIn(str(Path.home()), text)

    def test_sensitive_values_never_appear(self):
        import app
        svc = self.service([record()])
        svc.error_log = diagnostics.ErrorLog(app.ALLOWED)
        api = app.Api(svc)

        def fail(**kw):
            raise PinError(f"PIN {SECRETS['pin']} rejected at {SECRETS['home path']}/x {SECRETS['internal url']}",
                           "pin_invalid", reason=f"{SECRETS['error message']} {SECRETS['home path']}")

        def crash(**kw):
            raise RuntimeError(f"{SECRETS['error message']} in {SECRETS['home path']}/.keymelier {SECRETS['internal url']}")
        svc.pin_update = fail
        svc.sync_now = crash
        api.call("pin_update", {"token_id": "tok-1", "current": SECRETS["pin"], "new": "31415926"})
        api.call("sync_now", {})
        svc.error_log.record(f"{SECRETS['home path']}/op", f"code {SECRETS['internal url']}")
        api.client_error(f"TypeError at file://{SECRETS['home path']}/{SECRETS['error message']}")
        text = self.text(svc)
        self.assert_clean(text)
        report = json.loads(text)
        errors = report["recent_errors"]
        self.assertEqual([(e["operation"], e["code"]) for e in errors],
                         [("pin_update", "pin_invalid"), ("sync_now", "error"), ("other", "other")])
        self.assertEqual(errors[0]["reason"], "other", "a reason with free text is replaced")
        self.assertEqual(report["ui_script_errors"], 1)
        self.assertEqual(report["keys"], {"connected": 1, "in_history": 1})
        self.assertEqual(report["data"]["advisories"]["company_sources"], {"ok": 1, "invalid": 1})
        self.assertEqual(report["settings"]["language"], "de")

    def test_only_the_listed_fields(self):
        report = self.service([]).diagnostics()
        self.assertEqual(set(report), {"format", "created", "app", "system", "settings", "keys", "sync", "data",
                                       "recent_errors", "ui_script_errors"})
        self.assertEqual(set(report["sync"]), {"configured", "active", "problem"})
        self.assertEqual(set(report["settings"]),
                         {"language", "history_enabled", "remember_sites", "stateless", "onboarding_done"})
        self.assertEqual(set(report["data"]["advisories"]), {"source", "updated", "count", "company_sources"})

    def test_commit_in_the_report_matches_the_build(self):
        full = "0123456789abcdef0123456789abcdef01234567"
        svc = self.service([])
        for build, expected in (({"commit": full, "modified": False}, (full, False)),
                                ({"commit": full, "modified": True}, (full, True)),
                                ({"commit": "not a commit /Users/alice"}, (None, None))):
            with self.subTest(build=build):
                info = {"signed": False, "notarized": False, "ci": False, "commit": build.get("commit"),
                        "modified": build.get("modified")}
                with patch.object(service_mod.build_info, "load", return_value=info):
                    report = svc.diagnostics()
                self.assertEqual((report["app"]["build"]["commit"], report["app"]["build"]["modified"]), expected)
                self.assertNotIn("/Users/alice", json.dumps(report))

    def test_works_without_a_key(self):
        report = self.service([]).diagnostics()
        self.assertEqual(report["keys"]["connected"], 0)
        self.assertEqual(report["format"], "keymelier-diagnostics")
        self.assert_clean(json.dumps(report))

    def test_filters(self):
        self.assertEqual(diagnostics.code("pin_invalid"), "pin_invalid")
        for bad in ("Pin Invalid", "x" * 41, "a/b", "https://x", 5, "ok\n"):
            self.assertEqual(diagnostics.code(bad), "other", bad)
        self.assertIsNone(diagnostics.timestamp("yesterday at /Users/alice"))
        self.assertEqual(diagnostics.timestamp("2026-09-27T10:00:00+00:00"), "2026-09-27T10:00:00+00:00")
        self.assertIsNone(diagnostics.count(True))
        self.assertEqual(diagnostics.enum("secret-gui", diagnostics.GUIS), "other")
        log = diagnostics.ErrorLog({"tokens"})
        for _ in range(diagnostics.MAX_ERRORS + 5):
            log.record("tokens", "busy")
        self.assertEqual(len(log.items()), diagnostics.MAX_ERRORS)

    def test_linux_distribution_is_reduced_to_id_and_version(self):
        os_release = 'NAME="Contoso Linux"\nID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Alice\'s laptop"\nHOME_URL="https://intra"\n'
        with patch.object(diagnostics.sys, "platform", "linux"), \
                patch("builtins.open", unittest.mock.mock_open(read_data=os_release)):
            self.assertEqual(diagnostics._distribution(), "ubuntu 24.04")
        with patch.object(diagnostics.sys, "platform", "linux"), \
                patch("builtins.open", unittest.mock.mock_open(read_data='ID="my host"\nVERSION_ID=1\n')):
            self.assertEqual(diagnostics._distribution(), "other 1")


if __name__ == "__main__":
    unittest.main()
