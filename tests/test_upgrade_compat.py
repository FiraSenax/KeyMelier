"""Upgrade from published releases: their stored data must keep its meaning.

The fixtures in tests/fixtures/compat/<tag>/ were written by the code of that
release (tools/make_compat_fixtures.py): history.json and settings.json with
named keys, passkeys (listed and searched), authenticator accounts, a lost
key with a ticked service, a running key replacement and a sync id.

This covers data compatibility only; installing the new version over the old
one is a separate, manual check (TESTING.md).
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fido2tool_core import service as service_mod
from fido2tool_core.history import History

FIXTURES = Path(__file__).parent / "fixtures" / "compat"
TAGS = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())


class Scanner:
    def set_callbacks(self, **kw):
        pass


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class UpgradeCompatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("KEYMELIER_STATELESS", None)

    def copy(self, tag):
        d = Path(self.tmp.name) / tag
        shutil.copytree(FIXTURES / tag, d)
        meta = json.loads((d / "keys.json").read_text())
        self.features = meta["features"]
        return d, meta["keys"]

    def service(self, d, history=None):
        with patch.object(service_mod, "SETTINGS_FILE", d / "settings.json"), \
                patch.object(service_mod, "secret_get", return_value=None):
            svc = service_mod.KeyService(Scanner(), None, history=history or History(d / "history.json", enabled=True))
        return svc

    def test_fixtures_exist_for_published_releases(self):
        self.assertGreaterEqual(len(TAGS), 5, TAGS)
        self.assertIn("v1.4.0", TAGS, "last release before the account model")

    def test_history_keeps_its_meaning(self):
        for tag in TAGS:
            with self.subTest(tag):
                d, k = self.copy(tag)
                h = History(d / "history.json", enabled=True)
                a, b, c = h.get(k["A"]), h.get(k["B"]), h.get(k["C"])
                self.assertEqual((a["label"], b["label"], c["label"]), ("Everyday key", "Backup key", "Old office key"))
                # lost key and the service already handled
                self.assertTrue(c.get("lost_since"))
                self.assertEqual(c.get("lost_done"), ["aws.amazon.com"])
                # running replacement with its progress (1.5+)
                if self.features["replace"]:
                    self.assertEqual(a["replace"]["new"], k["B"])
                    self.assertEqual(a["replace"]["done"], ["pk:github.com|erika"])
                # what is on the keys
                self.assertEqual({s["rp_id"]: s["count"] for s in a["sites"]}, {"github.com": 1, "login.microsoft.com": 2})
                self.assertEqual([u["name"] for s in a["sites"] for u in s["users"] if s["rp_id"] == "login.microsoft.com"],
                                 ["a@contoso.example", "b@contoso.example"])
                self.assertEqual([s["rp_id"] for s in b["sites"]], ["github.com"])
                if self.features["probe"]:
                    self.assertIn("sites_probed", b, "searched key stays marked as searched")
                self.assertEqual(len(a["inventory"]["oath"]["items"]), 2)
                self.assertIn("pin_changed", [e["type"] for e in a["events"]])
                # verdicts are never trusted from disk
                self.assertTrue(all(e["snapshot"]["security_status"] == "UNKNOWN" for e in h.list()))

    def test_settings_and_sync_id_survive(self):
        for tag in TAGS:
            with self.subTest(tag):
                d, _k = self.copy(tag)
                svc = self.service(d)
                with patch.object(service_mod, "SETTINGS_FILE", d / "settings.json"):
                    st = svc.get_settings()
                    self.assertEqual((st["lang"], st["personal_mode"], st["remember_sites"], st["history_enabled"]),
                                     ("de", True, True, True))
                    # 1.8+: whoever finished the introduction does not get it again after an update
                    self.assertEqual(st.get("onboarding_done", False), self.features.get("onboarding", False))
                    if self.features["sync"]:
                        self.assertEqual(st["sync_device"], "0123456789abcdef")
                        status = svc.sync_status()
                        # passphrase not in the (test) keychain: sync stays off and says why – nothing crashes
                        self.assertFalse(status["active"])
                        self.assertEqual(status["problem"], "sync_keychain")
                        self.assertTrue(status["configured"])

    def test_loading_and_saving_is_stable(self):
        """Old data loaded, saved by the new version and loaded again means the same."""
        for tag in TAGS:
            with self.subTest(tag):
                d, k = self.copy(tag)
                first = History(d / "history.json", enabled=True)
                before = {e["key_id"]: {f: e.get(f) for f in ("label", "lost_since", "lost_done", "replace", "sites", "inventory")}
                          for e in first.list()}
                first.rename(k["A"], "Everyday key")          # forces a save in the new format
                for _ in range(2):                              # repeated loads change nothing
                    again = History(d / "history.json", enabled=True)
                    after = {e["key_id"]: {f: e.get(f) for f in ("label", "lost_since", "lost_done", "replace", "sites", "inventory")}
                             for e in again.list()}
                    self.assertEqual(after, before)

    def test_saving_twice_writes_identical_files(self):
        """Once converted by a save, further load/save cycles change nothing at all."""
        for tag in TAGS:
            with self.subTest(tag):
                d, _k = self.copy(tag)
                path = d / "history.json"
                History(path, enabled=True)._save()
                first = path.read_bytes()
                for _ in range(3):
                    History(path, enabled=True)._save()
                self.assertEqual(path.read_bytes(), first)

    def test_stateless_mode_does_not_touch_old_data(self):
        for tag in TAGS:
            with self.subTest(tag):
                d, k = self.copy(tag)
                digest = sha(d / "history.json")
                with patch.dict(os.environ, {"KEYMELIER_STATELESS": "1"}):
                    h = History(d / "history.json", enabled=True)
                    self.assertFalse(h.enabled)
                    self.assertEqual(h.list(), [], "nothing is read in stateless mode")
                    h.rename(k["A"], "x")
                self.assertEqual(sha(d / "history.json"), digest)

    def test_history_switched_off_keeps_the_file(self):
        for tag in TAGS:
            with self.subTest(tag):
                d, _k = self.copy(tag)
                settings = json.loads((d / "settings.json").read_text())
                settings["history_enabled"] = False
                (d / "settings.json").write_text(json.dumps(settings))
                digest = sha(d / "history.json")
                with patch.object(service_mod, "SETTINGS_FILE", d / "settings.json"):
                    svc = service_mod.KeyService(Scanner(), None, history=History(d / "history.json", enabled=False))
                    self.assertFalse(svc.history.enabled)
                self.assertEqual(sha(d / "history.json"), digest, "switched-off history is left as it is")

    def test_account_model_reads_old_data(self):
        """The UI's account model on each release's data (Node; skipped without it)."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        for tag in TAGS:
            with self.subTest(tag):
                d, k = self.copy(tag)
                h = History(d / "history.json", enabled=True)
                entries = json.dumps(h.list())
                script = f"""
const {{ buildAccountModel, cellState, buildReplacePlan, replacePlanItems }} = require({json.dumps(str(Path(__file__).parent.parent / 'static' / 'accounts.js'))});
const m = buildAccountModel({entries});
const row = m.rows.find(r => r.account === 'erika' && r.kind === 'passkey');
const plan = buildReplacePlan(m, {json.dumps(k['A'])}, {json.dumps(k['B'])});
const lost = m.rows.find(r => r.rpId === 'aws.amazon.com');
console.log(JSON.stringify({{ erika: row.status, bCoverage: m.keyInfo.get({json.dumps(k['B'])}).coverage,
  notAsked: cellState(m, m.rows.find(r => r.account === 'a@contoso.example'), {json.dumps(k['B'])}).unknown,
  plan: replacePlanItems(plan).length, lost: lost.status }}));
"""
                out = json.loads(subprocess.run([node, "-e", script], capture_output=True, text=True, check=True).stdout)
                self.assertEqual(out["erika"], "passkey_multi", "passkey on both keys")
                if self.features["probe"]:
                    self.assertEqual(out["bCoverage"], "probe")
                    self.assertTrue(out["notAsked"], "not searched there = unknown, never 'not there'")
                else:
                    self.assertEqual(out["bCoverage"], "full")
                self.assertGreater(out["plan"], 0)
                self.assertEqual(out["lost"], "unclear_lost", "display name only + lost key: never a backup")


if __name__ == "__main__":
    unittest.main()
