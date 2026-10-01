"""Failure cases: what the user sees and what is kept when things go wrong.

Each test checks observable behaviour (returned result, stored data, files
on disk). Related cases elsewhere:
- wrong PIN is sent once, never retried; transport failure ends a search
  incomplete; cancel keeps results: tests/test_probe.py
- sync file incomplete / damaged / other passphrase, own file unreadable:
  tests/test_sync.py
- PIN dialog cancelled (no unlock sent) and retried: tests/ui/ui_test.cjs
Real hardware (unplugging a key mid-operation) is in HARDWARE_TESTS.md.
"""

import contextlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fido2tool_core import service as service_mod
from fido2tool_core import sync
from fido2tool_core.history import History
from fido2tool_core.scanner import DeviceNotFound, TokenRecord


def record(serial):
    return TokenRecord('tok', '/dev/test', 'Key', serial, 'vendor', 'aaguid', [], [], {}, [], None, None, '', 'now')


class FakeScanner:
    """A key that can be plugged in and pulled out."""

    def __init__(self, rec):
        self.rec, self.present = rec, True

    def set_callbacks(self, **kw):
        pass

    def get(self, token_id):
        if not self.present:
            raise DeviceNotFound(token_id)
        return self.rec

    @contextlib.contextmanager
    def session(self, token_id, **kw):
        if not self.present:
            raise DeviceNotFound(token_id)
        yield self.rec, object()


RPS = [{"rp_id": "github.com", "rp_name": "GitHub", "rp_id_hash": "0" * 64,
        "credentials": [{"user_name": "erika", "display_name": "Erika"}]}]


class KeyRemovedWhileReadingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = patch.object(service_mod, "SETTINGS_FILE", Path(self.tmp.name) / "settings.json")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.scanner = FakeScanner(record("42"))
        self.history = History(Path(self.tmp.name) / "history.json", enabled=True)
        self.svc = service_mod.KeyService(self.scanner, None, history=self.history)
        self.svc.card_apps = lambda token_id: {"apps": {}}
        for p in (patch.object(service_mod.passkeys_mod, "capabilities", return_value={"supported": True}),
                  patch.object(service_mod.auth, "is_unlocked", return_value=True)):
            p.start()
            self.addCleanup(p.stop)

    def read(self, list_passkeys):
        with patch.object(service_mod.passkeys_mod, "list_passkeys", side_effect=list_passkeys):
            return self.svc.read_contents("tok")

    def test_pulled_out_mid_read_is_reported_and_keeps_known_data(self):
        self.read(lambda token_id, ctap2: {"rps": RPS})              # a first, complete read
        before = self.history.list()[0]["sites"]

        def pulled(token_id, ctap2):
            self.scanner.present = False
            raise OSError("device disconnected")
        got = self.read(pulled)
        self.assertTrue(got["removed"], "the UI is told the key left")
        self.assertEqual(got["failed"], ["passkeys"])
        self.assertIsNone(got["sites"], "no count is claimed for what was not read")
        self.assertEqual(self.history.list()[0]["sites"], before, "known passkeys are not deleted")

    def test_after_reconnecting_the_read_works_again(self):
        self.scanner.present = False
        self.assertTrue(self.read(lambda t, c: {"rps": RPS})["removed"])
        self.scanner.present = True
        got = self.read(lambda t, c: {"rps": RPS})
        self.assertEqual((got["sites"], got["failed"], got["removed"]), (1, [], False))
        self.assertEqual([s["rp_id"] for s in self.history.list()[0]["sites"]], ["github.com"])

    def test_a_part_failing_while_the_key_stays_is_not_a_removal(self):
        got = self.read(lambda t, c: (_ for _ in ()).throw(OSError("busy")))
        self.assertEqual((got["failed"], got["removed"]), (["passkeys"], False))


class SearchAfterCancelTests(unittest.TestCase):
    def test_a_new_search_runs_after_a_cancelled_one(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(service_mod, "SETTINGS_FILE", Path(tmp.name) / "settings.json"):
            svc = service_mod.KeyService(FakeScanner(record("7")), None, history=History(Path(tmp.name) / "h.json", enabled=True))
            seen = []

            def probe(ctap2, rp_ids, pin=None, progress=None, cancelled=None):
                seen.append(cancelled())
                return {"complete": not cancelled(), "results": []}
            with patch("fido2tool_core.passkey_probe.probe", side_effect=probe):
                svc.passkeys_probe_cancel("tok")       # user stopped the previous search
                svc.passkeys_probe("tok")
                svc.passkeys_probe("tok")
            self.assertEqual(seen, [False, False], "a stop only affects the search it was meant for")


class SyncFolderOfflineTests(unittest.TestCase):
    def test_folder_away_for_a_while_loses_nothing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        folder = tmp / "cloud"
        folder.mkdir()
        h = History(tmp / "h.json", enabled=True)
        h.set_sites(record("1"), [])
        s = sync.Syncer(h, lambda n, p: None, lambda: True)
        s._folder = sync.SyncFolder(folder, sync.new_device_id(), "correct horse battery", "machine-a")
        s.run_once()
        own = s._folder.own_path.read_bytes()
        folder.rename(tmp / "unplugged")                     # network drive gone
        h.rename(h.list()[0]["key_id"], "changed while offline")
        self.assertEqual(s.run_once()["errors"], [], "a short outage is not reported at once")
        errors = s.run_once()["errors"]
        self.assertEqual([e["code"] for e in errors], ["sync_folder"], "a lasting outage is reported")
        (tmp / "unplugged").rename(folder)                   # back
        status = s.run_once()
        self.assertEqual(status["errors"], [], "recovers by itself")
        self.assertNotEqual(s._folder.own_path.read_bytes(), own, "the offline change is written")
        other = History(tmp / "other.json", enabled=True)
        other.merge_sync(sync.unseal(s._folder.own_path.read_bytes(), "correct horse battery")[1]["history"])
        self.assertEqual(other.list()[0]["label"], "changed while offline")


class InterruptedSaveTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_leftover_temporary_file_does_not_matter(self):
        h = History(self.dir / "history.json", enabled=True)
        h.set_sites(record("1"), [{"rp_id": "a.com", "name": "", "count": 1, "users": []}])
        (self.dir / ".keymelier-abc123").write_text('{"version": 1, "keys": [')   # crash before rename
        again = History(self.dir / "history.json", enabled=True)
        self.assertEqual(len(again.list()), 1)
        self.assertIsNone(again.load_problem)

    def test_unreadable_history_is_kept_not_overwritten(self):
        path = self.dir / "history.json"
        path.write_text('{"version": 1, "keys": [{"key_id": "abc", "label": "important"')   # cut off
        broken = path.read_bytes()
        h = History(path, enabled=True)
        self.assertEqual(h.list(), [])
        kept = self.dir / h.load_problem["file"]
        self.assertEqual(h.load_problem["code"], "history_unreadable")
        self.assertEqual(kept.read_bytes(), broken, "the unreadable file is kept as it was")
        h.set_sites(record("1"), [])                          # the app keeps working …
        self.assertEqual(kept.read_bytes(), broken, "… without touching the kept file")
        self.assertTrue(path.exists())
        self.assertIsNone(History(path, enabled=True).load_problem, "next start is clean")

    def test_unreadable_settings_are_kept_and_reported(self):
        settings = self.dir / "settings.json"
        settings.write_text('{"lang": "de", "personal_mode": fal')
        with patch.object(service_mod, "SETTINGS_FILE", settings):
            svc = service_mod.KeyService(FakeScanner(record("1")), None,
                                         history=History(self.dir / "h.json", enabled=True))
            st = svc.get_settings()
            self.assertEqual([p["code"] for p in st["problems"]], ["settings_unreadable"])
            kept = self.dir / st["problems"][0]["file"]
            self.assertTrue(kept.read_text().startswith('{"lang": "de"'))
            svc.set_settings({"lang": "fr"})                  # defaults, then a new file
            self.assertEqual(json.loads(settings.read_text())["lang"], "fr")
            self.assertTrue(kept.exists(), "the old settings stay for the user")


    def locked(self, path, times=None):
        """Reading `path` fails with PermissionError (another program holds it) – always, or `times` times."""
        real, calls = Path.read_text, []
        real_bytes = Path.read_bytes

        def guard(fn):
            def read(p, *a, **kw):
                if Path(p) == path and (times is None or len(calls) < times):
                    calls.append(p)
                    raise PermissionError(13, "The process cannot access the file")
                return fn(p, *a, **kw)
            return read
        return patch.multiple(Path, read_text=guard(real), read_bytes=guard(real_bytes)), calls

    def test_locked_settings_are_neither_moved_nor_overwritten(self):
        settings = self.dir / "settings.json"
        settings.write_text('{"lang": "de", "sync_folder": "/x"}', encoding="utf-8")
        blocked, _ = self.locked(settings)
        with patch.object(service_mod, "SETTINGS_FILE", settings), blocked, patch("time.sleep"):
            svc = service_mod.KeyService(FakeScanner(record("1")), None,
                                         history=History(self.dir / "h.json", enabled=True))
            st = svc.get_settings()
            self.assertEqual([p["code"] for p in st["problems"]], ["settings_locked"])
            svc.set_settings({"lang": "fr"})               # would lose sync_folder: not written
        self.assertEqual(json.loads(settings.read_text()), {"lang": "de", "sync_folder": "/x"})
        self.assertEqual([f.name for f in self.dir.iterdir() if "unreadable" in f.name], [])

    def test_a_briefly_locked_settings_file_is_read_after_a_retry(self):
        settings = self.dir / "settings.json"
        settings.write_text('{"lang": "de"}', encoding="utf-8")
        blocked, calls = self.locked(settings, times=2)
        with patch.object(service_mod, "SETTINGS_FILE", settings), blocked, \
                patch("fido2tool_core.storage.SHARING_VIOLATIONS", True), \
                patch("time.sleep"):
            svc = service_mod.KeyService(FakeScanner(record("1")), None,
                                         history=History(self.dir / "h.json", enabled=True))
            self.assertEqual(svc.get_settings()["lang"], "de")
        self.assertEqual(len(calls), 2)

    def test_locked_history_is_neither_moved_nor_overwritten(self):
        path = self.dir / "history.json"
        h = History(path, enabled=True)
        h.update_snapshot(record("1"))
        before = path.read_bytes()
        blocked, _ = self.locked(path)
        with blocked, patch("time.sleep"):
            h2 = History(path, enabled=True)
        self.assertEqual(h2.load_problem["code"], "history_locked")
        h2.update_snapshot(record("2"))                     # the app keeps working …
        self.assertEqual(path.read_bytes(), before, "… without overwriting the locked history")
        self.assertEqual([f.name for f in self.dir.iterdir() if "unreadable" in f.name], [])

    def test_set_aside_failing_does_not_stop_the_start(self):
        settings = self.dir / "settings.json"
        settings.write_text('{"broken', encoding="utf-8")
        with patch.object(service_mod, "SETTINGS_FILE", settings), \
                patch.object(service_mod, "set_aside", side_effect=PermissionError(13, "locked")):
            svc = service_mod.KeyService(FakeScanner(record("1")), None,
                                         history=History(self.dir / "h.json", enabled=True))
            self.assertEqual([p["code"] for p in svc.get_settings()["problems"]], ["settings_locked"])
        self.assertEqual(settings.read_text(), '{"broken')


if __name__ == "__main__":
    unittest.main()


class FingerprintUnlockCancelTests(unittest.TestCase):
    """The unlock dialog asks for the finger first; "Enter PIN instead" and
    closing the dialog must stop the key waiting for a finger."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = patch.object(service_mod, "SETTINGS_FILE", Path(tmp.name) / "settings.json")
        p.start()
        self.addCleanup(p.stop)
        self.svc = service_mod.KeyService(FakeScanner(record("9")), None, history=History(Path(tmp.name) / "h.json", enabled=True))

    def test_cancel_stops_a_waiting_fingerprint_unlock(self):
        import threading
        waiting, outcome = threading.Event(), {}

        def unlock(token_id, ctap2, pin=None, use_uv=False, cancel=None):
            waiting.set()
            if cancel.wait(5):                      # what the key does on a CTAP cancel
                raise service_mod.auth.AuthError("Cancelled.", "cancelled")
            outcome["timed_out"] = True

        def run():
            try:
                self.svc.unlock("tok", method="uv")
            except service_mod.auth.AuthError as e:
                outcome["code"] = e.code
        with patch.object(service_mod.auth, "unlock", side_effect=unlock):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.assertTrue(waiting.wait(5))
            self.assertEqual(self.svc.unlock_cancel("tok"), {"cancelled": True})
            worker.join(5)
        self.assertEqual(outcome, {"code": "cancelled"})
        self.assertEqual(self.svc.unlock_cancel("tok"), {"cancelled": False}, "nothing left waiting afterwards")

    def test_pin_unlock_has_nothing_to_cancel(self):
        seen = []
        with patch.object(service_mod.auth, "unlock", side_effect=lambda *a, **kw: seen.append(kw)):
            self.svc.unlock("tok", pin="123456")
        self.assertIsNone(seen[0]["cancel"])
        self.assertEqual(self.svc.unlock_cancel("tok"), {"cancelled": False})

    def test_the_cancel_event_reaches_the_key(self):
        import threading
        from fido2.ctap2.pin import ClientPin
        info = type("Info", (), {"options": {"clientPin": True, "uv": True}})()
        ctap2 = type("Ctap2", (), {"info": info})()
        event, seen = threading.Event(), {}

        def get_uv_token(self_, permissions=None, permissions_rpid=None, event=None, on_keepalive=None):
            seen["event"] = event
            return b"token"
        with patch.object(ClientPin, "__init__", lambda self_, c: setattr(self_, "protocol", type("P", (), {"VERSION": 2})())), \
                patch.object(ClientPin, "get_uv_token", get_uv_token), \
                patch.object(service_mod.auth, "_permissions", return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
                patch.object(service_mod.auth, "uv_unlock_available", return_value=True):
            service_mod.auth.unlock("cancel-test", ctap2, use_uv=True, cancel=event)
        service_mod.auth.forget("cancel-test")
        self.assertIs(seen["event"], event)
