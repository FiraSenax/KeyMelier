import json
import os
import tempfile
import unittest
from pathlib import Path

from fido2tool_core import sync
from fido2tool_core.history import History
from fido2tool_core.scanner import TokenRecord

PW = "correct horse battery"


def record(serial):
    return TokenRecord('id' + serial, '/dev/test', 'Key', serial, 'vendor', 'aaguid', [], [], {}, [], None, None, '', 'now')


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self):
        data = sync.seal({"x": 1}, PW, "a" * 16)
        self.assertEqual(sync.unseal(data, PW), ("a" * 16, {"x": 1}))
        self.assertNotIn(b'"x"', data, "payload is encrypted")

    def test_wrong_passphrase_and_tampering_are_rejected(self):
        data = sync.seal({"x": 1}, PW, "a" * 16)
        with self.assertRaises(sync.SyncError) as e:
            sync.unseal(data, "another passphrase")
        self.assertEqual(e.exception.code, "sync_passphrase")
        header = json.loads(data)
        header["device"] = "b" * 16            # header is bound to the ciphertext
        with self.assertRaises(sync.SyncError):
            sync.unseal(json.dumps(header).encode(), PW)
        for junk in (b"", b"not json", b'{"format": "other"}', json.dumps({**json.loads(data), "ct": "!!"}).encode()):
            with self.assertRaises(sync.SyncError):
                sync.unseal(junk, PW)


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = History(Path(self.tmp.name) / 'a.json', enabled=True)
        self.b = History(Path(self.tmp.name) / 'b.json', enabled=True)
        self.a.track_forgotten = self.b.track_forgotten = True
        self.kid = self.a.set_sites(record('1'), [{'rp_id': 'x.com', 'name': 'X', 'count': 1, 'users': [{'name': 'erika'}]}])['key_id']

    def sync_ab(self):
        self.b.merge_sync(self.a.sync_state())
        self.a.merge_sync(self.b.sync_state())

    def test_new_key_arrives_without_verdicts(self):
        self.a.update_snapshot(record('1'))
        self.a._entries[self.kid]["snapshot"]["security_status"] = "OK"
        self.assertTrue(self.b.merge_sync(self.a.sync_state()))
        entry = self.b.get(self.kid)
        self.assertEqual(entry["snapshot"]["security_status"], "UNKNOWN")
        self.assertTrue(entry["snapshot"]["imported"])
        self.assertEqual(entry["sites"][0]["source"], "sync")
        self.assertFalse(self.b.merge_sync(self.a.sync_state()), "merging twice changes nothing")

    def test_newest_label_and_lost_decision_win(self):
        self.sync_ab()
        self.a.rename(self.kid, "Office")
        self.b.rename(self.kid, "Desk")          # later
        self.sync_ab()
        self.assertEqual(self.a.get(self.kid)["label"], "Desk")
        self.a.set_lost(self.kid, True)
        self.sync_ab()
        self.assertTrue(self.b.get(self.kid).get("lost_since"))
        self.b.set_lost(self.kid, False)          # found again on the other computer
        self.sync_ab()
        self.assertNotIn("lost_since", self.a.get(self.kid), "un-marking travels too")

    def test_forgotten_key_is_removed_elsewhere_unless_seen_again(self):
        self.sync_ab()
        self.a.forget(self.kid)
        self.sync_ab()
        self.assertIsNone(self.b.get(self.kid))
        # plugged in again later on B: it comes back everywhere
        self.b.update_snapshot(record('1'))
        self.sync_ab()
        self.assertIsNotNone(self.a.get(self.kid))

    def test_contents_are_not_taken_when_remembering_is_off(self):
        self.b.merge_sync(self.a.sync_state(), keep_contents=False)
        self.assertNotIn("sites", self.b.get(self.kid))

    def test_removal_marks_only_while_syncing(self):
        h = History(Path(self.tmp.name) / 'c.json', enabled=True)
        kid = h.update_snapshot(record('9'))['key_id']
        h.forget(kid)
        self.assertNotIn(kid, (Path(self.tmp.name) / 'c.json').read_text())
        self.a.forget(self.kid)
        self.a.stop_tracking_forgotten()
        self.assertNotIn(self.kid, (Path(self.tmp.name) / 'a.json').read_text())


class FolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "cloud"
        self.dir.mkdir()

    def computer(self, name, passphrase=PW, device=None, machine=None):
        """One simulated computer: its own history file and machine id."""
        h = History(Path(self.tmp.name) / f'{name}.json', enabled=True)
        events = []
        s = sync.Syncer(h, lambda n, p: events.append(n), lambda: True)
        s.new_ids = []
        s._on_new_device = s.new_ids.append
        s._folder = sync.SyncFolder(self.dir, device or sync.new_device_id(), passphrase, machine or f"machine-{name}")
        h.track_forgotten = True
        return h, s, events

    def restart(self, name, h, device, machine=None, passphrase=PW):
        """Same computer, KeyMelier started again (history file kept)."""
        h2 = History(Path(self.tmp.name) / f'{name}.json', enabled=True)
        s = sync.Syncer(h2, lambda n, p: None, lambda: True)
        s.new_ids = []
        s._on_new_device = s.new_ids.append
        s._folder = sync.SyncFolder(self.dir, device, passphrase, machine or f"machine-{name}")
        h2.track_forgotten = True
        return h2, s

    def labels(self, h):
        return sorted(e["key_id"] for e in h.list())

    def test_four_computers_converge(self):
        pcs = [self.computer(n) for n in "abcd"]
        for i, (h, _s, _e) in enumerate(pcs):
            h.set_sites(record(str(i)), [{'rp_id': f'site{i}.com', 'name': '', 'count': 1, 'users': [{'name': 'me'}]}])
        for _ in range(2):
            for _h, s, _e in pcs:
                s.run_once()
        for h, s, events in pcs:
            self.assertEqual(len(h.list()), 4)
            self.assertEqual(len(s.status()["devices"]), 3)
        self.assertIn("history_synced", pcs[0][2])
        self.assertEqual(len(list(self.dir.glob("KeyMelier-*.kmsync"))), 4)

    def test_foreign_and_broken_files(self):
        h, s, _ = self.computer("a")
        other_h, other_s, _ = self.computer("b", passphrase="a different passphrase")
        other_h.update_snapshot(record('1'))
        other_s.run_once()
        (self.dir / "notes.txt").write_text("hello")
        victim = next(self.dir.glob("KeyMelier-*.kmsync"))
        (self.dir / "KeyMelier-0123456789abcdef.kmsync").write_bytes(victim.read_bytes())   # renamed copy
        if hasattr(os, "symlink"):
            os.symlink("/etc/hosts", self.dir / "KeyMelier-fedcba9876543210.kmsync")
        self.assertEqual(s.run_once(full=True)["errors"], [], "first sight: may still be arriving")
        status = s.run_once(full=True)
        codes = sorted(e["code"] for e in status["errors"])
        self.assertIn("sync_passphrase", codes)
        self.assertEqual(h.list(), [], "nothing from unreadable files")

    def test_file_still_arriving_is_retried_not_reported(self):
        h, s, _ = self.computer("a")
        other_h, other_s, _ = self.computer("b")
        other_h.update_snapshot(record('1'))
        other_s.run_once()
        path = next(self.dir.glob("KeyMelier-*.kmsync"))
        full = path.read_bytes()
        path.write_bytes(full[: len(full) // 2])          # cloud client still downloading
        self.assertEqual(s.run_once()["errors"], [])
        self.assertEqual(h.list(), [])
        path.write_bytes(full)                            # download finished
        self.assertEqual(s.run_once()["errors"], [])
        self.assertEqual(len(h.list()), 1)

    def test_both_writing_at_the_same_time(self):
        pcs = [self.computer(n) for n in "ab"]
        for i, (h, s, _e) in enumerate(pcs):
            h.set_sites(record(str(i)), [])
        for _ in range(3):   # interleaved rounds; every change of either side arrives
            for i, (h, s, _e) in enumerate(pcs):
                h.rename(h.list()[0]["key_id"], f"from {i}")
                s.run_once()
        for h, s, _e in pcs:
            s.run_once()
        a, b = (sorted((e["key_id"], e["label"]) for e in h.list()) for h, _s, _e in pcs)
        self.assertEqual(a, b, "both computers end with the same state")
        self.assertEqual(len(list(self.dir.glob("*.tmp"))), 0, "no temporary files left")

    # ── Same device id / own file (review 1.6.0) ──────────────────────────

    def test_shared_id_while_first_computer_stays_offline(self):
        """Repro: A syncs, B takes A's id and syncs while A is offline, C must get both."""
        a_h, a_s, _ = self.computer("a")
        a_h.set_sites(record('1'), [])
        a_s.run_once()                                       # A: entry 1, then offline for good
        b_h, b_s, _ = self.computer("b", device=a_s._folder.device)
        b_h.set_sites(record('2'), [])
        b_s.run_once()
        c_h, c_s, _ = self.computer("c")
        c_s.run_once()
        self.assertEqual(len(c_h.list()), 2, "C gets A's and B's entry")
        self.assertEqual(len(b_s.new_ids), 1, "B noticed the shared id and took a new one")
        self.assertEqual(b_s.status()["notice"]["code"], "sync_shared_id")
        self.assertEqual(len(b_h.list()), 2, "B kept A's data too")

    def test_normal_restart_keeps_the_device_id(self):
        h, s, _ = self.computer("a")
        h.set_sites(record('1'), [])
        s.run_once()
        device = s._folder.device
        for _ in range(3):
            h2, s2 = self.restart("a", h, device)
            s2.run_once()
            self.assertEqual(s2.new_ids, [])
            self.assertEqual(s2._folder.device, device)
            self.assertIsNone(s2.status()["notice"])
            self.assertEqual(len(h2.list()), 1)

    def test_restart_with_lost_local_history_recovers_from_own_file(self):
        h, s, _ = self.computer("a")
        h.set_sites(record('1'), [])
        s.run_once()
        (Path(self.tmp.name) / 'a.json').unlink()           # local history gone
        h2, s2 = self.restart("a", h, s._folder.device)
        s2.run_once()
        self.assertEqual(len(h2.list()), 1, "own file is merged before it is rewritten")

    def test_two_instances_start_at_once_with_the_same_id(self):
        device = sync.new_device_id()
        a_h, a_s, _ = self.computer("a", device=device)
        b_h, b_s, _ = self.computer("b", device=device)
        a_h.set_sites(record('1'), [])
        b_h.set_sites(record('2'), [])
        # both write before either has seen the other (the race)
        a_s._folder.write(a_h.sync_state())
        b_s._folder.write(b_h.sync_state())
        for _ in range(3):
            a_s.run_once()
            b_s.run_once()
        self.assertEqual(self.labels(a_h), self.labels(b_h))
        self.assertEqual(len(a_h.list()), 2)
        self.assertNotEqual(a_s._folder.device, b_s._folder.device)
        c_h, c_s, _ = self.computer("c")
        c_s.run_once()
        self.assertEqual(len(c_h.list()), 2)

    def test_unreadable_own_file_is_never_overwritten(self):
        for case in ("incomplete", "damaged", "other passphrase"):
            with self.subTest(case):
                for f in self.dir.iterdir():
                    f.unlink()
                device = sync.new_device_id()
                a_h, a_s, _ = self.computer(f"a-{case}", device=device)
                a_h.set_sites(record('1'), [])
                a_s.run_once()
                own = self.dir / f"KeyMelier-{device}.kmsync"
                good = own.read_bytes()
                if case == "incomplete":
                    bad = good[: len(good) // 2]
                elif case == "damaged":
                    bad = b"garbage"
                else:
                    bad = sync.seal({"history": {}}, "some other passphrase", device)
                own.write_bytes(bad)
                h2, s2 = self.restart(f"a-{case}", a_h, device)
                h2.set_sites(record('2'), [])
                s2.run_once()
                self.assertEqual(own.read_bytes(), bad, "left untouched for inspection")
                self.assertEqual(len(s2.new_ids), 1)
                self.assertEqual(s2.status()["notice"], {"code": "sync_own_unreadable", "file": own.name})
                self.assertEqual(len(h2.list()), 2, "local data kept")
                if case == "incomplete":                    # the cloud finishes the download later
                    own.write_bytes(good)
                    s2.run_once()
                    self.assertEqual(len(h2.list()), 2)
                else:                                       # stays reported as another computer's file
                    s2.run_once()
                    self.assertTrue(any(e["file"] == own.name for e in s2.status()["errors"]))

    def test_restart_after_conflict_keeps_the_new_id(self):
        a_h, a_s, _ = self.computer("a")
        a_h.set_sites(record('1'), [])
        a_s.run_once()
        b_h, b_s, _ = self.computer("b", device=a_s._folder.device)
        b_s.run_once()
        new = b_s.new_ids[-1]                                # what the service stores in its settings
        for _ in range(2):
            h2, s2 = self.restart("b", b_h, new)
            s2.run_once()
            self.assertEqual(s2.new_ids, [], "no new id on every start")
            self.assertEqual(s2._folder.device, new)

    def test_same_device_id_on_two_computers(self):
        a_h, a_s, _ = self.computer("a")
        b_h, b_s, _ = self.computer("b")
        b_s._folder.change_device(a_s._folder.device)     # e.g. settings copied to a new Mac
        a_h.update_snapshot(record('1'))
        b_h.update_snapshot(record('2'))
        b_s.run_once()
        a_s.run_once()                                    # finds B's file under its own id
        b_s.run_once()
        self.assertEqual(len(a_s.new_ids) + len(b_s.new_ids), 1, "exactly one computer moves")
        self.assertNotEqual(b_s._folder.device, a_s._folder.device)
        for _ in range(2):
            a_s.run_once()
            b_s.run_once()
        self.assertEqual(len(a_h.list()), 2)
        self.assertEqual(len(b_h.list()), 2)

    def test_probe_folder(self):
        with self.assertRaises(sync.SyncError) as e:
            sync.probe_folder(self.dir, "short", "a" * 16)
        self.assertEqual(e.exception.code, "sync_passphrase_short")
        _h, s, _ = self.computer("b")
        _h.update_snapshot(record('1'))
        s.run_once()
        with self.assertRaises(sync.SyncError) as e:
            sync.probe_folder(self.dir, "wrong passphrase!", "a" * 16)
        self.assertEqual(e.exception.code, "sync_passphrase")
        self.assertEqual(sync.probe_folder(self.dir, PW, "a" * 16), {"others": 1})
        with self.assertRaises(sync.SyncError):
            sync.probe_folder(self.dir / "missing", PW, "a" * 16)


if __name__ == "__main__":
    unittest.main()
