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

    def computer(self, name, passphrase=PW):
        h = History(Path(self.tmp.name) / f'{name}.json', enabled=True)
        events = []
        s = sync.Syncer(h, lambda n, p: events.append(n), lambda: True)
        s._folder = sync.SyncFolder(self.dir, sync.new_device_id(), passphrase)
        h.track_forgotten = True
        return h, s, events

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
        status = s.run_once(full=True)
        codes = sorted(e["code"] for e in status["errors"])
        self.assertIn("sync_passphrase", codes)
        self.assertEqual(h.list(), [], "nothing from unreadable files")

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
