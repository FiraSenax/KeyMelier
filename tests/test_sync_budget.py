"""Hostile peers cannot monopolize derivation; valid peers remain reachable."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keymelier_core import sync


class SyncBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = sync.SyncFolder(self.root, 'f' * 16, 'synthetic secret')
        self.addCleanup(self.folder.close)
        self.derive = patch.object(sync, '_derive', return_value=b'k' * 32).start()
        self.addCleanup(patch.stopall)

    def peer(self, number, damaged=False):
        ident = f'{number:016x}'
        data = sync.seal({'history': {'peer': number}}, 'synthetic secret', ident, number.to_bytes(16, 'big'))
        if damaged:
            doc = json.loads(data)
            doc['ct'] = sync._b64(b'bad ciphertext')
            data = json.dumps(doc).encode()
        path = self.root / f'KeyMelier-{ident}.kmsync'
        path.write_bytes(data)
        return path

    def test_kdf_limit_and_round_robin_reach_valid_peers_after_bad_ones(self):
        for n in range(1, 11):
            self.peer(n, damaged=n < 9)
        self.derive.reset_mock()
        seen = []
        for _ in range(3):
            before = self.derive.call_count
            found, _ = self.folder.read_others()
            self.assertLessEqual(self.derive.call_count - before, sync.ROUND_KDFS)
            seen.extend(p['history']['peer'] for p in found)
            for peer in found:
                self.folder.acknowledge(peer)
        self.assertEqual(seen, [9, 10])
        self.assertEqual(len(self.folder._seen), 2)

    def test_failed_file_is_not_redecrypted_until_change_expiry_or_manual_retry(self):
        path = self.peer(1, damaged=True)
        with patch.object(sync, '_unseal', wraps=sync._unseal) as unseal:
            self.folder.read_others()
            _, errors = self.folder.read_others()
            self.assertEqual(unseal.call_count, 1)
            self.assertEqual(errors[0]['code'], 'sync_passphrase')
            self.folder.read_others(only_new=False)
            self.assertEqual(unseal.call_count, 2)
            with patch.object(sync.time, 'monotonic', return_value=10**12):
                self.folder.read_others()
            self.assertEqual(unseal.call_count, 3)
            self.peer(1)
            found, errors = self.folder.read_others()
            self.assertEqual(found[0]['history']['peer'], 1)
            self.assertEqual(errors, [])
        self.assertTrue(path.exists())

    def test_failed_merge_is_retried_and_failure_cache_is_bounded(self):
        self.peer(1)
        found, _ = self.folder.read_others()
        self.folder.reject(found[0], 'sync_damaged')
        self.assertNotIn(found[0]['file'], self.folder._seen)
        self.assertEqual(self.folder.read_others()[0], [])
        self.assertEqual(len(self.folder.read_others(only_new=False)[0]), 1)
        for n in range(sync.FAILED_FILES + 5):
            self.folder._remember_failure(str(n), (), 'sync_damaged')
        self.assertEqual(len(self.folder._failed), sync.FAILED_FILES)

    def test_file_batch_limit_and_full_sync_do_not_starve_later_files(self):
        for n in range(1, 6):
            self.peer(n)
        with patch.object(sync, 'ROUND_FILES', 2):
            seen = []
            for _ in range(3):
                peers, _ = self.folder.read_others(only_new=False)
                self.assertLessEqual(len(peers), 2)
                seen.extend(p['history']['peer'] for p in peers)
        self.assertEqual(seen[:5], [1, 2, 3, 4, 5])

    def test_byte_budget_defers_without_consuming_file(self):
        first = self.peer(1)
        self.peer(2)
        with patch.object(sync, 'ROUND_BYTES', first.stat().st_size):
            peers, _ = self.folder.read_others()
            self.assertEqual([p['history']['peer'] for p in peers], [1])
            self.folder.acknowledge(peers[0])
            peers, _ = self.folder.read_others()
            self.assertEqual([p['history']['peer'] for p in peers], [2])

    def test_setup_cannot_accept_an_unexamined_folder_after_budget_exhaustion(self):
        for n in range(1, 6):
            self.peer(n, damaged=n < 5)
        with self.assertRaises(sync.SyncError) as error:
            sync.probe_folder(self.root, 'synthetic secret', 'f' * 16)
        self.assertEqual(error.exception.code, 'sync_probe_limit')
        self.assertEqual(len(list(self.root.iterdir())), 5)
        # No auth check at all in the first batch must not enable a wrong password.
        with patch.object(sync, 'ROUND_FILES', 1):
            (self.root / 'KeyMelier-0000000000000000.kmsync').write_bytes(b'invalid')
            with self.assertRaises(sync.SyncError) as error:
                sync.probe_folder(self.root, 'synthetic secret', 'f' * 16)
            self.assertEqual(error.exception.code, 'sync_probe_limit')
