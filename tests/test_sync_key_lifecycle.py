"""Sync wire compatibility, scoped key caching and explicit lifetime limits."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fido2tool_core import sync


# Produced by the pre-fix implementation with public synthetic inputs.
LEGACY_V1 = (b'{"format": "keymelier-sync", "v": 1, "device": "aaaaaaaaaaaaaaaa", '
             b'"salt": "AAECAwQFBgcICQoLDA0ODw==", "nonce": "AAECAwQFBgcICQoL", '
             b'"ct": "P1//omXNatW+ZT2m/xj6yYeE0+HLzJDLxmRnOoHLibock8VIXvb2GPCs5MlyRtq1"}')


class SyncKeyLifecycleTests(unittest.TestCase):
    def test_wire_format_and_key_derivation_remain_compatible_with_existing_files(self):
        payload = {'history': {'synthetic': True}}
        self.assertEqual(sync.unseal(LEGACY_V1, 'compatibility test only'), ('a' * 16, payload))
        with patch.object(sync.os, 'urandom', return_value=bytes(range(12))):
            self.assertEqual(sync.seal(payload, 'compatibility test only', 'a' * 16, bytes(range(16))), LEGACY_V1)

    def test_same_salt_is_cached_only_within_its_passphrase_session(self):
        first, second = sync._SessionKeys('synthetic alpha'), sync._SessionKeys('synthetic beta')
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        salt = bytes(range(16))
        with patch.object(sync, '_derive', wraps=sync._derive) as derive, \
             patch.object(sync.hashlib, 'sha256', side_effect=AssertionError('no fast passphrase hash')):
            alpha = first.derive(salt)
            self.assertEqual(first.derive(salt), alpha)
            self.assertNotEqual(second.derive(salt), alpha)
        self.assertEqual(derive.call_count, 2)
        self.assertEqual(list(first._keys), [salt])

    def test_cache_is_bounded_and_evicted_keys_are_derived_again(self):
        keys = sync._SessionKeys('synthetic only')
        self.addCleanup(keys.close)
        with patch.object(sync, '_derive', return_value=b'k' * 32) as derive:
            for n in range(33):
                keys.derive(n.to_bytes(16, 'big'))
            self.assertEqual(len(keys._keys), 32)
            self.assertNotIn(bytes(16), keys._keys)
            keys.derive(bytes(16))
            self.assertEqual(derive.call_count, 34)
            self.assertEqual(len(keys._keys), 32)

    def test_concurrent_requests_for_one_salt_do_not_repeat_scrypt(self):
        keys = sync._SessionKeys('synthetic only')
        self.addCleanup(keys.close)
        entered, release = threading.Event(), threading.Event()
        outcomes = []

        def derive(*args):
            entered.set()
            if not release.wait(3):
                raise AssertionError('test did not release derivation')
            return b'k' * 32

        def run():
            try:
                outcomes.append(keys.derive(bytes(16)))
            except Exception as error:
                outcomes.append(error)

        with patch.object(sync, '_derive', side_effect=derive) as mocked:
            workers = [threading.Thread(target=run, daemon=True) for _ in range(2)]
            for worker in workers:
                worker.start()
            try:
                self.assertTrue(entered.wait(3))
            finally:
                release.set()
                for worker in workers:
                    worker.join(3)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(outcomes, [b'k' * 32, b'k' * 32])
            mocked.assert_called_once()

    def test_reconfiguration_and_disable_release_previous_session_secrets(self):
        syncer = sync.Syncer(Mock(), Mock(), lambda: False)
        with patch.object(syncer, 'start'), patch.object(sync, '_derive', return_value=b'k' * 32):
            syncer.configure(Path('/synthetic'), 'a' * 16, 'synthetic alpha')
            first = syncer._folder._keys
            first.derive(bytes(16))
            syncer.configure(Path('/synthetic'), 'a' * 16, 'synthetic beta')
            second = syncer._folder._keys
            self.assertIsNot(first, second)
            second.derive(bytes(16))
            syncer.configure(None, None, None)
        for retired in (first, second):
            self.assertIsNone(retired._passphrase)
            self.assertEqual(retired._keys, {})
            with self.assertRaises(sync.SyncError) as caught:
                retired.derive(bytes(16))
            self.assertEqual(caught.exception.code, 'sync_disabled')
        self.assertFalse(syncer.active)

    def test_probe_releases_keys_even_if_reading_fails(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(sync, 'SyncFolder') as constructor:
            probe = constructor.return_value
            probe.read_others.side_effect = sync.SyncError('synthetic failure', 'sync_damaged')
            with self.assertRaises(sync.SyncError):
                sync.probe_folder(Path(folder), 'synthetic only', 'a' * 16)
            probe.close.assert_called_once()
