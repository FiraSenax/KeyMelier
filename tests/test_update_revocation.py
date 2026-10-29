import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keymelier_core import app_update, update_revocation as revocation


class UpdateRevocationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bundled = self.root / 'bundled.json'
        self.cache = self.root / 'cache.json'
        self.bundled.write_bytes(self.document([]))
        self.key = revocation.fingerprint()
        for p in (patch.object(revocation, 'BUNDLED', self.bundled),
                  patch.object(revocation, 'CACHE', self.cache),
                  patch.object(revocation, '_seen', set()),
                  patch.object(revocation, 'stateless', return_value=False)):
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def document(keys):
        return json.dumps({'version': 1, 'revoked': keys}).encode()

    def response(self, keys):
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.headers = {}
        resp.iter_content.return_value = [self.document(keys)]
        return resp

    def test_observed_revocation_survives_restart_removal_and_offline(self):
        with patch('requests.get', return_value=self.response([self.key])), self.assertRaises(revocation.RevokedKeyError):
            revocation.ensure_allowed(refresh=True)
        self.assertIn(self.key, revocation.parse(self.cache.read_bytes()))
        for response in (self.response([]), OSError('offline')):
            with patch.object(revocation, '_seen', set()), patch('requests.get', side_effect=[response]) as get:
                with self.assertRaises(revocation.RevokedKeyError):
                    revocation.ensure_allowed(refresh=True)
                get.assert_not_called()

    def test_bundled_revocation_is_sticky_too(self):
        self.bundled.write_bytes(self.document([self.key]))
        with self.assertRaises(revocation.RevokedKeyError):
            revocation.ensure_allowed()
        self.bundled.write_bytes(self.document([]))
        with patch.object(revocation, '_seen', set()), self.assertRaises(revocation.RevokedKeyError):
            revocation.ensure_allowed()

    def test_stale_aggregate_cache_from_another_process_cannot_remove_current_key_stop(self):
        self.bundled.write_bytes(self.document([self.key]))
        with self.assertRaises(revocation.RevokedKeyError):
            revocation.ensure_allowed()
        self.bundled.write_bytes(self.document([]))
        self.cache.write_bytes(self.document([]))
        with patch.object(revocation, '_seen', set()), self.assertRaises(revocation.RevokedKeyError):
            revocation.ensure_allowed()

    def test_remote_failure_does_not_revoke_an_unlisted_key(self):
        with patch('requests.get', side_effect=OSError('offline')):
            revocation.ensure_allowed(refresh=True)
        self.assertFalse(self.cache.exists())
        with patch('requests.get', return_value=self.response(['a' * 64])):
            revocation.ensure_allowed(refresh=True)
        self.assertNotIn(self.key, revocation.parse(self.cache.read_bytes()))

    def test_invalid_remote_list_cannot_grant_trust_or_erase_known_revocations(self):
        self.cache.write_bytes(self.document(['a' * 64]))
        with patch('requests.get', return_value=self.response(['not a fingerprint'])):
            revocation.ensure_allowed(refresh=True)
        self.assertEqual(revocation.parse(self.cache.read_bytes()), {'a' * 64})
        for data in (b'{}', self.document(['../key.pem']), self.document([{}]),
                     b'{"version":true,"revoked":[]}', b' ' * (revocation.MAX_BYTES + 1)):
            with self.subTest(data_length=len(data)), self.assertRaises(ValueError):
                revocation.parse(data)

    def test_invalid_local_cache_fails_closed(self):
        self.cache.write_bytes(b'invalid')
        with self.assertRaises(ValueError):
            revocation.ensure_allowed()
        with self.assertRaises(app_update.UpdateError):
            app_update.open_download(self.root / 'installer.exe')

    def test_revocation_blocks_check_download_and_open_before_network_or_execution(self):
        from test_app_update import ASSET
        self.cache.write_bytes(self.document([self.key]))
        with patch('requests.get') as get, patch('subprocess.Popen') as execute:
            result = app_update.check()
            self.assertTrue(result['revoked'])
            self.assertTrue(result['failed'])
            self.assertNotIn('asset', result)
            with self.assertRaisesRegex(app_update.UpdateError, '^revoked$'):
                app_update.download(ASSET)
            with self.assertRaisesRegex(app_update.UpdateError, '^revoked$'):
                app_update.open_download(self.root / 'installer.exe')
            get.assert_not_called()
            execute.assert_not_called()

    def test_revocation_arriving_at_open_time_blocks_installer(self):
        with patch('requests.get', return_value=self.response([self.key])), patch('subprocess.Popen') as execute:
            with self.assertRaisesRegex(app_update.UpdateError, '^revoked$'):
                app_update.open_download(self.root / 'installer.exe')
            execute.assert_not_called()

    def test_stateless_mode_remembers_only_within_process(self):
        with patch.object(revocation, 'stateless', return_value=True), \
             patch('requests.get', return_value=self.response([self.key])):
            with self.assertRaises(revocation.RevokedKeyError):
                revocation.ensure_allowed(refresh=True)
            with self.assertRaises(revocation.RevokedKeyError):
                revocation.ensure_allowed()
        self.assertFalse(self.cache.exists())


if __name__ == '__main__':
    unittest.main()
