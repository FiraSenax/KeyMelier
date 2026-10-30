"""Default encryption, legacy uptake and failure paths use a synthetic keyring."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from keymelier_core.history import History


class HistoryEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'history.json'
        self.cipher = Fernet(Fernet.generate_key())
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop('KEYMELIER_ENCRYPT_HISTORY', None)
        os.environ.pop('KEYMELIER_STATELESS', None)
        self.mock = patch('keymelier_core.history.history_cipher', return_value=self.cipher)
        self.keyring = self.mock.start()
        self.addCleanup(self.mock.stop)

    def test_new_history_defaults_to_encrypted_and_reopens(self):
        history = History(self.path, enabled=True)
        history._save()
        self.assertFalse(self.path.exists())
        raw = self.path.with_suffix('.encrypted').read_bytes()
        self.assertEqual(json.loads(self.cipher.decrypt(raw))['keys'], [])
        self.assertTrue(History(self.path, enabled=True).enabled)
        self.keyring.assert_called_with(create=False)

    def test_every_published_fixture_migrates_without_changing_legacy_bytes(self):
        fixtures = Path(__file__).parent / 'fixtures/compat'
        for directory in fixtures.iterdir():
            if not directory.is_dir():
                continue
            with self.subTest(version=directory.name):
                target = Path(self.tmp.name) / directory.name / 'history.json'
                target.parent.mkdir()
                shutil.copyfile(directory / 'history.json', target)
                original = target.read_bytes()
                old = History(target, enabled=True, encrypted=False)
                baseline = old.list()
                original = target.read_bytes()  # legacy normalization is separate
                encrypted = History(target, enabled=True)
                self.assertEqual(encrypted.list(), baseline)
                self.assertEqual(target.read_bytes(), original)
                self.assertTrue(target.with_suffix('.encrypted').exists())
                encrypted._save()
                self.assertEqual(History(target, enabled=True).list(), baseline)
                self.assertEqual(target.read_bytes(), original)

    def test_existing_encrypted_history_wins_over_stale_plaintext(self):
        self.path.write_text('{"keys": [{"key_id": "stale"}]}')
        self.path.with_suffix('.encrypted').write_bytes(self.cipher.encrypt(b'{"keys": []}'))
        self.assertEqual(History(self.path, enabled=True).list(), [])
        self.keyring.assert_called_once_with(create=False)

    def test_locked_keyring_or_wrong_key_never_falls_back_or_overwrites(self):
        self.path.write_text('{"keys": []}')
        original = self.path.read_bytes()
        for error in (RuntimeError('locked'), FileNotFoundError('keyring unavailable')):
            with self.subTest(error=type(error)), patch('keymelier_core.history.history_cipher', side_effect=error):
                history = History(self.path, enabled=True)
                self.assertFalse(history.enabled)
                self.assertEqual(history.load_problem['code'], 'history_locked')
                history._save()
                self.assertEqual(self.path.read_bytes(), original)
                self.assertFalse(self.path.with_suffix('.encrypted').exists())
        encrypted = Fernet(Fernet.generate_key()).encrypt(b'{"keys": []}')
        self.path.with_suffix('.encrypted').write_bytes(encrypted)
        history = History(self.path, enabled=True)
        self.assertFalse(history.enabled)
        self.assertEqual(self.path.with_suffix('.encrypted').read_bytes(), encrypted)
        self.keyring.assert_called_with(create=False)

    def test_disabled_and_stateless_do_not_access_keyring_or_migrate(self):
        self.path.write_text('{"keys": []}')
        History(self.path, enabled=False)
        with patch.dict(os.environ, KEYMELIER_STATELESS='1'):
            History(self.path, enabled=True)
        self.keyring.assert_not_called()
        self.assertFalse(self.path.with_suffix('.encrypted').exists())

    def test_enabling_migrates_and_explicit_plaintext_opt_out_still_works(self):
        self.path.write_text('{"keys": []}')
        history = History(self.path)
        history.set_enabled(True)
        self.assertTrue(self.path.with_suffix('.encrypted').exists())
        self.keyring.reset_mock()
        with patch.dict(os.environ, KEYMELIER_ENCRYPT_HISTORY='0'):
            legacy = History(self.path, enabled=True)
            legacy._save()
        self.keyring.assert_not_called()
        self.assertEqual(json.loads(self.path.read_text())['keys'], [])

    def test_invalid_legacy_data_is_kept_and_not_imported(self):
        self.path.write_bytes(b'{broken')
        history = History(self.path, enabled=True)
        self.assertFalse(history.enabled)
        self.assertEqual(self.path.read_bytes(), b'{broken')
        self.assertFalse(self.path.with_suffix('.encrypted').exists())

    def test_privacy_cleanup_preserves_locked_file_without_recursing(self):
        encrypted = Fernet(Fernet.generate_key()).encrypt(b'{"keys": []}')
        self.path.with_suffix('.encrypted').write_bytes(encrypted)
        history = History(self.path, enabled=False)
        history.clear_sites()
        history.clear_sites()
        self.assertTrue(history._read_blocked)
        self.assertEqual(history.load_problem['code'], 'history_locked')
        self.assertEqual(self.path.with_suffix('.encrypted').read_bytes(), encrypted)
        self.keyring.assert_called_once()

    def test_retry_after_unlock_can_save_and_clears_problem(self):
        with patch('keymelier_core.history.history_cipher', side_effect=RuntimeError('locked')):
            history = History(self.path, enabled=True)
        self.assertTrue(history._read_blocked)
        history.set_enabled(True)
        self.assertTrue(history.enabled)
        self.assertFalse(history._read_blocked)
        self.assertIsNone(history.load_problem)
        self.assertTrue(self.path.with_suffix('.encrypted').exists())
