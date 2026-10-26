"""Trust expiry, secret-safe errors and persistence boundaries; no real devices."""
import csv
import dataclasses
import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2.ctap2.pin import ClientPin
from keymelier_core import app_update, attestation, auth, cards, revocation, storage, yubikey_apps
from keymelier_core import exporter, service, sync
from keymelier_core.bridge import ALLOWED, dispatch
from keymelier_core.history import History
from keymelier_core.mds3 import MDS3Client
from keymelier_core.pin import PinError
from keymelier_core.scanner import TokenRecord, TokenScanner

SECRET = "pin=271828 /Users/private/account@example.test"


def record():
    return TokenRecord("key-1", "fake-hid", "YubiKey", "1234", "Yubico",
                       "00000000-0000-0000-0000-000000000001", [], [], {}, [],
                       None, None, "", "now", vendor_id=0x1050)


class AuditRegressions(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.addCleanup(patch.stopall)
        patch.object(service, "SETTINGS_FILE", self.root / "settings.json").start()
        self.scanner = TokenScanner()
        self.key = record()
        self.scanner._known[self.key.path] = self.key
        self.history = History(self.root / "history.json", enabled=True)
        self.service = service.KeyService(self.scanner, Mock(), history=self.history)

    def test_stateless_public_and_low_level_writes_are_blocked(self):
        import app
        api = app.Api(self.service)
        api._window = Mock()
        existing = self.root / "existing"
        existing.write_text("keep")
        patch.object(app, "LOCK_FILE", self.root / "lock" ).start()
        patch.object(app, "ROOT_DIR", self.root).start()
        patch.object(revocation, "CRL_DIR", self.root / "crls").start()
        url = "https://crl.globalsign.com/test.crl"
        revocation.CRL_DIR.mkdir()
        crl = revocation._disk_path(url)
        crl.write_bytes(b"keep")
        with patch.dict(os.environ, KEYMELIER_STATELESS="1"), \
             patch.object(storage, "_native_keyring") as keyring, \
             patch.object(service, "secret_delete") as delete_secret, \
             patch.object(app.subprocess, "run") as subprocess_run:
            blocked = [lambda: storage.atomic_write(self.root / "new" / "data", "secret"),
                       lambda: storage.set_aside(existing),
                       lambda: storage.replace_file(existing, self.root / "renamed"),
                       lambda: storage.secret_set("secret", "value"),
                       lambda: storage.secret_delete("secret"),
                       lambda: storage.history_cipher(),
                       lambda: sync.probe_folder(self.root, "a long enough passphrase", "a" * 16),
                       lambda: exporter.CSVExporter().export(self.key)]
            for action in blocked:
                with self.assertRaises(ValueError):
                    action()
            for method in (self.service.export_all, self.service.history_export, self.service.update_download):
                with self.assertRaises(PinError):
                    method()
            with self.assertRaises(app_update.UpdateError):
                app_update.download({})
            self.history.update_snapshot(self.key)  # even an object created before stateless mode
            self.service.set_settings({"lang": "de", "history_enabled": True})
            self.service.sync_disable(remove_file=True)
            revocation._drop_cached(url)
            self.assertIsNone(api.save_text("export.txt", SECRET))
            self.assertFalse(api.gpg_import("-----BEGIN PGP PUBLIC KEY BLOCK-----")["ok"])
            self.assertFalse(api.open_licenses())
            self.assertTrue(app._single_instance())
            keyring.assert_not_called()
            delete_secret.assert_not_called()
            subprocess_run.assert_not_called()
            api._window.create_file_dialog.assert_not_called()
        self.assertEqual(existing.read_text(), "keep")
        self.assertEqual(crl.read_bytes(), b"keep")
        self.assertEqual({p.relative_to(self.root).as_posix() for p in self.root.rglob("*")},
                         {"existing", "crls", "crls/" + crl.name})

    def test_encrypted_history_without_native_keyring_never_falls_back(self):
        unavailable = type("Backend", (), {"__module__": "keyring.backends.fail"})()
        with patch.dict(os.environ, KEYMELIER_ENCRYPT_HISTORY="1"), \
             patch("keyring.get_keyring", return_value=unavailable):
            history = History(self.root / "encrypted.json", enabled=True)
            with self.assertRaisesRegex(RuntimeError, "no plaintext"):
                history.update_snapshot(self.key)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_turning_tracking_off_scrubs_even_disabled_history(self):
        self.history.add_event(self.key, "passkey_deleted", site="internal.example", user="private-account")
        self.history.set_sites(self.key, [{"rp_id": "internal.example", "users": [{"name": "private-account"}]}])
        self.service.set_settings({"history_enabled": False})
        self.service.set_settings({"remember_sites": False})
        self.assertFalse(self.history.enabled)
        text = self.history._path.read_text()
        self.assertNotIn("internal.example", text)
        self.assertNotIn("private-account", text)
        self.assertIn("passkey_deleted", text)

    def test_import_and_sync_do_not_restore_opted_out_event_details(self):
        self.history.add_event(self.key, "passkey_deleted", site="internal.example", user="private-account")
        exported = self.history.export()
        self.service.set_settings({"remember_sites": False})
        self.service.history_import(json.dumps(exported))
        self.history.merge_sync({"keys": exported["keys"]}, keep_contents=False)
        text = self.history._path.read_text()
        self.assertNotIn("internal.example", text)
        self.assertNotIn("private-account", text)

    def test_attestation_errors_never_echo_pin_or_paths(self):
        with patch("fido2.ctap2.Ctap2", side_effect=RuntimeError(SECRET)), \
             self.assertLogs("keymelier_core.attestation", level="WARNING") as logs:
            result = attestation.run(None, self.key.aaguid, pin=SECRET)
        self.assertNotIn(SECRET, str(dataclasses.asdict(result)) + str(logs.output))
        self.assertEqual(result.status, "UNVERIFIED")
        with patch("fido2.ctap2.Ctap2") as factory:
            factory.return_value.make_credential.side_effect = RuntimeError(SECRET)
            result = attestation.run(None, self.key.aaguid)
            self.assertEqual(factory.return_value.make_credential.call_args.kwargs["options"], {"rk": False})
        self.assertNotIn(SECRET, str(dataclasses.asdict(result)))
        self.assertFalse(result.passed)

    def test_card_and_background_errors_are_safe(self):
        for translate in (cards.map_card_error, yubikey_apps._otp_error):
            self.assertNotIn(SECRET, translate(RuntimeError(SECRET)).message)
        self.service._exporter.export.side_effect = RuntimeError(SECRET)
        self.assertNotIn(SECRET, str(self.service.export_all()))
        self.service.emit = Mock()
        with patch.object(self.scanner, "_open", side_effect=RuntimeError(SECRET)):
            self.scanner._run_attestation(self.key, pin=SECRET)
        self.assertNotIn(SECRET, str(self.key.attestation))
        with patch.object(self.scanner, "session", side_effect=RuntimeError(SECRET)), \
             patch.object(self.scanner, "start_attestation"):
            self.service._run_reset(self.key)
        self.assertNotIn(SECRET, str(self.service.emit.call_args_list))

    def test_desktop_callbacks_do_not_expose_file_errors_or_ui_log_text(self):
        import app
        api = app.Api(self.service)
        api._window = Mock()
        api._window.create_file_dialog.side_effect = OSError(SECRET)
        exposed = Mock()
        app._expose_bridge(exposed, api)
        callbacks = {fn.__name__: fn for fn in exposed.expose.call_args.args}
        with self.assertLogs("keymelier", level="INFO") as logs:
            self.assertIsNone(callbacks["save_text"]("test.txt", "contents"))
            self.assertIsNone(callbacks["open_text"]())
            callbacks["client_log"](SECRET)
            callbacks["client_error"](SECRET)
        self.assertNotIn(SECRET, str(logs.output))
        self.assertEqual(self.service.error_log.ui_errors, 1)

    def test_metadata_or_crl_expiry_invalidates_cached_positive_results(self):
        mds = MDS3Client()
        mds._entries = [{}]
        self.scanner._mds3 = mds
        for next_update, verified_until in [("2000-01-01", "2999-01-01T00:00:00+00:00"),
                                             ("2999-01-01", "2000-01-01T00:00:00+00:00"),
                                             ("2999-01-01", None), ("2999-01-01", "bad-date")]:
            for query in (lambda: self.scanner.get(self.key.id), self.scanner.get_all):
                mds._next_update, mds._verified_until = next_update, verified_until
                self.key.security_status = "OK"
                self.key.attestation = {"status": "VERIFIED", "passed": True, "chain_valid": True}
                query()
                self.assertEqual(self.key.security_status, "UNKNOWN")
                self.assertEqual(self.key.attestation["status"], "UNVERIFIED")
                self.assertFalse(self.key.attestation["passed"])

    def test_unlock_is_key_scoped_and_expires_at_300_seconds(self):
        ctap = SimpleNamespace(info=SimpleNamespace(options={"clientPin": True}))
        self.addCleanup(lambda: auth.forget(self.key.id, disconnected=True))
        with patch.object(auth.time, "monotonic", return_value=1000) as clock, \
             patch.object(auth, "_permissions", return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
             patch("fido2.ctap2.pin.ClientPin", return_value=SimpleNamespace(
                 protocol=SimpleNamespace(VERSION=2), get_pin_token=Mock(return_value=b"token"))):
            auth.unlock(self.key.id, ctap, pin=SECRET)
            self.assertFalse(auth.is_unlocked("different-key"))
            clock.return_value = 1299.999
            self.assertTrue(auth.is_unlocked(self.key.id))
            clock.return_value = 1300
            self.assertFalse(auth.is_unlocked(self.key.id))
            self.assertNotIn(self.key.id, auth._tokens)

    def test_polling_skips_initial_reader_discovery_and_known_card_operations(self):
        descriptor = SimpleNamespace(path=self.key.path)
        with patch("fido2.hid.list_descriptors", return_value=[descriptor]), \
             patch("fido2.hid.open_connection") as open_hid:
            for mapped in (False, True):
                self.service._reader_tokens = {"Yubico Reader": self.key.id} if mapped else {}
                with self.service._hold_reader("Yubico Reader"):
                    current, busy = self.scanner._enumerate_devices()
                    self.assertEqual(current, {})
                    self.assertEqual(busy, {self.key.path})
                    self.scanner._reconcile(current, busy)
                    self.assertIs(self.scanner.get(self.key.id), self.key)
                open_hid.assert_not_called()
            self.scanner._known.clear()
            with self.assertRaises(PinError):
                with self.service._hold_reader("Yubico Reader"):
                    self.fail("retired device must not bypass the lock")

    def test_ctap_session_prevents_polling(self):
        @contextmanager
        def fake_device(_):
            yield object()
        descriptor = SimpleNamespace(path=self.key.path, vid=self.key.vendor_id, pid=self.key.product_id,
                                     product_name=self.key.product_name, serial_number=self.key.serial_number)
        with patch("fido2.hid.list_descriptors", return_value=[descriptor]), \
             patch("keymelier_core.scanner._hid_device", fake_device), \
             patch("fido2.ctap2.Ctap2", return_value=SimpleNamespace(info=SimpleNamespace(aaguid=self.key.aaguid))):
            with self.scanner.session(self.key.id, refresh=False):
                self.assertEqual(self.scanner._enumerate_devices(), ({}, {self.key.path}))

    def test_csv_export_neutralizes_every_dangerous_prefix(self):
        with patch.object(exporter, "EXPORT_DIR", self.root):
            for prefix in ("=", "+", "-", "@", "\t", "\r", "\n", "  ="):
                self.key.product_name = prefix + "formula"
                path = exporter.CSVExporter().export(self.key)
                rows = list(csv.reader(io.StringIO(path.read_text())))
                self.assertTrue(rows[1][rows[0].index("model")].startswith("'"))

    def test_service_helpers_are_not_public_rpc_methods(self):
        public = {name for name, value in vars(service.KeyService).items()
                  if not name.startswith("_") and callable(value)}
        self.assertEqual(public, ALLOWED)
        for name in ("_run_update_loop", "_sync_flush", "_link_allowed"):
            self.assertEqual(dispatch(self.service, name)["code"], "unknown_method")


if __name__ == "__main__":
    unittest.main()
