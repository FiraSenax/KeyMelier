"""Existing keys must survive unconfirmed, failed and concurrent writes."""
import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2tool_core import cards, openpgp_app, piv_app, yubikey_apps
from fido2tool_core.cards import CardError, Cards
from fido2tool_core.service import KeyService


class OverwriteGuardTests(unittest.TestCase):
    def setUp(self):
        self.svc = KeyService.__new__(KeyService)
        self.record = SimpleNamespace(serial_number='100')
        self.svc._card = Mock(return_value=(self.record, 'reader'))
        self.svc._cards = Cards()
        self.svc._log = Mock()
        self.svc._remember_contents = Mock(return_value=False)
        self.svc.piv = self.svc.openpgp = Mock(return_value={})
        self.connections = []

        def open_connection(_type):
            conn = Mock()
            self.connections.append(conn)
            return conn

        device = SimpleNamespace(reader=SimpleNamespace(name='reader'), open_connection=open_connection)
        self.addCleanup(patch.stopall)
        patch.object(cards, '_reader_devices', return_value=[device]).start()

    def invoke(self, kind, **kwargs):
        if kind == 'piv':
            return self.svc.piv_generate('key', kwargs.pop('slot', '9a'), 'ECCP256', 'CN=test', 1, '123456', **kwargs)
        return self.svc.openpgp_generate('key', 'rsa2048', 'test', **kwargs)

    def info(self, kind, present):
        if kind == 'piv':
            return {'slots': [{'slot': '9a', 'cert': None, 'key': {'type': 'ECCP256'} if present else None}]}
        return {'keys': [{'present': present}]}

    def test_piv_slot_aliases_cannot_bypass_existing_key_confirmation(self):
        with patch.object(piv_app, 'info', return_value=self.info('piv', True)), \
             patch.object(piv_app, 'generate') as generate:
            for slot in ('9a', '9A', '0x9a', '09a', ' 9a '):
                with self.subTest(slot=slot), self.assertRaises(CardError) as caught:
                    self.invoke('piv', slot=slot)
                self.assertEqual(caught.exception.code, 'confirm_replace')
            generate.assert_not_called()

    def test_check_and_generation_use_the_same_still_open_connection(self):
        for kind, module, method in [('piv', piv_app, 'generate'), ('pgp', openpgp_app, 'generate_keys')]:
            with self.subTest(kind=kind):
                checked = []

                def read(conn):
                    checked.append(conn)
                    return self.info(kind, False)

                def write(conn, *args):
                    self.assertIs(conn, checked[0])
                    conn.close.assert_not_called()
                    return {'user_id': 'test'}

                with patch.object(module, 'info', side_effect=read), patch.object(module, method, side_effect=write):
                    self.invoke(kind)
                self.assertEqual(len(checked), 1)
                checked[0].close.assert_called_once()

    def test_invalid_and_attestation_slots_are_rejected_before_device_access(self):
        for slot in ('f9', '0xf9', 'garbage', None, 154):
            with self.subTest(slot=slot), self.assertRaises(CardError) as caught:
                self.invoke('piv', slot=slot, replace=True)
            self.assertEqual(caught.exception.code, 'invalid_input')
        self.svc._card.assert_not_called()

    def test_failed_occupancy_read_never_generates_a_key(self):
        for kind, module, method in [('piv', piv_app, 'generate'), ('pgp', openpgp_app, 'generate_keys')]:
            with self.subTest(kind=kind), patch.object(module, 'info', side_effect=CardError('unreadable', 'card_error')), \
                 patch.object(module, method) as generate:
                with self.assertRaises(CardError):
                    self.invoke(kind)
                generate.assert_not_called()

    def test_only_literal_true_confirms_replacement(self):
        for kind, module, method in [('piv', piv_app, 'generate'), ('pgp', openpgp_app, 'generate_keys')]:
            with self.subTest(kind=kind), patch.object(module, 'info', return_value=self.info(kind, True)), \
                 patch.object(module, method, return_value={'user_id': 'test'}) as generate:
                for value in (False, None, 1, 'true'):
                    with self.assertRaises(CardError):
                        self.invoke(kind, replace=value)
                generate.assert_not_called()
                self.invoke(kind, replace=True)
                generate.assert_called_once()

    def test_concurrent_requests_cannot_both_generate_into_an_empty_slot(self):
        for kind, module, method in [('piv', piv_app, 'generate'), ('pgp', openpgp_app, 'generate_keys')]:
            with self.subTest(kind=kind):
                start = threading.Barrier(2)
                outcomes = []
                present = False

                def write(conn, *args):
                    nonlocal present
                    present = True
                    return {'user_id': 'test'}

                def run():
                    try:
                        start.wait(timeout=3)
                        self.invoke(kind)
                        outcomes.append('generated')
                    except CardError as error:
                        outcomes.append(error.code)
                    except Exception as error:
                        outcomes.append(repr(error))

                with patch.object(module, 'info', side_effect=lambda conn: self.info(kind, present)), \
                     patch.object(module, method, side_effect=write) as generate:
                    workers = [threading.Thread(target=run, daemon=True) for _ in range(2)]
                    for worker in workers:
                        worker.start()
                    for worker in workers:
                        worker.join(3)
                        self.assertFalse(worker.is_alive())
                    self.assertCountEqual(outcomes, ['generated', 'confirm_replace'])
                    generate.assert_called_once()

    def test_otp_occupancy_and_write_hold_the_same_locks(self):
        self.svc._otp_lock = threading.Lock()
        self.svc._yubikey = Mock(return_value=self.record)
        self.svc.otp = Mock(return_value={})
        held = False
        present = False

        @contextmanager
        def hold(token_id):
            nonlocal held
            held = True
            try:
                yield
            finally:
                held = False

        def status(serial):
            self.assertTrue(held)
            self.assertTrue(self.svc._otp_lock.locked())
            return {'slots': [{'slot': 1, 'configured': present}]}

        def write(*args):
            nonlocal present
            self.assertTrue(held)
            self.assertTrue(self.svc._otp_lock.locked())
            present = True
            return 'synthetic-secret'

        self.svc._otp_hold = hold
        for method, protocol, args in [('otp_static', 'otp_static_password', ('password',)),
                                        ('otp_hmac', 'otp_challenge_response', ())]:
            with self.subTest(method=method), patch.object(yubikey_apps, 'otp_status', side_effect=status), \
                 patch.object(yubikey_apps, protocol, side_effect=write) as generate:
                present = False
                getattr(self.svc, method)('key', 1, *args)
                with self.assertRaises(CardError) as caught:
                    getattr(self.svc, method)('key', 1, *args)
                self.assertEqual(caught.exception.code, 'confirm_replace')
                generate.assert_called_once()
                self.assertFalse(held)
                self.assertFalse(self.svc._otp_lock.locked())
