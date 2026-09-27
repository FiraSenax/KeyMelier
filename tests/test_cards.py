import tempfile
import unittest
import unittest.mock
from contextlib import contextmanager
from pathlib import Path

from fido2tool_core import cards, openpgp_app, piv_app, yubikey_apps
from fido2tool_core.cards import CardError, Cards
from fido2tool_core.history import History
from fido2tool_core.scanner import TokenRecord


def record():
    return TokenRecord('id', '/dev/test', 'Key', 'serial', 'vendor', 'aaguid',
                       [], [], {}, [], None, None, '', 'now')


class CardTests(unittest.TestCase):
    def test_cardholder_name_is_shown_first_name_first(self):
        holder = bytes([0x65, 0x13]) + bytes([0x5B, 0x11]) + b'Mustermann<<Erika'
        self.assertEqual(openpgp_app._cardholder_name(holder), 'Erika Mustermann')
        self.assertEqual(openpgp_app._cardholder_name(bytes([0x65, 0x02, 0x5B, 0x00])), '')

    def test_read_retries_once_on_transient_card_error_only(self):
        c = Cards()
        calls = []

        @contextmanager
        def fake_connect(reader, timeout=10.0):
            yield object()

        c.connect = fake_connect
        with unittest.mock.patch.object(cards.time, 'sleep'):
            def flaky(conn):
                calls.append(1)
                if len(calls) == 1:
                    raise CardError('SW=6EE0', 'card_error')
                return 'ok'
            self.assertEqual(c.read('r', flaky), 'ok')
            self.assertEqual(len(calls), 2)

            calls.clear()

            def busy(conn):
                calls.append(1)
                raise CardError('busy', 'busy')
            with self.assertRaises(CardError):
                c.read('r', busy)
            self.assertEqual(len(calls), 1)

    def test_connection_holds_the_fido_side(self):
        c = Cards()
        events = []

        @contextmanager
        def hold(reader):
            events.append('hold')
            yield
            events.append('release')

        class Device:
            reader = type('R', (), {'name': 'r'})()

            def open_connection(self, _type):
                events.append('open')
                return type('C', (), {'close': lambda self: events.append('close')})()

        c.hold = hold
        with unittest.mock.patch.object(cards, '_reader_devices', return_value=[Device()]):
            with c.connect('r'):
                events.append('use')
        self.assertEqual(events, ['hold', 'open', 'use', 'close', 'release'])

    def test_inventory_is_kept_and_cleared_with_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = History(Path(tmp) / 'history.json', enabled=True)
            summary = h.set_inventory(record(), 'oath', [{'issuer': 'GitHub', 'name': 'me'}])
            self.assertEqual(summary['inventory']['oath']['items'][0]['issuer'], 'GitHub')
            h.clear_sites()
            self.assertNotIn('inventory', h.get(summary['key_id']))

    def test_openpgp_pin_rules(self):
        with self.assertRaises(CardError) as e:
            openpgp_app._check_pin('12345', openpgp_app.MIN_USER_PIN, 'pgp_user_short')
        self.assertEqual(e.exception.code, 'pgp_user_short')
        with self.assertRaises(CardError):
            openpgp_app._check_pin('x' * 128, openpgp_app.MIN_ADMIN_PIN, 'pgp_admin_short')
        openpgp_app._check_pin('12345678', openpgp_app.MIN_ADMIN_PIN, 'pgp_admin_short')


    def test_piv_pin_length_and_otp_access_code(self):
        for bad in ('12345', '123456789'):
            with self.assertRaises(CardError):
                piv_app._check_pin(bad, 'piv_pin_length')
        piv_app._check_pin('123456', 'piv_pin_length')
        self.assertIsNone(yubikey_apps._access_code(''))
        self.assertEqual(yubikey_apps._access_code('010203040506'), bytes.fromhex('010203040506'))
        for bad in ('0102', 'zz0203040506'):
            with self.assertRaises(CardError):
                yubikey_apps._access_code(bad)

    def test_fido2_over_usb_cannot_be_turned_off(self):
        from yubikit.management import CAPABILITY, TRANSPORT
        all_caps = CAPABILITY.FIDO2 | CAPABILITY.OATH | CAPABILITY.PIV
        info = unittest.mock.Mock(is_locked=False, supported_capabilities={TRANSPORT.USB: all_caps})
        info.config.enabled_capabilities = {TRANSPORT.USB: all_caps}
        session = unittest.mock.Mock()
        session.read_device_info.return_value = info
        with unittest.mock.patch('yubikit.management.ManagementSession', return_value=session):
            with self.assertRaises(CardError) as e:
                yubikey_apps.set_interfaces(object(), 'usb', {'FIDO2': False})
            self.assertEqual(e.exception.code, 'usb_fido2_required')
            session.write_device_config.assert_not_called()
            yubikey_apps.set_interfaces(object(), 'usb', {'OATH': False})
            written = session.write_device_config.call_args[0][0].enabled_capabilities[TRANSPORT.USB]
            self.assertFalse(written & CAPABILITY.OATH)
            self.assertTrue(written & CAPABILITY.FIDO2)


    def test_third_party_licenses_cover_bundled_packages(self):
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / 'tools'))
        import third_party_licenses
        text = third_party_licenses.build()
        for name in ('fido2', 'yubikey-manager', 'pywebview', 'cryptography', 'pyscard'):
            self.assertIn(f'\n{name} ', text)
        self.assertIn('github.com/LudovicRousseau/pyscard', text)
        self.assertIn('GNU LESSER GENERAL PUBLIC LICENSE', text)
        self.assertIn('PSF License', text)


if __name__ == '__main__':
    unittest.main()
