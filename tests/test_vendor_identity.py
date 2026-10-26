"""Read-only protocols, strict response parsing and conservative history."""
import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from keymelier_core import vendor_info
from keymelier_core.history import History, key_id
from keymelier_core.scanner import TokenRecord, _apply_vendor_info


class VendorIdentityTests(unittest.TestCase):
    def test_token2_reads_only_get_info_on_the_existing_hid_channel(self):
        device = Mock()
        device.call.return_value = b'\xd1\x0a1234567890\x90\x00'
        self.assertEqual(vendor_info.read(device, 0x349E, 0x0022),
                         {'serial': '1234567890', 'serial_source': 'token2'})
        self.assertEqual(device.call.call_args.args, (0x41, bytes.fromhex('8033000012d110') + bytes(16)))
        self.assertIsNotNone(device.call.call_args.kwargs['event'])
        self.assertEqual(device.call.call_count, 1)

    def test_token2_bad_status_lengths_encoding_and_placeholder_ids_are_ignored(self):
        for reply in [b'', b'\x90\x00', b'\xd1\x041234\x6a\x80', b'\xd1\x051234\x90\x00',
                      b'\xd1\x041234extra\x90\x00', b'\xd1\x04zzzz\x90\x00',
                      b'\xd1\x040000\x90\x00', b'\xd1\x04ffff\x90\x00']:
            self.assertIsNone(vendor_info.read(Mock(call=Mock(return_value=reply)), 0x349E, 0x0022))

    def test_trussed_uuid_is_scoped_to_known_products_and_exact_length(self):
        for vid, pid in vendor_info.TRUSSED_IDS:
            device = Mock(call=Mock(return_value=bytes(range(16))))
            self.assertEqual(vendor_info.read(device, vid, pid)['serial'], bytes(range(16)).hex())
            self.assertEqual(device.call.call_args.args, (0x62, b''))
            for bad in (bytes(16), b'\xff' * 16, b'123', b'x' * 17):
                device.call.return_value = bad
                self.assertIsNone(vendor_info.read(device, vid, pid))
        for vid, pid in [(0x20A0, 0x42DD), (0x20A0, 0x42B1), (0x1209, 0xB000), (1, 2)]:
            device = Mock()
            self.assertIsNone(vendor_info.read(device, vid, pid))
            device.call.assert_not_called()

    def test_unsupported_device_does_not_expose_private_error(self):
        device = Mock(call=Mock(side_effect=RuntimeError('private-serial-12345')))
        with self.assertLogs('keymelier_core.vendor_info', level='DEBUG') as logs:
            self.assertIsNone(vendor_info.read(device, 0x349E, 0x0022))
        self.assertNotIn('private-serial', str(logs.output))

    def test_touch_requests_and_late_replies_cannot_establish_identity(self):
        def waiting(command, payload, *, event, on_keepalive):
            on_keepalive(2)
            self.assertTrue(event.is_set())
            return bytes(range(16))
        self.assertIsNone(vendor_info.read(Mock(call=waiting), 0x20A0, 0x42B2))
        def expired(command, payload, *, event, on_keepalive):
            event.set()
            return b'\xd1\x041234\x90\x00'
        self.assertIsNone(vendor_info.read(Mock(call=expired), 0x349E, 0x22))

    def test_new_vendor_serials_separate_keys_and_preserve_legacy_history(self):
        base = TokenRecord('connection', 'path', 'Token2', None, 'Token2', 'model-aaguid',
                           [], [], {}, [], None, None, '', 'now', vendor_id=0x349E, product_id=0x22)
        with tempfile.TemporaryDirectory() as tmp:
            history = History(Path(tmp) / 'history.json', enabled=True)
            history.update_snapshot(base)
            legacy_id = key_id(base)
            for serial in ('1234567890', '1234567891'):
                record = dataclasses.replace(base)
                _apply_vendor_info(record, {'serial': serial, 'serial_source': 'token2'})
                summary = history.update_snapshot(record)
                self.assertNotEqual(summary['key_id'], legacy_id)
                self.assertNotIn('replaces', summary)
            self.assertEqual(len(history._entries), 3)
            self.assertIsNone(history._entries[legacy_id]['snapshot']['serial_number'])
