"""A reused HID path must not carry old authorization or attestation state."""
import dataclasses
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2tool_core.scanner import DeviceNotFound, TokenRecord, TokenScanner


def record(token_id='old-connection', serial='100'):
    return TokenRecord(token_id, 'fake-hid', 'Test Key', serial, 'vendor',
                       '00000000-0000-0000-0000-000000000001', [], [], {}, [],
                       None, None, '', 'now', vendor_id=0x1234, product_id=1)


class DeviceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.scanner = TokenScanner(poll_interval=0)
        self.old = record()
        self.scanner._known[self.old.path] = self.old
        self.descriptor = SimpleNamespace(path=self.old.path, vid=self.old.vendor_id,
                                          pid=self.old.product_id, serial_number=self.old.serial_number,
                                          product_name=self.old.product_name)
        self.info = SimpleNamespace(aaguid=self.old.aaguid, versions=[], extensions=[],
                                    options={}, pin_uv_protocols=[])
        self.ctap = SimpleNamespace(info=self.info)
        self.device = object()
        self.addCleanup(patch.stopall)
        patch('fido2.hid.list_descriptors', return_value=[self.descriptor]).start()
        patch('fido2.ctap2.Ctap2', return_value=self.ctap).start()

        @contextmanager
        def hid_device(descriptor):
            yield self.device

        patch('fido2tool_core.scanner._hid_device', hid_device).start()
        self.scanner.start_attestation = Mock()

    def scan(self, current, busy=None):
        with patch.object(self.scanner, '_enumerate_devices', return_value=(current, busy or set())), \
             patch('fido2tool_core.scanner.time.sleep', side_effect=lambda _: self.scanner.stop()):
            self.scanner.run_forever()

    def test_changed_identity_is_refused_before_yielding_a_session(self):
        for obj, attribute, changed in [(self.descriptor, 'serial_number', '200'),
                                         (self.descriptor, 'vid', 0x5678),
                                         (self.descriptor, 'pid', 2),
                                         (self.info, 'aaguid', '00000000-0000-0000-0000-000000000002')]:
            with self.subTest(attribute=attribute), patch.object(obj, attribute, changed):
                with self.assertRaises(DeviceNotFound):
                    with self.scanner.session(self.old.id, refresh=False):
                        self.fail('old request reached the replacement device')

    def test_matching_identity_can_open(self):
        with self.scanner.session(self.old.id, refresh=False) as (seen, ctap):
            self.assertIs(seen, self.old)
            self.assertIs(ctap, self.ctap)

    def test_vendor_serial_is_rechecked_on_the_open_connection(self):
        self.old.vendor_id = self.descriptor.vid = 0x1050
        self.descriptor.serial_number = None
        for details in ({'serial': '200'}, None):
            with self.subTest(details=details), patch('fido2tool_core.scanner.vendor_info.read', return_value=details):
                with self.assertRaises(DeviceNotFound):
                    with self.scanner.session(self.old.id, refresh=False):
                        self.fail('a changed/unverifiable vendor serial must stop the request')
        with patch('fido2tool_core.scanner.vendor_info.read', return_value={'serial': '100'}) as read:
            with self.scanner.session(self.old.id, refresh=False):
                pass
            read.assert_called_once_with(self.device, 0x1050, 1)

    def test_record_replaced_while_waiting_for_device_lock_is_rejected(self):
        replacement = record('new-connection')

        class SwitchingLock:
            def acquire(inner, **kwargs):
                self.scanner._known[self.old.path] = replacement
                return True

            def release(inner):
                pass

        with patch.object(self.scanner, '_device_lock', return_value=SwitchingLock()):
            with self.assertRaises(DeviceNotFound):
                with self.scanner._open(self.old, 0):
                    self.fail('queued request used a new connection')

    def test_poll_replacement_disconnects_old_before_connecting_fresh(self):
        self.old.attestation = {'status': 'VERIFIED'}
        replacement = record('new-connection', '200')
        events = []
        self.scanner.on_disconnect = lambda r: events.append(('removed', r.id))
        self.scanner.on_connect = lambda r: events.append(('added', r.id))
        self.scan({self.old.path: replacement})
        self.assertEqual(events, [('removed', self.old.id), ('added', replacement.id)])
        self.assertIs(self.scanner.get(replacement.id), replacement)
        with self.assertRaises(DeviceNotFound):
            self.scanner.get(self.old.id)
        self.assertIsNone(replacement.attestation)
        self.assertNotEqual(replacement.security_status, 'OK')
        self.scanner.start_attestation.assert_called_once_with(replacement)

    def test_normal_poll_keeps_connection_id_and_busy_device(self):
        self.scan({self.old.path: dataclasses.replace(self.old, id='unused-scan-id')})
        self.assertIs(self.scanner.get(self.old.id), self.old)
        self.scan({}, {self.old.path})
        self.assertIs(self.scanner.get(self.old.id), self.old)
        self.scanner.start_attestation.assert_not_called()

    def test_reconnect_gets_a_new_connection_id_even_at_the_same_path(self):
        first = self.scanner._enumerate_devices()[0][self.old.path]
        second = self.scanner._enumerate_devices()[0][self.old.path]
        self.assertNotEqual(first.id, second.id)

    def test_late_attestation_does_not_publish_an_update_for_a_removed_connection(self):
        self.scanner._known[self.old.path] = record('new-connection')
        self.scanner.on_update = Mock()
        self.scanner._run_attestation(self.old)
        self.scanner.on_update.assert_not_called()
