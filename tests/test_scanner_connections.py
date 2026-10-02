"""Device lifecycle regressions using fake HID connections, never real keys."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2tool_core.scanner import TokenRecord, TokenScanner


class ScannerConnectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = TokenScanner()
        self.descriptor = SimpleNamespace(path='fake-hid', vid=0x1234, pid=1,
                                          product_name='Test Key', serial_number='100')
        self.record = TokenRecord('fake-key', 'fake-hid', 'Test Key', '100', 'vendor',
                                  '00000000-0000-0000-0000-000000000001', [], [], {}, [],
                                  None, None, '', 'now', vendor_id=0x1234, product_id=1)
        self.scanner._known[self.record.path] = self.record
        self.connection = Mock()
        self.device = Mock()
        self.device.close.side_effect = lambda: self.connection.close()
        self.ctap = Mock()
        self.ctap.info = SimpleNamespace(aaguid=self.record.aaguid, versions=[], extensions=[],
                                         options={}, pin_uv_protocols=[])
        self.addCleanup(patch.stopall)
        patch('fido2.hid.list_descriptors', return_value=[self.descriptor]).start()
        self.open_connection = patch('fido2.hid.open_connection', return_value=self.connection).start()
        self.construct = patch('fido2.hid.CtapHidDevice', return_value=self.device).start()
        self.ctap_factory = patch('fido2.ctap2.Ctap2', return_value=self.ctap).start()

    def assert_lock_released(self):
        lock = self.scanner._device_lock(self.record.path)
        self.assertTrue(lock.acquire(blocking=False))
        lock.release()

    def test_failed_hid_initialization_closes_connection_in_scan_and_session(self):
        error = OSError('device removed during INIT')
        self.construct.side_effect = error
        records, busy = self.scanner._enumerate_devices()
        self.assertEqual((records, busy), ({}, set()))
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()

        self.connection.reset_mock()
        with self.assertRaises(OSError) as caught:
            with self.scanner._open(self.record, 0):
                self.fail('must not yield a failed device')
        self.assertIs(caught.exception, error)
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()

    def test_get_info_failure_closes_connection_in_scan_and_session(self):
        self.ctap_factory.side_effect = OSError('getInfo failed')
        self.scanner._enumerate_devices()
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()
        self.connection.reset_mock()
        with self.assertRaises(OSError):
            with self.scanner._open(self.record, 0):
                self.fail('must not yield a failed CTAP session')
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()

    def test_success_keeps_connection_open_until_operation_finishes(self):
        with self.scanner._open(self.record, 0) as ctap:
            self.assertIs(ctap, self.ctap)
            self.connection.close.assert_not_called()
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()

    def test_operation_failure_closes_connection_without_masking_error(self):
        error = ValueError('operation failed')
        self.connection.close.side_effect = OSError('already disconnected')
        with self.assertRaises(ValueError) as caught:
            with self.scanner._open(self.record, 0):
                raise error
        self.assertIs(caught.exception, error)
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()

    def test_open_failure_releases_lock_without_closing_unowned_connection(self):
        self.open_connection.side_effect = OSError('cannot open')
        with self.assertRaises(OSError):
            with self.scanner._open(self.record, 0):
                self.fail('must not yield')
        self.connection.close.assert_not_called()
        self.assert_lock_released()

    def test_close_error_does_not_mask_initialization_error(self):
        error = OSError('INIT failed')
        self.construct.side_effect = error
        self.connection.close.side_effect = OSError('close failed')
        with self.assertRaises(OSError) as caught:
            with self.scanner._open(self.record, 0):
                self.fail('must not yield')
        self.assertIs(caught.exception, error)
        self.connection.close.assert_called_once_with()
        self.assert_lock_released()
