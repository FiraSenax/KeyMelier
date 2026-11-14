"""OTP access diagnostics; no devices, permissions or system state changed."""
import unittest
from unittest.mock import patch

from keymelier_core import yubikey_apps


class OtpErrorTests(unittest.TestCase):
    def test_secure_input_explains_denied_hid_access_without_retry(self):
        for code in ("-536870174", "3758097122", "0xE00002E2", "not permitted"):
            with self.subTest(code=code), patch.object(yubikey_apps, "_secure_input_active", return_value=True):
                error = yubikey_apps._otp_error(OSError(f"Failed to open device: {code}"))
            self.assertEqual(error.code, "otp_secure_input")
            self.assertIn("even with Input Monitoring allowed", error.message)

    def test_existing_permission_and_unrelated_error_contracts_survive(self):
        with patch.object(yubikey_apps, "_secure_input_active", return_value=False):
            self.assertEqual(yubikey_apps._otp_error(OSError("not permitted")).code, "otp_permission")
        with patch.object(yubikey_apps, "_secure_input_active") as check:
            self.assertEqual(yubikey_apps._otp_error(OSError("disconnected")).code, "card_error")
            check.assert_not_called()

    def test_detection_only_calls_the_read_only_api_on_macos(self):
        for active in (True, False):
            with self.subTest(active=active), patch.object(yubikey_apps.sys, "platform", "darwin"), \
                    patch("ctypes.CDLL") as load:
                load.return_value.IsSecureEventInputEnabled.return_value = active
                self.assertEqual(yubikey_apps._secure_input_active(), active)
                load.assert_called_once_with("/System/Library/Frameworks/Carbon.framework/Carbon")
                self.assertEqual(load.return_value.mock_calls, [unittest.mock.call.IsSecureEventInputEnabled()])
        for platform in ("linux", "win32"):
            with self.subTest(platform=platform), patch.object(yubikey_apps.sys, "platform", platform), \
                    patch("ctypes.CDLL") as load:
                self.assertFalse(yubikey_apps._secure_input_active())
                load.assert_not_called()

    def test_unavailable_native_api_keeps_permission_fallback(self):
        for error in (OSError("unavailable"), AttributeError("unavailable")):
            with self.subTest(error=type(error).__name__), patch.object(yubikey_apps.sys, "platform", "darwin"), \
                    patch("ctypes.CDLL", side_effect=error):
                self.assertEqual(yubikey_apps._otp_error(OSError("not permitted")).code, "otp_permission")


if __name__ == "__main__":
    unittest.main()
