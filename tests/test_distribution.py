"""Package updates must never cross over to the GitHub EXE installer."""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

from keymelier_core import app_update, distribution
from keymelier_core.pin import PinError
from keymelier_core.service import KeyService


class DistributionTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "native Windows package API")
    def test_unpacked_test_runner_has_no_package_identity(self):
        self.assertFalse(distribution.is_msix())

    def test_windows_package_identity_and_unexpected_errors(self):
        with patch.object(distribution.sys, "platform", "win32"):
            with patch.object(distribution, "_package_status", return_value=122):
                self.assertTrue(distribution.is_msix())
            with patch.object(distribution, "_package_status", return_value=15700):
                self.assertFalse(distribution.is_msix())
            with patch.object(distribution, "_package_status", return_value=5):
                with self.assertRaises(OSError):
                    distribution.is_msix()

    def test_non_windows_does_not_call_windows_api(self):
        with patch.object(distribution.sys, "platform", "darwin"), \
             patch.object(distribution, "_package_status") as query:
            self.assertFalse(distribution.is_msix())
            query.assert_not_called()

    def test_packaged_updates_do_not_contact_github_or_open_installers(self):
        with patch.object(app_update, "is_msix", return_value=True), \
             patch("requests.get") as request, patch("subprocess.Popen") as launch:
            result = app_update.check()
            self.assertTrue(result["managed"])
            self.assertFalse(result["newer"])
            self.assertNotIn("asset", result)
            with self.assertRaises(app_update.UpdateError):
                app_update.download({})
            with self.assertRaises(app_update.UpdateError):
                app_update.open_download(Path("old-installer.exe"))
            request.assert_not_called()
            launch.assert_not_called()

    def test_identity_failure_does_not_enable_github_updates(self):
        with patch.object(app_update, "is_msix", side_effect=OSError("identity error")), \
             patch("requests.get") as request:
            self.assertTrue(app_update.check()["failed"])
            with self.assertRaises(OSError):
                app_update.download({})
            request.assert_not_called()

    def test_service_refuses_even_cached_downloads_and_refreshes_trust_data(self):
        with patch.object(KeyService, "_stored_settings", return_value={}):
            service = KeyService(Mock(), Mock(), mds3_client=Mock(), advisories=Mock(), history=Mock())
        service._app_update = {"newer": True, "asset": {"name": "old-installer.exe"}}
        service._update_path = Mock()
        with patch.object(app_update, "is_msix", return_value=True):
            for method in (service.update_download, service.update_open):
                with self.assertRaises(PinError):
                    method()
            with patch.object(service, "data_status", return_value={}):
                service.check_updates()
        service._mds3.refresh_if_stale.assert_called_once()
        service._advisories.check_for_update.assert_called_once()
        service._scanner.reevaluate_all.assert_called_once()
        self.assertTrue(service._app_update["managed"])
