"""Distinguish absent optional data from denied access and programming errors."""
import unittest
from unittest.mock import Mock, patch

from yubikit.core import NotSupportedError
from yubikit.core.smartcard import ApduError, SW
from keymelier_core import cards, openpgp_app, piv_app


def apdu(status):
    return ApduError(b'', status)


class CardFailureTests(unittest.TestCase):
    def test_optional_reads_only_suppress_absent_or_unsupported_commands(self):
        for error in (NotSupportedError(), apdu(SW.FILE_NOT_FOUND)):
            self.assertEqual(openpgp_app._optional_read(Mock(side_effect=error), 'absent'), 'absent')
        for error in (RuntimeError('synthetic bug'), apdu(0x6982), OSError('disconnected')):
            with self.assertRaises(type(error)):
                openpgp_app._optional_read(Mock(side_effect=error))

    def test_failed_certificate_deletion_never_continues_to_private_key_deletion(self):
        session = Mock()
        session.version = (5, 7, 0)
        with patch.object(piv_app, '_session', return_value=session), patch.object(piv_app, '_authenticate'):
            session.delete_certificate.side_effect = apdu(0x6982)
            with self.assertRaises(cards.CardError):
                piv_app.delete(None, '9a', key=True)
            session.delete_key.assert_not_called()
            session.delete_certificate.side_effect = apdu(SW.FILE_NOT_FOUND)
            piv_app.delete(None, '9a', key=True)
            session.delete_key.assert_called_once()

    def test_unexpected_mapped_errors_log_only_safe_locations(self):
        try:
            raise RuntimeError('PIN=secret /Users/private/account@example.test')
        except RuntimeError as error:
            with self.assertLogs('keymelier_core.cards', level='ERROR') as logs:
                mapped = cards.map_card_error(error)
        self.assertIn('test_card_failures.py:', str(logs.output))
        self.assertIn('RuntimeError', str(logs.output))
        for forbidden in ('secret', '/Users/private', 'account@example.test', 'raise RuntimeError'):
            self.assertNotIn(forbidden, str(logs.output) + mapped.message)

    def test_default_management_key_probe_does_not_hide_programming_or_transport_failure(self):
        for error in (RuntimeError('bug'), OSError('removed')):
            with self.assertRaises(type(error)):
                piv_app._is_default_mgmt(Mock(authenticate=Mock(side_effect=error)))
        self.assertFalse(piv_app._is_default_mgmt(Mock(authenticate=Mock(side_effect=apdu(0x6982)))))
