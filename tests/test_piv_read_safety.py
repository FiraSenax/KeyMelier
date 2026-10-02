"""A read error must never make an occupied PIV slot look empty."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import TOUCH_POLICY
from fido2tool_core import piv_app
from fido2tool_core.cards import CardError


class PivReadSafetyTests(unittest.TestCase):
    def session(self):
        session = Mock(version=(5,7,0))
        session.get_pin_metadata.return_value = SimpleNamespace(attempts_remaining=3, default_value=False)
        session.get_puk_metadata.return_value = SimpleNamespace(attempts_remaining=3, default_value=False)
        session.get_management_key_metadata.return_value = SimpleNamespace(default_value=False, touch_policy=TOUCH_POLICY.NEVER)
        session.get_certificate.side_effect = ApduError(b'', SW.FILE_NOT_FOUND)
        session.get_slot_metadata.side_effect = ApduError(b'', SW.REFERENCE_DATA_NOT_FOUND)
        return session

    def info(self, session):
        with patch.object(piv_app, '_session', return_value=session), patch('ykman.piv.get_pivman_data', return_value=SimpleNamespace(has_protected_key=True)):
            return piv_app.info(None)

    def test_confirmed_empty_slots_are_still_supported(self):
        result = self.info(self.session())
        self.assertEqual(len(result['slots']),4)
        self.assertTrue(all(s['cert'] is None and s['key'] is None for s in result['slots']))

    def test_read_and_parse_failures_abort_instead_of_returning_empty_slots(self):
        for method, failure in [('get_certificate',OSError('card removed')), ('get_certificate',ValueError('malformed certificate')),
                                ('get_slot_metadata',ApduError(b'', SW.SECURITY_CONDITION_NOT_SATISFIED))]:
            with self.subTest(method=method):
                session = self.session()
                getattr(session,method).side_effect = failure
                with self.assertRaises(CardError):
                    self.info(session)
