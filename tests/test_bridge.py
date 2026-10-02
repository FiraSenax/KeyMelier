"""Service boundary rejects malformed calls and never leaks unexpected errors."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from fido2tool_core.bridge import dispatch
from fido2tool_core.diagnostics import ErrorLog
from fido2tool_core.pin import PinError


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.service = SimpleNamespace(error_log=ErrorLog(('unlock',)), unlock=Mock(return_value={'unlocked':True}))

    def test_bad_method_and_arguments_never_reach_device(self):
        for method, args in [([], {}), ('__dict__', {}), ('unlock', []), ('unlock', {1: 'value'}),
                             ('unlock', {'token_id': []}), ('unlock', {'token_id': ''})]:
            with self.subTest(method=method, args=args):
                self.assertFalse(dispatch(self.service, method, args)['ok'])
        self.service.unlock.assert_not_called()

    def test_missing_argument_is_rejected_before_handler(self):
        self.service.unlock = lambda token_id: {'unlocked': True}
        self.assertEqual(dispatch(self.service, 'unlock', {})['code'], 'invalid_input')
        self.assertTrue(dispatch(self.service, 'unlock', {'token_id':'tok'})['ok'])

    def test_internal_type_error_is_not_reported_as_bad_user_input(self):
        self.service.unlock.side_effect = TypeError('secret=123456-private-account')
        with self.assertLogs('fido2tool_core.bridge', level='ERROR') as logs:
            result = dispatch(self.service, 'unlock', {})
        self.assertEqual(result['status'], 500)
        self.assertEqual(result['code'], 'error')
        self.assertNotIn('123456-private-account', str(result)+str(logs.output))

    def test_domain_error_keeps_actionable_result_but_not_log_text(self):
        self.service.unlock.side_effect = PinError('Please enter the PIN.', 'pin_required')
        with self.assertLogs('fido2tool_core.bridge', level='WARNING') as logs:
            result = dispatch(self.service, 'unlock', {})
        self.assertEqual(result['error'], 'Please enter the PIN.')
        self.assertEqual(result['code'], 'pin_required')
        self.assertNotIn('Please enter the PIN.', str(logs.output))
