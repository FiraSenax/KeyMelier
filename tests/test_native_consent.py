"""A renderer cannot approve, replay or retarget a destructive operation."""
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from keymelier_core.bridge import ALLOWED, dispatch
from keymelier_core.consent import NativeConsent, OPERATIONS


class NativeConsentTests(unittest.TestCase):
    def setUp(self):
        self.record = SimpleNamespace(id='connection-1', path='synthetic', serial_number='123',
                                      aaguid='model', vendor_id=1, product_id=2,
                                      product_name='Key\nInjected message\u202e')
        self.service = SimpleNamespace(_scanner=Mock(), _stored_settings=lambda: {'lang': 'de'}, error_log=Mock())
        self.service._scanner.get.return_value = self.record
        self.called = Mock(return_value={})
        self.service.pin_update = lambda token_id, new_pin: self.called(token_id, new_pin)
        self.confirm = Mock(return_value=True)
        self.consent = NativeConsent(self.service, self.confirm, Path(__file__).resolve().parents[1] / 'data/native-ui.json')

    def call(self, **kwargs):
        return dispatch(self.service, 'pin_update', kwargs or {'token_id': self.record.id, 'new_pin': 'private-secret'},
                        authorize=self.consent.authorize)

    def test_native_approval_is_required_for_each_request_and_contains_no_secret(self):
        for result in (False, None, 1, 'true'):
            self.confirm.return_value = result
            self.assertEqual(self.call()['code'], 'cancelled')
        self.called.assert_not_called()
        self.confirm.return_value = True
        self.assertTrue(self.call()['ok'])
        self.confirm.return_value = False
        self.assertFalse(self.call()['ok'])
        self.called.assert_called_once()
        message = self.confirm.call_args.args[1]
        self.assertIn('PIN', message)
        self.assertIn('123', message)
        self.assertNotIn('private-secret', message)
        self.assertNotIn('\u202e', message)
        self.assertNotIn('Key\nInjected', message)

    def test_missing_arguments_and_unknown_methods_do_not_prompt(self):
        self.assertFalse(self.call(token_id='connection-1')['ok'])
        self.assertFalse(dispatch(self.service, '__dict__', authorize=self.consent.authorize)['ok'])
        self.confirm.assert_not_called()

    def test_key_replaced_during_dialog_is_rejected(self):
        def approve(*_):
            self.service._scanner.get.return_value = SimpleNamespace(**vars(self.record))
            return True
        self.confirm.side_effect = approve
        self.assertEqual(self.call()['code'], 'not_found')
        self.called.assert_not_called()

    def test_arguments_are_copied_before_confirmation(self):
        args = {'token_id': self.record.id, 'new_pin': 'original'}
        def approve(*_):
            args['new_pin'] = 'changed'
            return True
        self.confirm.side_effect = approve
        dispatch(self.service, 'pin_update', args, authorize=self.consent.authorize)
        self.called.assert_called_once_with(self.record.id, 'original')

    def test_dialog_failure_and_concurrent_calls_fail_closed(self):
        self.confirm.side_effect = RuntimeError('private-secret')
        with self.assertLogs('keymelier_core.bridge', level='ERROR') as logs:
            self.assertEqual(self.call()['code'], 'error')
        self.assertNotIn('private-secret', str(logs.output))
        self.called.assert_not_called()
        entered, release = threading.Event(), threading.Event()
        def confirm(*_):
            entered.set()
            return release.wait(3)
        self.confirm.side_effect = confirm
        worker = threading.Thread(target=self.call)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertEqual(self.call()['code'], 'busy')
        finally:
            release.set()
            worker.join(3)
        self.called.assert_called_once()

    def test_every_native_operation_has_bundled_translations_and_is_allowlisted(self):
        self.assertLessEqual(set(OPERATIONS), ALLOWED)
        self.assertEqual(len(self.consent.texts), 11)
        for language in self.consent.texts.values():
            for _, key in OPERATIONS.values():
                self.assertTrue(language[key])
        self.service.tokens = lambda: []
        self.assertTrue(dispatch(self.service, 'tokens', authorize=self.consent.authorize)['ok'])
        self.confirm.assert_not_called()

    def test_all_classified_operations_are_blocked_without_native_consent(self):
        self.confirm.return_value = False
        for method in OPERATIONS:
            with self.subTest(method=method):
                effect = Mock()
                setattr(self.service, method, effect)
                args = {'token_id': self.record.id} if method not in ('history_forget', 'sync_disable') else {'kid': 'synthetic', 'remove_file': True}
                result = dispatch(self.service, method, args, authorize=self.consent.authorize)
                self.assertEqual(result['code'], 'cancelled')
                effect.assert_not_called()
