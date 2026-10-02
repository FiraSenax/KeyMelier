"""Authentication lifecycle regressions; no device, PIN retries or OS keychain."""
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fido2.ctap2.pin import ClientPin
from fido2tool_core import auth
from fido2tool_core.operations import PendingOperations


class AuthLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.key = 'lifecycle-test'
        auth.forget(self.key, disconnected=True)
        self.addCleanup(lambda: auth.forget(self.key, disconnected=True))

    def test_disconnect_forgets_capability_but_lock_preserves_it(self):
        auth._uv_limited.add(self.key)
        auth.forget(self.key)
        self.assertTrue(auth.uv_limited(self.key))
        auth.forget(self.key, disconnected=True)
        self.assertFalse(auth.uv_limited(self.key))

    def test_scoped_token_refuses_settings_and_expiration(self):
        P = ClientPin.PERMISSION
        auth._tokens[self.key] = auth.ManagementToken(2, b'secret-value', time.monotonic()+30, int(P.CREDENTIAL_MGMT))
        self.assertEqual(auth.get_token(self.key, P.CREDENTIAL_MGMT)[1], b'secret-value')
        with self.assertRaises(auth.AuthError) as caught:
            auth.get_token(self.key, P.AUTHENTICATOR_CFG)
        self.assertEqual(caught.exception.code, 'locked')
        self.assertNotIn('secret-value', repr(auth._tokens[self.key]))
        auth._tokens[self.key] = auth.ManagementToken(2, b'secret-value', 0, int(P.CREDENTIAL_MGMT))
        with self.assertRaises(auth.AuthError):
            auth.get_token(self.key)
        self.assertNotIn(self.key, auth._tokens)

    def test_late_unlock_cannot_restore_a_locked_or_cancelled_session(self):
        ctap = SimpleNamespace(info=SimpleNamespace(options={'clientPin': True, 'uv': True}))
        for action in ('lock', 'cancel'):
            with self.subTest(action=action):
                cancel = threading.Event()
                def finish(*args, **kwargs):
                    if action == 'lock':
                        auth.forget(self.key)
                    else:
                        cancel.set()
                    return b'secret'
                with patch.object(ClientPin, '__init__', lambda p,c: setattr(p,'protocol',SimpleNamespace(VERSION=2))), \
                     patch.object(ClientPin, 'get_uv_token', side_effect=finish), \
                     patch.object(auth, '_permissions', return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
                     patch.object(auth, 'uv_unlock_available', return_value=True):
                    with self.assertRaises(auth.AuthError) as caught:
                        auth.unlock(self.key, ctap, use_uv=True, cancel=cancel)
                self.assertEqual(caught.exception.code, 'cancelled')
                self.assertFalse(auth.is_unlocked(self.key))
                self.assertNotIn(self.key, auth._pending)

    def test_duplicate_wait_does_not_replace_cancellation_target(self):
        waits = PendingOperations()
        with waits.start(self.key) as first:
            with self.assertRaises(auth.AuthError) as caught:
                with waits.start(self.key):
                    self.fail('second operation must not start')
            self.assertEqual(caught.exception.code, 'busy')
            self.assertTrue(waits.cancel(self.key))
            self.assertTrue(first.is_set())
        self.assertFalse(waits.cancel(self.key))
        with waits.start(self.key) as second:
            self.assertFalse(second.is_set())

    def test_failure_releases_operation_slot(self):
        waits = PendingOperations()
        with self.assertRaises(ValueError):
            with waits.start(self.key):
                raise ValueError('failed')
        with waits.start(self.key) as event:
            self.assertFalse(event.is_set())
