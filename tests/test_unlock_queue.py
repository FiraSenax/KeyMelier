"""A lock/cancel must reach PIN requests queued before device access."""
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2.ctap2.pin import ClientPin
from fido2tool_core import auth, service
from fido2tool_core.history import History


class UnlockQueueTests(unittest.TestCase):
    def test_lock_or_cancel_prevents_queued_pin_from_using_the_device(self):
        for action in ('lock', 'unlock_cancel'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                auth.forget('queued-key', disconnected=True)
                self.addCleanup(auth.forget, 'queued-key', disconnected=True)
                waiting, release = threading.Event(), threading.Event()
                ctap = SimpleNamespace(info=SimpleNamespace(options={'clientPin': True}))
                scanner = Mock()

                @contextmanager
                def session(*args, **kwargs):
                    waiting.set()
                    if not release.wait(3):
                        raise AssertionError('test did not release the queued session')
                    yield object(), ctap

                scanner.session = session
                with patch.object(service, 'SETTINGS_FILE', Path(folder) / 'settings.json'):
                    svc = service.KeyService(scanner, None, history=History(Path(folder) / 'history.json'))
                outcome = []

                def run():
                    try:
                        svc.unlock('queued-key', pin='synthetic-pin')
                        outcome.append('unlocked')
                    except auth.AuthError as error:
                        outcome.append(error.code)

                with patch.object(auth, '_permissions', return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
                     patch.object(ClientPin, '__init__', lambda p, c: setattr(p, 'protocol', SimpleNamespace(VERSION=2))), \
                     patch.object(ClientPin, 'get_pin_token', return_value=b'synthetic-token') as get_token:
                    worker = threading.Thread(target=run, daemon=True)
                    worker.start()
                    try:
                        self.assertTrue(waiting.wait(3))
                        getattr(svc, action)('queued-key')
                    finally:
                        release.set()
                        worker.join(3)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(outcome, ['cancelled'])
                    self.assertFalse(auth.is_unlocked('queued-key'))
                    get_token.assert_not_called()

    def test_pin_result_after_cancellation_does_not_cache_a_token(self):
        ctap = SimpleNamespace(info=SimpleNamespace(options={'clientPin': True}))
        cancel = threading.Event()
        auth.forget('pin-in-flight', disconnected=True)
        self.addCleanup(auth.forget, 'pin-in-flight', disconnected=True)

        def finish(*args, **kwargs):
            cancel.set()
            return b'synthetic-token'

        with patch.object(auth, '_permissions', return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
             patch.object(ClientPin, '__init__', lambda p, c: setattr(p, 'protocol', SimpleNamespace(VERSION=2))), \
             patch.object(ClientPin, 'get_pin_token', side_effect=finish):
            with self.assertRaises(auth.AuthError) as caught:
                auth.unlock('pin-in-flight', ctap, pin='synthetic-pin', cancel=cancel)
        self.assertEqual(caught.exception.code, 'cancelled')
        self.assertFalse(auth.is_unlocked('pin-in-flight'))
