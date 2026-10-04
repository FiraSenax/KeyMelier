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
    def test_lock_or_cancel_reaches_pin_waiting_for_cancelled_fingerprint(self):
        for action in ('lock', 'unlock_cancel'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                token_id = 'waiting-for-fingerprint'
                auth.forget(token_id, disconnected=True)
                self.addCleanup(auth.forget, token_id, disconnected=True)
                waiting = threading.Event()
                ctap = SimpleNamespace(info=SimpleNamespace(options={'clientPin': True}))

                @contextmanager
                def session(*args, **kwargs):
                    yield object(), ctap

                scanner = Mock()
                scanner.session = Mock(side_effect=session)
                with patch.object(service, 'SETTINGS_FILE', Path(folder) / 'settings.json'):
                    svc = service.KeyService(scanner, None, history=History(Path(folder) / 'history.json'))
                original_wait = svc._unlock_waits._released.wait

                def observed_wait(timeout=None):
                    waiting.set()
                    return original_wait(timeout)

                outcome = []

                def run():
                    try:
                        svc.unlock(token_id, pin='synthetic-pin')
                        outcome.append('unlocked')
                    except auth.AuthError as error:
                        outcome.append(error.code)

                with patch.object(svc._unlock_waits._released, 'wait', side_effect=observed_wait), \
                     patch.object(auth, '_permissions', return_value=ClientPin.PERMISSION.CREDENTIAL_MGMT), \
                     patch.object(ClientPin, '__init__', lambda p, c: setattr(p, 'protocol', SimpleNamespace(VERSION=2))), \
                     patch.object(ClientPin, 'get_pin_token', return_value=b'synthetic-token') as get_token:
                    # The finger wait still owns the slot after "Enter PIN instead".
                    with svc._unlock_waits.start(token_id):
                        svc.unlock_cancel(token_id)
                        worker = threading.Thread(target=run, daemon=True)
                        worker.start()
                        entered_wait = waiting.wait(3)
                        getattr(svc, action)(token_id)
                        worker.join(3)
                        stopped_before_release = not worker.is_alive()
                    worker.join(3)
                    self.assertTrue(entered_wait)
                    self.assertTrue(stopped_before_release, 'cancel must not wait for the finger operation')
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(outcome, ['cancelled'])
                    scanner.session.assert_not_called()
                    get_token.assert_not_called()
                    self.assertFalse(auth.is_unlocked(token_id))

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


class PendingSlotTests(unittest.TestCase):
    """"Enter PIN instead" while the key still ends the finger wait: the PIN
    request waits for the cancelled request's slot instead of failing busy."""

    def test_cancel_reaches_all_waiters_and_a_later_request_can_start(self):
        from fido2tool_core.operations import PendingOperations
        ops = PendingOperations()
        waiting = [threading.Event(), threading.Event()]
        outcome = []
        original_wait = ops._released.wait

        def observed_wait(timeout=None):
            waiting[int(threading.current_thread().name)].set()
            return original_wait(timeout)

        def run():
            try:
                with ops.start('key', wait=3):
                    outcome.append('started')
            except auth.AuthError as error:
                outcome.append(error.code)

        workers = [threading.Thread(target=run, name=str(i), daemon=True) for i in range(2)]
        with patch.object(ops._released, 'wait', side_effect=observed_wait):
            with ops.start('key'):
                ops.cancel('key')
                for worker in workers:
                    worker.start()
                entered_wait = [event.wait(3) for event in waiting]
                ops.cancel('key')
                for worker in workers:
                    worker.join(3)
                stopped_before_release = all(not worker.is_alive() for worker in workers)
            for worker in workers:
                worker.join(3)
        self.assertTrue(all(entered_wait))
        self.assertTrue(stopped_before_release)
        self.assertEqual(outcome, ['cancelled', 'cancelled'])
        self.assertFalse(ops.cancel('key'), 'finished waiters leave no stale cancellation target')
        with ops.start('key') as cancel:
            self.assertFalse(cancel.is_set(), 'a new request is independent of earlier cancellations')
            self.assertTrue(ops.cancel('key'))
            self.assertTrue(cancel.is_set())
        self.assertFalse(ops.cancel('key'))

    def test_wait_timeout_leaves_no_pending_request(self):
        from fido2tool_core.operations import PendingOperations
        ops = PendingOperations()
        with ops.start('key'):
            ops.cancel('key')
            with self.assertRaises(auth.AuthError) as busy:
                with ops.start('key', wait=0.01):
                    self.fail('timed-out request started')
            self.assertEqual(busy.exception.code, 'busy')
        self.assertFalse(ops.cancel('key'), 'timed-out waiters must be removed')
        with ops.start('key') as cancel:
            self.assertFalse(cancel.is_set())

    def test_waits_for_a_cancelled_operation_but_not_for_a_running_one(self):
        from fido2tool_core.operations import PendingOperations
        ops = PendingOperations()
        entered, leave, got = threading.Event(), threading.Event(), []

        def finger_wait():
            with ops.start('key'):
                entered.set()
                leave.wait(3)
        worker = threading.Thread(target=finger_wait, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(3))
        with self.assertRaises(auth.AuthError) as busy:
            with ops.start('key', wait=1):
                pass
        self.assertEqual(busy.exception.code, 'busy', 'a running request is not queued behind')

        ops.cancel('key')
        threading.Timer(0.1, leave.set).start()   # the key confirms the cancel a moment later

        with ops.start('key', wait=3):
            got.append('pin request ran')
        worker.join(3)
        self.assertEqual(got, ['pin request ran'])
