"""Synthetic clipboard only: never read or replace the developer's clipboard."""
import unittest
from unittest.mock import Mock

from keymelier_core.clipboard import Clipboard, EXPIRY_SECONDS


class Board:
    def __init__(self):
        self.count = 0
        self.text = None
        self.sensitive = False

    def write(self, text, sensitive=False):
        self.count += 1
        self.text, self.sensitive = text, sensitive
        return self.count

    def clear(self, generation):
        if self.count == generation:
            self.text = None
            self.count += 1


class ClipboardTests(unittest.TestCase):
    def setUp(self):
        self.board = Board()
        self.timers = []

        def timer(seconds, callback):
            timer = Mock(seconds=seconds, callback=callback)
            self.timers.append(timer)
            return timer

        self.clipboard = Clipboard(lambda: None, backend=self.board, invoke=lambda fn: fn(), timer=timer)

    def test_secret_expires_without_retaining_text_in_timer(self):
        self.assertTrue(self.clipboard.copy('synthetic-code', True))
        self.assertTrue(self.board.sensitive)
        timer = self.timers[0]
        self.assertEqual(timer.seconds, EXPIRY_SECONDS)
        self.assertTrue(timer.daemon)
        timer.start.assert_called_once()
        self.assertNotIn('synthetic-code', vars(self.clipboard).values())
        self.assertNotIn('synthetic-code', [cell.cell_contents for cell in timer.callback.__closure__])
        timer.callback()
        self.assertIsNone(self.board.text)

    def test_same_text_copied_elsewhere_is_not_cleared(self):
        self.clipboard.copy('same', True)
        self.board.write('same')  # native ownership changed, even though text is equal
        self.timers[0].callback()
        self.assertEqual(self.board.text, 'same')

    def test_old_timer_cannot_clear_new_secret_or_public_text(self):
        self.clipboard.copy('old', True)
        self.clipboard.copy('new', True)
        self.timers[0].cancel.assert_called_once()
        self.timers[0].callback()  # cancelled timer already dispatched
        self.assertEqual(self.board.text, 'new')
        self.clipboard.copy('public certificate')
        self.timers[1].callback()
        self.assertEqual(self.board.text, 'public certificate')
        self.assertFalse(self.board.sensitive)
        self.assertEqual(len(self.timers), 2)

    def test_copy_failure_is_reported_and_does_not_cancel_existing_expiry(self):
        self.clipboard.copy('existing', True)
        self.clipboard.invoke = Mock(side_effect=RuntimeError('synthetic failure'))
        with self.assertLogs('keymelier_core.clipboard'):
            self.assertFalse(self.clipboard.copy('failed', True))
        self.timers[0].cancel.assert_not_called()
        self.clipboard.invoke = lambda fn: fn()
        self.timers[0].callback()
        self.assertIsNone(self.board.text)

    def test_invalid_input_never_reaches_native_board(self):
        for text, sensitive in [(None, False), ('a' * 16385, True), ('text', 'true')]:
            self.assertFalse(self.clipboard.copy(text, sensitive))
        self.assertEqual(self.board.count, 0)
