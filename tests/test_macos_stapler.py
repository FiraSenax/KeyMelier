import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import macos_stapler


class MacOSStaplerTests(unittest.TestCase):
    def result(self, code, output=''):
        return subprocess.CompletedProcess([], code, output, '')

    def test_connection_loss_is_retried_but_still_requires_success(self):
        lost = self.result(68, 'Error Domain=NSURLErrorDomain Code=-1005 "The network connection was lost."')
        success = self.result(0, 'The validate action worked!')
        with patch.object(macos_stapler.subprocess, 'run', side_effect=[lost, success]) as command, \
                patch.object(macos_stapler.time, 'sleep') as sleep:
            self.assertIs(macos_stapler.run('validate', 'test.app'), success)
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args_list[0], command.call_args_list[1])
        sleep.assert_called_once_with(5)

    def test_persistent_connection_loss_remains_a_failure_after_three_attempts(self):
        lost = self.result(68, 'NSURLErrorDomain Code=-1005')
        with patch.object(macos_stapler.subprocess, 'run', return_value=lost) as command, \
                patch.object(macos_stapler.time, 'sleep') as sleep:
            self.assertIs(macos_stapler.run('staple', 'test.dmg'), lost)
        self.assertEqual(command.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 15])

    def test_other_ticket_failures_are_not_retried(self):
        for result in (self.result(68, 'Ticket invalid'), self.result(65, 'NSURLErrorDomain Code=-1005')):
            with self.subTest(code=result.returncode), \
                    patch.object(macos_stapler.subprocess, 'run', return_value=result) as command, \
                    patch.object(macos_stapler.time, 'sleep') as sleep:
                self.assertIs(macos_stapler.run('validate', 'test.app'), result)
            command.assert_called_once()
            sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
