import os
import unittest
from unittest.mock import patch

from keymelier_core.selftest import _check_replacements


class SelfTestProbeTests(unittest.TestCase):
    def test_malformed_probe_is_a_failed_check_without_aborting_report(self):
        for raw in ('{', 'null', '[]', '"private-fixture"', '{"qt":123}', '{"unknown":"value"}'):
            results = []

            def check(name, fn):
                try:
                    results.append((name, fn(), ""))
                except Exception as error:
                    results.append((name, False, str(error)))

            with self.subTest(raw=raw), patch.dict(os.environ, KEYMELIER_LIBRARY_PROBE=raw):
                _check_replacements(check)
                self.assertEqual(results, [("replacement: probe configuration", False,
                                            "Invalid library probe configuration")])

    def test_default_probe_and_explicit_replacement(self):
        results = []
        with patch.dict(os.environ, KEYMELIER_LIBRARY_PROBE='{}'):
            _check_replacements(lambda name, fn: results.append((name, fn())))
        self.assertEqual(results, [("replacement: probe configuration", True)])
        import smartcard.System
        with patch.dict(os.environ, KEYMELIER_LIBRARY_PROBE='{"pyscard":"changed-library"}'), \
                patch.object(smartcard.System, "__keymelier_replacement_probe__", "changed-library", create=True):
            _check_replacements(lambda name, fn: results.append((name, fn())))
        self.assertEqual(results[-1], ("replacement: pyscard", True))

