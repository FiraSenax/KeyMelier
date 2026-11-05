"""Rejected policy input must not disappear into a successful empty assessment."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from datetime import datetime, timezone

from keymelier_core import advisories, policy
from keymelier_core.advisories import AdvisoryChecker
from keymelier_core.scanner import TokenScanner
from tests.test_policy import AAGUID, DATA, FW_5_4, OFFICIAL_ID, corp, keypair, write_source
from tests.test_rc4_review import record


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        cache = patch.object(advisories, 'CACHE_DIR', Path(temporary.name))
        cache.start()
        self.addCleanup(cache.stop)

    def test_scanner_blocks_ok_but_preserves_warning_and_critical(self):
        mds = Mock()
        mds.lookup.return_value = {'metadataStatement': {}}
        mds.get_highest_security_status.return_value = 'FIDO_CERTIFIED_L2'
        mds.is_current.return_value = True
        with patch.object(policy, 'read_raw', return_value={'AdvisorySources': [{}]}):
            checker = AdvisoryChecker(DATA)
        scanner = TokenScanner(mds3_client=mds, advisory_checker=checker)
        token = record()
        token.aaguid = AAGUID
        token.attestation = {'status': 'VERIFIED', 'passed': True}
        for severity, expected in ((None, 'UNKNOWN'), ('HIGH', 'WARNING'), ('CRITICAL', 'CRITICAL')):
            checker.use({'updated': datetime.now(timezone.utc).isoformat(),
                         'advisories': [corp(aaguid=AAGUID, severity=severity)] if severity else []}, 'test')
            scanner._enrich_record(token)
            self.assertEqual(token.security_status, expected)
        token.security_status = 'OK'
        self.assertTrue(scanner._expire_assessment(token))
        self.assertEqual(token.security_status, 'UNKNOWN')

    def test_absent_and_explicit_empty_are_valid(self):
        for raw in ({}, {"AdvisorySources": []}):
            with self.subTest(raw=raw), patch.object(policy, 'read_raw', return_value=raw):
                checker = AdvisoryChecker(DATA)
                self.assertTrue(checker.policy_is_current())
                self.assertFalse(checker.info()['policy_config_error'])

    def test_bad_entries_preserve_valid_sources_and_official_findings(self):
        priv, pub = keypair()
        with tempfile.TemporaryDirectory() as tmp:
            valid = {'Name': 'IT', 'Location': write_source(Path(tmp), priv, [corp()]), 'PublicKey': pub}
            bad_entries = [None, {}, {**valid, 'PublicKey': 'bad'}, {**valid, 'Location': 'https://'},
                           {**valid, 'Location': 'relative.json'},
                           {**valid, 'Name': ''}, valid]
            for bad in bad_entries:
                with self.subTest(bad=bad), patch.object(policy, 'read_raw', return_value={'AdvisorySources': [valid, bad]}):
                    checker = AdvisoryChecker(DATA)
                    self.assertFalse(checker.policy_is_current())
                    self.assertTrue(checker.info()['policy_config_error'])
                    self.assertEqual(len(checker.info()['policy']), 1)
                    self.assertEqual(checker.info()['policy'][0]['count'], 1)
                    self.assertIn(OFFICIAL_ID, [a['id'] for a in checker.check(AAGUID, FW_5_4, 'Yubico')])
                    self.assertIsInstance(policy.advisory_sources(), list)

    def test_invalid_container_read_failure_and_source_limit(self):
        pub = keypair()[1]
        entries = [{'Name': str(i), 'Location': 'https://example.com/a', 'PublicKey': pub}
                   for i in range(policy.MAX_SOURCES + 1)]
        for raw in ([], {'AdvisorySources': None}, {'AdvisorySources': {}},
                    policy.PolicyRead(failed=True), {'AdvisorySources': entries}):
            with self.subTest(raw=raw):
                sources, failed = policy.advisory_configuration(raw)
                self.assertTrue(failed)
                self.assertLessEqual(len(sources), policy.MAX_SOURCES)

    def test_file_readers_distinguish_absence_rejection_and_malformed_data(self):
        for reader in (policy._read_linux, policy._read_mac):
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'policy'
                self.assertEqual(policy.advisory_configuration(reader(path)), ([], False))
                path.write_text('malformed', encoding='utf-8')
                for protected in (True, False):
                    with patch.object(policy, '_protected', return_value=protected):
                        self.assertTrue(policy.advisory_configuration(reader(path))[1])
                with patch.object(Path, 'stat', side_effect=PermissionError):
                    self.assertTrue(policy.advisory_configuration(reader(path))[1])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'policy.json'
            path.write_text(json.dumps([]))
            with patch.object(policy, '_protected', return_value=True):
                self.assertTrue(policy.advisory_configuration(policy._read_linux(path))[1])

    def test_windows_absence_denial_and_partial_enumeration(self):
        class Handle:
            def __enter__(self): return self
            def __exit__(self, *args): pass

        pub = keypair()[1]
        for error, failed in ((FileNotFoundError(), False), (PermissionError(), True)):
            fake = SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=lambda *a: (_ for _ in ()).throw(error))
            with patch.dict(sys.modules, {'winreg': fake}):
                self.assertEqual(policy.advisory_configuration(policy._read_windows())[1], failed)
        for code in (259, 5):
            end = OSError('synthetic registry error')
            end.winerror = code
            def enum_key(handle, index):
                if index == 0:
                    return 'IT'
                raise end
            fake = SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=lambda *a: Handle(), EnumKey=enum_key,
                                   QueryValueEx=lambda h, k: ({'Location': 'https://example.com/a', 'PublicKey': pub}[k], 1))
            with patch.dict(sys.modules, {'winreg': fake}):
                sources, failed = policy.advisory_configuration(policy._read_windows())
            self.assertEqual(len(sources), 1)
            self.assertEqual(failed, code != 259)

    def test_reader_exception_blocks_ok_until_restart_with_corrected_policy(self):
        with patch.object(policy, '_read_windows', side_effect=PermissionError), patch.object(sys, 'platform', 'win32'):
            checker = AdvisoryChecker(DATA)
        self.assertFalse(checker.policy_is_current())
        with patch.object(policy, 'read_raw', return_value={}):
            self.assertTrue(AdvisoryChecker(DATA).policy_is_current())
