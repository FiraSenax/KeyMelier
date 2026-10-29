import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keymelier_core import updates
from keymelier_core.scanner import TokenRecord, TokenScanner
from tools import advisories_sign


class AdvisoryFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        self.key = Ed25519PrivateKey.generate()
        public = base64.b64encode(self.key.public_key().public_bytes_raw()).decode()
        verify = updates.verify
        patcher = patch.object(updates, 'verify', side_effect=lambda data, sig: verify(data, sig, public))
        patcher.start()
        self.addCleanup(patcher.stop)
        clock = patch.object(updates, 'datetime', wraps=datetime)
        clock.start().now.return_value = self.now
        self.addCleanup(clock.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = Path(tmp.name) / 'advisories.json'
        for name, value in [('CACHE_FILE', self.cache), ('CACHE_SIG', self.cache.with_suffix('.json.sig')),
                            ('stateless', Mock(return_value=False))]:
            patcher = patch.object(updates, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def document(self, days_old):
        return {'updated': (self.now - timedelta(days=days_old)).isoformat(), 'advisories': []}

    def fetch(self, document, current, *, tamper=False):
        data = json.dumps(document).encode()
        signature = base64.b64encode(self.key.sign(data))
        if tamper:
            data += b' '

        def get(url, **kwargs):
            response = MagicMock()
            response.__enter__.return_value = response
            response.headers = {}
            response.iter_content.return_value = [signature if url == updates.SIGNATURE_URL else data]
            return response

        with patch('requests.get', side_effect=get):
            return updates.fetch(current)

    def write_signed(self, path, document):
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(document).encode()
        path.write_bytes(data)
        Path(str(path) + '.sig').write_bytes(base64.b64encode(self.key.sign(data)))

    def status(self, document):
        mds = Mock()
        mds.lookup.return_value = {'metadataStatement': {}}
        mds.get_highest_security_status.return_value = 'FIDO_CERTIFIED_L2'
        mds.is_current.return_value = True
        advisories = Mock(document=document)
        advisories.check.return_value = []
        record = TokenRecord('id', '/dev/test', 'test', 'serial', 'vendor', 'aaguid',
                             [], [], {}, [], None, None, '', 'now')
        record.attestation = {'status': 'VERIFIED'}
        TokenScanner(mds3_client=mds, advisory_checker=advisories)._enrich_record(record)
        return record.security_status

    def test_replaying_older_or_equal_signed_document_cannot_restore_ok(self):
        current = self.document(90)
        for age in (400, 90):
            with self.subTest(age=age):
                self.assertEqual(self.status(current), 'UNKNOWN')
                self.assertIsNone(self.fetch(self.document(age), current))
                self.assertEqual(self.status(current), 'UNKNOWN')
                self.assertFalse(self.cache.exists())

    def test_newer_but_stale_signed_document_keeps_unknown(self):
        downloaded = self.fetch(self.document(60), self.document(90))
        self.assertEqual(downloaded, self.document(60))
        self.assertEqual(self.status(downloaded), 'UNKNOWN')

    def test_fresh_signed_document_restores_ok_only_for_that_document(self):
        stale = self.document(90)
        downloaded = self.fetch(self.document(1), stale)
        self.assertEqual(self.status(downloaded), 'OK')
        self.assertEqual(self.status(stale), 'UNKNOWN')
        self.assertEqual(updates._read_signed(self.cache, self.cache.with_suffix('.json.sig')), downloaded)

    def test_invalid_signature_cannot_refresh_or_replace_cache(self):
        current = self.fetch(self.document(90), None)
        before = self.cache.read_bytes()
        self.assertIsNone(self.fetch(self.document(1), current, tamper=True))
        self.assertEqual(self.cache.read_bytes(), before)
        self.assertEqual(self.status(current), 'UNKNOWN')

    def test_future_download_never_replaces_valid_cache(self):
        current = self.fetch(self.document(3), None)
        before = self.cache.read_bytes()
        self.assertIsNone(self.fetch(self.document(-365), current))
        self.assertEqual(self.cache.read_bytes(), before)

    def test_future_cache_is_ignored_and_can_recover_to_correctly_dated_update(self):
        bundled = self.cache.parent / 'bundled'
        self.write_signed(bundled / 'advisories.json', self.document(7))
        self.write_signed(self.cache, self.document(-365))
        self.assertEqual(updates.load_best(bundled), (self.document(7), 'bundled'))
        # Also recover an in-memory document loaded by an older application.
        corrected = self.fetch(self.document(1), self.document(-365))
        self.assertEqual(corrected, self.document(1))
        self.assertEqual(updates.load_best(bundled), (corrected, 'downloaded'))

    def test_future_bundle_cannot_win_over_valid_cache(self):
        bundled = self.cache.parent / 'bundled'
        self.write_signed(bundled / 'advisories.json', self.document(-365))
        self.assertEqual(updates.load_best(bundled), (None, 'bundled'))
        self.write_signed(self.cache, self.document(7))
        self.assertEqual(updates.load_best(bundled), (self.document(7), 'downloaded'))

    def test_future_clock_tolerance_remains_bounded(self):
        tolerated = self.document(-1)
        self.assertEqual(self.fetch(tolerated, self.document(1)), tolerated)
        # Within the allowed clock skew, the anti-rollback rule still applies.
        self.assertIsNone(self.fetch(self.document(0), tolerated))
        too_far = {'updated': (self.now + timedelta(days=1, seconds=1)).isoformat(), 'advisories': []}
        self.assertIsNone(self.fetch(too_far, tolerated))

    def test_signed_date_bounds_and_malformed_dates(self):
        for age, expected in [(0, True), (44, True), (45, False), (46, False), (-1, True), (-2, False)]:
            with self.subTest(age=age):
                self.assertEqual(updates.is_fresh(self.document(age)), expected)
        for document in [None, {}, {'updated': 'bad'}, {'updated': None}, {'updated': []}]:
            with self.subTest(document=document):
                self.assertFalse(updates.is_fresh(document))
        self.assertTrue(updates.is_fresh({'updated': '2026-10-29T12:00:00Z'}))
        self.assertTrue(updates.is_fresh({'updated': '2026-10-29'}))


class AdvisoryReleaseGateTests(unittest.TestCase):
    def test_release_gate_checks_signed_date_and_authenticity(self):
        now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        with tempfile.TemporaryDirectory() as tmp, patch.object(updates, 'datetime', wraps=datetime) as clock:
            clock.now.return_value = now
            path = Path(tmp) / 'advisories.json'
            for age, accepted in [(0, True), (13, True), (14, False), (33, False), (-2, False)]:
                with self.subTest(age=age):
                    data = json.dumps({'updated': (now - timedelta(days=age)).isoformat(), 'advisories': []}).encode()
                    path.write_bytes(data)
                    Path(str(path) + '.sig').write_bytes(base64.b64encode(key.sign(data)))
                    advisories_sign.verify_file(path, public)  # legacy signature-only CLI stays valid
                    if accepted:
                        advisories_sign.verify_file(path, public, max_age_days=14)
                    else:
                        with self.assertRaises(ValueError):
                            advisories_sign.verify_file(path, public, max_age_days=14)
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'SIGNATURE INVALID'):
                advisories_sign.verify_file(path, public, max_age_days=14)


if __name__ == '__main__':
    unittest.main()
