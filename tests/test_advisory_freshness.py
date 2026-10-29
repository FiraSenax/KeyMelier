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

    def test_signed_date_bounds_and_malformed_dates(self):
        for age, expected in [(0, True), (44, True), (45, False), (46, False), (-1, True), (-2, False)]:
            with self.subTest(age=age):
                self.assertEqual(updates.is_fresh(self.document(age)), expected)
        for document in [None, {}, {'updated': 'bad'}, {'updated': None}, {'updated': []}]:
            with self.subTest(document=document):
                self.assertFalse(updates.is_fresh(document))
        self.assertTrue(updates.is_fresh({'updated': '2026-10-29T12:00:00Z'}))
        self.assertTrue(updates.is_fresh({'updated': '2026-10-29'}))


if __name__ == '__main__':
    unittest.main()
