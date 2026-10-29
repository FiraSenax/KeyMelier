"""RC7 follow-up: preserve local data and guard the repository emergency stop."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from keymelier_core import history
from keymelier_core.firmware import decode_firmware

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from check_update_revocation import check  # noqa: E402


class LocalHistoryClockTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'history.json'
        self.kid = 'a' * 16
        self.future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(timespec='microseconds')
        for p in (patch.object(history, 'stateless', return_value=False),
                  patch.dict(os.environ, {'KEYMELIER_ENCRYPT_HISTORY': '0'})):
            p.start()
            self.addCleanup(p.stop)

    def write(self, stamp):
        self.entry = {'key_id': self.kid, 'snapshot': {}, 'events': [], 'connect_count': 1,
                      'first_seen': stamp, 'last_seen': stamp, 'lost_since': stamp, 'lost_at': stamp,
                      'label': 'Local name', 'label_at': stamp, 'lost_done': ['example.com'],
                      'replace': {'new': 'b' * 16, 'since': stamp, 'done': ['pk:example.com']},
                      'replace_at': stamp, 'sites_updated': stamp,
                      'sites': [{'rp_id': 'example.com', 'checked': stamp}],
                      'inventory': {'oath': {'updated': stamp, 'items': []}},
                      'probe_rp': {'example.com': {'checked': stamp}}}
        self.path.write_text(json.dumps({'version': 1, 'keys': [self.entry]}))

    def test_local_clock_errors_survive_load_empty_sync_save_and_restart(self):
        for stamp in (self.future, 'invalid date'):
            with self.subTest(stamp=stamp):
                self.write(stamp)
                local = history.History(self.path, enabled=True)
                self.assertEqual(len(local.list()), 1)
                local.merge_sync({})
                local.rename(self.kid, 'Renamed')  # an ordinary save must not erase unrelated state
                restored = history.History(self.path, enabled=True).get(self.kid)
                for field, value in self.entry.items():
                    if field not in ('snapshot', 'label', 'label_at'):
                        self.assertEqual(restored[field], value, field)

    def test_valid_local_offset_normalizes_without_changing_the_instant(self):
        self.write('2020-01-01T12:00:00+02:00')
        loaded = history.History(self.path, enabled=True).get(self.kid)
        self.assertEqual(loaded['lost_since'], '2020-01-01T10:00:00.000000+00:00')
        self.assertEqual(loaded['lost_done'], ['example.com'])

    def test_preserved_future_clock_cannot_pin_merge_decisions(self):
        for method in ('import', 'sync'):
            with self.subTest(method=method):
                self.write(self.future)
                local = history.History(self.path, enabled=True)
                now = history._now()
                incoming = {'key_id': self.kid, 'label': 'Current name', 'label_at': now,
                            'lost_at': now, 'replace_at': now}
                if method == 'sync':
                    local.merge_sync({'keys': [incoming]})
                else:
                    local.import_({'format': 'keymelier-history', 'keys': [incoming]})
                saved = local.get(self.kid)
                self.assertEqual(saved['label'], 'Current name')
                self.assertNotIn('lost_since', saved, 'a valid later decision can explicitly clear lost')
                self.assertNotIn('replace', saved)

    def test_incoming_future_values_remain_rejected(self):
        self.write(self.future)
        incoming = history._clean_entry(self.entry, source='sync')
        for field in ('lost_since', 'lost_at', 'label_at', 'replace_at', 'sites_updated'):
            self.assertNotIn(field, incoming)
        self.assertEqual(incoming['last_seen'], '1970-01-01T00:00:00.000000+00:00')

    def test_unknown_local_chronology_does_not_authorize_remote_deletion(self):
        self.write(self.future)
        local = history.History(self.path, enabled=True)
        local.merge_sync({'forgotten': {self.kid: '2020-01-01T00:00:00Z'}})
        self.assertEqual(local.get(self.kid)['lost_since'], self.future)


class EmergencyStopGuardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'revoked.json'
        self.key = 'a' * 64

    def test_active_key_requires_matching_explicit_acknowledgement_and_reason(self):
        for acknowledgement in (None, {}, {'fingerprint': 'b' * 64, 'reason': 'Confirmed incident'},
                                {'fingerprint': self.key, 'reason': ''}):
            with self.subTest(acknowledgement=acknowledgement):
                self.path.write_text(json.dumps({'version': 1, 'revoked': [self.key],
                                                 'emergency_stop': acknowledgement}))
                with self.assertRaises(ValueError):
                    check(self.path, self.key)
        self.path.write_text(json.dumps({'version': 1, 'revoked': [self.key],
                                         'emergency_stop': {'fingerprint': self.key, 'reason': 'Confirmed incident'}}))
        check(self.path, self.key)

    def test_other_revocations_allowed_but_stale_acknowledgement_rejected(self):
        self.path.write_text(json.dumps({'version': 1, 'revoked': ['b' * 64]}))
        check(self.path, self.key)
        self.path.write_text(json.dumps({'version': 1, 'revoked': [], 'emergency_stop': {}}))
        with self.assertRaises(ValueError):
            check(self.path, self.key)


class FirmwareFallbackTests(unittest.TestCase):
    def test_three_digit_decimal_fallback_and_known_vendor_packing(self):
        self.assertEqual(decode_firmware(503, 'unknown vendor'), '0.5.3')
        self.assertEqual(decode_firmware(1203, 'unknown vendor'), '0.12.3')
        self.assertEqual(decode_firmware(50403, 'unknown vendor'), '5.4.3')
        for vendor in ('Yubico', 'Token2', 'Nitrokey'):
            self.assertEqual(decode_firmware(0x050003, vendor), '5.0.3')
            self.assertEqual(decode_firmware(503, vendor), '0.1.247')
