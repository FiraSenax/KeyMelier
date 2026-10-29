"""Reproduce the RC4 review's trust-boundary failures against the current tree."""
import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import app
from keymelier_core import advisories, history, sync
from keymelier_core.firmware import decode_firmware
from keymelier_core.mds3 import MDS3Client
from keymelier_core.scanner import TokenRecord, TokenScanner

DATA = Path(__file__).resolve().parent.parent / 'data'


def record():
    return TokenRecord('id', '/dev/test', 'Key', 'serial', 'vendor', 'aaguid', [], [], {}, [], None, None, '', 'now')


class ManagedTrustTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.private = Ed25519PrivateKey.generate()
        self.source = {'name': 'IT', 'location': str(self.root / 'source.json'),
                       'public_key': base64.b64encode(self.private.public_key().public_bytes_raw()).decode()}
        p = patch.object(advisories, 'CACHE_DIR', self.root / 'cache')
        p.start()
        self.addCleanup(p.stop)
        self.now = datetime.now(timezone.utc)

    def write(self, age=0, entries=None):
        data = json.dumps({'updated': (self.now - timedelta(days=age)).isoformat(), 'advisories': entries or []}).encode()
        Path(self.source['location']).write_bytes(data)
        Path(self.source['location'] + '.sig').write_bytes(base64.b64encode(self.private.sign(data)))

    def checker(self, defer=False):
        checker = advisories.AdvisoryChecker(DATA, [self.source], defer_policy=defer)
        checker.use({'updated': self.now.isoformat(), 'advisories': []}, 'test')
        return checker

    def scanner(self, checker):
        mds = Mock()
        mds.lookup.return_value = {'metadataStatement': {}}
        mds.get_highest_security_status.return_value = 'FIDO_CERTIFIED_L2'
        mds.is_current.return_value = True
        scanner = TokenScanner(mds3_client=mds, advisory_checker=checker)
        token = record()
        token.attestation = {'status': 'VERIFIED', 'passed': True}
        scanner._enrich_record(token)
        return scanner, token

    def test_pending_unreachable_invalid_and_expired_sources_prevent_ok(self):
        self.write()
        checker = self.checker(defer=True)
        self.assertEqual(self.scanner(checker)[1].security_status, 'UNKNOWN')
        checker.load_policy_sources()
        self.assertEqual(self.scanner(checker)[1].security_status, 'OK')
        Path(self.source['location']).unlink()
        checker.load_policy_sources()
        self.assertEqual(self.scanner(checker)[1].security_status, 'UNKNOWN')
        self.write()
        Path(self.source['location'] + '.sig').write_text('bad signature')
        checker.load_policy_sources()
        self.assertEqual(self.scanner(checker)[1].security_status, 'UNKNOWN')
        self.source['name'] = 'different cache identity'
        self.write(age=46)
        self.assertEqual(self.scanner(self.checker())[1].security_status, 'UNKNOWN')

    def test_cached_warning_and_rollback_floor_survive_restart(self):
        entry = {'id': 'CORP-1', 'affected_aaguids': ['00000000-1111-2222-3333-444444444444'], 'severity': 'HIGH'}
        self.write(entries=[entry])
        self.assertTrue(self.checker().policy_is_current())
        self.write(age=1)
        restarted = self.checker()
        self.assertFalse(restarted.policy_is_current())
        self.assertEqual(restarted.check(entry['affected_aaguids'][0], None)[0]['id'], 'CORP-1')
        Path(self.source['location']).unlink()
        self.assertEqual(self.checker().check(entry['affected_aaguids'][0], None)[0]['id'], 'CORP-1')

    def test_tampered_cache_cannot_authorize_a_document(self):
        self.write()
        self.checker()
        cache = advisories._cache_path(self.source)
        value = json.loads(cache.read_bytes())
        value['data'] = base64.b64encode(b'{"updated":"9999-01-01","advisories":[]}').decode()
        cache.write_text(json.dumps(value))
        Path(self.source['location']).unlink()
        checker = self.checker()
        self.assertIsNone(checker._extra['IT']['document'])
        self.assertFalse(checker.policy_is_current())

    def test_expiry_downgrades_ok_without_waiting_for_network_refresh(self):
        self.write()
        checker = self.checker()
        scanner, token = self.scanner(checker)
        self.assertEqual(token.security_status, 'OK')
        checker.document['updated'] = (self.now - timedelta(days=46)).isoformat()
        self.assertTrue(scanner._expire_assessment(token))
        self.assertEqual(token.security_status, 'UNKNOWN')
        self.assertEqual(token.attestation['status'], 'VERIFIED', 'advisory age does not invalidate the device signature')

    def test_invalid_cache_shape_and_failed_cache_write_do_not_authorize_ok(self):
        self.write()
        checker = self.checker()
        cache = advisories._cache_path(self.source)
        for value in ([], None, {'data': '', 'signature': []}):
            cache.write_text(json.dumps(value))
            pending = self.checker(defer=True)
            self.assertIsNone(pending._extra['IT']['document'])
            self.assertFalse(pending.policy_is_current())
        with patch.object(advisories, 'atomic_write', side_effect=OSError('read-only')):
            checker.load_policy_sources()
        self.assertFalse(checker.policy_is_current())
        checker.load_policy_sources()
        self.assertTrue(checker.policy_is_current())

    def test_policy_check_does_not_authorize_ok_during_a_reload(self):
        self.write()
        checker = self.checker()
        read = advisories._read_source

        def reading(location):
            self.assertFalse(checker.policy_is_current())
            return read(location)
        with patch.object(advisories, '_read_source', side_effect=reading):
            checker.load_policy_sources()
        self.assertTrue(checker.policy_is_current())

    def test_managed_http_redirect_is_rejected_without_following_it(self):
        response = MagicMock(status_code=302)
        response.__enter__.return_value = response
        with patch('requests.get', return_value=response) as get:
            with self.assertRaises(ValueError):
                advisories._read_source('https://intranet.example/a.json')
        self.assertFalse(get.call_args.kwargs['allow_redirects'])
        response.iter_content.assert_not_called()


class SyncInputTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        # Real AES-GCM/authentication, cheap deterministic KDF for malformed-input tests.
        p = patch.object(sync, '_derive', return_value=b'K' * 32)
        p.start()
        self.addCleanup(p.stop)

    def encrypted_plaintext(self, plaintext):
        header = {'format': sync.FORMAT, 'v': sync.VERSION, 'device': 'a' * 16, 'salt': sync._b64(b'S' * 16)}
        nonce = b'N' * 12
        ciphertext = AESGCM(b'K' * 32).encrypt(nonce, plaintext, sync._aad(header))
        return json.dumps({**header, 'nonce': sync._b64(nonce), 'ct': sync._b64(ciphertext)}).encode()

    def test_nested_or_invalid_json_is_a_reportable_file_error(self):
        for plain in (b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}', b'not json', b'[]',
                      b'{"n":' + b'9' * 5000 + b'}'):
            for data in (plain, self.encrypted_plaintext(plain)):
                with self.subTest(length=len(data)), self.assertRaises(sync.SyncError) as error:
                    sync.unseal(data, 'passphrase')
                self.assertEqual(error.exception.code, 'sync_damaged')

    def test_poison_peer_does_not_prevent_good_merge_or_local_write(self):
        cloud = self.root / 'cloud'
        cloud.mkdir()
        local = history.History(self.root / 'local.json', enabled=True)
        peer = history.History(enabled=False)
        peer.update_snapshot(record())
        runner = sync.Syncer(local, lambda *_: None, lambda: True)
        runner._folder = sync.SyncFolder(cloud, 'f' * 16, 'passphrase')
        bad = cloud / ('KeyMelier-' + 'a' * 16 + '.kmsync')
        good = cloud / ('KeyMelier-' + 'b' * 16 + '.kmsync')
        bad.write_bytes(sync.seal({'history': {'forgotten': ['wrong type']}}, 'passphrase', 'a' * 16))
        good.write_bytes(sync.seal({'history': peer.sync_state()}, 'passphrase', 'b' * 16))
        runner.run_once()
        self.assertEqual(len(local.list()), 1)
        self.assertTrue(runner._folder.own_path.exists())
        self.assertNotIn(bad.name, runner._folder._seen)
        self.assertIn(good.name, runner._folder._seen)
        self.assertEqual(runner.run_once()['errors'], [{'file': bad.name, 'code': 'sync_damaged'}])
        bad.write_bytes(sync.seal({'history': {}}, 'passphrase', 'a' * 16))
        self.assertEqual(runner.run_once()['errors'], [])
        self.assertIn(bad.name, runner._folder._seen)

    def test_future_tombstone_cannot_remove_or_pin_a_key(self):
        local = history.History(enabled=False)
        kid = local.update_snapshot(record())['key_id']
        local.merge_sync({'forgotten': {kid: '9999-01-01T00:00:00+00:00'}})
        self.assertIsNotNone(local.get(kid))
        self.assertEqual(local.sync_state()['forgotten'], {})
        local._forgotten[kid] = '9999-01-01T00:00:00+00:00'  # recover pre-fix state too
        local.merge_sync({})
        self.assertIsNotNone(local.get(kid))
        self.assertEqual(local.sync_state()['forgotten'], {})

    def test_timestamp_offsets_compare_by_instant_and_future_fields_do_not_win(self):
        local = history.History(enabled=False)
        kid = local.update_snapshot(record())['key_id']
        local.rename(kid, 'local')
        local._entries[kid]['label_at'] = '2020-01-01T10:00:00+00:00'
        local.merge_sync({'keys': [{'key_id': kid, 'label': 'earlier', 'label_at': '2020-01-01T11:00:00+02:00'}]})
        self.assertEqual(local.get(kid)['label'], 'local')
        local.merge_sync({'keys': [{'key_id': kid, 'label': 'future', 'label_at': '9999-01-01T00:00:00Z',
                                   'lost_at': '9999-01-01T00:00:00Z', 'lost_since': '9999-01-01T00:00:00Z'}]})
        self.assertEqual(local.get(kid)['label'], 'local')
        self.assertNotIn('lost_since', local.get(kid))
        self.assertEqual(history._clean_stamp('2020-01-01T11:00:00+02:00'), '2020-01-01T09:00:00.000000+00:00')

    def test_tombstones_are_bounded_and_bad_structure_has_no_partial_effect(self):
        local = history.History(enabled=False)
        before = local.sync_state()
        with self.assertRaises(ValueError):
            local.merge_sync({'forgotten': [], 'keys': [{'key_id': 'a' * 16}]})
        self.assertEqual(local.sync_state(), before)
        with patch.object(history, 'MAX_FORGOTTEN', 2):
            local.merge_sync({'forgotten': {f'{n:016x}': history._now() for n in range(5)}})
        self.assertEqual(len(local.sync_state()['forgotten']), 2)

    def test_imported_test_claims_are_marked_and_never_become_a_verdict(self):
        for source in ('import', 'sync'):
            entry = history._clean_entry({'key_id': 'a' * 16, 'events': [
                {'type': kind, 'ts': history._now(), 'passed': True, 'source': 'local'}
                for kind in ('attestation', 'function_test')]}, source=source)
            self.assertEqual([event['source'] for event in entry['events']], [source, source])
            self.assertEqual(entry['snapshot']['security_status'], 'UNKNOWN')

    def test_timestamp_normalization_does_not_duplicate_existing_local_events(self):
        local = history.History(enabled=False)
        kid = local.add_event(record(), 'attestation', passed=True)['key_id']
        local._entries[kid]['events'][0]['ts'] = '2020-01-01T01:00:00+01:00'
        peer = local.sync_state()
        peer['keys'][0]['events'][0]['ts'] = '2020-01-01T00:00:00Z'
        local.merge_sync(peer)
        self.assertEqual(len(local.get(kid)['events']), 1)
        self.assertNotIn('source', local.get(kid)['events'][0], 'the local test remains local')

    def test_locked_encrypted_history_preserves_bytes_and_allows_startup(self):
        path = self.root / 'history.json'
        encrypted = path.with_suffix('.encrypted')
        encrypted.write_bytes(b'opaque encrypted data')
        with patch.dict(os.environ, KEYMELIER_ENCRYPT_HISTORY='1'), \
                patch.object(history, 'history_cipher', side_effect=RuntimeError('keychain locked')):
            local = history.History(path, enabled=True)
            local.update_snapshot(record())
            self.assertFalse(local.enabled)
            self.assertEqual(local.load_problem['code'], 'history_locked')
            self.assertFalse(path.exists())
            self.assertEqual(encrypted.read_bytes(), b'opaque encrypted data')


class SmallerBoundaryTests(unittest.TestCase):
    def test_device_pin_minimum_is_bounded_and_malformed_setting_disabled(self):
        from keymelier_core import key_config
        info = SimpleNamespace(options={'setMinPINLength': True})
        with patch('fido2.ctap2.config.Config.is_supported', return_value=True), \
                patch.object(key_config.auth, 'uv_unlock_available', return_value=False):
            for value in ('4" autofocus="', True, 0, 64, None, 6):
                info.min_pin_length = value
                caps = key_config.capabilities(SimpleNamespace(info=info))
                self.assertIs(type(caps['min_pin_length']), int)
                self.assertEqual(caps['can_set_min_pin'], value == 6)

    def test_external_urls_reject_parser_ambiguity(self):
        api = app.Api(SimpleNamespace(_link_allowed=lambda _: False))
        with patch('webbrowser.open') as browser, patch.object(app, 'open_with_system') as linux:
            for url in ('https://evil.example\\@github.com/', 'https://user@github.com/',
                        'https://github.com/\n', 'https://github.com:invalid/', 'https://[bad'):
                api.open_url(url)
            browser.assert_not_called()
            linux.assert_not_called()
            api.open_url('https://github.com/FiraSenax/KeyMelier')
            self.assertEqual(browser.call_count + linux.call_count, 1)

    def test_sync_folder_requires_native_selection_or_saved_configuration(self):
        service = Mock()
        service._stored_settings.return_value = {}
        api = app.Api(service)
        with patch.object(app, 'dispatch', return_value={'ok': True}) as dispatch:
            args = {'folder': r'\\attacker.example\share', 'passphrase': 'a long passphrase'}
            self.assertFalse(api.call('sync_enable', args)['ok'])
            dispatch.assert_not_called()
            api._selected_sync_folder = args['folder']
            self.assertTrue(api.call('sync_enable', args)['ok'])
            api._selected_sync_folder = None
            service._stored_settings.return_value = {'sync_folder': args['folder']}
            self.assertTrue(api.call('sync_enable', args)['ok'])

    def test_short_decimal_firmware_does_not_skip_affected_range(self):
        self.assertEqual(decode_firmware(1203, 'unknown vendor'), '0.12.3')

    def test_latest_certification_and_compromise_precedence(self):
        client = MDS3Client.__new__(MDS3Client)
        reports = [{'status': 'FIDO_CERTIFIED_L2', 'effectiveDate': '2020-01-01'},
                   {'status': 'NOT_FIDO_CERTIFIED', 'effectiveDate': '2021-01-01'}]
        with patch.object(client, 'lookup', return_value={'statusReports': reports}):
            self.assertEqual(client.get_highest_security_status('test'), 'NOT_FIDO_CERTIFIED')
            reports.reverse()
            self.assertEqual(client.get_highest_security_status('test'), 'NOT_FIDO_CERTIFIED')
            reports.append({'status': 'REVOKED', 'effectiveDate': '2019-01-01'})
            self.assertEqual(client.get_highest_security_status('test'), 'REVOKED')


if __name__ == '__main__':
    unittest.main()
