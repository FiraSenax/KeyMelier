import dataclasses
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2tool_core.attestation import AttestationResult, _finalize, _chain_validates, _verify_signature
from fido2tool_core.scanner import TokenRecord, TokenScanner
from fido2tool_core.history import History
from fido2tool_core.exporter import CSVExporter, _safe_cell
from fido2tool_core.service import KeyService
from fido2tool_core import updates


def record():
    return TokenRecord('id', '/dev/test', '=EVIL()', 'serial', 'vendor', 'aaguid',
                       [], [], {}, [], None, None, '', 'now')


def cert(name, key, issuer=None, issuer_key=None, ca=False, days=2, path_length=None, sign=True):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=3))
        .not_valid_after(now+timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca and sign, ca, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False))
    return builder.sign(issuer_key or key, hashes.SHA256())


class SecurityTests(unittest.TestCase):
    def test_attestation_requires_all_evidence(self):
        for evidence in [(None,None,None), (True,None,None), (True,True,None), (True,None,True)]:
            r = AttestationResult(aaguid_match=evidence[0], sig_valid=evidence[1], chain_valid=evidence[2])
            _finalize(r)
            self.assertEqual(r.status, 'UNVERIFIED')
            self.assertFalse(r.passed)
        r = AttestationResult(aaguid_match=True, sig_valid=True, chain_valid=True)
        _finalize(r)
        self.assertTrue(r.passed)
        r.checks.append({'passed':False})
        _finalize(r)
        self.assertEqual(r.status, 'FAILED')

    def test_path_constraints(self):
        rk, ik, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        root = cert('root', rk, ca=True, path_length=1)
        inter = cert('inter', ik, root, rk, ca=True, path_length=0)
        leaf = cert('leaf', lk, inter, ik)
        self.assertTrue(_chain_validates(leaf, [inter], root))
        self.assertTrue(_chain_validates(leaf, [inter, root], root))
        expired = cert('leaf', lk, inter, ik, days=-1)
        self.assertFalse(_chain_validates(expired, [inter], root))
        not_ca = cert('inter', ik, root, rk)
        self.assertFalse(_chain_validates(leaf, [not_ca], root))
        bad_usage = cert('inter', ik, root, rk, ca=True, sign=False)
        self.assertFalse(_chain_validates(leaf, [bad_usage], root))
        short_root = cert('root', rk, ca=True, path_length=0)
        self.assertFalse(_chain_validates(leaf, [inter], short_root))
        other_root = cert('other', rk, ca=True)
        self.assertFalse(_chain_validates(leaf, [inter], other_root))

    def test_cose_algorithm_binding(self):
        key = ec.generate_private_key(ec.SECP256R1())
        sig = key.sign(b'data', ec.ECDSA(hashes.SHA256()))
        _verify_signature(key.public_key(), sig, b'data', -7)
        with self.assertRaises(Exception):
            _verify_signature(key.public_key(), sig, b'data', -257)
        with self.assertRaises(Exception):
            _verify_signature(key.public_key(), sig, b'changed', -7)

    def test_unknown_and_severity_precedence(self):
        r = record()
        scanner = TokenScanner()
        scanner._enrich_record(r)
        self.assertEqual(r.security_status, 'UNKNOWN')
        mds = Mock()
        mds.lookup.return_value = {'metadataStatement': {}}
        mds.get_highest_security_status.return_value = 'REVOKED'
        mds.is_current.return_value = True
        adv = Mock(document={})
        adv.check.return_value = [{'id':'test', 'severity':'MEDIUM'}]
        scanner = TokenScanner(mds3_client=mds, advisory_checker=adv)
        scanner._enrich_record(r)
        self.assertEqual(r.security_status, 'CRITICAL')
        adv.check.return_value = []
        mds.get_highest_security_status.return_value = 'FIDO_CERTIFIED_L2'
        scanner._enrich_record(r)
        self.assertEqual(r.security_status, 'OK')
        mds.is_current.return_value = False
        scanner._enrich_record(r)
        self.assertEqual(r.security_status, 'UNKNOWN')
        mds.lookup.return_value = None
        scanner._enrich_record(r)
        self.assertIsNone(r.mds_status)
        adv.check.side_effect = ValueError('unavailable')
        scanner._enrich_record(r)
        self.assertEqual(r.security_status, 'UNKNOWN')

    def test_privacy_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'private'/'history.json'
            h = History(path)
            h.update_snapshot(record())
            self.assertFalse(path.exists())
            h.set_enabled(True)
            self.assertTrue(path.exists())
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            before = path.read_bytes()
            with patch.dict(os.environ, KEYMELIER_STATELESS='1'):
                h = History(path, enabled=True)
                h.update_snapshot(record())
                self.assertEqual(path.read_bytes(), before)
                with self.assertRaises(ValueError):
                    CSVExporter().export(record())

    def test_default_service_does_not_export_or_store_sites(self):
        with tempfile.TemporaryDirectory() as tmp, patch('fido2tool_core.service.SETTINGS_FILE', Path(tmp)/'settings.json'):
            exporter = Mock()
            service = KeyService(TokenScanner(), exporter, history=History(Path(tmp)/'history.json'))
            r = record()
            service._on_connect(r)
            service._log(r, 'passkey_deleted', site='company.internal', user='alice')
            exporter.export.assert_not_called()
            self.assertNotIn('company.internal', json.dumps(service.history.get(service.history.list()[0]['key_id'])))

    def test_csv_formula_injection(self):
        for value in ['=CMD()', '+CMD()', '-CMD()', '@CMD()', '  =CMD()', '\tvalue']:
            self.assertTrue(_safe_cell(value).startswith("'"))
        self.assertEqual(_safe_cell('plain'), 'plain')

    def test_unsigned_bundled_advisory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(updates, 'CACHE_FILE', Path(tmp)/'absent'):
            Path(tmp, 'advisories.json').write_text('{"updated":"2026-01-01T00:00:00Z","advisories":[]}')
            self.assertIsNone(updates.load_best(Path(tmp))[0])

class ExtendedSecurityTests(unittest.TestCase):
    def test_none_and_unsupported_attestation_are_unverified(self):
        import hashlib
        import uuid
        from fido2tool_core import attestation
        aaguid = str(uuid.uuid4())
        auth_data = hashlib.sha256(b'fido2tool.local').digest() + b'\x41' + b'\0'*4 + uuid.UUID(aaguid).bytes + b'\0\0'
        for fmt in ['none', 'unknown-format']:
            response = SimpleNamespace(fmt=fmt, auth_data=auth_data, att_stmt={})
            with patch('fido2.ctap2.Ctap2') as ctap:
                ctap.return_value.make_credential.return_value = response
                result = attestation.run(None, aaguid)
            self.assertEqual(result.status, 'UNVERIFIED')
            self.assertFalse(result.passed)
            self.assertIsNone(result.sig_valid)
            self.assertIsNone(result.chain_valid)

    def test_mismatched_request_is_failure(self):
        import uuid
        from fido2tool_core import attestation
        aaguid = str(uuid.uuid4())
        data = b'\0'*32 + b'\x41' + b'\0'*4 + uuid.UUID(aaguid).bytes + b'\0\0'
        with patch('fido2.ctap2.Ctap2') as ctap:
            ctap.return_value.make_credential.return_value = SimpleNamespace(fmt='none',auth_data=data,att_stmt={})
            result = attestation.run(None, aaguid)
        self.assertEqual(result.status, 'FAILED')

    def test_expired_metadata_never_current(self):
        from fido2tool_core.mds3 import MDS3Client
        m = MDS3Client()
        m._entries = [{}]
        m._next_update = '2000-01-01'
        m._verified_until = '2999-01-01T00:00:00+00:00'
        self.assertFalse(m.is_current())
        m._next_update = '2999-01-01'
        m._verified_until = '2000-01-01T00:00:00+00:00'
        self.assertFalse(m.is_current())

    def test_unknown_status_does_not_hide_revocation(self):
        from fido2tool_core.mds3 import MDS3Client
        m = MDS3Client()
        m._index([{'aaguid':'test','statusReports':[{'status':'NEW_UNKNOWN'}, {'status':'REVOKED'}]}])
        self.assertEqual(m.get_highest_security_status('test'), 'REVOKED')

    def test_revocation_fails_closed(self):
        from fido2tool_core.revocation import check_chain_revocation, _fetch_crl
        with self.assertRaises(ValueError):
            _fetch_crl('http://127.0.0.1/private')
        rk, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        root = cert('root', rk, ca=True)
        leaf = cert('leaf', lk, root, rk)
        with self.assertRaises(Exception):
            check_chain_revocation([leaf, root])  # no CRL distribution points

    def test_crl_good_revoked_expired_and_bad_signature(self):
        from fido2tool_core.revocation import check_chain_revocation
        rk, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        root = cert('root', rk, ca=True)
        now = datetime.now(timezone.utc)
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'leaf')]))
            .issuer_name(root.subject).public_key(lk.public_key()).serial_number(123)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier('https://crl.globalsign.com/test.crl')],
                relative_name=None, reasons=None, crl_issuer=None)]),False).sign(rk,hashes.SHA256()))
        for case in ['good','revoked','expired','wrong-key']:
            builder = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
                .last_update(now-timedelta(days=2)).next_update(now+timedelta(days=-1 if case=='expired' else 1)))
            if case=='revoked':
                builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(123)
                    .revocation_date(now-timedelta(days=1)).build())
            crl = builder.sign(lk if case=='wrong-key' else rk,hashes.SHA256())
            with patch('fido2tool_core.revocation._fetch_crl', return_value=crl):
                if case=='good':
                    self.assertGreater(check_chain_revocation([leaf,root]), now)
                else:
                    with self.assertRaises(ValueError):
                        check_chain_revocation([leaf,root])

    def test_revoked_signer_is_never_soft_failed(self):
        import base64
        from cryptography.hazmat.primitives.serialization import Encoding
        from fido2tool_core import mds_verify
        from fido2tool_core.revocation import RevokedError
        k = ec.generate_private_key(ec.SECP256R1())
        leaf = cert('mds.fidoalliance.org', k)
        header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "ES256", "x5c": [base64.b64encode(leaf.public_bytes(Encoding.DER)).decode()]}).encode()).rstrip(b'=').decode()
        token = f"{header}.e30.AA"
        with patch('fido2tool_core.certificates.validate_path', return_value=[leaf]):
            with patch('fido2tool_core.revocation.check_chain_revocation', side_effect=RevokedError('revoked')):
                for required in (True, False):
                    with self.assertRaises(mds_verify.MdsVerificationError):
                        mds_verify.verify_jwt(token, require_revocation=required)
            # merely unavailable: only the strict mode refuses; display mode goes on to the signature check
            with patch('fido2tool_core.revocation.check_chain_revocation', side_effect=ValueError('unavailable')):
                with self.assertRaisesRegex(mds_verify.MdsVerificationError, 'revocation'):
                    mds_verify.verify_jwt(token, require_revocation=True)
                with self.assertRaises(mds_verify.MdsVerificationError) as ctx:
                    mds_verify.verify_jwt(token, require_revocation=False)
                self.assertNotIn('revocation', str(ctx.exception))  # got past revocation
        from fido2tool_core.mds3 import MDS3Client
        m = MDS3Client()
        m._entries = [{}]
        m._next_update = '2999-01-01'
        m._verified_until = None  # revocation not established
        self.assertFalse(m.is_current())

    def test_crl_disk_cache_is_revalidated(self):
        from fido2tool_core import revocation
        rk, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        root = cert('root', rk, ca=True)
        now = datetime.now(timezone.utc)
        # A forged CRL on disk (signed by the wrong key) must not be accepted
        forged = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
            .last_update(now-timedelta(days=1)).next_update(now+timedelta(days=1)).sign(lk, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as tmp, patch.object(revocation, 'CRL_DIR', Path(tmp)), \
             patch.object(revocation, '_CACHE', {}):
            url = 'https://crl.globalsign.com/test.crl'
            revocation._save_disk(url, forged)
            self.assertIsNotNone(revocation._load_disk(url))
            leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'leaf')]))
                .issuer_name(root.subject).public_key(lk.public_key()).serial_number(7)
                .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None)]), False)
                .sign(rk, hashes.SHA256()))
            with self.assertRaises(ValueError):
                revocation.check_chain_revocation([leaf, root])

    def test_invalid_cached_crl_is_replaced_by_download(self):
        from fido2tool_core import revocation
        rk, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        root = cert('root', rk, ca=True)
        now = datetime.now(timezone.utc)
        url = 'https://crl.globalsign.com/test.crl'
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'leaf')]))
            .issuer_name(root.subject).public_key(lk.public_key()).serial_number(9)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None)]), False)
            .sign(rk, hashes.SHA256()))
        def crl(key):
            return (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
                .last_update(now-timedelta(hours=1)).next_update(now+timedelta(days=1)).sign(key, hashes.SHA256()))
        good = crl(rk)
        with tempfile.TemporaryDirectory() as tmp, patch.object(revocation, 'CRL_DIR', Path(tmp)), \
             patch.object(revocation, '_CACHE', {}):
            revocation._save_disk(url, crl(lk))  # forged/corrupt copy on disk
            downloads = []
            def download(u, allow_cache=True):
                if allow_cache:
                    return revocation._load_disk(u)
                downloads.append(u)
                return good
            with patch.object(revocation, '_fetch_crl', side_effect=download):
                self.assertGreater(revocation.check_chain_revocation([leaf, root]), now)
            self.assertEqual(downloads, [url])
            self.assertEqual(revocation._load_disk(url).public_bytes(
                __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER),
                good.public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER))

    def test_no_double_download_without_cache(self):
        from fido2tool_core import revocation
        rk, lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
        root = cert('root', rk, ca=True)
        now = datetime.now(timezone.utc)
        url = 'https://crl.globalsign.com/test.crl'
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'leaf')]))
            .issuer_name(root.subject).public_key(lk.public_key()).serial_number(10)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None)]), False)
            .sign(rk, hashes.SHA256()))
        calls = []
        def offline(u, allow_cache=True):
            calls.append(allow_cache)
            raise ValueError("MDS CRL download failed")
        with tempfile.TemporaryDirectory() as tmp, patch.object(revocation, 'CRL_DIR', Path(tmp)), \
             patch.object(revocation, '_CACHE', {}), patch.object(revocation, '_fetch_crl', side_effect=offline):
            with self.assertRaises(ValueError):
                revocation.check_chain_revocation([leaf, root])
        self.assertEqual(calls, [True])

    def test_fresh_cache_is_reverified_when_revocation_returns(self):
        from fido2tool_core import mds3
        m = mds3.MDS3Client()
        m._entries = [{}]
        m._next_update = '2999-01-01'
        m._verified_until = None  # started offline
        future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        def reload():
            m._verified_until = future
            return [{'aaguid': 'x'}]
        with patch.object(m, '_is_cache_fresh', return_value=True), patch.object(m, '_load_cache', side_effect=reload):
            self.assertTrue(m.refresh_if_stale())
        self.assertTrue(m.is_current())
        with patch.object(m, '_is_cache_fresh', return_value=True), patch.object(m, '_load_cache') as again:
            self.assertFalse(m.refresh_if_stale())  # already current: no work
            again.assert_not_called()

    def test_encrypted_history_and_no_plaintext_fallback(self):
        from cryptography.fernet import Fernet
        cipher = Fernet(Fernet.generate_key())
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, KEYMELIER_ENCRYPT_HISTORY='1'), patch('fido2tool_core.history.history_cipher',return_value=cipher):
            path = Path(tmp)/'history.json'
            h = History(path, enabled=True)
            h.update_snapshot(record())
            self.assertFalse(path.exists())
            raw = path.with_suffix('.encrypted').read_bytes()
            self.assertNotIn(b'serial',raw)
            self.assertEqual(len(History(path,enabled=True).list()),1)
            path.with_suffix('.encrypted').write_bytes(raw[:-2]+b'xx')
            with self.assertRaises(RuntimeError):
                History(path,enabled=True)

    def test_enable_history_preserves_previous_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'history.json'
            h = History(path, enabled=True)
            old = record()
            old.aaguid = 'old'
            h.update_snapshot(old)
            h = History(path)
            h.update_snapshot(record())
            h.set_enabled(True)
            self.assertEqual(len(History(path,enabled=True).list()),2)

    def test_disabling_sites_scrubs_old_event_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = History(Path(tmp)/'history.json', enabled=True)
            h.add_event(record(), 'passkey_deleted', site='internal.example',user='alice')
            h.clear_sites()
            self.assertNotIn('internal.example', h._path.read_text())


if __name__ == '__main__':
    unittest.main()
