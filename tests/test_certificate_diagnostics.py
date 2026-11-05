"""Real synthetic chains: better explanations must never grant trust."""
import base64
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from OpenSSL import crypto

from keymelier_core.attestation import _verify_chain_against_mds3
from keymelier_core.certificates import validation_failure_reason
from tests.test_security import cert


def der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


class CertificateDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.rk, self.ik, self.lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        self.root = cert('synthetic root', self.rk, ca=True, path_length=1)
        self.inter = cert('synthetic intermediate', self.ik, self.root, self.rk, ca=True)

    def verify(self, leaf, roots=None):
        mds = Mock()
        mds.is_current.return_value = True
        mds.lookup.return_value = {'metadataStatement': {'attestationRootCertificates': [
            base64.b64encode(der(root)).decode('ascii') for root in (roots or [self.root])]}}
        return _verify_chain_against_mds3([der(leaf), der(self.inter)], 'synthetic-model', mds)

    def test_expired_leaf_is_unverified_with_reason(self):
        result, detail = self.verify(cert('leaf', self.lk, self.inter, self.ik, days=-1))
        self.assertIsNone(result)
        self.assertIn('cryptographically intact', detail)
        self.assertIn('expired or not yet valid', detail)

    def test_ca_leaf_is_unverified_with_reason(self):
        result, detail = self.verify(cert('leaf', self.lk, self.inter, self.ik, ca=True))
        self.assertIsNone(result)
        self.assertIn('marked as a CA', detail)

    def test_real_openssl_path_length_failure_is_explained(self):
        short_root = cert('synthetic root', self.rk, ca=True, path_length=0)
        result, detail = self.verify(cert('leaf', self.lk, self.inter, self.ik), [short_root])
        self.assertIsNone(result)
        self.assertIn('path length', detail)

    def test_later_valid_root_still_verifies(self):
        short_root = cert('synthetic root', self.rk, ca=True, path_length=0)
        result, detail = self.verify(cert('leaf', self.lk, self.inter, self.ik), [short_root, self.root])
        self.assertTrue(result)
        self.assertIn('Chain valid:', detail)
        self.assertNotIn('Reason:', detail)

    def test_unknown_error_text_is_not_exposed_or_trusted(self):
        with patch('keymelier_core.certificates.validate_path', side_effect=RuntimeError('PRIVATE <markup>')):
            result, detail = self.verify(cert('leaf', self.lk, self.inter, self.ik))
        self.assertIsNone(result)
        self.assertIn('no specific reason', detail)
        self.assertNotIn('PRIVATE', detail)
        self.assertNotIn('<markup>', detail)

    def test_openssl_message_is_not_forwarded(self):
        for code in (9, 10, 24, 25, 26, 32, 34, 79, 999):
            with self.subTest(code=code):
                error = crypto.X509StoreContextError('PRIVATE', [code, 0, 'PRIVATE'], None)
                self.assertNotIn('PRIVATE', validation_failure_reason(error))
