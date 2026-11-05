"""Compatibility for explicitly trusted v1 roots, without weakening JWT trust."""
import unittest
import warnings

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from OpenSSL import crypto

from keymelier_core.certificates import validate_path
from tests.test_security import cert


def legacy_root(key, *, version=0, days=1, signer=None):
    # CertificateBuilder deliberately produces v3; use OpenSSL only to create
    # legacy test input. No deprecated APIs are used in production validation.
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        root = crypto.X509()
        root.set_version(version)
        root.set_serial_number(1)
        root.get_subject().CN = 'Synthetic legacy root'
        root.set_issuer(root.get_subject())
        root.gmtime_adj_notBefore(-3 * 86400)
        root.gmtime_adj_notAfter(days * 86400)
        root.set_pubkey(crypto.PKey.from_cryptography_key(key))
        root.sign(crypto.PKey.from_cryptography_key(signer or key), 'sha256')
        return root.to_cryptography()


class LegacyAnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())

    def test_explicit_v1_anchor_accepts_a_valid_chain(self):
        root = legacy_root(self.key)
        leaf = cert('leaf', self.leaf_key, root, self.key)
        self.assertEqual(validate_path(leaf, [], root, strict=False), [leaf, root])

    def test_strict_jwt_validation_still_rejects_v1_anchor(self):
        root = legacy_root(self.key)
        leaf = cert('leaf', self.leaf_key, root, self.key)
        with self.assertRaises(x509.ExtensionNotFound):
            validate_path(leaf, [], root)

    def test_legacy_exception_does_not_admit_bad_certificates(self):
        for kind in ('expired_root', 'expired_leaf', 'bad_self_signature', 'wrong_leaf_signer',
                     'missing_v3_constraints', 'explicit_non_ca', 'ca_leaf', 'non_ca_intermediate'):
            with self.subTest(kind=kind):
                root = legacy_root(self.key, days=-1 if kind == 'expired_root' else 1,
                                   signer=self.other if kind == 'bad_self_signature' else None,
                                   version=2 if kind == 'missing_v3_constraints' else 0)
                if kind == 'explicit_non_ca':
                    root = cert('root', self.key, ca=False)
                intermediates = []
                issuer, signing_key = root, self.key
                if kind == 'non_ca_intermediate':
                    issuer = cert('intermediate', self.other, root, self.key, ca=False)
                    signing_key = self.other
                    intermediates = [issuer]
                leaf = cert('leaf', self.leaf_key, issuer,
                            self.other if kind == 'wrong_leaf_signer' else signing_key,
                            days=-1 if kind == 'expired_leaf' else 1, ca=kind == 'ca_leaf')
                with self.assertRaises(Exception):
                    validate_path(leaf, intermediates, root, strict=False)
