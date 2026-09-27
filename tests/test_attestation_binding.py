import uuid
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from fido2tool_core.attestation import AAGUID_EXTENSION, _model_binding, _verify_chain_against_mds3
from fido2tool_core.certificates import validate_path

AAGUID = "2fc0579f-8113-47ea-b116-bb5a8db9202a"
OTHER = "cb69481e-8ff7-4039-93ec-0a2729a154a8"


def make(name, key, issuer=None, issuer_key=None, ca=False, bc=True, aaguid=None):
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .issuer_name((issuer or None).subject if issuer else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30)))
    if bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if aaguid:
        raw = b"\x04\x10" + uuid.UUID(aaguid).bytes
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(AAGUID_EXTENSION), raw), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


class AttestationBindingTests(unittest.TestCase):
    def setUp(self):
        self.rk, self.ik, self.lk = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        self.root = make("root", self.rk, ca=True)
        self.inter = make("inter", self.ik, self.root, self.rk, ca=True)

    def test_packed_leaf_must_name_the_claimed_model(self):
        leaf = make("leaf", self.lk, self.inter, self.ik, aaguid=AAGUID).public_bytes(Encoding.DER)
        self.assertTrue(_model_binding("packed", leaf, AAGUID, AAGUID, None)[0])
        self.assertIs(_model_binding("packed", leaf, OTHER, OTHER, None)[0], False)
        bare = make("leaf", self.lk, self.inter, self.ik).public_bytes(Encoding.DER)
        self.assertIsNone(_model_binding("packed", bare, AAGUID, AAGUID, None)[0])

    def test_u2f_needs_zero_aaguid_and_listed_key_id(self):
        leaf_cert = make("u2f", self.lk, self.inter, self.ik)
        leaf = leaf_cert.public_bytes(Encoding.DER)
        ski = x509.SubjectKeyIdentifier.from_public_key(self.lk.public_key()).digest.hex()
        mds = Mock()
        mds.lookup.return_value = {"attestationCertificateKeyIdentifiers": [ski]}
        zero = "00000000-0000-0000-0000-000000000000"
        self.assertTrue(_model_binding("fido-u2f", leaf, zero, AAGUID, mds)[0])
        self.assertIsNone(_model_binding("fido-u2f", leaf, AAGUID, AAGUID, mds)[0])
        mds.lookup.return_value = {"attestationCertificateKeyIdentifiers": []}
        self.assertIsNone(_model_binding("fido-u2f", leaf, zero, AAGUID, mds)[0])

    def test_leaf_without_basic_constraints_and_intermediate_anchor(self):
        leaf = make("legacy", self.lk, self.inter, self.ik, bc=False)
        validate_path(leaf, [], self.inter, strict=False)          # intermediate as trust anchor (PARTIAL_CHAIN)
        validate_path(leaf, [self.inter], self.root, strict=False)  # no basicConstraints on the leaf

    def test_forged_chain_fails_and_profile_issue_is_unverified(self):
        import base64
        mds = Mock(is_current=Mock(return_value=True))
        mds.lookup.return_value = {"metadataStatement": {"attestationRootCertificates": [
            base64.b64encode(self.root.public_bytes(Encoding.DER)).decode()]}}
        other = ec.generate_private_key(ec.SECP256R1())
        forged = make("forged", self.lk, make("fake", other, ca=True), other).public_bytes(Encoding.DER)
        self.assertIs(_verify_chain_against_mds3([forged], AAGUID, mds)[0], False)
        # A leaf that is itself marked as CA violates the profile, but is signed by the vendor chain
        odd = make("odd", self.lk, self.inter, self.ik, ca=True)
        chain = [odd.public_bytes(Encoding.DER), self.inter.public_bytes(Encoding.DER)]
        self.assertIsNone(_verify_chain_against_mds3(chain, AAGUID, mds)[0])


if __name__ == "__main__":
    unittest.main()
