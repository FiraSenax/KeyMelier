"""Real signatures with synthetic CTAP responses: binding matters too."""
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData
from fido2tool_core import function_test


class FunctionTestTests(unittest.TestCase):
    def device(self, *, stage=None, wrong_rp=False, missing_up=False, wrong_id=False, bad_sig=False, always_uv=False, flags_extra=0):
        key = ec.generate_private_key(ec.SECP256R1())
        cred = AttestedCredentialData.create(bytes(16), b'test-credential', ES256.from_cryptography_key(key.public_key()))
        rp = hashlib.sha256(function_test.RP['id'].encode()).digest()
        F = AuthenticatorData.FLAG
        def data(which):
            flags = F.UP | flags_extra
            if stage == which and missing_up:
                flags &= ~F.UP
            return AuthenticatorData.create(bytes(32) if stage == which and wrong_rp else rp,
                flags | (F.AT if which == 'register' else 0), 0,
                cred if which == 'register' else b'')
        def assertion(rp_id, cdh, **kwargs):
            auth_data = data('sign_in')
            sig = key.sign(bytes(auth_data)+cdh, ec.ECDSA(hashes.SHA256()))
            return SimpleNamespace(auth_data=auth_data, signature=b'bad' if bad_sig else sig,
                credential={'type':'public-key', 'id':b'other' if wrong_id else cred.credential_id})
        return SimpleNamespace(info=SimpleNamespace(options={'alwaysUv':always_uv}),
            make_credential=Mock(return_value=SimpleNamespace(auth_data=data('register'))),
            get_assertion=Mock(side_effect=assertion))

    def test_valid_roundtrip_and_zero_counter(self):
        result = function_test.run(self.device())
        self.assertTrue(result['ok'])
        self.assertFalse(result['user_verified'])
        self.assertEqual(len(result['steps']), 3)

    def test_request_binding_and_presence_on_both_responses(self):
        for stage in ('register', 'sign_in'):
            for fault in ('wrong_rp', 'missing_up'):
                with self.subTest(stage=stage, fault=fault):
                    key = self.device(stage=stage, **{fault:True})
                    result = function_test.run(key)
                    self.assertFalse(result['ok'])
                    self.assertFalse(result['steps'][-1]['ok'])
                    if stage == 'register':
                        key.get_assertion.assert_not_called()

    def test_wrong_credential_or_signature_never_passes(self):
        for kwargs in ({'wrong_id':True}, {'bad_sig':True}):
            self.assertFalse(function_test.run(self.device(**kwargs))['ok'])

    def test_required_uv_cannot_be_missing(self):
        self.assertFalse(function_test.run(self.device(always_uv=True))['ok'])
        self.assertTrue(function_test.run(self.device(always_uv=True, flags_extra=AuthenticatorData.FLAG.UV))['ok'])

    def test_backup_state_requires_backup_eligibility(self):
        self.assertFalse(function_test.run(self.device(flags_extra=AuthenticatorData.FLAG.BS))['ok'])
