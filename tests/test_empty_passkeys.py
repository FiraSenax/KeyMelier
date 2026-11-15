"""Empty-key enumeration compatibility; actual library, synthetic wire replies."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fido2.ctap import CtapError
from fido2.ctap2.credman import CredentialManagement as CM
from keymelier_core import auth, passkeys


class EmptyPasskeyTests(unittest.TestCase):
    def setUp(self):
        self.key = 'empty-passkeys-synthetic'
        self.addCleanup(auth.forget, self.key, disconnected=True)
        auth._tokens[self.key] = auth.ManagementToken(1, b't' * 32, float('inf'), 4)
        self.ctap = SimpleNamespace(info=SimpleNamespace(
            versions=['FIDO_2_1_PRE'], options={'credentialMgmtPreview': True}),
            credential_mgmt=Mock())

    def populated_reply(self, sub_cmd, **kwargs):
        if sub_cmd == CM.CMD.ENUMERATE_RPS_BEGIN:
            return {CM.RESULT.RP: {'id': 'example.test', 'name': 'Synthetic service'},
                    CM.RESULT.RP_ID_HASH: b'r' * 32, CM.RESULT.TOTAL_RPS: 1}
        if sub_cmd == CM.CMD.ENUMERATE_CREDS_BEGIN:
            return {CM.RESULT.USER: {'id': b'synthetic-user', 'name': 'Synthetic account'},
                    CM.RESULT.CREDENTIAL_ID: {'id': b'synthetic-credential'},
                    CM.RESULT.TOTAL_CREDENTIALS: 1}
        self.fail('Unexpected credential-management command')

    def test_explicitly_empty_key_needs_no_rp_enumeration(self):
        # Observed K33 metadata, followed by its empty RP-begin response.
        # The library raises KeyError for that second response if called.
        self.ctap.credential_mgmt.side_effect = [
            {CM.RESULT.EXISTING_CRED_COUNT: 0, CM.RESULT.MAX_REMAINING_COUNT: 128}, {}]
        result = passkeys.list_passkeys(self.key, self.ctap)
        self.assertEqual(result, {'existing': 0, 'remaining': 128, 'rps': []})
        self.assertEqual(self.ctap.credential_mgmt.call_count, 1)
        self.assertEqual(self.ctap.credential_mgmt.call_args.kwargs['sub_cmd'], CM.CMD.GET_CREDS_METADATA)

    def test_nonempty_key_still_enumerates_accounts(self):
        def reply(sub_cmd, **kwargs):
            if sub_cmd == CM.CMD.GET_CREDS_METADATA:
                return {CM.RESULT.EXISTING_CRED_COUNT: 1, CM.RESULT.MAX_REMAINING_COUNT: 127}
            return self.populated_reply(sub_cmd, **kwargs)
        self.ctap.credential_mgmt.side_effect = reply
        result = passkeys.list_passkeys(self.key, self.ctap)
        self.assertEqual(result['existing'], 1)
        self.assertEqual(result['rps'][0]['rp_id'], 'example.test')
        self.assertEqual(result['rps'][0]['credentials'][0]['user_name'], 'Synthetic account')
        self.assertEqual(self.ctap.credential_mgmt.call_count, 3)

    def test_missing_or_malformed_count_does_not_hide_accounts(self):
        for count in (None, False, 0.0, '0', -1):
            with self.subTest(count=count):
                def reply(sub_cmd, **kwargs):
                    if sub_cmd == CM.CMD.GET_CREDS_METADATA:
                        return {} if count is None else {CM.RESULT.EXISTING_CRED_COUNT: count}
                    return self.populated_reply(sub_cmd, **kwargs)
                self.ctap.credential_mgmt.side_effect = reply
                result = passkeys.list_passkeys(self.key, self.ctap)
                self.assertEqual(len(result['rps']), 1)
                self.assertEqual(len(result['rps'][0]['credentials']), 1)

    def test_nonempty_metadata_with_malformed_enumeration_still_fails(self):
        self.ctap.credential_mgmt.side_effect = [{CM.RESULT.EXISTING_CRED_COUNT: 1}, {}]
        with self.assertRaises(KeyError):
            passkeys.list_passkeys(self.key, self.ctap)

    def test_metadata_authentication_failure_is_not_an_empty_key(self):
        self.ctap.credential_mgmt.side_effect = CtapError(CtapError.ERR.PIN_AUTH_INVALID)
        with self.assertRaises(auth.AuthError) as caught:
            passkeys.list_passkeys(self.key, self.ctap)
        self.assertEqual(caught.exception.code, 'locked')
        self.assertFalse(auth.is_unlocked(self.key))


if __name__ == '__main__':
    unittest.main()
