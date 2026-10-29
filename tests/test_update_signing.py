import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keymelier_core import update_auth

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import update_signing


class UpdateSigningTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / 'release'
        self.folder.mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.public = self.root / 'public.txt'
        self.public.write_text(base64.b64encode(self.key.public_key().public_bytes_raw()).decode())
        self.pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        self.commit = 'a' * 40
        (self.folder / 'SOURCE_COMMIT.txt').write_text(self.commit + '\n')
        (self.folder / 'KeyMelier-macOS.dmg').write_bytes(b'harmless test image')
        self.sums = self.folder / 'SHA256SUMS.txt'
        self.sums.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                                     for p in sorted(self.folder.iterdir())))
        for patcher in (patch.object(update_auth, 'PUBLIC_KEY_FILE', self.public),
                        patch.dict(os.environ, {update_signing.SECRET: self.pem.decode()})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_sign_verify_and_client_share_the_exact_protocol(self):
        update_signing.sign(self.folder, 'v1.8.7-rc.4', self.commit)
        update_signing.verify(self.folder, 'v1.8.7-rc.4', self.commit)
        signature = (self.folder / update_auth.SIGNATURE_FILE).read_bytes()
        update_auth.verify('v1.8.7-rc.4', self.sums.read_bytes(), signature)
        for tag in ('v1.8.7-rc.3', 'v1.8.7', 'v1.8.8', '1.8.7-rc.4'):
            with self.subTest(tag=tag), self.assertRaises(update_auth.SignatureError):
                update_auth.verify(tag, self.sums.read_bytes(), signature)
        for changed in (self.sums.read_bytes() + b' ', b'other bytes'):
            with self.assertRaises(update_auth.SignatureError):
                update_auth.verify('v1.8.7-rc.4', changed, signature)

    def test_invalid_signature_key_and_tag_fail_closed(self):
        for signature in (b'', b'!!', base64.b64encode(b'x' * 64), b'x' * 257):
            with self.subTest(signature_length=len(signature)), self.assertRaises(update_auth.SignatureError):
                update_auth.verify('v1.8.7', self.sums.read_bytes(), signature)
        for tag in ('v1.8.7\n', 'v1.8.7-rc.0', 'v1.8.7-rc.04', 'v01.8.7', '../v1.8.7'):
            with self.subTest(tag=tag), self.assertRaises(update_auth.SignatureError):
                update_auth.signing_payload(tag, self.sums.read_bytes())
        self.public.write_text('')
        with self.assertRaises(update_auth.SignatureError):
            update_signing.sign(self.folder, 'v1.8.7', self.commit)
        self.assertFalse((self.folder / update_auth.SIGNATURE_FILE).exists())

    def test_emergency_acknowledgement_never_permits_signing_with_the_revoked_key(self):
        from keymelier_core import update_revocation
        key = update_revocation.fingerprint()
        bundled = self.root / 'revoked.json'
        bundled.write_text(json.dumps({'version': 1, 'revoked': [key],
                                        'emergency_stop': {'fingerprint': key, 'reason': 'Confirmed incident'}}))
        with patch.object(update_revocation, 'BUNDLED', bundled), \
                patch.object(update_revocation, 'stateless', return_value=True), \
                patch.object(update_revocation, '_seen', set()):
            with self.assertRaises(update_revocation.RevokedKeyError):
                update_signing.sign(self.folder, 'v1.8.7-rc.8', self.commit)
        self.assertFalse((self.folder / update_auth.SIGNATURE_FILE).exists())

    def test_signer_rejects_mismatched_key_commit_and_changed_files(self):
        self.public.write_text(base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode())
        with self.assertRaisesRegex(ValueError, 'does not match'):
            update_signing.sign(self.folder, 'v1.8.7', self.commit)
        self.public.write_text(base64.b64encode(self.key.public_key().public_bytes_raw()).decode())
        with self.assertRaisesRegex(ValueError, 'Source commit'):
            update_signing.sign(self.folder, 'v1.8.7', 'b' * 40)
        (self.folder / 'KeyMelier-macOS.dmg').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs from its checksum'):
            update_signing.sign(self.folder, 'v1.8.7', self.commit)
        self.assertFalse((self.folder / update_auth.SIGNATURE_FILE).exists())

    def test_signer_rejects_missing_duplicate_and_traversal_entries(self):
        original = self.sums.read_bytes()
        for data in (original.splitlines(keepends=True)[0], original + original,
                     b'0' * 64 + b'  ../outside\n'):
            with self.subTest(data_length=len(data)), self.assertRaises(ValueError):
                self.sums.write_bytes(data)
                update_signing.sign(self.folder, 'v1.8.7', self.commit)

    def test_setup_is_repeatable_and_sends_private_key_only_on_stdin(self):
        private = self.root / 'backup.pem'
        public = self.root / 'new-public.txt'
        sent = []
        def gh(*args, input=None):
            self.assertNotIn('PRIVATE KEY', ' '.join(args))
            if args[0] == 'api':
                return b'{"deployment_branch_policy":{"custom_branch_policies":true}}'
            if args[1] == 'list':
                return json.dumps([{'name': update_signing.SECRET}] if sent else []).encode()
            self.assertEqual(args[:3], ('secret', 'set', update_signing.SECRET))
            sent.append(input)
            return b''
        output = io.StringIO()
        with patch.object(update_signing, '_gh', side_effect=gh), contextlib.redirect_stdout(output):
            update_signing.setup(private, public)
            first_public = public.read_bytes()
            update_signing.setup(private, public)
        self.assertEqual(sent, [private.read_bytes(), private.read_bytes()])
        self.assertEqual(public.read_bytes(), first_public)
        self.assertNotIn('PRIVATE KEY', output.getvalue())
        if os.name != 'nt':
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)

    def test_setup_preserves_backup_on_upload_failure_and_refuses_silent_rotation(self):
        private = self.root / 'backup.pem'
        public = self.root / 'new-public.txt'
        def failed(*args, **kwargs):
            if args[0] == 'api':
                return b'{"deployment_branch_policy":{"custom_branch_policies":true}}'
            if args[1] == 'list':
                return b'[]'
            raise subprocess.CalledProcessError(1, 'gh')
        with patch.object(update_signing, '_gh', side_effect=failed), self.assertRaises(subprocess.CalledProcessError):
            update_signing.setup(private, public)
        self.assertTrue(private.exists())
        self.assertFalse(public.exists())
        public.write_bytes(self.public.read_bytes())  # another, already trusted key
        before = private.read_bytes()
        with patch.object(update_signing, '_gh', side_effect=failed), self.assertRaisesRegex(ValueError, 'rotation'):
            update_signing.setup(private, public)
        self.assertEqual(private.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
