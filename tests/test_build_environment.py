import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from tools.check_build_environment import verify_scripts


class BuildEnvironmentTests(unittest.TestCase):
    def test_clean_scripts_pass_and_untracked_copy_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"var text = '%(text_select)s';"
            (root/'customize.js').write_bytes(data)
            expected = {'customize.js':base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')}
            self.assertEqual(verify_scripts(root,expected), [])
            (root/'customize 2.js').write_bytes(data)
            self.assertIn('unexpected pywebview script: customize 2.js', verify_scripts(root,expected))
            (root/'customize 2.js').unlink()
            (root/'customize.js').write_bytes(b'modified')
            self.assertIn('modified pywebview script: customize.js',verify_scripts(root,expected))
            (root/'customize.js').unlink()
            self.assertIn('missing pywebview script: customize.js',verify_scripts(root,expected))
