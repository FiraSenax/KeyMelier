"""Signed data must survive Git's Windows-style checkout unchanged."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fido2tool_core.updates import verify

ROOT = Path(__file__).resolve().parent.parent


class SignedCheckoutTests(unittest.TestCase):
    def test_autocrlf_preserves_signed_advisory_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'
            repo.mkdir()
            (repo / 'data').mkdir()
            for name in ('.gitattributes', 'data/advisories.json', 'data/advisories.json.sig'):
                shutil.copyfile(ROOT / name, repo / name)
            def git(*args):
                subprocess.run(['git', '-c', 'core.autocrlf=true', *args], cwd=repo,
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            git('init')
            git('add', '.gitattributes', 'data/advisories.json', 'data/advisories.json.sig')
            # Force a fresh checkout through the conversion machinery.
            (repo / 'data/advisories.json').unlink()
            (repo / 'data/advisories.json.sig').unlink()
            git('checkout-index', '--all', '--force')
            data = (repo / 'data/advisories.json').read_bytes()
            self.assertEqual(data, (ROOT / 'data/advisories.json').read_bytes())
            self.assertTrue(verify(data, (repo / 'data/advisories.json.sig').read_text(encoding='ascii')))


if __name__ == '__main__':
    unittest.main()
