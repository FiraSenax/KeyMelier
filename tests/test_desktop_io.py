"""No subprocess is launched; imports use only temporary synthetic files."""
import tempfile
import unittest
import os
import sys
from pathlib import Path
from unittest.mock import patch

from keymelier_core import desktop_io


class DesktopIOTests(unittest.TestCase):
    def test_gpg_import_releases_card_with_platform_companion(self):
        import app
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as folder:
            for platform, executable, companion in (
                ('win32', 'gpg.exe', 'gpgconf.exe'),
                ('darwin', 'gpg', 'gpgconf'),
                ('linux', 'gpg2', 'gpgconf'),
            ):
                with self.subTest(platform=platform):
                    gpg = Path(folder) / executable
                    config = Path(folder) / companion
                    config.touch()
                    with patch.object(app.sys, 'platform', platform), \
                         patch.object(app, '_gpg', return_value=str(gpg)), \
                         patch.object(app, 'stateless', return_value=False), \
                         patch.object(app, 'host_env', return_value=None), \
                         patch.object(app.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
                        result = app.Api.gpg_import(None, '-----BEGIN PGP PUBLIC KEY BLOCK-----\nQA')
                        self.assertTrue(result['ok'])
                        self.assertEqual([call.args[0] for call in run.call_args_list], [
                            [str(gpg), '--batch', '--import'],
                            [str(gpg), '--batch', '--card-status'],
                            [str(config), '--kill', 'scdaemon'],
                        ])
                    config.unlink()

    def test_known_gpg_installations_precede_path_and_custom_paths_remain_supported(self):
        known = (r'C:\Program Files\GnuPG\bin\gpg.exe' if sys.platform == 'win32' else
                 '/opt/homebrew/bin/gpg' if sys.platform == 'darwin' else '/usr/bin/gpg')
        with tempfile.TemporaryDirectory() as folder:
            custom = Path(folder) / ('gpg.exe' if sys.platform == 'win32' else 'gpg')
            with patch.dict(desktop_io.os.environ, {'PATH': os.pathsep.join((folder, '.', 'relative', ''))}), \
                 patch.object(desktop_io, '_executable', side_effect=lambda p: str(p) if str(p) in (
                     known, str(custom)) else None) as executable:
                self.assertEqual(desktop_io.gpg_path(), known)
                executable.assert_called_once_with(known)
                executable.side_effect = lambda p: str(p) if str(p) == str(custom) else None
                self.assertEqual(desktop_io.gpg_path(), str(custom))
                self.assertTrue(all(Path(str(c.args[0])).is_absolute() for c in executable.call_args_list))

    def test_relative_current_directory_and_nonexecutable_files_are_rejected(self):
        self.assertIsNone(desktop_io._executable('gpg'))
        self.assertIsNone(desktop_io._executable(Path.cwd() / 'gpg'))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'gpg'
            path.write_text('not an executable')
            path.chmod(0o600)
            with patch.object(desktop_io.os, 'access', return_value=False):
                self.assertIsNone(desktop_io._executable(path))
            self.assertIsNone(desktop_io._executable(Path(folder)))
            (Path(folder) / 'subdir').mkdir()
            with patch.object(Path, 'cwd', return_value=Path(folder)):
                self.assertIsNone(desktop_io._executable(Path(folder) / 'subdir' / '..' / 'gpg'))

    def test_import_is_strict_bounded_and_accepts_utf8_bom(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.json'
            for data in (b'{"label":"\xff"}', b'\xff\xfe{}'):
                path.write_bytes(data)
                self.assertEqual(desktop_io.read_import(path)['code'], 'history_encoding')
                self.assertEqual(path.read_bytes(), data)
            path.write_bytes(b'\xef\xbb\xbf{"label":"valid"}')
            self.assertEqual(desktop_io.read_import(path), '{"label":"valid"}')
            with patch.object(desktop_io, 'MAX_IMPORT', 10):
                self.assertEqual(desktop_io.read_import(path)['code'], 'history_too_large')
            path.unlink()
            self.assertEqual(desktop_io.read_import(path)['code'], 'history_invalid')
