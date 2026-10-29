"""No subprocess is launched; imports use only temporary synthetic files."""
import tempfile
import unittest
import os
import sys
from pathlib import Path
from unittest.mock import patch

from keymelier_core import desktop_io


class DesktopIOTests(unittest.TestCase):
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
