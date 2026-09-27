import json
import tempfile
import unittest
from pathlib import Path

from fido2tool_core.history import History
from fido2tool_core.scanner import TokenRecord


def record(serial):
    return TokenRecord('id' + serial, '/dev/test', 'Key', serial, 'vendor', 'aaguid', [], [], {}, [], None, None, '', 'now')


class ReplaceProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'h.json'
        self.h = History(self.path, enabled=True)
        self.old = self.h.set_sites(record('1'), [{'rp_id': 'a.com', 'name': 'A', 'count': 1, 'users': []}])['key_id']
        self.new = self.h.update_snapshot(record('2'))['key_id']

    def test_progress_is_saved_and_only_user_confirmations(self):
        self.h.set_replace(self.old, self.new)
        self.h.set_replace_done(self.old, 'pk:a.com|x', True)
        saved = {e['key_id']: e for e in json.loads(self.path.read_text())['keys']}
        self.assertEqual(saved[self.old]['replace']['new'], self.new)
        self.assertEqual(saved[self.old]['replace']['done'], ['pk:a.com|x'])
        # the keys themselves are untouched: sites stay, nothing is marked lost or removed
        self.assertEqual(len(saved[self.old]['sites']), 1)
        self.assertNotIn('lost_since', saved[self.old])

    def test_invalid_pairs_are_refused(self):
        self.assertIsNone(self.h.set_replace(self.old, self.old))
        self.assertIsNone(self.h.set_replace(self.old, 'f' * 16))
        self.assertIsNone(self.h.set_replace_done(self.old, 'x', True), 'no replacement started')

    def test_choosing_another_new_key_starts_over(self):
        third = self.h.update_snapshot(record('3'))['key_id']
        self.h.set_replace(self.old, self.new)
        self.h.set_replace_done(self.old, 'a', True)
        self.h.set_replace(self.old, self.new)  # same key again keeps progress
        self.assertEqual(self.h.get(self.old)['replace']['done'], ['a'])
        self.h.set_replace(self.old, third)
        self.assertEqual(self.h.get(self.old)['replace']['done'], [])
        self.h.set_replace(self.old, None)
        self.assertNotIn('replace', self.h.get(self.old))

    def test_forgetting_contents_forgets_progress(self):
        self.h.set_replace(self.old, self.new)
        self.h.set_replace_done(self.old, 'pk:a.com|x', True)
        self.h.clear_sites()
        self.assertNotIn('replace', self.h.get(self.old))

    def test_without_storage_nothing_is_written(self):
        path = Path(self.tmp.name) / 'off.json'
        h = History(path, enabled=False)
        old = h.set_sites(record('1'), [])['key_id']
        new = h.update_snapshot(record('2'))['key_id']
        h.set_replace(old, new)
        h.set_replace_done(old, 'a', True)
        self.assertEqual(h.get(old)['replace']['done'], ['a'])  # kept for this session
        self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
