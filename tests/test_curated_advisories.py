"""Vendor-documented fixed-version boundaries, using real MDS model AAGUIDs."""
import json
from pathlib import Path
import unittest

from keymelier_core.advisories import AdvisoryChecker


class CuratedAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.checker = AdvisoryChecker.__new__(AdvisoryChecker)
        self.checker._advisories = json.loads((Path(__file__).parents[1] / 'data/advisories.json').read_text())['advisories']

    def findings(self, aaguid, version):
        major, minor, patch = map(int, version.split('.'))
        return self.checker.get_cve_ids(aaguid, (major << 16) | (minor << 8) | patch, 'Yubico')

    def test_protocol_two_starts_at_vendor_minimum_and_ends_at_574(self):
        for aaguid, minimum, below in [
            ('ee882879-721c-4913-9775-3dfcce97072a', '5.4.1', '5.4.0'),
            ('d8522d9f-575b-4866-88a9-ba99fa02f35b', '5.5.0', '5.4.3')]:
            with self.subTest(aaguid=aaguid):
                self.assertNotIn('CVE-2025-29991', self.findings(aaguid, below))
                self.assertIn('CVE-2025-29991', self.findings(aaguid, minimum))
                self.assertIn('CVE-2025-29991', self.findings(aaguid, '5.7.3'))
                self.assertNotIn('CVE-2025-29991', self.findings(aaguid, '5.7.4'))

    def test_rp_enumeration_uses_separate_fixed_versions(self):
        for aaguid, affected, fixed in [
            ('ee882879-721c-4913-9775-3dfcce97072a', '5.4.3', '5.7.0'),
            ('c1f9a0bc-1dd2-404a-b27f-8e29047a43fd', '5.4.3', '5.7.2'),
            ('d8522d9f-575b-4866-88a9-ba99fa02f35b', '5.6.3', '5.6.4')]:
            with self.subTest(aaguid=aaguid):
                self.assertIn('CVE-2024-35311', self.findings(aaguid, affected))
                self.assertNotIn('CVE-2024-35311', self.findings(aaguid, fixed))

    def test_fixed_model_and_unrelated_vendor_do_not_inherit_findings(self):
        self.assertEqual(self.findings('ff4dac45-ede8-4ec2-aced-cf66103f4335', '5.7.4'), [])
        self.assertEqual(self.findings('00000000-0000-0000-0000-000000000001', '5.4.2'), [])


if __name__ == '__main__':
    unittest.main()
