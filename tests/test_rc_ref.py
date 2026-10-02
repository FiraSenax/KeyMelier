import unittest
from tools.check_rc_ref import validate


class ReleaseCandidateRefTests(unittest.TestCase):
    def test_candidate_version_and_number_are_exact(self):
        self.assertEqual(validate('v1.8.3-rc.1','1.8.3'),1)
        self.assertEqual(validate('v1.8.3-rc.12','1.8.3'),12)
        for tag in ('v1.8.2-rc.1','v1.8.3','v1.8.3-rc.0','v1.8.3-rc.01','v1.8.3-rc.x','v1x8x3-rc.1'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate(tag,'1.8.3')
