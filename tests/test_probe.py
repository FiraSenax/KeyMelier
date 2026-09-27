import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fido2.ctap import CtapError

from fido2tool_core import passkey_probe
from fido2tool_core.auth import AuthError
from fido2tool_core.history import History
from fido2tool_core.scanner import TokenRecord

ERR = CtapError.ERR


def record():
    return TokenRecord('id', '/dev/test', 'Key', '123', 'vendor', 'aaguid', [], [], {}, [], None, None, '', 'now')


class FakeKey:
    """Answers get_assertion per rpId: list of users, a CtapError code, or an Exception."""

    def __init__(self, sites, next_fails_after=None):
        self.sites = sites
        self.queue = []
        self.next_fails_after = next_fails_after
        self.asked = []

    def get_assertion(self, rp_id, cdh, **kw):
        self.asked.append(rp_id)
        answer = self.sites.get(rp_id, ERR.NO_CREDENTIALS)
        if isinstance(answer, Exception):
            raise answer
        if not isinstance(answer, list):
            raise CtapError(answer)
        self.queue = list(answer[1:])
        self.served = 1
        return SimpleNamespace(number_of_credentials=len(answer), user=answer[0])

    def get_next_assertion(self):
        if self.next_fails_after is not None and self.served >= self.next_fails_after:
            raise CtapError(ERR.NOT_ALLOWED)
        self.served += 1
        return SimpleNamespace(user=self.queue.pop(0))


def u(name):
    return {'id': b'x', 'name': name}


class ProbeTests(unittest.TestCase):
    def statuses(self, scan):
        return {r['rp_id']: r['status'] for r in scan['results']}

    def test_each_outcome_is_classified(self):
        key = FakeKey({
            'a.com': [u('alice@a.com')],
            'b.com': ERR.NO_CREDENTIALS,
            'c.com': ERR.UNSUPPORTED_OPTION,
            'd.com': ERR.PUAT_REQUIRED,
            'e.com': ERR.OTHER,
        })
        scan = passkey_probe.probe(key, ['a.com', 'b.com', 'c.com', 'd.com', 'e.com'])
        self.assertTrue(scan['complete'])
        self.assertEqual(self.statuses(scan), {'a.com': 'found', 'b.com': 'none', 'c.com': 'unsupported',
                                               'd.com': 'uv_required', 'e.com': 'error'})

    def test_several_accounts_and_failure_while_walking(self):
        key = FakeKey({'login.microsoft.com': [u('a@x'), u('b@x'), u('c@x')]}, next_fails_after=2)
        r = passkey_probe.probe(key, ['login.microsoft.com'])['results'][0]
        self.assertEqual(r['count'], 3)
        self.assertEqual([x['name'] for x in r['users']], ['a@x', 'b@x'])
        self.assertTrue(r['partial'])

    def test_pin_error_aborts_without_retrying(self):
        key = FakeKey({'a.com': ERR.PIN_AUTH_INVALID, 'b.com': [u('x')]})
        with self.assertRaises(AuthError):
            passkey_probe.probe(key, ['a.com', 'b.com'])
        self.assertEqual(key.asked, ['a.com'])  # stopped immediately, no second attempt

    def test_wrong_pin_is_tried_once(self):
        calls = []

        class Pin:
            def __init__(self, ctap2):
                self.protocol = None

            def get_pin_token(self, pin):
                calls.append(pin)
                raise CtapError(ERR.PIN_INVALID)

            def get_pin_retries(self):
                return (5, None)

        with patch('fido2.ctap2.pin.ClientPin', Pin):
            with self.assertRaises(AuthError):
                passkey_probe.probe(FakeKey({}), ['a.com'], pin='0000')
        self.assertEqual(calls, ['0000'])

    def test_transport_failure_and_timeout_end_scan_as_incomplete(self):
        key = FakeKey({'a.com': [u('x')], 'b.com': OSError('device gone'), 'c.com': [u('y')]})
        scan = passkey_probe.probe(key, ['a.com', 'b.com', 'c.com'])
        self.assertFalse(scan['complete'])
        self.assertEqual(self.statuses(scan), {'a.com': 'found', 'b.com': 'error'})

    def test_cancel_keeps_results_so_far(self):
        key = FakeKey({'a.com': [u('x')]})
        state = {'n': 0}

        def cancelled():
            state['n'] += 1
            return state['n'] > 1

        scan = passkey_probe.probe(key, ['a.com', 'b.com', 'c.com'], cancelled=cancelled)
        self.assertFalse(scan['complete'])
        self.assertEqual(self.statuses(scan), {'a.com': 'found'})


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = History(Path(self.tmp.name) / 'h.json', enabled=True)
        self.h.merge_probe(record(), [
            {'rp_id': 'a.com', 'status': 'found', 'count': 1, 'users': [{'name': 'alice'}]},
            {'rp_id': 'b.com', 'status': 'found', 'count': 1, 'users': []},
            {'rp_id': 'c.com', 'status': 'found', 'count': 1, 'users': []},
        ], True, 3)

    def sites(self):
        entry = self.h.get(self.h.list()[0]['key_id'])
        return {s['rp_id']: s for s in entry['sites']}

    def test_only_explicit_none_removes_a_site(self):
        self.h.merge_probe(record(), [
            {'rp_id': 'a.com', 'status': 'none'},
            {'rp_id': 'b.com', 'status': 'error'},
            {'rp_id': 'c.com', 'status': 'unsupported'},
        ], True, 3)
        self.assertEqual(set(self.sites()), {'b.com', 'c.com'})

    def test_aborted_scan_keeps_unasked_sites(self):
        self.h.merge_probe(record(), [{'rp_id': 'a.com', 'status': 'error'}], False, 3)
        self.assertEqual(set(self.sites()), {'a.com', 'b.com', 'c.com'})
        self.assertEqual(self.sites()['a.com']['source'], 'probe')
        probe = self.h.get(self.h.list()[0]['key_id'])['probe']
        self.assertFalse(probe['complete'])

    def test_listing_replaces_probe_data_and_marks_source(self):
        self.h.set_sites(record(), [{'rp_id': 'x.com', 'name': 'X', 'count': 1, 'users': []}])
        sites = self.sites()
        self.assertEqual(set(sites), {'x.com'})
        self.assertEqual(sites['x.com']['source'], 'list')


if __name__ == '__main__':
    unittest.main()
