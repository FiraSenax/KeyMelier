import unittest
from unittest.mock import Mock
from fido2tool_core.network import read_limited


class NetworkLimitsTests(unittest.TestCase):
    def response(self, chunks, headers=None):
        return Mock(headers=headers or {}, iter_content=Mock(return_value=iter(chunks)))

    def test_missing_or_understated_length_does_not_bypass_limit(self):
        for headers in ({}, {'Content-Length':'1'}):
            with self.assertRaises(ValueError):
                read_limited(self.response([b'123', b'456'], headers), 5)

    def test_oversize_header_rejected_before_read(self):
        response = self.response([], {'Content-Length':'100'})
        with self.assertRaises(ValueError):
            read_limited(response, 5)
        response.iter_content.assert_not_called()

    def test_exact_limit_and_empty_chunks(self):
        self.assertEqual(read_limited(self.response([b'', b'123', b'45']), 5), b'12345')

    def test_http_error_prevents_parsing(self):
        response = self.response([b'error'])
        response.raise_for_status.side_effect = OSError('HTTP error')
        with self.assertRaises(OSError):
            read_limited(response, 100)
        response.iter_content.assert_not_called()
