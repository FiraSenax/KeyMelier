import unittest
from unittest.mock import Mock
from keymelier_core.network import read_limited


class TrustBundleTests(unittest.TestCase):
    def test_certifi_does_not_trust_compromised_emsign_chain(self):
        """GHSA-6q48-6c7w-9gw2: inspect the actual trust store, not just its version."""
        import hashlib
        import ssl
        import certifi

        # An explicit context loads only certifi, not the host's separate CA store.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=certifi.where())
        roots = context.get_ca_certs(binary_form=True)
        self.assertTrue(roots, "certifi must supply a usable CA bundle")
        fingerprints = {hashlib.sha256(cert).hexdigest() for cert in roots}
        # SHA-256 of emSign ECC Root CA - G3, removed by the upstream security fix.
        self.assertNotIn("86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
                         fingerprints, "certifi still trusts the compromised emSign chain")


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
