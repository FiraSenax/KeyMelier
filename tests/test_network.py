import unittest
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock
from unittest.mock import patch
from keymelier_core import network
from keymelier_core.network import bounded_get, read_limited
import requests


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


class NetworkDeadlineTests(unittest.TestCase):
    def test_trickling_headers_and_body_cannot_extend_total_deadline(self):
        stop = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                try:
                    if self.path == '/headers':
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    else:
                        self.send_response(200)
                        self.send_header('Content-Length', '10000')
                        self.end_headers()
                    while not stop.wait(0.01):
                        self.wfile.write(b'x')
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ('headers', 'body'):
                started = time.monotonic()
                with self.subTest(path=path), self.assertRaises(requests.Timeout):
                    with bounded_get(f'http://127.0.0.1:{server.server_port}/{path}',
                                     stream=True, timeout=0.1, total_timeout=0.2) as response:
                        read_limited(response, 20000)
                self.assertLess(time.monotonic() - started, 1.5)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_stuck_header_workers_are_bounded_and_late_results_discarded(self):
        entered, release = threading.Event(), threading.Event()
        slots = threading.BoundedSemaphore(1)

        def stalled(*args, **kwargs):
            entered.set()
            release.wait(2)
            return Mock()

        with patch.object(network, '_SLOTS', slots), patch('requests.get', side_effect=stalled) as get:
            try:
                with self.assertRaises(requests.Timeout):
                    with bounded_get('https://synthetic.invalid', total_timeout=0.1):
                        self.fail('late headers must not be delivered')
                self.assertTrue(entered.is_set())
                with self.assertRaisesRegex(requests.Timeout, 'concurrency'):
                    with bounded_get('https://synthetic.invalid'):
                        self.fail('no second worker may be created')
                get.assert_called_once()
            finally:
                release.set()
                self.assertTrue(slots.acquire(timeout=2))
                slots.release()
