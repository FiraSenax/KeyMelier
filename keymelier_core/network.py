"""Bound HTTP response size, elapsed time and concurrent blocking reads.

Requests' read timeout is an inactivity timeout, not a transfer deadline. The
caller consumes a bounded queue with one monotonic deadline, including headers.
Workers only fetch bytes: timed-out results cannot update application state.
Socket shutdown interrupts body reads. DNS/header reads in third-party code may
outlive cancellation; at most four daemon workers can exist, and new calls fail
closed while those slots remain occupied. No unbounded executor queue is used.
"""
import queue
import socket
import threading
import time
from contextlib import contextmanager

import requests

TOTAL_TIMEOUT = 45
DOWNLOAD_TIMEOUT = 15 * 60
_SLOTS = threading.BoundedSemaphore(4)


class _Transfer:
    def __init__(self, url, kwargs, seconds):
        self.deadline = time.monotonic() + seconds
        self.events = queue.Queue(maxsize=2)
        self.stop = threading.Event()
        self.read = threading.Event()
        self.response = None
        self.worker = threading.Thread(target=self.run, args=(url, kwargs), daemon=True,
                                       name='keymelier-http')

    def send(self, kind, value):
        while not self.stop.is_set() and time.monotonic() < self.deadline:
            try:
                self.events.put((kind, value), timeout=0.05)
                return True
            except queue.Full:
                pass
        return False

    def run(self, url, kwargs):
        try:
            with requests.get(url, **kwargs) as response:
                self.response = response
                if not self.send('headers', response):
                    return
                # Let the caller reject status/size/redirect headers before any
                # response body is consumed.
                if not self.read.wait(max(0, self.deadline - time.monotonic())) or self.stop.is_set():
                    return
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not self.send('chunk', chunk):
                        return
                self.send('end', None)
        except Exception as error:
            self.send('error', error)
        finally:
            _SLOTS.release()

    def receive(self):
        remaining = self.deadline - time.monotonic()
        if remaining > 0:
            try:
                kind, value = self.events.get(timeout=remaining)
                if time.monotonic() >= self.deadline:
                    raise requests.Timeout('HTTP transfer exceeded its total time limit')
                if kind == 'error':
                    raise value
                return kind, value
            except queue.Empty:
                pass
        raise requests.Timeout('HTTP transfer exceeded its total time limit')

    def cancel(self):
        self.stop.set()
        self.read.set()
        # Never call Response.close on the waiting thread: it can wait for a
        # blocked buffered read. shutdown wakes that read without acquiring its
        # lock; the owning worker closes the response/session in its finally.
        raw = getattr(self.response, 'raw', None)
        connection = getattr(raw, '_connection', None)
        stream = getattr(getattr(raw, '_fp', None), 'fp', None)
        candidates = (getattr(connection, 'sock', None),
                      getattr(getattr(stream, 'raw', None), '_sock', None))
        for sock in candidates:
            if isinstance(sock, socket.socket):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.worker.join(timeout=0.05)

    def iter_content(self, chunk_size=64 * 1024):
        self.read.set()
        while True:
            kind, value = self.receive()
            if kind == 'end':
                return
            yield value

    @property
    def headers(self):
        return self.response.headers

    @property
    def status_code(self):
        return self.response.status_code

    def raise_for_status(self):
        self.response.raise_for_status()


@contextmanager
def bounded_get(url, *, total_timeout=TOTAL_TIMEOUT, **kwargs):
    """Requests-compatible streamed GET with a total caller-visible deadline."""
    if not 0 < total_timeout <= DOWNLOAD_TIMEOUT:
        raise ValueError('Invalid HTTP time limit')
    kwargs['stream'] = True
    if not _SLOTS.acquire(blocking=False):
        raise requests.Timeout('HTTP concurrency limit reached')
    transfer = _Transfer(url, kwargs, total_timeout)
    try:
        transfer.worker.start()
    except Exception:
        _SLOTS.release()
        raise
    try:
        kind, _ = transfer.receive()
        if kind != 'headers':
            raise ValueError('Missing HTTP response')
        yield transfer
    finally:
        transfer.cancel()


def read_limited(response, max_bytes: int) -> bytes:
    """Read a streamed response, including decompressed bytes, with a hard cap.

    Callers own the response context, URL policy and timeout. Content-Length
    is only an early rejection hint; missing or incorrect headers cannot bypass
    the actual byte limit.
    """
    response.raise_for_status()
    length = response.headers.get("Content-Length")
    if length is not None and (int(length) < 0 or int(length) > max_bytes):
        raise ValueError("HTTP response exceeds the size limit")
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if len(body) + len(chunk) > max_bytes:
            raise ValueError("HTTP response exceeds the size limit")
        body.extend(chunk)
    return bytes(body)
