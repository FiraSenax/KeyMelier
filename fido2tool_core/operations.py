"""Single-flight, cancellable operations keyed by a connected device.

Registration precedes acquiring the device session, so cancellation also reaches
an operation queued behind another device call. Cleanup only removes its owner.
"""

import threading
from contextlib import contextmanager

from fido2tool_core.auth import AuthError


class PendingOperations:
    def __init__(self):
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}

    @contextmanager
    def start(self, device_id: str):
        event = threading.Event()
        with self._lock:
            if device_id in self._events:
                raise AuthError("The key is busy.", "busy", status=409)
            self._events[device_id] = event
        try:
            yield event
        finally:
            with self._lock:
                if self._events.get(device_id) is event:
                    del self._events[device_id]

    def cancel(self, device_id: str) -> bool:
        with self._lock:
            event = self._events.get(device_id)
            if event is not None:
                event.set()
            return event is not None
