"""Single-flight, cancellable operations keyed by a connected device.

Registration precedes acquiring the device session, so cancellation also reaches
an operation queued behind another device call. Cleanup only removes its owner.
"""

import threading
import time
from contextlib import contextmanager

from fido2tool_core.auth import AuthError


class PendingOperations:
    def __init__(self):
        self._lock = threading.Lock()
        self._released = threading.Condition(self._lock)
        self._events: dict[str, threading.Event] = {}

    @contextmanager
    def start(self, device_id: str, wait: float = 0.0):
        """wait: how long to wait for a *cancelled* operation to give up its
        slot (e.g. "Enter PIN instead" while the key still ends the finger
        wait). A running, not cancelled operation is refused at once."""
        event = threading.Event()
        deadline = time.monotonic() + wait
        with self._released:
            while device_id in self._events:
                remaining = deadline - time.monotonic()
                if not self._events[device_id].is_set() or remaining <= 0:
                    raise AuthError("The key is busy.", "busy", status=409)
                self._released.wait(remaining)
            self._events[device_id] = event
        try:
            yield event
        finally:
            with self._released:
                if self._events.get(device_id) is event:
                    del self._events[device_id]
                self._released.notify_all()

    def cancel(self, device_id: str) -> bool:
        with self._lock:
            event = self._events.get(device_id)
            if event is not None:
                event.set()
            return event is not None
