"""Single-flight, cancellable operations keyed by a connected device.

Registration precedes waiting for either a cancelled operation or the device
session, so cancellation also reaches queued calls. Cleanup only removes its owner.
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
        self._waiters: dict[str, set[threading.Event]] = {}

    @contextmanager
    def start(self, device_id: str, wait: float = 0.0):
        """wait: how long to wait for a *cancelled* operation to give up its
        slot (e.g. "Enter PIN instead" while the key still ends the finger
        wait). A running, not cancelled operation is refused at once."""
        event = threading.Event()
        deadline = time.monotonic() + wait
        with self._released:
            # A second cancel/lock must reach the new PIN request while the
            # cancelled fingerprint operation still owns the active slot.
            waiters = self._waiters.setdefault(device_id, set())
            waiters.add(event)
            try:
                while device_id in self._events:
                    if event.is_set():
                        raise AuthError("Cancelled.", "cancelled")
                    remaining = deadline - time.monotonic()
                    if not self._events[device_id].is_set() or remaining <= 0:
                        raise AuthError("The key is busy.", "busy", status=409)
                    self._released.wait(remaining)
                # The old operation may have finished before we woke up.
                if event.is_set():
                    raise AuthError("Cancelled.", "cancelled")
                self._events[device_id] = event
            finally:
                waiters.remove(event)
                if not waiters:
                    del self._waiters[device_id]
        try:
            yield event
        finally:
            with self._released:
                if self._events.get(device_id) is event:
                    del self._events[device_id]
                self._released.notify_all()

    def cancel(self, device_id: str) -> bool:
        with self._released:
            events = self._waiters.get(device_id, set()).copy()
            event = self._events.get(device_id)
            if event is not None:
                events.add(event)
            for event in events:
                event.set()
            self._released.notify_all()
            return bool(events)
