"""Smart card (CCID) access for a key's non-FIDO applications.

OATH (authenticator codes), PIV (certificates), OpenPGP and the YubiKey OTP
slots live behind the key's smart card interface, not the FIDO HID one. This
module finds the PC/SC reader that belongs to a FIDO key, serialises access
to it and translates the typical failures into user-facing errors.

YubiKeys are matched by serial number (read through the management
application); other vendors by their USB product name, which appears in the
reader name.
"""

import logging
import threading
import time
from contextlib import contextmanager, nullcontext

from fido2tool_core.pin import PinError

logger = logging.getLogger(__name__)


class CardError(PinError):
    """User-facing smart card error."""


# Applications KeyMelier can show, with the AID used to detect them
def _aids():
    from yubikit.core.smartcard import AID
    return {"oath": AID.OATH, "piv": AID.PIV, "openpgp": AID.OPENPGP, "otp": AID.OTP}


def _reader_devices():
    from ykman.pcsc import list_devices
    try:
        return list_devices(name_filter="")  # every reader, not only YubiKeys
    except Exception as e:
        logger.debug("PC/SC not available: %s", e)
        return []


def map_card_error(e) -> CardError:
    text = str(e)
    lowered = text.lower()
    if "sharing violation" in lowered or "exclusive" in lowered or "in use" in lowered:
        return CardError(
            "The key's smart card interface is used by another program (often GnuPG). "
            "Close it, e.g. with `gpgconf --kill scdaemon`, and try again.", "card_in_use")
    if "no smart card" in lowered or "removed" in lowered or "unresponsive" in lowered:
        return CardError("The key is no longer connected.", "not_found", status=404)
    return CardError(f"Smart card error: {text}", "card_error")


class Cards:
    def __init__(self):
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        # Optional callable(reader) -> context manager, entered around every
        # card connection (the service uses it to pause FIDO polling)
        self.hold = None

    def _lock(self, reader: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(reader, threading.Lock())

    @contextmanager
    def connect(self, reader: str, timeout: float = 10.0):
        """Exclusive SmartCardConnection to the named reader."""
        from yubikit.core.smartcard import SmartCardConnection

        device = next((d for d in _reader_devices() if d.reader.name == reader), None)
        if device is None:
            raise CardError("The key is no longer connected.", "not_found", status=404)
        lock = self._lock(reader)
        if not lock.acquire(timeout=timeout):
            raise CardError("The key is busy. Try again in a moment.", "busy", status=409)
        conn = None
        try:
            with (self.hold(reader) if self.hold else nullcontext()):
                try:
                    conn = device.open_connection(SmartCardConnection)
                except CardError:
                    raise
                except Exception as e:
                    raise map_card_error(e) from None
                try:
                    yield conn
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        finally:
            lock.release()

    def read(self, reader: str, fn, timeout: float = 10.0):
        """Run a read-only operation; retry once on a transient card error.

        Some keys (e.g. Token2) answer the first command after FIDO traffic
        with a spurious status word; a fresh connection fixes it.
        """
        for attempt in (1, 2):
            try:
                with self.connect(reader, timeout) as conn:
                    return fn(conn)
            except CardError as e:
                if e.code != "card_error" or attempt == 2:
                    raise
                logger.debug("Retrying card read on %s after: %s", reader, e.message)
                time.sleep(0.4)

    def _serial_of(self, reader: str) -> str | None:
        """Serial of the YubiKey behind a reader, read fresh every time: reader
        names are reused when keys are swapped, so a cache could point an
        operation at the wrong key."""
        if "yubico" not in reader.lower():
            return None
        try:
            from yubikit.management import ManagementSession
            with self.connect(reader, timeout=3.0) as conn:
                info = ManagementSession(conn).read_device_info()
                return str(info.serial) if info.serial else None
        except Exception as e:
            logger.debug("Could not read serial via %s: %s", reader, e)
            return None

    def find_reader(self, record) -> str | None:
        """PC/SC reader that belongs to a connected FIDO key, or None.

        Refuses (CardError "ambiguous") instead of guessing when more than one
        reader could be this key – operations must never hit another key.
        """
        readers = [d.reader.name for d in _reader_devices()]
        yubikey = record.vendor_id == 0x1050 or "yubi" in (record.product_name or "").lower()
        if yubikey:
            candidates = [name for name in readers if "yubico" in name.lower()]
            if record.serial_number:
                matches = [name for name in candidates if self._serial_of(name) == str(record.serial_number)]
                if len(matches) > 1:
                    raise CardError("Two devices report the same serial number – refusing to continue.",
                                    "ambiguous_key")
                return matches[0] if matches else None
            if len(candidates) > 1:
                raise CardError("Several YubiKeys are connected and this one has no readable serial "
                                "number. Plug in only this key.", "ambiguous_key")
            return candidates[0] if candidates else None
        product = (record.product_name or "").lower()
        if not product:
            return None
        matches = [name for name in readers if product in name.lower()]
        if len(matches) > 1:
            raise CardError("Several keys of this model are connected. Plug in only this key.", "ambiguous_key")
        return matches[0] if matches else None

    def applets(self, reader: str) -> dict:
        """Which of the supported applications the card answers to."""
        from yubikit.core.smartcard import ApplicationNotAvailableError, SmartCardProtocol

        def probe(conn):
            found = {}
            protocol = SmartCardProtocol(conn)
            for name, aid in _aids().items():
                try:
                    protocol.select(aid)
                    found[name] = True
                except ApplicationNotAvailableError:
                    found[name] = False
                except Exception as e:
                    # Transient (card reset, another program): let the caller retry
                    logger.debug("Selecting %s on %s failed: %s", name, reader, e)
                    raise map_card_error(e) from None
            return found

        return self.read(reader, probe)
