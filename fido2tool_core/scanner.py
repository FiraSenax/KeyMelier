import hashlib
import threading
import time
import uuid
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class DeviceBusy(Exception):
    """Raised when a device is locked by another operation (e.g. attestation)."""


class DeviceNotFound(Exception):
    """Raised when a token id is unknown or the device is no longer attached."""


@dataclass
class TokenRecord:
    id: str
    path: str
    product_name: str
    serial_number: Optional[str]
    manufacturer: str
    aaguid: str
    fido2_versions: list
    extensions: list
    options: dict
    pin_protocols: list
    max_cred_count: Optional[int]
    firmware_version_raw: Optional[int]
    firmware_version_str: str
    first_seen: str
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    form_factor: Optional[str] = None   # e.g. "usb-c-nano" (from vendor tools)
    fips: bool = False
    nfc: Optional[bool] = None
    min_pin_length: int = 4
    force_pin_change: bool = False
    remaining_disc_creds: Optional[int] = None
    security_status: str = "PENDING"
    cve_ids: list = field(default_factory=list)
    advisories: list = field(default_factory=list)  # {id, title, severity, cvss, note, references}
    mds_description: Optional[str] = None
    mds_status: Optional[str] = None
    mds_authenticator_version: Optional[int] = None
    mds_icon: Optional[str] = None  # vendor icon from MDS3 (data:image/... URL)
    attestation: Optional[dict] = None  # serialised AttestationResult
    algorithms: list = field(default_factory=list)  # COSE algorithm IDs from getInfo


from fido2tool_core.firmware import decode_firmware as _decode_firmware
from fido2tool_core import vendor_info


def _apply_vendor_info(record: "TokenRecord", details: Optional[dict]) -> None:
    if not details:
        return
    if details.get("serial") and not record.serial_number:
        record.serial_number = details["serial"]
    version = details.get("version")
    if version:
        major, minor, patch = (list(version) + [0, 0, 0])[:3]
        record.firmware_version_raw = (major << 16) | (minor << 8) | patch
        record.firmware_version_str = f"{major}.{minor}.{patch}"
    record.form_factor = details.get("form_factor") or record.form_factor
    record.fips = details.get("fips", False)
    record.nfc = details.get("nfc")


def _infer_manufacturer(product_name: str) -> str:
    name_lower = (product_name or "").lower()
    if "yubikey" in name_lower or "yubico" in name_lower:
        return "Yubico"
    if "feitian" in name_lower or "epass" in name_lower or "biopass" in name_lower:
        return "Feitian"
    if "token2" in name_lower:
        return "Token2"
    if "solokey" in name_lower or "solo" in name_lower:
        return "SoloKeys"
    if "nitrokey" in name_lower:
        return "Nitrokey"
    if "titan" in name_lower:
        return "Google"
    if "thetis" in name_lower:
        return "Thetis"
    if "hidglobal" in name_lower or "hid global" in name_lower:
        return "HID Global"
    return "Unknown"


def _aaguid_bytes_to_str(aaguid) -> str:
    if aaguid is None:
        return "00000000-0000-0000-0000-000000000000"
    if isinstance(aaguid, (bytes, bytearray)):
        return str(uuid.UUID(bytes=bytes(aaguid)))
    return str(aaguid).lower()


def _token_id(path_key: str) -> str:
    """Stable, URL-safe id for a HID path (raw paths contain slashes/backslashes)."""
    return hashlib.sha256(path_key.encode()).hexdigest()[:16]


def _apply_info(record: "TokenRecord", info) -> None:
    """Copy the mutable parts of a getInfo response onto a record."""
    record.options = dict(info.options or {})
    record.min_pin_length = getattr(info, "min_pin_length", 4) or 4
    record.force_pin_change = bool(getattr(info, "force_pin_change", False))
    record.remaining_disc_creds = getattr(info, "remaining_disc_creds", None)
    algs = []
    for entry in getattr(info, "algorithms", None) or []:
        alg = entry.get("alg") if isinstance(entry, dict) else getattr(entry, "alg", None)
        if isinstance(alg, int):
            algs.append(alg)
    record.algorithms = algs


class TokenScanner:
    def __init__(self, poll_interval: float = 1.0, mds3_client=None, advisory_checker=None):
        self.poll_interval = poll_interval
        self._mds3 = mds3_client
        self._advisory = advisory_checker
        self._known: dict[str, TokenRecord] = {}
        self._lock = threading.Lock()
        self._running = False
        # One lock per HID path. Whoever holds it owns the device's CTAP channel;
        # the poll loop skips locked devices and treats them as still present.
        self._device_locks: dict[str, threading.Lock] = {}

        self.on_connect: Callable[[TokenRecord], None] = lambda r: None
        self.on_disconnect: Callable[[TokenRecord], None] = lambda r: None
        self.on_update: Callable[[TokenRecord], None] = lambda r: None
        # Called for each newly connected key; returning True means the key was
        # taken over (e.g. for a pending factory reset) and must not be touched
        # by the attestation test.
        self.intercept_connect: Callable[[TokenRecord], bool] = lambda r: False

    def set_callbacks(self, on_connect, on_disconnect, on_update):
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.on_update = on_update

    def _device_lock(self, path_key: str) -> threading.Lock:
        with self._lock:
            return self._device_locks.setdefault(path_key, threading.Lock())

    @contextmanager
    def hold(self, token_id: str, timeout: float = 10.0):
        """Keep the poll loop off a key's FIDO interface (without opening it).

        Some keys (e.g. Token2) reject smart card commands while FIDO traffic
        runs, and the poll loop talks to every key once per second.
        """
        record = self.get(token_id)
        lock = self._device_lock(record.path)
        if not lock.acquire(timeout=timeout):
            raise DeviceBusy(record.path)
        try:
            yield record
        finally:
            lock.release()

    def _enumerate_devices(self) -> tuple[dict[str, TokenRecord], set[str]]:
        """Return (records of idle devices, paths of devices currently locked)."""
        result = {}
        busy = set()
        try:
            from fido2.hid import CtapHidDevice, list_descriptors, open_connection
            from fido2.ctap2 import Ctap2
            descriptors = list(list_descriptors())
        except Exception as e:
            logger.debug("HID enumerate error: %s", e)
            return result, busy

        for desc in descriptors:
            path_key = str(desc.path)
            lock = self._device_lock(path_key)
            if not lock.acquire(blocking=False):
                busy.add(path_key)
                continue
            dev = None
            try:
                dev = CtapHidDevice(desc, open_connection(desc))
                info = Ctap2(dev).info
                with self._lock:
                    is_new = path_key not in self._known

                aaguid_str = _aaguid_bytes_to_str(info.aaguid)
                fw_raw = getattr(info, "firmware_version", None)
                product = getattr(desc, "product_name", None) or ""
                serial = getattr(desc, "serial_number", None)
                manufacturer = _infer_manufacturer(product)

                record = TokenRecord(
                    id=_token_id(path_key),
                    path=path_key,
                    product_name=product,
                    serial_number=serial or None,
                    manufacturer=manufacturer,
                    aaguid=aaguid_str,
                    fido2_versions=list(info.versions or []),
                    extensions=list(info.extensions or []),
                    options={},
                    pin_protocols=list(info.pin_uv_protocols or []),
                    max_cred_count=getattr(info, "max_creds_in_list", None),
                    firmware_version_raw=fw_raw,
                    firmware_version_str=_decode_firmware(fw_raw, manufacturer),
                    first_seen=datetime.now(timezone.utc).isoformat(),
                )
                _apply_info(record, info)
                record.vendor_id = getattr(desc, "vid", None)
                record.product_id = getattr(desc, "pid", None)
                if is_new:
                    # Serial, real firmware, form factor – only once per plug-in
                    _apply_vendor_info(record, vendor_info.read(dev, record.vendor_id, record.product_id))
                result[path_key] = record
            except Exception as e:
                logger.debug("Could not read CTAP2 info from device: %s", e)
            finally:
                if dev is not None:
                    try:
                        dev.close()
                    except Exception:
                        pass
                lock.release()

        return result, busy

    def get(self, token_id: str) -> TokenRecord:
        with self._lock:
            for record in self._known.values():
                if record.id == token_id:
                    return record
        raise DeviceNotFound(token_id)

    @contextmanager
    def _open(self, record: TokenRecord, timeout: float):
        """Lock the device and yield a fresh Ctap2 session on it."""
        from fido2.hid import CtapHidDevice, list_descriptors, open_connection
        from fido2.ctap2 import Ctap2

        lock = self._device_lock(record.path)
        if not lock.acquire(timeout=timeout):
            raise DeviceBusy(record.path)
        dev = None
        try:
            desc = next(
                (d for d in list_descriptors() if str(d.path) == record.path), None
            )
            if desc is None:
                raise DeviceNotFound(record.id)
            dev = CtapHidDevice(desc, open_connection(desc))
            yield Ctap2(dev)
        finally:
            if dev is not None:
                try:
                    dev.close()
                except Exception:
                    pass
            lock.release()

    @contextmanager
    def session(self, token_id: str, timeout: float = 3.0, refresh: bool = True):
        """Exclusive CTAP2 session on a known token.

        Yields (record, ctap2). Raises DeviceNotFound / DeviceBusy. With
        refresh=True the record is re-read from getInfo afterwards and
        on_update is fired, so state changes (PIN set, credentials deleted, ...)
        reach the UI. Use refresh=False for read-only operations.
        """
        record = self.get(token_id)
        with self._open(record, timeout) as ctap2:
            try:
                yield record, ctap2
            finally:
                if refresh:
                    try:
                        _apply_info(record, ctap2.get_info())
                    except Exception as e:
                        logger.debug("Post-session getInfo failed: %s", e)
        if not refresh:
            return
        try:
            self.on_update(record)
        except Exception as e:
            logger.error("on_update callback error (post-session): %s", e)

    def start_attestation(self, record: TokenRecord, pin: str | None = None, use_uv: bool = False):
        """Run the attestation test in the background.

        It takes the device lock itself and fires on_update when done.
        """
        threading.Thread(
            target=self._run_attestation,
            args=(record, pin, use_uv),
            daemon=True,
            name=f"attestation-{record.id}",
        ).start()

    def _run_attestation(self, record: TokenRecord, pin: str | None = None, use_uv: bool = False):
        """Run the attestation test in its own thread, holding the device lock.

        Calls on_update when done so the UI refreshes automatically.
        """
        try:
            import fido2tool_core.attestation as attestation_mod

            with self._open(record, timeout=10.0) as ctap2:
                att_result = attestation_mod.run(ctap2.device, record.aaguid, self._mds3,
                                                 pin=pin, use_uv=use_uv)
                record.attestation = _attestation_to_dict(att_result)
        except DeviceNotFound:
            record.attestation = {
                "ran": False, "passed": False,
                "error": "Device no longer accessible for attestation test",
                "checks": [],
            }
        except Exception as e:
            logger.warning("Attestation test failed for %s: %s", record.product_name, e)
            record.attestation = {
                "ran": False, "passed": False,
                "error": str(e),
                "checks": [],
            }

        # Push the update to the UI now that attestation is complete
        try:
            self.on_update(record)
        except Exception as e:
            logger.error("on_update callback error (post-attestation): %s", e)

    def _enrich_record(self, record: TokenRecord):
        record.mds_status = None
        record.mds_description = None
        record.mds_authenticator_version = None
        record.mds_icon = None
        record.cve_ids = []
        record.advisories = []
        advisory_ok = False
        advisory_level = None
        try:
            if self._mds3:
                entry = self._mds3.lookup(record.aaguid)
                if entry:
                    ms = entry.get("metadataStatement", {})
                    record.mds_description = ms.get("description")
                    record.mds_authenticator_version = ms.get("authenticatorVersion")
                    # USB names are often generic ("FIDO2 Security Key"); the
                    # metadata description usually names the vendor
                    if record.manufacturer == "Unknown" and record.mds_description:
                        record.manufacturer = _infer_manufacturer(record.mds_description)
                    icon = ms.get("icon")
                    # Only inline images; anything else is ignored
                    if isinstance(icon, str) and icon.startswith("data:image/") and len(icon) < 200_000:
                        record.mds_icon = icon
                    record.mds_status = self._mds3.get_highest_security_status(record.aaguid)
        except Exception as e:
            logger.warning("MDS3 enrichment failed: %s", e)

        try:
            if self._advisory:
                advisories = self._advisory.check(record.aaguid, record.firmware_version_raw,
                                                   manufacturer=record.manufacturer)
                record.cve_ids = [a["id"] for a in advisories]
                record.advisories = [
                    {k: a.get(k) for k in ("id", "title", "severity", "cvss", "note", "references")}
                    for a in advisories
                ]
                advisory_ok = self._advisory.document is not None
                if any(a.get("severity") == "CRITICAL" for a in advisories):
                    advisory_level = "CRITICAL"
                elif advisories:
                    advisory_level = "WARNING"
        except Exception as e:
            logger.warning("Advisory check failed: %s", e)

        # Fall back to MDS3 status
        revoked_statuses = {
            "REVOKED", "ATTESTATION_KEY_COMPROMISE",
            "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE"
        }
        warn_statuses = {"UPDATE_AVAILABLE", "USER_VERIFICATION_BYPASS"}

        if record.mds_status in revoked_statuses or advisory_level == "CRITICAL":
            record.security_status = "CRITICAL"
        elif record.mds_status in warn_statuses or advisory_level == "WARNING":
            record.security_status = "WARNING"
        elif (advisory_ok and self._mds3 and self._mds3.is_current()
              and record.mds_status in {
                  "FIDO_CERTIFIED", "FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L1plus",
                  "FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L2plus",
                  "FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"}):
            record.security_status = "OK"
        else:
            record.security_status = "UNKNOWN"

    def run_forever(self):
        self._running = True
        logger.info("Scanner started, polling every %.1fs", self.poll_interval)
        while self._running:
            try:
                current, busy = self._enumerate_devices()

                with self._lock:
                    # Locked devices are in use, not removed
                    known_paths = set(self._known.keys())
                    present_paths = set(current.keys()) | busy

                    added = set(current.keys()) - known_paths
                    removed = known_paths - present_paths

                    for path in added:
                        record = current[path]
                        self._enrich_record(record)
                        self._known[path] = record
                        try:
                            self.on_connect(record)
                        except Exception as e:
                            logger.error("on_connect callback error: %s", e)
                        try:
                            intercepted = self.intercept_connect(record)
                        except Exception as e:
                            logger.error("intercept_connect error: %s", e)
                            intercepted = False
                        if not intercepted:
                            self.start_attestation(record)

                    for path in removed:
                        # Keep the device lock: a worker (attestation, enrollment)
                        # may still hold it, and a fresh lock would let the
                        # poll loop open the device concurrently.
                        record = self._known.pop(path)
                        try:
                            self.on_disconnect(record)
                        except Exception as e:
                            logger.error("on_disconnect callback error: %s", e)

            except Exception as e:
                logger.error("Scanner loop error: %s", e)

            time.sleep(self.poll_interval)

    def reevaluate_all(self):
        """Re-run metadata/advisory enrichment on connected keys (after updates)."""
        for record in self.get_all():
            record.security_status = "PENDING"
            record.cve_ids = []
            record.advisories = []
            self._enrich_record(record)
            try:
                self.on_update(record)
            except Exception as e:
                logger.error("on_update callback error (reevaluate): %s", e)

    def get_all(self) -> list[TokenRecord]:
        with self._lock:
            return list(self._known.values())

    def stop(self):
        self._running = False


def _attestation_to_dict(att) -> dict:
    import dataclasses
    return dataclasses.asdict(att)
