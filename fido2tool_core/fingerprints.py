"""Fingerprint management: list, enroll, rename, remove.

Requires the key to be unlocked first (see fido2tool_core.auth). Enrollment is
interactive (several touches) and runs in a background thread that reports
progress through a callback; it can be cancelled via a threading.Event.
"""

import logging
import threading

from fido2.ctap2.pin import ClientPin

from fido2tool_core import auth
from fido2tool_core.auth import AuthError

logger = logging.getLogger(__name__)

SAMPLE_TIMEOUT_MS = 30000

# token_id -> cancel event of the running enrollment
_enrollments: dict[str, threading.Event] = {}
_enrollments_lock = threading.Lock()


def _small_int(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _bio(ctap2, protocol=None, token=None):
    from fido2.ctap2.bio import BioEnrollment, FPBioEnrollment

    if not BioEnrollment.is_supported(ctap2.info):
        raise AuthError("This key has no fingerprint sensor.", "unsupported", reason="no_sensor")
    return FPBioEnrollment(ctap2, protocol, token)


def _template_id(hex_id: str) -> bytes:
    try:
        return bytes.fromhex(hex_id or "")
    except ValueError:
        raise AuthError("Invalid fingerprint id.", "invalid_input") from None


def capabilities(ctap2) -> dict:
    from fido2.ctap2.bio import BioEnrollment

    info = ctap2.info
    caps = {
        "supported": BioEnrollment.is_supported(info),
        "pin_set": (info.options or {}).get("clientPin") is True,
        "uv_unlock": auth.uv_unlock_available(info),
        "max_samples": None,
        "max_name_bytes": None,
    }
    if caps["supported"]:
        try:
            sensor = _bio(ctap2).get_fingerprint_sensor_info()
            # Device-supplied: accept small integers only (they end up in markup)
            caps["max_samples"] = _small_int(sensor.get(BioEnrollment.RESULT.MAX_SAMPLES_REQUIRED), 1, 64)
            caps["max_name_bytes"] = _small_int(sensor.get(BioEnrollment.RESULT.MAX_TEMPLATE_FRIENDLY_NAME), 1, 255)
        except Exception as e:
            logger.debug("Sensor info unavailable: %s", e)
    return caps


def list_fingerprints(token_id: str, ctap2) -> list[dict]:
    bio = _bio(ctap2, *auth.get_token(token_id, ClientPin.PERMISSION.BIO_ENROLL))
    enrolled = auth.call(token_id, bio.enumerate_enrollments)
    items = [{"id": bytes(tid).hex(), "name": name or ""} for tid, name in enrolled.items()]
    items.sort(key=lambda f: f["name"].lower())
    return items


def _validate_name(name: str, max_bytes) -> str:
    name = (name or "").strip()
    if max_bytes and len(name.encode("utf-8")) > max_bytes:
        raise AuthError(f"The name is too long (max. {max_bytes} bytes).", "name_too_long", max=max_bytes)
    return name


def rename(token_id: str, ctap2, template_hex: str, name: str) -> None:
    name = _validate_name(name, capabilities(ctap2)["max_name_bytes"])
    if not name:
        raise AuthError("Please enter a name.", "invalid_input")
    bio = _bio(ctap2, *auth.get_token(token_id, ClientPin.PERMISSION.BIO_ENROLL))
    auth.call(token_id, lambda: bio.set_name(_template_id(template_hex), name))


def remove(token_id: str, ctap2, template_hex: str) -> None:
    bio = _bio(ctap2, *auth.get_token(token_id, ClientPin.PERMISSION.BIO_ENROLL))
    auth.call(token_id, lambda: bio.remove_enrollment(_template_id(template_hex)))
    logger.info("Fingerprint removed")


def is_enrolling(token_id: str) -> bool:
    with _enrollments_lock:
        return token_id in _enrollments


def begin_enrollment(token_id: str) -> threading.Event:
    """Reserve the enrollment slot for a key; returns its cancel event."""
    with _enrollments_lock:
        if token_id in _enrollments:
            raise AuthError("An enrollment is already running on this key.", "busy_enrolling", status=409)
        event = threading.Event()
        _enrollments[token_id] = event
        return event


def end_enrollment(token_id: str) -> None:
    with _enrollments_lock:
        _enrollments.pop(token_id, None)


def cancel_enrollment(token_id: str) -> bool:
    with _enrollments_lock:
        event = _enrollments.get(token_id)
    if event:
        event.set()
    return event is not None


def enroll(token_id: str, ctap2, name: str, cancel: threading.Event, on_progress) -> str:
    """Enroll a new fingerprint, blocking until done. Returns the template id (hex).

    on_progress(dict) is called with {"stage": "touch"} when the key waits for
    a finger, and {"stage": "sample", "feedback", "remaining", "total"} after
    each captured sample.
    """
    from fido2.ctap import STATUS
    from fido2.ctap2.bio import FPBioEnrollment

    caps = capabilities(ctap2)
    name = _validate_name(name, caps["max_name_bytes"])
    bio = _bio(ctap2, *auth.get_token(token_id, ClientPin.PERMISSION.BIO_ENROLL))
    total = caps["max_samples"]

    def keepalive(status):
        if status == STATUS.UPNEEDED:
            on_progress({"stage": "touch"})

    template_id = None
    try:
        on_progress({"stage": "touch"})
        template_id, feedback, remaining = auth.call(
            token_id, lambda: bio.enroll_begin(SAMPLE_TIMEOUT_MS, cancel, keepalive)
        )
        if total is None or remaining + 1 > total:
            total = remaining + 1
        on_progress({"stage": "sample", "feedback": feedback.name, "remaining": remaining, "total": total})

        while remaining > 0:
            if cancel.is_set():
                raise AuthError("Cancelled.", "cancelled")
            feedback, remaining = auth.call(
                token_id,
                lambda: bio.enroll_capture_next(template_id, SAMPLE_TIMEOUT_MS, cancel, keepalive),
            )
            if feedback == FPBioEnrollment.FEEDBACK.NO_USER_ACTIVITY:
                raise AuthError("No finger was detected in time.", "timeout")
            on_progress({"stage": "sample", "feedback": feedback.name, "remaining": remaining, "total": total})
    except Exception:
        # Leave the key in a clean state; the half-enrolled template is discarded
        if template_id is not None:
            try:
                bio.enroll_cancel()
            except Exception:
                pass
        raise

    if name:
        try:
            auth.call(token_id, lambda: bio.set_name(template_id, name))
        except AuthError as e:
            logger.warning("Fingerprint enrolled but naming failed: %s", e.code)
    logger.info("Fingerprint enrolled")
    return bytes(template_id).hex()
