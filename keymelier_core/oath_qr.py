"""Local PNG/JPEG QR import. No network, temporary copies or device writes."""

import base64
import io
import re
from urllib.parse import parse_qs, unquote, urlparse

from keymelier_core.pin import PinError

MAX_IMAGE_BYTES = 20_000_000
MAX_IMAGE_PIXELS = 20_000_000


def parse_uri(uri: str) -> dict:
    """Return editable OATH fields, rejecting ambiguous or lossy imports."""
    from yubikit.oath import CredentialData

    try:
        if len(uri) > 8192:
            raise ValueError()
        parsed = urlparse(uri)
        if (parsed.scheme != "otpauth" or parsed.netloc not in {"totp", "hotp"}
                or parsed.fragment or not parsed.path.startswith("/")):
            raise ValueError()
        params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=12)
        if (any(len(v) != 1 for v in params.values())
                or params.keys() - {"secret", "issuer", "algorithm", "digits", "period", "counter"}):
            raise ValueError()
        label = unquote(parsed.path[1:])
        if ":" in label and "issuer" in params and label.split(":", 1)[0] != params["issuer"][0]:
            raise ValueError()
        data = CredentialData.parse_uri(uri)
        if (not data.name.strip() or not data.secret or len(data.secret) > 128
                or data.digits not in (6, 7, 8) or not 1 <= data.period <= 300
                or not 0 <= data.counter <= 0xFFFFFFFF or len(data.get_id()) > 64
                or re.search(r"[\x00-\x1f\x7f]", data.name + (data.issuer or ""))):
            raise ValueError()
        if parsed.netloc == "hotp" and ("counter" not in params or "period" in params):
            raise ValueError()
        if parsed.netloc == "totp" and "counter" in params:
            raise ValueError()
        return {
            "issuer": data.issuer or "", "name": data.name,
            "secret": base64.b32encode(data.secret).decode("ascii").rstrip("="),
            "oath_type": data.oath_type.name, "algorithm": data.hash_algorithm.name,
            "digits": data.digits, "period": data.period, "counter": data.counter,
        }
    except Exception:
        # Never echo a URI, secret, account or decoder exception.
        raise PinError("This QR code is not a supported authenticator account.", "qr_invalid") from None


def decode_image(raw: bytes) -> dict:
    from PIL import Image
    import zxingcpp

    if len(raw) > MAX_IMAGE_BYTES:
        raise PinError("The image is too large.", "qr_large")
    try:
        with Image.open(io.BytesIO(raw), formats=("PNG", "JPEG")) as source:
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise PinError("The image is too large.", "qr_large")
            # Only decode pixels after the dimensions have passed the limit.
            source.load()
            with source.convert("RGB") as pixels:
                results = zxingcpp.read_barcodes(pixels, formats=zxingcpp.BarcodeFormat.QRCode)
    except PinError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise PinError("The image is too large.", "qr_large") from None
    except Exception:
        raise PinError("Choose a readable PNG or JPEG image.", "qr_image") from None
    codes = {r.text for r in results if r.valid and r.text.startswith(("otpauth:", "otpauth-migration:"))}
    if not codes:
        raise PinError("No authenticator QR code was found in this image.", "qr_no_code")
    if len(codes) != 1:
        raise PinError("The image contains several accounts. Choose one QR code.", "qr_multiple")
    return parse_uri(codes.pop())


def read_image(path) -> dict:
    with open(path, "rb") as source:
        return decode_image(source.read(MAX_IMAGE_BYTES + 1))
