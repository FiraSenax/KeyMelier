"""Bound untrusted HTTP response bodies before parsing or verifying them."""


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
