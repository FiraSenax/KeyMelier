"""Check GitHub for a newer KeyMelier release (notification only, no install)."""

import logging
import re

from fido2tool_core.version import __version__

logger = logging.getLogger(__name__)

RELEASES_API = "https://api.github.com/repos/FiraSenax/KeyMelier/releases/latest"


def _parse(version: str) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", (version or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def check() -> dict:
    """Return {current, latest, newer, url, published_at} (latest may be None)."""
    import requests

    result = {"current": __version__, "latest": None, "newer": False, "url": None, "published_at": None}
    try:
        resp = requests.get(RELEASES_API, timeout=15, headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 404:
            return result  # no release published yet
        resp.raise_for_status()
        release = resp.json()
    except Exception as e:
        logger.info("App update check failed: %s", e)
        return result
    latest = _parse(release.get("tag_name", ""))
    current = _parse(__version__)
    if latest is None or release.get("draft") or release.get("prerelease"):
        return result
    result.update(
        latest=".".join(map(str, latest)),
        newer=current is not None and latest > current,
        url=release.get("html_url"),
        published_at=release.get("published_at"),
    )
    if result["newer"]:
        logger.info("KeyMelier %s is available (running %s)", result["latest"], __version__)
    return result
