"""Check GitHub for a newer KeyMelier release and download it on request.

KeyMelier never installs anything by itself: it downloads the disk image or
installer for this platform, verifies it against the release's published
SHA-256 checksums and opens it – the user installs, like VLC and co.
"""

import hashlib
import logging
import re
import sys
from pathlib import Path

from fido2tool_core.version import __version__

logger = logging.getLogger(__name__)

RELEASES_API = "https://api.github.com/repos/FiraSenax/KeyMelier/releases/latest"
DOWNLOAD_PREFIX = "https://github.com/FiraSenax/KeyMelier/releases/download/"
MAX_SIZE = 500 * 1024 * 1024
ASSETS = {  # platform -> preferred download, fallback
    "darwin": ("KeyMelier-macOS.dmg", "KeyMelier-macOS.zip"),
    "win32": ("KeyMelier-Windows-Setup.exe", "KeyMelier-Windows.zip"),
}


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
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets", [])
              if str(a.get("browser_download_url", "")).startswith(DOWNLOAD_PREFIX)}
    for name in ASSETS.get(sys.platform, ()):
        if name in assets and "SHA256SUMS.txt" in assets:
            result["asset"] = {"name": name, "url": assets[name], "sums": assets["SHA256SUMS.txt"]}
            break
    if result["newer"]:
        logger.info("KeyMelier %s is available (running %s)", result["latest"], __version__)
    return result


class UpdateError(Exception):
    pass


def _download_dir() -> Path:
    downloads = Path.home() / "Downloads"
    return downloads if downloads.is_dir() else Path.home()


def download(asset: dict, progress=None) -> Path:
    """Download the asset, verify its SHA-256 against SHA256SUMS.txt of the
    same release and return the local path. Deletes the file on mismatch."""
    import requests

    name, url, sums_url = asset.get("name"), asset.get("url"), asset.get("sums")
    if name not in {n for pair in ASSETS.values() for n in pair} or \
            not all(str(u).startswith(DOWNLOAD_PREFIX) for u in (url, sums_url)):
        raise UpdateError("Unexpected download location.")
    try:
        sums = requests.get(sums_url, timeout=30).text
    except Exception as e:
        raise UpdateError(f"Could not load the checksums: {e}") from None
    expected = next((line.split()[0].lower() for line in sums.splitlines()
                     if line.strip().endswith(name) and re.fullmatch(r"[0-9a-fA-F]{64}", line.split()[0])), None)
    if expected is None:
        raise UpdateError("The release publishes no checksum for this file.")

    target = _download_dir() / name
    n = 1
    while target.exists():
        target = target.with_name(f"{Path(name).stem} ({n}){Path(name).suffix}")
        n += 1
    partial = target.with_name(target.name + ".part")
    digest = hashlib.sha256()
    try:
        with requests.get(url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length") or 0)
            if total > MAX_SIZE:
                raise UpdateError("The download is unexpectedly large.")
            done = 0
            with open(partial, "wb") as f:
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    done += len(chunk)
                    if done > MAX_SIZE:
                        raise UpdateError("The download is unexpectedly large.")
                    digest.update(chunk)
                    f.write(chunk)
                    if progress and total:
                        progress(min(99, done * 100 // total))
    except UpdateError:
        partial.unlink(missing_ok=True)
        raise
    except Exception as e:
        partial.unlink(missing_ok=True)
        raise UpdateError(f"Download failed: {e}") from None
    if digest.hexdigest() != expected:
        partial.unlink(missing_ok=True)
        raise UpdateError("checksum")
    partial.rename(target)
    logger.info("Update %s downloaded and verified", name)
    return target


def open_download(path: Path) -> None:
    """Open the verified disk image (Finder shows it) or start the installer."""
    import os
    import subprocess
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606 – verified installer chosen by the user
