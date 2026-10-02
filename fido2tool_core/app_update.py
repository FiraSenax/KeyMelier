"""Check GitHub for a newer KeyMelier release and download it on request.

KeyMelier never installs anything by itself: it downloads the disk image or
installer for this platform, verifies it against the release's published
SHA-256 checksums and opens it – the user installs, like VLC and co.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import re
import sys
from pathlib import Path

from fido2tool_core.network import read_limited
from fido2tool_core.version import __version__

logger = logging.getLogger(__name__)

RELEASES_API = "https://api.github.com/repos/FiraSenax/KeyMelier/releases/latest"
DOWNLOAD_PREFIX = "https://github.com/FiraSenax/KeyMelier/releases/download/"
MAX_SIZE = 500 * 1024 * 1024
ASSETS = {  # platform -> preferred download, fallback
    "darwin": ("KeyMelier-macOS.dmg", "KeyMelier-macOS.zip"),
    "win32": ("KeyMelier-Windows-Setup.exe", "KeyMelier-Windows.zip"),
    "linux": ("KeyMelier-Linux-x86_64.AppImage", "KeyMelier-Linux-aarch64.AppImage"),
}
LINUX_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def _parse(version: str) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", (version or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def check() -> dict:
    """Return {current, latest, newer, url, published_at} (latest may be None)."""
    import requests

    result = {"current": __version__, "latest": None, "newer": False, "url": None, "published_at": None,
              "failed": False}
    try:
        resp = requests.get(RELEASES_API, timeout=15, headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 404:
            return result  # no release published yet
        resp.raise_for_status()
        release = resp.json()
    except Exception as e:
        logger.info("App update check failed: %s", e)
        result["failed"] = True   # offline or GitHub unreachable – say so when asked
        return result
    if not isinstance(release, dict) or not isinstance(release.get("tag_name", ""), str) or not isinstance(release.get("assets", []), list):
        result["failed"] = True
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
              if isinstance(a, dict) and isinstance(a.get("name"), str)
              and isinstance(a.get("browser_download_url"), str) and a["browser_download_url"].startswith(DOWNLOAD_PREFIX)}
    import platform
    arch = LINUX_ARCH.get(platform.machine().lower())
    for name in ASSETS.get(sys.platform, ()):
        if name.endswith(".AppImage") and not name.endswith(f"-{arch}.AppImage"):
            continue   # the build for another processor
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

    if not isinstance(asset, dict):
        raise UpdateError("Unexpected download location.")
    name, url, sums_url = asset.get("name"), asset.get("url"), asset.get("sums")
    if not isinstance(name, str) or name not in {n for pair in ASSETS.values() for n in pair}:
        raise UpdateError("Unexpected download location.")
    # Both files must belong to exactly the same project release, not merely
    # share a URL prefix. No queries, traversal, encoded separators or fragments.
    match = re.fullmatch(re.escape(DOWNLOAD_PREFIX) + r"(v?\d+\.\d+\.\d+)/" + re.escape(name), str(url))
    if not match or sums_url != DOWNLOAD_PREFIX + match[1] + "/SHA256SUMS.txt":
        raise UpdateError("Unexpected download location.")
    try:
        with requests.get(sums_url, timeout=30, stream=True) as response:
            sums = read_limited(response, 128 * 1024).decode("utf-8")
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("Could not load the checksums.") from None
    matches = []
    for line in sums.splitlines():
        entry = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if entry and entry[2] == name:
            matches.append(entry[1].lower())
    if len(matches) != 1:
        raise UpdateError("The release must publish exactly one checksum for this file.")

    directory = _download_dir()
    partial = None
    digest = hashlib.sha256()
    try:
        # Exclusive, random, owner-only temporary file; never follow an old
        # predictable .part symlink or truncate somebody else's download.
        with tempfile.NamedTemporaryFile(prefix=".keymelier-", suffix=".part", dir=directory, delete=False) as f:
            partial = Path(f.name)
            with requests.get(url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("Content-Length") or 0)
                if total < 0 or total > MAX_SIZE:
                    raise UpdateError("The download is unexpectedly large.")
                done = 0
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    done += len(chunk)
                    if done > MAX_SIZE:
                        raise UpdateError("The download is unexpectedly large.")
                    digest.update(chunk)
                    f.write(chunk)
                    if progress and total:
                        progress(min(99, done * 100 // total))
            f.flush()
            os.fsync(f.fileno())
        if digest.hexdigest() != matches[0]:
            raise UpdateError("checksum")
        target = _publish_download(partial, directory, name)
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("Download failed.") from None
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)
    logger.info("Update %s downloaded and verified", name)
    return target


def _publish_download(partial: Path, directory: Path, name: str) -> Path:
    """Reserve a destination exclusively, including against dangling symlinks.

    Copy only verified bytes. Exclusive creation works on NTFS and removable
    filesystems without requiring hard links. The caller receives the path only
    once the copy is complete; a failed copy removes only our new file.
    """
    for n in range(1000):
        target = directory / (name if n == 0 else f"{Path(name).stem} ({n}){Path(name).suffix}")
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        try:
            with os.fdopen(fd, "wb") as dest, partial.open("rb") as source:
                shutil.copyfileobj(source, dest)
                dest.flush()
                os.fsync(dest.fileno())
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return target
    raise UpdateError("Too many existing downloads. Choose a clean download folder.")


def open_download(path: Path) -> None:
    """Open the verified disk image (Finder shows it), start the installer, or
    show the AppImage in the file manager (Linux)."""
    import os
    import subprocess
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606 – verified installer chosen by the user
    else:
        # Linux: an AppImage is not installed – mark it executable and show it in the file manager
        from fido2tool_core.desktop import open_with_system
        path.chmod(0o755)
        open_with_system(str(path.parent))
