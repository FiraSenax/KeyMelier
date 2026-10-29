"""Check GitHub for a newer KeyMelier release and download it on request.

KeyMelier never installs anything by itself: it downloads the disk image or
installer for this platform and verifies its SHA-256 against independently
signed, release-bound checksums. Opening it requires a separate user action.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import json
import re
import sys
from pathlib import Path

from keymelier_core.network import read_limited
from keymelier_core.distribution import is_msix
from keymelier_core.version import __version__
from keymelier_core import build_info, update_auth, update_revocation

logger = logging.getLogger(__name__)

RELEASES_API = "https://api.github.com/repos/FiraSenax/KeyMelier/releases/latest"
RC_RELEASES_API = "https://api.github.com/repos/FiraSenax/KeyMelier/releases?per_page=100"
DOWNLOAD_PREFIX = "https://github.com/FiraSenax/KeyMelier/releases/download/"
VERSION_PATTERN = update_auth.VERSION_PATTERN
MAX_SIZE = 500 * 1024 * 1024
ASSETS = {  # platform -> preferred download, fallback
    "darwin": ("KeyMelier-macOS.dmg", "KeyMelier-macOS.zip"),
    "win32": ("KeyMelier-Windows-Setup.exe", "KeyMelier-Windows.zip"),
    "linux": ("KeyMelier-Linux-x86_64.AppImage", "KeyMelier-Linux-aarch64.AppImage"),
}
LINUX_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def _parse(version: str) -> tuple[int, ...] | None:
    m = re.fullmatch(VERSION_PATTERN, version) if isinstance(version, str) and len(version) <= 64 else None
    if not m:
        return None
    # RC numbers compare numerically; the final version follows every RC.
    return (*map(int, m.group(1, 2, 3)), 0 if m[4] else 1, int(m[4] or 0))


def current_version() -> str:
    return (build_info.load().get("release_tag") or __version__).removeprefix("v")


def _asset(release: dict) -> dict | None:
    import platform

    prefix = DOWNLOAD_PREFIX + release["tag_name"] + "/"
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets", [])
              if isinstance(a, dict) and isinstance(a.get("name"), str)
              and a.get("browser_download_url") == prefix + a["name"]}
    arch = LINUX_ARCH.get(platform.machine().lower())
    for name in ASSETS.get(sys.platform, ()):
        if name.endswith(".AppImage") and not name.endswith(f"-{arch}.AppImage"):
            continue
        if name in assets and "SHA256SUMS.txt" in assets and update_auth.SIGNATURE_FILE in assets:
            return {"name": name, "url": assets[name], "sums": assets["SHA256SUMS.txt"],
                    "signature": assets[update_auth.SIGNATURE_FILE]}
    return None


def check(include_rc: bool = False) -> dict:
    """Return {current, latest, newer, url, published_at} (latest may be None)."""
    import requests

    running = current_version()
    result = {"current": running, "latest": None, "newer": False, "url": None, "published_at": None,
              "failed": False, "channel": "rc" if include_rc else "stable"}
    try:
        if is_msix():
            result["managed"] = True
            return result
        update_revocation.ensure_allowed(refresh=True)
        releases = []
        # Always include /latest, even if many newer prereleases fill the list.
        for url in ([RELEASES_API, RC_RELEASES_API] if include_rc else [RELEASES_API]):
            with requests.get(url, timeout=15, stream=True,
                              headers={"Accept": "application/vnd.github+json"}) as resp:
                if resp.status_code == 404:
                    continue  # no release published yet
                data = json.loads(read_limited(resp, 4 * 1024 * 1024 if url == RC_RELEASES_API else 1024 * 1024))
            if url == RELEASES_API and isinstance(data, dict):
                releases.append(data)
            elif url == RC_RELEASES_API and isinstance(data, list):
                releases.extend(data)
            else:
                raise ValueError("Unexpected release response")
    except update_revocation.RevokedKeyError:
        result.update(failed=True, revoked=True)
        return result
    except Exception as e:
        logger.info("App update check failed: %s", type(e).__name__)
        result["failed"] = True   # offline or GitHub unreachable – say so when asked
        return result
    candidates = []
    for release in releases:
        if not isinstance(release, dict) or not isinstance(release.get("assets", []), list):
            continue
        version = _parse(release.get("tag_name"))
        if version is None or release.get("draft"):
            continue
        rc = version[3] == 0
        if rc and (not include_rc or release.get("prerelease") is not True):
            continue
        if not rc and release.get("prerelease"):
            continue
        asset = _asset(release)
        if rc and not asset:
            continue  # do not offer a candidate before this platform's files are uploaded
        candidates.append((version, release, asset))
    if not candidates:
        return result
    latest, release, asset = max(candidates, key=lambda item: item[0])
    current = _parse(running)
    result.update(
        latest=release["tag_name"].removeprefix("v"),
        newer=current is not None and latest > current,
        url="https://github.com/FiraSenax/KeyMelier/releases/tag/" + release["tag_name"],
        published_at=release.get("published_at"),
        prerelease=latest[3] == 0,
    )
    if asset:
        result["asset"] = asset
    if result["newer"]:
        logger.info("KeyMelier %s is available (running %s)", result["latest"], running)
    return result


class UpdateError(Exception):
    pass


def _require_allowed_key(*, refresh=False):
    try:
        update_revocation.ensure_allowed(refresh=refresh)
    except update_revocation.RevokedKeyError:
        raise UpdateError('revoked') from None
    except (OSError, ValueError):
        raise UpdateError('Could not verify the local update revocation state.') from None


def _download_dir() -> Path:
    downloads = Path.home() / "Downloads"
    return downloads if downloads.is_dir() else Path.home()


def download(asset: dict, progress=None) -> Path:
    """Authenticate the release-bound checksums before downloading its asset.

    Return the local path only after the file matches the signed checksum.
    Missing/invalid signatures never fall back to unsigned checksums.
    """
    import requests
    from keymelier_core.storage import stateless

    if is_msix():
        raise UpdateError("This installation is updated through its MSIX package.")
    if stateless():
        raise UpdateError("Downloads are disabled in stateless mode.")

    if not isinstance(asset, dict):
        raise UpdateError("Unexpected download location.")
    name, url, sums_url = asset.get("name"), asset.get("url"), asset.get("sums")
    if not isinstance(name, str) or name not in {n for pair in ASSETS.values() for n in pair}:
        raise UpdateError("Unexpected download location.")
    # All files must belong to exactly the same project release, not merely
    # share a URL prefix. No queries, traversal, encoded separators or fragments.
    match = re.fullmatch(re.escape(DOWNLOAD_PREFIX) + r"(v?\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?)/" + re.escape(name), str(url))
    if (not match or _parse(match[1]) is None
            or sums_url != DOWNLOAD_PREFIX + match[1] + "/SHA256SUMS.txt"
            or asset.get('signature') != DOWNLOAD_PREFIX + match[1] + '/' + update_auth.SIGNATURE_FILE):
        raise UpdateError("Unexpected download location.")
    try:
        _require_allowed_key(refresh=True)
        with requests.get(sums_url, timeout=30, stream=True) as response:
            raw_sums = read_limited(response, update_auth.MAX_CHECKSUM_BYTES)
        with requests.get(asset['signature'], timeout=30, stream=True) as response:
            signature = read_limited(response, 256)
        update_auth.verify(match[1], raw_sums, signature)
        sums = raw_sums.decode('utf-8')
    except update_auth.SignatureError:
        raise UpdateError('signature') from None
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
        _require_allowed_key()
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
    if is_msix():
        raise UpdateError("This installation is updated through its MSIX package.")
    _require_allowed_key(refresh=True)
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606 – verified installer chosen by the user
    else:
        # Linux: an AppImage is not installed – mark it executable and show it in the file manager
        from keymelier_core.desktop import open_with_system
        path.chmod(0o755)
        open_with_system(str(path.parent))
