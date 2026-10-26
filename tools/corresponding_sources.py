"""Collect exact source archives alongside binaries and retain upstream notices.

The manifest is also bundled in the application. Downloads are size/hash
checked; Debian source versions come from the actually collected ELF files.
Archives are read, never extracted or executed on the build host.
"""
import hashlib
import io
import json
import platform
import re
import shlex
import subprocess
import sys
import tarfile
from importlib.metadata import distribution
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "build/source-downloads"


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def python_sources(names):
    pins = json.loads((ROOT / "packaging/python-sources.json").read_text())
    out = []
    for name in sorted({norm(n) for n in names} & pins.keys()):
        pin = pins[name]
        if distribution(name).version != pin["version"]:
            raise ValueError(f"Review corresponding source version for {name}")
        out.append({"component": name, **pin})
    return out


def debian_sources(packages):
    out = {}
    for name, version in sorted({(p["source_package"], p["source_version"]) for p in packages}):
        # --print-uris defaults to MD5 for historical compatibility. Request
        # the SHA-256 proof from the authenticated source index explicitly.
        query = subprocess.run(["apt-get", "-o", "Acquire::ForceHash=sha256",
                                "--print-uris", "--only-source", "source", f"{name}={version}"],
                               capture_output=True, text=True, check=True, cwd=CACHE)
        found = []
        for line in query.stdout.splitlines():
            if not line.startswith("'"):
                continue
            url, filename, size, checksum = shlex.split(line)
            if not checksum.startswith("SHA256:"):
                raise ValueError(f"No SHA-256 source proof for {name}: {filename}")
            location = urlsplit(url)
            # GitHub's Azure mirror serves HTTP only. Fetch the exact same
            # hash-pinned Ubuntu pool object from the official HTTPS archive.
            host = "archive.ubuntu.com" if location.netloc == "azure.archive.ubuntu.com" else location.netloc
            if location.scheme in {"http", "https"}:
                url = urlunsplit(("https", host, location.path, location.query, location.fragment))
            found.append(filename)
            out[filename] = {"component": name, "version": version, "filename": filename,
                             "url": url, "size": int(size), "sha256": checksum.split(":", 1)[1],
                             "modified": True, "modifications": "Ubuntu source package includes Debian patches/build rules"}
        if not any(n.endswith(".dsc") for n in found):
            raise ValueError(f"Complete source for {name}={version} unavailable; enable matching deb-src repositories")
    return list(out.values())


def fetch(source):
    filename = source["filename"]
    if Path(filename).name != filename or not source["url"].startswith("https://"):
        raise ValueError("Unsafe source archive location")
    if not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]) or not 0 < source["size"] < 1_500_000_000:
        raise ValueError(f"Invalid source manifest entry: {filename}")
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / (source["sha256"][:16] + "-" + filename)
    if target.is_file() and target.stat().st_size == source["size"]:
        with target.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() == source["sha256"]:
                return target
    partial = target.with_suffix(target.suffix + ".partial")
    digest, size = hashlib.sha256(), 0
    try:
        with requests.get(source["url"], stream=True, timeout=(20, 90)) as response, partial.open("wb") as dest:
            response.raise_for_status()
            for chunk in response.iter_content(1 << 20):
                size += len(chunk)
                if size > source["size"]:
                    raise ValueError(f"Source exceeds expected size: {filename}")
                digest.update(chunk)
                dest.write(chunk)
        if size != source["size"] or digest.hexdigest() != source["sha256"]:
            raise ValueError(f"Source checksum/size mismatch: {filename}")
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)
    return target


def archive_notices(path):
    """Preserve original license/notice texts, including Chromium's notices.

    This includes notices for optional upstream modules; it is not an assertion
    that every upstream module was linked into this particular application.
    """
    texts = []
    with tarfile.open(path, "r|*") as archive:
        for member in archive:
            name = Path(member.name).name
            notice_file = (re.match(r"^(?:LICEN[CS]E|COPYING|NOTICE|AUTHORS|COPYRIGHT|L?GPL[23]?)(?:[._-]|$)|^README\.chromium$", name, re.I)
                           or "/licenses/" in member.name.lower() and name.lower().endswith((".txt", ".md")))
            if not member.isfile() or member.size > 2_000_000 or not notice_file:
                continue
            raw = archive.extractfile(member).read()
            if b"\0" not in raw:
                texts.append("--- " + member.name + " ---\n" + raw.decode("utf-8", errors="replace"))
    return "\n\n".join(texts)


def prepare(names, packages=()):
    CACHE.mkdir(parents=True, exist_ok=True)
    sources = python_sources(names)
    notices = []
    if sys.platform.startswith("linux"):
        # Qt module mapping corresponds to QT_KEEP in keymelier.spec.
        for name in ("PySide6-Essentials", "PySide6-Addons", "shiboken6"):
            if distribution(name).version != "6.11.2":
                raise ValueError("Review the Qt corresponding source archives after a version change")
        pins = json.loads((ROOT / "packaging/linux-sources.json").read_text())
        sources += [{"component": filename.split("-everywhere")[0], "filename": filename, **pin}
                    for filename, pin in pins.items()]
        sources += debian_sources(packages)
    paths = []
    for source in sources:
        print("Corresponding source:", source["filename"], flush=True)
        path = fetch(source)
        paths.append(path)
        if sys.platform.startswith("linux") and source["filename"] in pins:
            # Cache extracted notices keyed to the checked source hash.
            saved = path.with_suffix(path.suffix + ".notices.txt")
            if not saved.is_file():
                saved.write_text(archive_notices(path), encoding="utf-8")
            text = saved.read_text(encoding="utf-8")
            if not text.strip():
                raise ValueError("No license notices found in " + source["filename"])
            notices.append((source["filename"] + " — upstream source notices (including optional components)", text))
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    modified = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT).strip())
    manifest = {"schema": 1, "source_commit": source_commit, "modified_worktree": modified,
                "sources": sources, "instructions": "LIBRARY-REPLACEMENT.txt"}
    target = ROOT / "build/THIRD_PARTY_SOURCES.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    label = {"darwin": "macOS", "win32": "Windows"}.get(sys.platform, "Linux-" + platform.machine())
    output = ROOT / "dist" / f"KeyMelier-Sources-{label}.tar"
    output.parent.mkdir(parents=True, exist_ok=True)
    app_source = subprocess.check_output(["git", "archive", "--format=tar", "--prefix=KeyMelier/", "HEAD"], cwd=ROOT)
    with tarfile.open(output, "w") as archive:
        for source, path in zip(sources, paths):
            archive.add(path, arcname="upstream/" + source["filename"], recursive=False)
        archive.add(target, arcname=target.name, recursive=False)
        archive.add(ROOT / "packaging/licenses/LIBRARY-REPLACEMENT.txt", arcname="LIBRARY-REPLACEMENT.txt", recursive=False)
        info = tarfile.TarInfo("KeyMelier-source.tar")
        info.size = len(app_source)
        archive.addfile(info, io.BytesIO(app_source))
    if modified:
        print("Source bundle refers to committed source only; dirty local builds must not be released.", flush=True)
    return target, notices
