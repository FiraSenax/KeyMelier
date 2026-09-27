#!/usr/bin/env python3
"""Validate release artifacts after packaging. Any problem exits 1.

    check_artifacts.py macos   DIST [--signed true|false] [--commit SHA]
    check_artifacts.py windows DIST [--signed true|false] [--commit SHA]
    check_artifacts.py linux   DIST --arch x86_64|aarch64 [--commit SHA]

--commit (and in release mode SOURCE_COMMIT.txt): the app inside each package
must name exactly this commit in data/build.json, built from an unmodified tree.
    check_artifacts.py release DIR --commit SHA --notes NOTES.md --mac-signed X --win-signed Y
                              [--report REPORT.md --jobs "test=success,build-linux=success,…"]
    check_artifacts.py restore-exec DIR

restore-exec (release job, right after downloading the artifacts): GitHub's
artifact transfer drops the execute bit; set it again on exactly the two
expected AppImages. A missing AppImage is an error; no other file is touched.

macos/windows (build jobs): the expected files exist and are not empty; the
ZIP lists the expected app structure; version in Info.plist / the Windows
version resources (app and installer) equals fido2tool_core/version.py; the
DMG mounts and holds the app and an Applications link (macOS); the signing
state matches what the build reports (ad-hoc vs. Developer ID on macOS,
Authenticode present or not on Windows); SBOM valid; license notices present.
linux: the AppImage is an executable ELF for the architecture with a
SquashFS image appended, which holds the app, the version, the page, the
signed advisories and the udev rules (read with unsquashfs).

release (release job, all files together): every expected file present and
not empty, nothing unexpected; SOURCE_COMMIT.txt equals the built commit;
dependency locks equal the repository's; SBOMs valid for this version;
ZIP structure and versions again; SHA256SUMS.txt lists exactly the other
files and every hash verifies; the release notes state the real signing
state (not notarized / not signed while unsigned).
"""

import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sbom  # noqa: E402

MAC_FILES = ("KeyMelier-macOS.dmg", "KeyMelier-macOS.zip", "KeyMelier-macOS.cdx.json", "THIRD_PARTY_LICENSES-macOS.txt")
WIN_FILES = ("KeyMelier-Windows-Setup.exe", "KeyMelier-Windows.zip", "KeyMelier-Windows.cdx.json",
             "THIRD_PARTY_LICENSES-Windows.txt")
LINUX_ARCHES = {"x86_64": 62, "aarch64": 183}   # ELF e_machine


def linux_files(arch: str) -> tuple:
    return (f"KeyMelier-Linux-{arch}.AppImage", f"KeyMelier-Linux-{arch}.cdx.json",
            f"THIRD_PARTY_LICENSES-Linux-{arch}.txt")


LINUX_FILES = tuple(f for arch in LINUX_ARCHES for f in linux_files(arch))
LOCKS = ("requirements.txt", "requirements-build.txt", "uv.lock")
RELEASE_FILES = MAC_FILES + WIN_FILES + LINUX_FILES + LOCKS + ("SOURCE_COMMIT.txt", "SHA256SUMS.txt")


def app_version() -> str:
    ns: dict = {}
    exec((ROOT / "fido2tool_core" / "version.py").read_text(), ns)
    return ns["__version__"]


# ── Windows PE files ─────────────────────────────────────────────────────────

def pe_info(data: bytes) -> dict:
    """{'file_version': (a, b, c, d) or None, 'signed': bool} of a PE file."""
    if data[:2] != b"MZ":
        raise ValueError("not a Windows executable")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("no PE header")
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    directories = opt + (96 if magic == 0x10B else 112)
    _cert_offset, cert_size = struct.unpack_from("<II", data, directories + 4 * 8)   # IMAGE_DIRECTORY_ENTRY_SECURITY
    version = None
    at = data.find(struct.pack("<I", 0xFEEF04BD))                                     # VS_FIXEDFILEINFO
    if at >= 0:
        ms, ls = struct.unpack_from("<II", data, at + 8)
        version = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    return {"file_version": version, "signed": cert_size > 0}


def _version_tuple(version: str) -> tuple:
    return tuple(int(x) for x in version.split(".")) + (0,)


# ── Checks ───────────────────────────────────────────────────────────────────

class Report:
    def __init__(self):
        self.problems: list[str] = []
        self.passed: list[str] = []

    def check(self, ok, what, detail=""):
        (self.passed if ok else self.problems).append(what + ("" if ok or not detail else f": {detail}"))
        return ok


def check_files(r: Report, folder: Path, names) -> None:
    for name in names:
        f = folder / name
        r.check(f.is_file() and f.stat().st_size > 0, f"{name} exists and is not empty")


def check_sbom(r: Report, path: Path, version: str, strict: bool) -> None:
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        r.check(False, f"{path.name} is valid JSON", str(e))
        return
    problems = sbom.validate(bom, version, strict=strict)
    r.check(not problems, f"{path.name} is a complete SBOM for {version}", "; ".join(problems[:5]))


def check_licenses(r: Report, path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    for needle in ("fido2", "cryptography", "Simple Icons", "PyInstaller"):
        r.check(needle in text, f"{path.name} names {needle}")


BUILD_JSON = {"mac": "KeyMelier.app/Contents/Resources/data/build.json", "win": "KeyMelier/_internal/data/build.json",
              "linux": "usr/lib/keymelier/_internal/data/build.json"}


def check_build_commit(r: Report, name: str, raw: str | bytes | None, commit: str | None) -> None:
    """The app inside the package names exactly the released commit, built from an unmodified tree."""
    if not commit:
        return
    try:
        info = json.loads(raw) if raw else None
    except ValueError:
        info = None
    r.check(isinstance(info, dict) and info.get("commit") == commit, f"{name}: built from commit {commit[:12]}",
            f"build.json says {info.get('commit') if isinstance(info, dict) else 'nothing'}")
    r.check(isinstance(info, dict) and info.get("modified") is False, f"{name}: built from an unmodified tree",
            f"modified: {info.get('modified') if isinstance(info, dict) else '?'}")


def zip_member(path: Path, member: str) -> bytes | None:
    try:
        with zipfile.ZipFile(path) as z:
            name = next((n for n in z.namelist() if n.replace("\\", "/") == member), None)
            return z.read(name) if name else None
    except (OSError, zipfile.BadZipFile):
        return None


def check_mac_zip(r: Report, path: Path, version: str) -> None:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            for entry in ("KeyMelier.app/Contents/Info.plist", "KeyMelier.app/Contents/MacOS/KeyMelier",
                          "KeyMelier.app/Contents/Resources/static/index.html",
                          "KeyMelier.app/Contents/Resources/data/advisories.json.sig"):
                r.check(entry in names, f"{path.name} contains {entry}")
            plist = plistlib.loads(z.read("KeyMelier.app/Contents/Info.plist"))
            r.check(plist.get("CFBundleShortVersionString") == version and plist.get("CFBundleVersion") == version,
                    f"{path.name}: Info.plist version {version}",
                    f"{plist.get('CFBundleShortVersionString')}/{plist.get('CFBundleVersion')}")
    except (OSError, zipfile.BadZipFile, KeyError) as e:
        r.check(False, f"{path.name} can be listed", str(e))


def check_win_zip(r: Report, path: Path, version: str, signed: bool | None) -> None:
    try:
        with zipfile.ZipFile(path) as z:
            names = {n.replace("\\", "/") for n in z.namelist()}
            exe = next((n for n in names if n.endswith("KeyMelier/KeyMelier.exe")), None)
            r.check(exe is not None, f"{path.name} contains KeyMelier/KeyMelier.exe")
            for suffix in ("static/index.html", "data/advisories.json.sig"):
                r.check(any(n.startswith("KeyMelier/") and n.endswith(suffix) for n in names),
                        f"{path.name} contains …/{suffix}")
            if exe:
                raw = z.read(next(n for n in z.namelist() if n.replace("\\", "/") == exe))
                info = pe_info(raw)
                r.check(info["file_version"] == _version_tuple(version), f"{path.name}: KeyMelier.exe version {version}",
                        str(info["file_version"]))
                if signed is not None:
                    r.check(info["signed"] == signed, f"{path.name}: KeyMelier.exe {'is' if signed else 'is not'} Authenticode-signed",
                            f"signature present: {info['signed']}")
    except (OSError, zipfile.BadZipFile, ValueError) as e:
        r.check(False, f"{path.name} can be listed", str(e))


def check_installer(r: Report, path: Path, version: str, signed: bool | None) -> None:
    try:
        info = pe_info(path.read_bytes())
    except (OSError, ValueError) as e:
        r.check(False, f"{path.name} is a Windows executable", str(e))
        return
    r.check(info["file_version"] == _version_tuple(version), f"{path.name}: version {version}", str(info["file_version"]))
    if signed is not None:
        r.check(info["signed"] == signed, f"{path.name} {'is' if signed else 'is not'} Authenticode-signed",
                f"signature present: {info['signed']}")


def check_dmg_container(r: Report, path: Path) -> None:
    with open(path, "rb") as f:
        f.seek(-512, 2)
        trailer = f.read(4)
    r.check(trailer == b"koly", f"{path.name} is a disk image (UDIF)")


def check_dmg_mounted(r: Report, path: Path, version: str) -> None:
    """macOS only: mount read-only and look inside."""
    mount = Path(tempfile.mkdtemp(prefix="km-dmg-"))
    try:
        subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount), str(path)],
                       check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        r.check(False, f"{path.name} mounts", e.stderr.decode(errors="replace")[:200])
        return
    try:
        app = mount / "KeyMelier.app"
        r.check((app / "Contents" / "MacOS" / "KeyMelier").is_file(), f"{path.name} holds KeyMelier.app")
        r.check((mount / "Applications").is_symlink(), f"{path.name} holds the Applications link")
        plist = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
        r.check(plist.get("CFBundleShortVersionString") == version, f"{path.name}: app version {version}",
                str(plist.get("CFBundleShortVersionString")))
        verify = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], capture_output=True, text=True)
        r.check(verify.returncode == 0, f"{path.name}: app signature is intact", verify.stderr[:200])
    finally:
        subprocess.run(["hdiutil", "detach", str(mount)], capture_output=True)


def check_mac_signing(r: Report, app: Path, signed: bool) -> None:
    out = subprocess.run(["codesign", "-dv", "--verbose=2", str(app)], capture_output=True, text=True).stderr
    if signed:
        r.check("Authority=Developer ID Application" in out, "app is Developer ID signed", out[-200:])
        staple = subprocess.run(["xcrun", "stapler", "validate", str(app)], capture_output=True, text=True)
        r.check(staple.returncode == 0, "notarization ticket is stapled", staple.stdout[-200:])
    else:
        r.check("Signature=adhoc" in out, "app is ad-hoc signed only (reported as not notarized)", out[-200:])


def appimage_offset(data: bytes) -> int | None:
    """Size of the ELF runtime = where the SquashFS image starts (64-bit little-endian ELF)."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    return shoff + shentsize * shnum


def squashfs_contents(path: Path, offset: int):
    """(set of paths, read(path) -> text) of the AppImage's file system, or None without unsquashfs."""
    def run(*args):
        return subprocess.run(["unsquashfs", "-o", str(offset), *args], capture_output=True, text=True,
                              timeout=120).stdout
    try:
        listing = run("-l", "-d", "", str(path))
    except FileNotFoundError:
        return None
    return {line.strip().lstrip("/") for line in listing.splitlines()}, lambda inner: run("-cat", str(path), inner)


def check_appimage(r: Report, path: Path, arch: str, version: str, commit: str | None = None) -> None:
    try:
        head = path.read_bytes()[:4 * 1024 * 1024]
    except OSError as e:
        r.check(False, f"{path.name} readable", str(e))
        return
    offset = appimage_offset(head)
    r.check(offset is not None, f"{path.name} is a 64-bit ELF")
    if offset is None:
        return
    machine, = struct.unpack_from("<H", head, 0x12)
    r.check(machine == LINUX_ARCHES[arch], f"{path.name} runs on {arch}", f"e_machine {machine}")
    r.check(head[8:11] == b"AI\x02", f"{path.name} is a type 2 AppImage")
    r.check(head[offset:offset + 4] == b"hsqs", f"{path.name} holds a SquashFS image")
    r.check(path.stat().st_mode & 0o111 != 0 or sys.platform == "win32", f"{path.name} is executable")
    contents = squashfs_contents(path, offset)
    if contents is None:
        r.check(False, "unsquashfs available (squashfs-tools) to look inside the AppImage")
        return
    entries, read = contents
    internal = "usr/lib/keymelier/_internal"
    for entry in ("AppRun", "keymelier.desktop", "usr/lib/keymelier/KeyMelier",
                  f"{internal}/static/index.html", f"{internal}/data/advisories.json.sig",
                  f"{internal}/THIRD_PARTY_LICENSES.txt", "usr/share/keymelier/70-keymelier.rules"):
        r.check(entry in entries, f"{path.name} contains {entry}")
    check_build_commit(r, path.name, read(BUILD_JSON["linux"]), commit)
    m = re.search(r'__version__\s*=\s*"([^"]+)"', read(f"{internal}/fido2tool_core/version.py"))
    r.check(m is not None and m.group(1) == version, f"{path.name}: app version {version}", m.group(1) if m else "none")


def check_sums(r: Report, folder: Path) -> None:
    sums = folder / "SHA256SUMS.txt"
    listed = {}
    for line in sums.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line.strip())
        if m:
            listed[m.group(2)] = m.group(1)
    expected = {p.name for p in folder.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"}
    r.check(set(listed) == expected, "SHA256SUMS.txt lists exactly the released files",
            f"missing {sorted(expected - set(listed))}, extra {sorted(set(listed) - expected)}")
    for name, digest in listed.items():
        f = folder / name
        r.check(f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest() == digest, f"checksum of {name}")


def check_notes(r: Report, notes: Path, mac_signed: bool, win_signed: bool) -> None:
    text = notes.read_text(encoding="utf-8")
    r.check(("Not notarized" in text) != mac_signed, "release notes state the macOS notarization correctly")
    r.check(("Not signed" in text) != win_signed, "release notes state the Windows signing correctly")
    for arch in LINUX_ARCHES:
        r.check(f"KeyMelier-Linux-{arch}.AppImage" in text, f"release notes name the Linux {arch} AppImage")
    r.check("AppImage" in text and "unsigned" in text.lower(), "release notes say the AppImages are unsigned")


def restore_exec(folder: Path) -> list[str]:
    """chmod 755 the expected AppImages in folder; returns the problems (missing files)."""
    problems = []
    for name in LINUX_FILES[0::3]:
        path = folder / name
        if not path.is_file():
            problems.append(f"{name} is missing in {folder}")
            continue
        path.chmod(0o755)
    return problems


def run(argv: list[str]) -> Report:
    r = Report()
    mode, folder = argv[0], Path(argv[1])
    opts = dict(zip(argv[2::2], argv[3::2]))
    flag = lambda key: None if opts.get(key) in (None, "") else opts[key] == "true"
    version = app_version()
    if mode == "macos":
        check_files(r, folder, MAC_FILES)
        check_mac_zip(r, folder / "KeyMelier-macOS.zip", version)
        check_build_commit(r, "KeyMelier-macOS.zip", zip_member(folder / "KeyMelier-macOS.zip", BUILD_JSON["mac"]),
                           opts.get("--commit"))
        check_dmg_container(r, folder / "KeyMelier-macOS.dmg")
        if sys.platform == "darwin":
            check_dmg_mounted(r, folder / "KeyMelier-macOS.dmg", version)
            if flag("--signed") is not None:
                check_mac_signing(r, folder / "KeyMelier.app", flag("--signed"))
        check_sbom(r, folder / "KeyMelier-macOS.cdx.json", version, strict="--strict-sbom" in argv)
        check_licenses(r, folder / "THIRD_PARTY_LICENSES-macOS.txt")
    elif mode == "windows":
        check_files(r, folder, WIN_FILES)
        check_win_zip(r, folder / "KeyMelier-Windows.zip", version, flag("--signed"))
        check_build_commit(r, "KeyMelier-Windows.zip", zip_member(folder / "KeyMelier-Windows.zip", BUILD_JSON["win"]),
                           opts.get("--commit"))
        check_installer(r, folder / "KeyMelier-Windows-Setup.exe", version, flag("--signed"))
        check_sbom(r, folder / "KeyMelier-Windows.cdx.json", version, strict="--strict-sbom" in argv)
        check_licenses(r, folder / "THIRD_PARTY_LICENSES-Windows.txt")
    elif mode == "linux":
        arch = opts.get("--arch", "")
        if arch not in LINUX_ARCHES:
            r.check(False, f"--arch is one of {sorted(LINUX_ARCHES)}", arch)
            return r
        appimage, bom, licenses = linux_files(arch)
        check_files(r, folder, (appimage, bom, licenses))
        check_appimage(r, folder / appimage, arch, version, opts.get("--commit"))
        check_sbom(r, folder / bom, version, strict="--strict-sbom" in argv)
        check_licenses(r, folder / licenses)
    elif mode == "release":
        check_files(r, folder, RELEASE_FILES)
        present = {p.name for p in folder.iterdir() if p.is_file()}
        r.check(present <= set(RELEASE_FILES), "no unexpected files", str(sorted(present - set(RELEASE_FILES))))
        commit = (folder / "SOURCE_COMMIT.txt").read_text().strip() if (folder / "SOURCE_COMMIT.txt").exists() else ""
        r.check(re.fullmatch(r"[0-9a-f]{40}", commit) is not None and commit == opts.get("--commit"),
                "SOURCE_COMMIT.txt is the built commit", f"{commit} vs {opts.get('--commit')}")
        for lock in LOCKS:
            f = folder / lock
            r.check(f.exists() and f.read_bytes() == (ROOT / lock).read_bytes(), f"{lock} equals the repository's")
        check_mac_zip(r, folder / "KeyMelier-macOS.zip", version)
        check_dmg_container(r, folder / "KeyMelier-macOS.dmg")
        check_win_zip(r, folder / "KeyMelier-Windows.zip", version, flag("--win-signed"))
        check_installer(r, folder / "KeyMelier-Windows-Setup.exe", version, flag("--win-signed"))
        for arch in LINUX_ARCHES:
            check_appimage(r, folder / linux_files(arch)[0], arch, version, commit)
        for name, kind in (("KeyMelier-macOS.zip", "mac"), ("KeyMelier-Windows.zip", "win")):
            check_build_commit(r, name, zip_member(folder / name, BUILD_JSON[kind]), commit)
        for name in ("KeyMelier-macOS.cdx.json", "KeyMelier-Windows.cdx.json", *LINUX_FILES[1::3]):
            check_sbom(r, folder / name, version, strict=True)
        for name in ("THIRD_PARTY_LICENSES-macOS.txt", "THIRD_PARTY_LICENSES-Windows.txt", *LINUX_FILES[2::3]):
            check_licenses(r, folder / name)
        if (folder / "SHA256SUMS.txt").exists():
            check_sums(r, folder)
        if opts.get("--notes"):
            check_notes(r, Path(opts["--notes"]), bool(flag("--mac-signed")), bool(flag("--win-signed")))
    else:
        r.check(False, f"unknown mode {mode}")
    return r


def write_report(path: Path, r: Report, folder: Path, commit: str, jobs: str) -> None:
    """Markdown report: commit, version, every artifact with size and SHA-256, job results, checks."""
    lines = ["# KeyMelier release check", "",
             f"- Commit: `{commit}`", f"- Version: {app_version()}",
             f"- Result: **{'passed' if not r.problems else 'FAILED'}** "
             f"({len(r.passed)} checks passed, {len(r.problems)} failed)", ""]
    if jobs:
        lines += ["## Jobs", "", "| Job | Result |", "|---|---|"]
        lines += [f"| {name} | {result} |" for name, _, result in
                  (item.partition("=") for item in jobs.split(",") if item)]
        lines.append("")
    lines += ["## Artifacts", "", "| File | Size | SHA-256 |", "|---|---|---|"]
    for f in sorted(p for p in folder.iterdir() if p.is_file()):
        lines.append(f"| {f.name} | {f.stat().st_size:,} B | `{hashlib.sha256(f.read_bytes()).hexdigest()}` |")
    lines += ["", "## Checks", ""] + [f"- FAIL {p}" for p in r.problems] + [f"- ok {p}" for p in r.passed]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    if sys.argv[1] == "restore-exec":
        problems = restore_exec(Path(sys.argv[2]))
        for p in problems:
            print(f"FAIL {p}")
        print("AppImages executable again" if not problems else "AppImages missing")
        return 1 if problems else 0
    r = run(sys.argv[1:])
    opts = dict(zip(sys.argv[3::2], sys.argv[4::2]))
    if opts.get("--report"):
        write_report(Path(opts["--report"]), r, Path(sys.argv[2]), opts.get("--commit", ""), opts.get("--jobs", ""))
    for p in r.problems:
        print(f"FAIL {p}")
    print(f"{len(r.passed)} checks passed, {len(r.problems)} failed ({sys.argv[1]}, version {app_version()})")
    return 1 if r.problems else 0


if __name__ == "__main__":
    sys.exit(main())
