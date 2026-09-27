"""tools/check_artifacts.py on synthetic artifacts (real formats, fictional content).

The real macOS artifacts are checked by the build job and locally with
`check_artifacts.py macos dist`; Windows and release mode need files built
on Windows / by CI, so their logic is exercised here, including failures.
"""

import hashlib
import io
import plistlib
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_artifacts as ca  # noqa: E402

VERSION = ca.app_version()
COMMIT = "a" * 40


def pe(version=VERSION, signed=False) -> bytes:
    """A minimal PE32+ image with a certificate directory entry and VS_FIXEDFILEINFO."""
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    opt = 0x40 + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<II", data, opt + 112 + 4 * 8, 0x300 if signed else 0, 0x80 if signed else 0)
    a, b, c = (int(x) for x in version.split("."))
    struct.pack_into("<IIII", data, 0x200, 0xFEEF04BD, 0x10000, (a << 16) | b, c << 16)
    return bytes(data)


def zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def plist(version=VERSION) -> bytes:
    return plistlib.dumps({"CFBundleShortVersionString": version, "CFBundleVersion": version})


LICENSES = "fido2 … cryptography … Simple Icons … PyInstaller bootloader"


def make_release(folder: Path, *, mac_version=VERSION, exe_version=VERSION, signed=False):
    (folder / "KeyMelier-macOS.zip").write_bytes(zip_bytes({
        "KeyMelier.app/Contents/Info.plist": plist(mac_version),
        "KeyMelier.app/Contents/MacOS/KeyMelier": b"\xcf\xfa\xed\xfe",
        "KeyMelier.app/Contents/Resources/static/index.html": b"<html>",
        "KeyMelier.app/Contents/Resources/data/advisories.json.sig": b"sig"}))
    (folder / "KeyMelier-macOS.dmg").write_bytes(b"\0" * 2048 + b"koly" + b"\0" * 508)
    (folder / "KeyMelier-Windows.zip").write_bytes(zip_bytes({
        "KeyMelier/KeyMelier.exe": pe(exe_version, signed),
        "KeyMelier/_internal/static/index.html": b"<html>",
        "KeyMelier/_internal/data/advisories.json.sig": b"sig"}))
    (folder / "KeyMelier-Windows-Setup.exe").write_bytes(pe(exe_version, signed))
    for name in ("KeyMelier-macOS.cdx.json", "KeyMelier-Windows.cdx.json"):
        (folder / name).write_text("{}")
    for name in ("THIRD_PARTY_LICENSES-macOS.txt", "THIRD_PARTY_LICENSES-Windows.txt"):
        (folder / name).write_text(LICENSES)
    for lock in ca.LOCKS:
        shutil.copy(ROOT / lock, folder / lock)
    (folder / "SOURCE_COMMIT.txt").write_text(COMMIT + "\n")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(folder.iterdir())]
    (folder / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
    notes = folder.parent / "notes.md"
    notes.write_text("macOS … **Not notarized** …\nWindows … **Not signed** …\n")
    return notes


class CheckArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dir = self.tmp / "artifacts"
        self.dir.mkdir()
        # SBOM contents are checked by tests/test_sbom.py; here only that the check runs
        p = patch.object(ca, "check_sbom", lambda r, path, version, strict: r.check(path.exists(), f"{path.name} sbom"))
        p.start()
        self.addCleanup(p.stop)

    def release(self, **kw):
        notes = make_release(self.dir, **kw)
        return ca.run(["release", str(self.dir), "--commit", COMMIT, "--notes", str(notes),
                       "--mac-signed", "false", "--win-signed", "false"])

    def test_pe_reader(self):
        self.assertEqual(ca.pe_info(pe("1.7.1", signed=True)), {"file_version": (1, 7, 1, 0), "signed": True})
        self.assertFalse(ca.pe_info(pe())["signed"])
        with self.assertRaises(ValueError):
            ca.pe_info(b"not an exe")

    def test_a_correct_release_passes(self):
        r = self.release()
        self.assertEqual(r.problems, [])
        self.assertGreater(len(r.passed), 30)

    def test_each_kind_of_problem_is_found(self):
        cases = {
            "missing file": lambda: (self.dir / "KeyMelier-Windows-Setup.exe").unlink(),
            "empty file": lambda: (self.dir / "KeyMelier-macOS.cdx.json").write_bytes(b""),
            "unexpected file": lambda: (self.dir / "debug.log").write_text("x"),
            "file changed after checksums": lambda: (self.dir / "KeyMelier-macOS.dmg").write_bytes(b"x" * 600),
            "wrong commit": lambda: (self.dir / "SOURCE_COMMIT.txt").write_text("b" * 40),
            "lock differs": lambda: (self.dir / "uv.lock").write_text("changed"),
            "notes claim nothing about signing": lambda: (self.tmp / "notes.md").write_text("all fine"),
            "license list incomplete": lambda: (self.dir / "THIRD_PARTY_LICENSES-Windows.txt").write_text("fido2"),
        }
        for name, damage in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.dir)
                self.dir.mkdir()
                notes = make_release(self.dir)
                damage()
                r = ca.run(["release", str(self.dir), "--commit", COMMIT, "--notes", str(notes),
                            "--mac-signed", "false", "--win-signed", "false"])
                self.assertTrue(r.problems, name)

    def test_wrong_versions_and_signing_state_are_found(self):
        self.assertTrue(any("Info.plist version" in p for p in self.release(mac_version="0.0.1").problems))
        shutil.rmtree(self.dir); self.dir.mkdir()
        self.assertTrue(any("version" in p for p in self.release(exe_version="0.0.0").problems),
                        "an installer built without /DAppVersion (0.0.0) is caught")
        shutil.rmtree(self.dir); self.dir.mkdir()
        r = self.release(signed=True)            # signed files, but reported as unsigned
        self.assertTrue(any("Authenticode" in p for p in r.problems))

    def test_windows_mode(self):
        make_release(self.dir)
        r = ca.run(["windows", str(self.dir), "--signed", "false"])
        self.assertEqual(r.problems, [])
        (self.dir / "KeyMelier-Windows.zip").write_bytes(zip_bytes({"KeyMelier/readme.txt": b"no exe"}))
        self.assertTrue(ca.run(["windows", str(self.dir), "--signed", "false"]).problems)


if __name__ == "__main__":
    unittest.main()
