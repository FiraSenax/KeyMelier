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


def appimage(arch="x86_64") -> bytes:
    """ELF header of a type 2 AppImage runtime, followed by the SquashFS magic."""
    data = bytearray(0x200)
    data[0:4], data[4], data[5] = b"\x7fELF", 2, 1
    data[8:11] = b"AI\x02"
    struct.pack_into("<H", data, 0x12, ca.LINUX_ARCHES[arch])
    struct.pack_into("<Q", data, 0x28, 0x100)          # section headers at 0x100 …
    struct.pack_into("<HH", data, 0x3A, 0x40, 2)       # … two of 64 bytes: image starts at 0x180
    data[0x180:0x184] = b"hsqs"
    return bytes(data)


INTERNAL = "usr/lib/keymelier/_internal"
APPIMAGE_FILES = {"AppRun", "keymelier.desktop", "usr/lib/keymelier/KeyMelier", f"{INTERNAL}/static/index.html",
                  f"{INTERNAL}/data/advisories.json.sig", f"{INTERNAL}/THIRD_PARTY_LICENSES.txt",
                  "usr/share/keymelier/70-keymelier.rules", f"{INTERNAL}/fido2tool_core/version.py"}


def fake_squashfs(version=VERSION, files=APPIMAGE_FILES):
    return lambda path, offset: (set(files), lambda inner: f'__version__ = "{version}"\n')


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
    for arch in ca.LINUX_ARCHES:
        path = folder / f"KeyMelier-Linux-{arch}.AppImage"
        path.write_bytes(appimage(arch))
        path.chmod(0o755)
    for name in ("KeyMelier-macOS.cdx.json", "KeyMelier-Windows.cdx.json", *ca.LINUX_FILES[1::3]):
        (folder / name).write_text("{}")
    for name in ("THIRD_PARTY_LICENSES-macOS.txt", "THIRD_PARTY_LICENSES-Windows.txt", *ca.LINUX_FILES[2::3]):
        (folder / name).write_text(LICENSES, encoding="utf-8")
    for lock in ca.LOCKS:
        shutil.copy(ROOT / lock, folder / lock)
    (folder / "SOURCE_COMMIT.txt").write_text(COMMIT + "\n")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(folder.iterdir())]
    (folder / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
    notes = folder.parent / "notes.md"
    notes.write_text("macOS … **Not notarized** …\nWindows … **Not signed** …\n"
                     "Linux: KeyMelier-Linux-x86_64.AppImage, KeyMelier-Linux-aarch64.AppImage (unsigned)\n",
                     encoding="utf-8")
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
        q = patch.object(ca, "squashfs_contents", fake_squashfs())   # unsquashfs is not on every runner
        q.start()
        self.addCleanup(q.stop)

    def release(self, **kw):
        notes = make_release(self.dir, **kw)
        return ca.run(["release", str(self.dir), "--commit", COMMIT, "--notes", str(notes),
                       "--mac-signed", "false", "--win-signed", "false"])

    def test_linux_build_job(self):
        out = self.tmp / "linux"
        out.mkdir()
        for name, content in zip(ca.linux_files("x86_64"), (appimage(), "{}", LICENSES)):
            (out / name).write_bytes(content) if isinstance(content, bytes) else (out / name).write_text(content, encoding="utf-8")
        (out / "KeyMelier-Linux-x86_64.AppImage").chmod(0o755)
        self.assertEqual(ca.run(["linux", str(out), "--arch", "x86_64"]).problems, [])
        with patch.object(ca, "squashfs_contents", fake_squashfs(version="0.0.1")):
            self.assertTrue(ca.run(["linux", str(out), "--arch", "x86_64"]).problems, "wrong version found")
        with patch.object(ca, "squashfs_contents", fake_squashfs(files=APPIMAGE_FILES - {"usr/share/keymelier/70-keymelier.rules"})):
            self.assertTrue(ca.run(["linux", str(out), "--arch", "x86_64"]).problems, "missing udev rules found")
        self.assertTrue(ca.run(["linux", str(out), "--arch", "aarch64"]).problems, "files for another arch")

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes")
    def test_release_after_artifact_download_restores_exactly_the_appimages(self):
        """download-artifact leaves every file at 0644: the release check fails until restore-exec ran."""
        notes = make_release(self.dir)
        for f in self.dir.iterdir():
            f.chmod(0o644)
        args = ["release", str(self.dir), "--commit", COMMIT, "--notes", str(notes),
                "--mac-signed", "false", "--win-signed", "false"]
        self.assertTrue(any("is executable" in p for p in ca.run(args).problems), "the check still demands +x")
        self.assertEqual(ca.restore_exec(self.dir), [])
        for f in self.dir.iterdir():
            expected = 0o755 if f.name in ca.LINUX_FILES[0::3] else 0o644
            self.assertEqual(f.stat().st_mode & 0o777, expected, f.name)
        self.assertEqual(ca.run(args).problems, [])

    def test_restore_exec_fails_visibly_on_a_missing_appimage(self):
        make_release(self.dir)
        (self.dir / "KeyMelier-Linux-aarch64.AppImage").unlink()
        problems = ca.restore_exec(self.dir)
        self.assertEqual(problems, [f"KeyMelier-Linux-aarch64.AppImage is missing in {self.dir}"])
        import subprocess
        out = subprocess.run([sys.executable, str(ROOT / "tools" / "check_artifacts.py"), "restore-exec", str(self.dir)],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("KeyMelier-Linux-aarch64.AppImage is missing", out.stdout)

    def test_release_job_order(self):
        """download → restore-exec → squashfs-tools → … → validate → publish."""
        text = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        job = text[text.index("\n  release:"):]
        order = [job.index(marker) for marker in (
            "actions/download-artifact", "check_artifacts.py restore-exec artifacts",
            "install -y --no-install-recommends squashfs-tools", "sha256sum * > SHA256SUMS.txt",
            "check_artifacts.py release artifacts", "action-gh-release")]
        self.assertEqual(order, sorted(order))

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
            "AppImage for the wrong processor": lambda: (self.dir / "KeyMelier-Linux-aarch64.AppImage")
                .write_bytes(appimage("x86_64")),
            "AppImage without file system": lambda: (self.dir / "KeyMelier-Linux-x86_64.AppImage")
                .write_bytes(appimage()[:0x180] + b"\0" * 128),
            "Linux AppImage missing": lambda: (self.dir / "KeyMelier-Linux-aarch64.AppImage").unlink(),
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
