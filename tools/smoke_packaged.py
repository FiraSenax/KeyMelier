"""Start test of the packaged app – the real build in dist/, not app.py.

    python tools/smoke_packaged.py [path-to-app]      (default: the build in dist/)

Starts the app with --self-test and a temporary home directory (no real
user data, no lock conflict with a running KeyMelier), waits for it to quit
and checks its report: backend libraries and bundled data, page loaded with
translations/icons/CSS, bridge round trips. Crashes, missing resources,
failed checks and timeouts exit 1. The report and the app's log are copied
to build/smoke-artifacts/ (SMOKE_ARTIFACTS to change).

The app opens a real window, so it needs a desktop session (macOS runners
and Windows runners have one; on Linux run it under Xvfb with a D-Bus session
and an unlocked Secret Service, see the CI job build-linux).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = int(os.environ.get("SMOKE_TIMEOUT", "150"))
MIN_CHECKS = 30   # a report with fewer checks is not a real pass


def default_app() -> Path:
    if sys.platform == "darwin":
        return ROOT / "dist" / "KeyMelier.app" / "Contents" / "MacOS" / "KeyMelier"
    if sys.platform == "win32":
        return ROOT / "dist" / "KeyMelier" / "KeyMelier.exe"
    return ROOT / "dist" / "KeyMelier" / "KeyMelier"


def screenshot(target: Path) -> None:
    """Best effort: the whole screen, for a hung start (CI artifact)."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["screencapture", "-x", str(target)], timeout=20, check=False)
        elif sys.platform == "win32":
            ps = ("Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
                  "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                  "$i=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
                  "[System.Drawing.Graphics]::FromImage($i).CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
                  f"$i.Save('{target}')")
            subprocess.run(["powershell", "-NoProfile", "-Command", ps], timeout=30, check=False)
        else:
            subprocess.run(["import", "-window", "root", str(target)], timeout=30, check=False)   # ImageMagick
    except Exception as e:  # a missing screenshot must not hide the real failure
        print(f"(no screenshot: {e})")


def main() -> int:
    app = (Path(sys.argv[1]) if len(sys.argv) > 1 else default_app()).resolve()   # it starts in a temporary folder
    if app.suffix == ".app":
        app = app / "Contents" / "MacOS" / "KeyMelier"
    extra_env = {"APPIMAGE_EXTRACT_AND_RUN": "1"} if app.suffix == ".AppImage" else {}   # no FUSE on CI
    if not app.is_file():
        print(f"FAIL: no packaged app at {app}")
        return 1
    artifacts = Path(os.environ.get("SMOKE_ARTIFACTS", ROOT / "build" / "smoke-artifacts"))
    artifacts.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix="km-smoke-home-"))
    result = home / "self-test.json"
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home),
           "APPDATA": str(home / "AppData" / "Roaming"), "LOCALAPPDATA": str(home / "AppData" / "Local"),
           **extra_env}
    env.pop("KEYMELIER_STATELESS", None)
    print(f"Starting {app} (temporary home {home})")
    proc = subprocess.Popen([str(app), "--self-test", str(result)], env=env, cwd=home,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        output, _ = proc.communicate(timeout=TIMEOUT)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        screenshot(artifacts / "timeout-screen.png")   # what the hung app shows
        proc.kill()
        output, _ = proc.communicate()
        code = None
    (artifacts / "app-output.log").write_text(output if isinstance(output, str) else output.decode("utf-8", "replace"),
                                              encoding="utf-8")
    for f in (result, result.with_suffix(".log"), home / "page-snapshot.txt", home / "page-snapshot.html"):
        if f.exists():
            shutil.copy(f, artifacts / f.name)

    failures = []
    if code is None:
        failures.append(f"timed out after {TIMEOUT}s")
    elif code != 0:
        failures.append(f"exit code {code}")
    report = json.loads(result.read_text(encoding="utf-8")) if result.exists() else None
    if report is None:
        failures.append("no self-test report written")
    else:
        for c in report["checks"]:
            print(f"{'ok  ' if c['ok'] else 'FAIL'} {c['name']}{'' if c['ok'] or not c['info'] else '  – ' + c['info']}")
        if not report.get("passed"):
            failures.append("failed checks")
        if len(report["checks"]) < MIN_CHECKS:
            failures.append(f"only {len(report['checks'])} checks reported (expected ≥ {MIN_CHECKS})")
    if not (home / "keymelier").is_dir():
        failures.append("the app did not use the temporary home (isolation not proven)")
    shutil.rmtree(home, ignore_errors=True)
    if failures:
        print("FAIL: " + "; ".join(failures) + f"  (logs: {artifacts})")
        return 1
    print(f"Packaged app start test passed ({len(report['checks'])} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
