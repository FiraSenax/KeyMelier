#!/usr/bin/env python3
"""Start test of already built Linux AppImages in clean distribution containers.

    linux_compat.py run APPIMAGE IMAGE [--emulated] [--out DIR]
    linux_compat.py report DIR...                     (Markdown summary, exit 1 if any failed)

The same AppImage file is used unchanged in every container (its SHA-256 is
recorded before it starts); nothing is rebuilt. Each container installs only
the documented runtime prerequisites and the test harness, then runs
tools/smoke_packaged.py under Xvfb (tests/linux/compat_inside.sh).

`--emulated` runs a container of another CPU architecture through QEMU; the
AppImage runtime cannot be executed there, so the unpacked copy of the same
file is started instead – reports say "emulated". Only native runs count as
evidence for an architecture (CI runs both natively).

Not covered by these tests: USB/key access, Wayland sessions, real desktops
(GNOME, KDE, …), GPU drivers – the containers have none of those.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORM = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}

# Supported distributions tested in CI (glibc ≥ 2.38, see docs/guide.html#linux);
# Arch Linux publishes no official ARM64 image
MATRIX = {
    "x86_64": ["ubuntu:24.04", "ubuntu:26.04", "debian:13", "fedora:43", "opensuse/leap:16.0", "archlinux:latest"],
    "aarch64": ["ubuntu:24.04", "ubuntu:26.04", "debian:13", "fedora:43", "opensuse/leap:16.0"],
}


def arch_of(appimage: Path) -> str:
    return next(a for a in PLATFORM if appimage.name.endswith(f"-{a}.AppImage"))


def run(appimage: Path, image: str, emulated: bool, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    arch = arch_of(appimage)
    timeout = os.environ.get("SMOKE_TIMEOUT", "900" if emulated else "300")   # emulation is ~5-10x slower
    cmd = ["docker", "run", "--rm", "--platform", PLATFORM[arch], "-e", f"SMOKE_TIMEOUT={timeout}",
           "-v", f"{ROOT}:/src:ro", "-v", f"{appimage.resolve().parent}:/app:ro", "-v", f"{out.resolve()}:/out",
           image, "bash", "/src/tests/linux/compat_inside.sh", f"/app/{appimage.name}",
           "emulated" if emulated else "native"]
    print(f"== {image} ({arch}, {'emulated' if emulated else 'native'})", flush=True)
    proc = subprocess.run(cmd, text=True, capture_output=True)
    (out / "container.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    try:
        result = json.loads((out / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        result = {"status": "failed", "detail": f"no result (container exit {proc.returncode})"}
    result.update(image=image, container_exit=proc.returncode)
    if result.get("status") == "passed" and proc.returncode != 0:
        result.update(status="failed", detail=f"container exit {proc.returncode}")
    (out / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"   {result['status']}: {result.get('detail')}  sha256 {result.get('sha256', '?')[:16]}…", flush=True)
    for lib in result.get("missing_required", []):
        print(f"   missing: {lib}")
    return result


def report(folders: list[Path]) -> tuple[str, bool]:
    rows, ok = [], True
    for f in folders:
        for path in sorted(f.rglob("result.json")):
            r = json.loads(path.read_text(encoding="utf-8"))
            ok &= r.get("status") == "passed"
            rows.append(r)
    lines = ["| Image | Distribution | Arch | Mode | glibc | Result | Checks | Missing host libraries | AppImage SHA-256 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r.get("arch", ""), r.get("image", ""))):
        missing = ", ".join(r.get("missing_required", [])) or "–"
        lines.append(f"| {r.get('image')} | {r.get('distribution', '?')} | {r.get('arch', '?')} | {r.get('mode', '?')} "
                     f"| {r.get('glibc', '').split()[-1] if r.get('glibc') else '?'} | **{r.get('status')}** "
                     f"| {r.get('passed_checks', 0)}/{r.get('checks', 0)} | {missing} | `{r.get('sha256', '?')}` |")
    if not rows:
        ok = False
        lines.append("| – | no results | | | | **failed** | | | |")
    lines += ["", "Container start tests only: no USB/key access, no Wayland, no real desktop or GPU driver."]
    return "\n".join(lines), ok


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "run":
        appimage, image = Path(argv[1]), argv[2]
        out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else \
            ROOT / "build" / "linux-compat" / f"{arch_of(appimage)}-{image.replace('/', '_').replace(':', '-')}"
        return 0 if run(appimage, image, "--emulated" in argv, out)["status"] == "passed" else 1
    if len(argv) >= 2 and argv[0] == "report":
        text, ok = report([Path(a) for a in argv[1:]])
        print(text)
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
