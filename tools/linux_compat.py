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

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORM = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}

# Supported distributions tested in CI (glibc ≥ 2.39, see docs/guide.html#linux);
# Arch Linux publishes no official ARM64 image
MATRIX = {
    "x86_64": ["ubuntu:24.04", "ubuntu:26.04", "debian:13", "fedora:43", "opensuse/leap:16.0", "archlinux:latest"],
    "aarch64": ["ubuntu:24.04", "ubuntu:26.04", "debian:13", "fedora:43", "opensuse/leap:16.0"],
}


MIN_CHECKS = 30   # the packaged start test reports far more; fewer means it did not really run
STATUSES = {"passed", "failed"}
MODES = {"native", "emulated"}


def validate_result(r) -> list[str]:
    """Problems with one result – empty only for a consistent, complete pass.

    Used by `run` and `report` alike, so a single run and the summary apply
    the same rules. `status: passed` alone is never trusted: a missing
    required host library, too few or failed checks, or a missing or invalid
    field make the result a failure. Missing OPTIONAL libraries (plugins such
    as the GTK theme) are reported but do not fail it.
    """
    if not isinstance(r, dict):
        return ["result is not a JSON object"]
    problems = []
    status = r.get("status")
    if status not in STATUSES:
        problems.append(f"invalid status {status!r}")
    if r.get("mode") not in MODES:
        problems.append(f"invalid mode {r.get('mode')!r} (native or emulated)")
    if r.get("arch") not in PLATFORM:
        problems.append(f"invalid arch {r.get('arch')!r}")
    sha = r.get("sha256")
    if not (isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
        problems.append("no SHA-256 of the tested AppImage")
    missing = r.get("missing_required")
    if not isinstance(missing, list) or not all(isinstance(m, str) for m in missing):
        problems.append("missing_required is not a list")
    elif missing:
        problems.append("required host libraries missing: " + ", ".join(missing))
    if not isinstance(r.get("missing_optional", []), list):
        problems.append("missing_optional is not a list")
    checks, passed = r.get("checks"), r.get("passed_checks")
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (checks, passed)):
        problems.append("check counts missing or invalid")
    elif status == "passed":
        if checks < MIN_CHECKS:
            problems.append(f"only {checks} checks ran (expected at least {MIN_CHECKS})")
        if passed != checks:
            problems.append(f"{checks - passed} of {checks} checks failed")
    if status == "failed":
        problems.append(f"start test failed: {r.get('detail', 'no detail')}")
    # Bound to the requested package and run (written by `run` before the container started)
    expected = r.get("expected")
    if not isinstance(expected, dict):
        problems.append("no expected package recorded (not produced by linux_compat.py run)")
    else:
        if sha != expected.get("sha256"):
            problems.append(f"tested SHA-256 {str(sha)[:16]}… is not the requested package {str(expected.get('sha256'))[:16]}…")
        if r.get("arch") != expected.get("arch"):
            problems.append(f"ran on {r.get('arch')!r}, requested {expected.get('arch')!r}")
        if r.get("mode") != expected.get("mode"):
            problems.append(f"mode {r.get('mode')!r}, requested {expected.get('mode')!r}")
        if not expected.get("run_id") or r.get("run_id") != expected.get("run_id"):
            problems.append("the report is not from this run (run id differs)")
    return problems


def load_result(path: Path) -> dict:
    """The result file, with its validation applied (status becomes 'failed' on any problem)."""
    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {"status": "failed", "detail": f"unreadable result {path.name}: {e}", "problems": [f"invalid JSON: {e}"],
                "image": path.parent.name}
    problems = validate_result(r)
    if not isinstance(r, dict):
        return {"status": "failed", "problems": problems, "image": path.parent.name}
    return {**r, "status": "passed" if not problems else "failed", "problems": problems}


def arch_of(appimage: Path) -> str:
    return next(a for a in PLATFORM if appimage.name.endswith(f"-{a}.AppImage"))


RESULT_FILES = ("result.json", "sha256.txt", "glibc.txt", "missing-required.txt", "missing-optional.txt",
                "install.log", "smoke.log", "container.log")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(appimage: Path, image: str, emulated: bool, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    for name in RESULT_FILES:   # a report left from an earlier run must never count
        (out / name).unlink(missing_ok=True)
    shutil.rmtree(out / "smoke", ignore_errors=True)
    arch = arch_of(appimage)
    expected = {"sha256": sha256_of(appimage), "arch": arch, "mode": "emulated" if emulated else "native",
                "run_id": secrets.token_hex(16)}
    timeout = os.environ.get("SMOKE_TIMEOUT", "900" if emulated else "300")   # emulation is ~5-10x slower
    owner = ["-e", f"HOST_UID={os.getuid()}", "-e", f"HOST_GID={os.getgid()}"] if hasattr(os, "getuid") else []
    cmd = ["docker", "run", "--rm", "--platform", PLATFORM[arch], "-e", f"SMOKE_TIMEOUT={timeout}", *owner,
           "-e", f"RUN_ID={expected['run_id']}",
           "-v", f"{ROOT}:/src:ro", "-v", f"{appimage.resolve().parent}:/app:ro", "-v", f"{out.resolve()}:/out",
           image, "bash", "/src/tests/linux/compat_inside.sh", f"/app/{appimage.name}",
           "emulated" if emulated else "native"]
    print(f"== {image} ({arch}, {'emulated' if emulated else 'native'})", flush=True)
    proc = subprocess.run(cmd, text=True, capture_output=True)
    (out / "container.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    raw = None
    if (out / "result.json").exists():
        try:
            raw = json.loads((out / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
    if isinstance(raw, dict):
        raw.update(expected=expected, image=image, container_exit=proc.returncode)
        (out / "result.json").write_text(json.dumps(raw, indent=1), encoding="utf-8")
        result = load_result(out / "result.json")
    else:
        result = {"status": "failed", "expected": expected, "image": image, "container_exit": proc.returncode,
                  "problems": [f"no readable result written by this run (container exit {proc.returncode})"]}
    result.update(image=image, container_exit=proc.returncode)
    if proc.returncode != 0:
        result["status"] = "failed"
        result["problems"] = result.get("problems", []) + [f"container exit {proc.returncode}"]
    (out / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"   {result['status']}: {'; '.join(result['problems']) or result.get('detail')}  "
          f"sha256 {str(result.get('sha256', '?'))[:16]}…", flush=True)
    for lib in result.get("missing_optional", []) or []:
        print(f"   optional, not found: {lib}")
    return result


def report(folders: list[Path]) -> tuple[str, bool]:
    rows, ok = [], True
    for f in folders:
        for path in sorted(f.rglob("result.json")):
            r = load_result(path)   # the same rules as a single run
            ok &= r["status"] == "passed"
            rows.append(r)
    cell = lambda values: ", ".join(str(v) for v in values) if isinstance(values, list) and values else "–"
    lines = ["| Image | Distribution | Arch | Mode | glibc | Result | Checks | Missing required libraries "
             "| Missing optional (plugins) | Problems | AppImage SHA-256 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (str(r.get("arch", "")), str(r.get("image", "")))):
        glibc = r.get("glibc") if isinstance(r.get("glibc"), str) and r.get("glibc") else "?"
        lines.append(f"| {r.get('image', '?')} | {r.get('distribution', '?')} | {r.get('arch', '?')} "
                     f"| {r.get('mode', '?')} | {glibc.split()[-1]} | **{r['status']}** "
                     f"| {r.get('passed_checks', '?')}/{r.get('checks', '?')} | {cell(r.get('missing_required'))} "
                     f"| {cell(r.get('missing_optional'))} | {cell(r.get('problems'))} | `{r.get('sha256', '?')}` |")
    if not rows:
        ok = False
        lines.append("| – | no results | | | | **failed** | | | | no result files found | |")
    # every distribution of one architecture must have tested the same package bytes
    by_arch: dict = {}
    for r in rows:
        by_arch.setdefault(r.get("arch"), set()).add(r.get("sha256"))
    for arch, shas in sorted(by_arch.items(), key=lambda kv: str(kv[0])):
        if len(shas) != 1:
            ok = False
            lines.append(f"| – | {arch}: different packages tested | {arch} | | | **failed** | | | "
                         f"| {len(shas)} different SHA-256 values in one architecture | |")
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
