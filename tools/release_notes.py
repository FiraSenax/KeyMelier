#!/usr/bin/env python3
"""Release notes with the actual signing state (release and release rehearsal).

    MAC_SIGNED=true|false WIN_SIGNED=true|false python3 tools/release_notes.py > release-notes.md

The wording that states the signing state is checked by
tools/check_artifacts.py (check_notes); keep both in step.
"""

import os
import sys


def notes(mac_signed: bool, win_signed: bool) -> str:
    lines = ["**Downloads**"]
    if mac_signed:
        lines.append("- `KeyMelier-macOS.dmg` – **macOS** (recommended): open it and drag KeyMelier to Applications "
                     "(replaces an older version). Developer ID signed and notarized.")
    else:
        lines.append("- `KeyMelier-macOS.dmg` – **macOS** (recommended): open it and drag KeyMelier to Applications "
                     "(replaces an older version). **Not notarized** – first launch: open it, click *Done*, then "
                     "*System Settings → Privacy & Security → Open Anyway*.")
    if win_signed:
        lines.append("- `KeyMelier-Windows-Setup.exe` – **Windows** installer (recommended): installs or updates "
                     "KeyMelier. Signed via SignPath Foundation.")
    else:
        lines.append("- `KeyMelier-Windows-Setup.exe` – **Windows** installer (recommended): installs or updates "
                     "KeyMelier. **Not signed** – if SmartScreen appears: *More info* → *Run anyway*.")
    lines += [
        "- `KeyMelier-Linux-x86_64.AppImage`, `KeyMelier-Linux-aarch64.AppImage` – **Linux** (x86-64 / ARM64): "
        "make it executable (`chmod +x`) and start it. **Unsigned** – compare the checksum. Needs glibc 2.38 or newer "
        "(e.g. Ubuntu 24.04, Debian 13, Fedora 39); if your key does not appear, see *Linux* in the documentation "
        "(udev rules).",
        "- `KeyMelier-macOS.zip`, `KeyMelier-Windows.zip` – the same apps without installer (portable).",
        "",
        "Checksums (SHA256SUMS.txt), dependency locks and the source commit are attached. Unsigned builds have no "
        "verified publisher – compare the checksums if in doubt.",
        "",
        "**Known limitations**",
        "- Linux: start-tested automatically in containers of the distributions listed under *Linux* in the "
        "documentation – without a security key, USB, Wayland or a real desktop. Key access on Linux has not been "
        "tested with hardware yet.",
        "- Automated tests use demo data and synthetic keys; results with real keys are recorded in the hardware "
        "test matrix (HARDWARE_TESTS.md).",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    sys.stdout.write(notes(os.environ.get("MAC_SIGNED") == "true", os.environ.get("WIN_SIGNED") == "true"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
