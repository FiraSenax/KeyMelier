#!/usr/bin/env python3
"""Regenerate all hash-pinned installs from uv.lock, or verify them with --check.

Run `uv lock` after editing pyproject.toml, then this script. This command never
updates the lock or resolves newer versions. CI uses the uv pinned in the
quality group and checks the exports without network access.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = {
    "requirements.txt": ["--no-default-groups"],
    "requirements-build.txt": ["--only-group", "build"],
    "requirements-quality.txt": ["--only-group", "quality"],
}
HEADER = "# Generated from uv.lock by python tools/export_requirements.py; do not edit.\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on drift without changing any file")
    args = parser.parse_args()
    uv = shutil.which("uv")
    if not uv:
        parser.error("uv is required; install requirements-quality.txt or activate its environment")
    try:
        subprocess.run([uv, "lock", "--check", "--offline", "--no-python-downloads"], cwd=ROOT, check=True)
        rendered = {}
        with tempfile.TemporaryDirectory(prefix="keymelier-exports-") as folder:
            for name, groups in EXPORTS.items():
                output = Path(folder) / name
                subprocess.run([uv, "export", "--frozen", "--offline", "--no-header",
                                "--no-emit-project", *groups, "--output-file", str(output)],
                               cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
                rendered[name] = HEADER + output.read_text(encoding="utf-8")
    except subprocess.CalledProcessError as error:
        return error.returncode

    changed = []
    for name, text in rendered.items():
        path = ROOT / name
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            changed.append(name)
            if not args.check:
                path.write_text(text, encoding="utf-8", newline="\n")
    if args.check and changed:
        print("Stale dependency exports: " + ", ".join(changed))
        print("Run python tools/export_requirements.py and commit all updated files.")
        return 1
    print("Updated " + ", ".join(changed) if changed else "All dependency exports match uv.lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
