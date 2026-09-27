#!/usr/bin/env python3
"""Write data/build.json before PyInstaller runs (fido2tool_core/build_info.py reads it).

    python3 tools/write_build_info.py [--signed true|false] [--notarized true|false] [--ci]

commit: the checked-out commit (`git rev-parse HEAD`); in CI it must equal
$GITHUB_SHA. modified: true if tracked files differ from that commit
(`git status --porcelain --untracked-files=no`) – a local build with
uncommitted changes never claims to be that exact commit. Without Git the
commit stays unknown. No paths, user or host names, no remote URLs.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "data" / "build.json"


def git(*args) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build_info(signed: bool, notarized: bool, ci: bool) -> dict:
    commit = git("rev-parse", "HEAD")
    if commit is None or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        commit = None
    status = git("status", "--porcelain", "--untracked-files=no") if commit else None
    expected = os.environ.get("GITHUB_SHA")
    if ci and expected and commit != expected:
        raise SystemExit(f"checked-out commit {commit} is not GITHUB_SHA {expected}")
    return {"signed": signed, "notarized": notarized, "ci": ci, "commit": commit,
            "modified": None if commit is None else bool(status)}


def main(argv: list[str]) -> int:
    pairs = [a for a in argv if a != "--ci"]
    opts = dict(zip(pairs[::2], pairs[1::2]))
    info = build_info(opts.get("--signed") == "true", opts.get("--notarized") == "true", "--ci" in argv)
    TARGET.write_text(json.dumps(info) + "\n", encoding="utf-8")
    print(f"{TARGET.relative_to(ROOT)}: {json.dumps(info)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
