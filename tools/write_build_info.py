#!/usr/bin/env python3
"""Write data/build.json before PyInstaller runs (fido2tool_core/build_info.py reads it).

    python3 tools/write_build_info.py [--signed true|false] [--notarized true|false] [--ci]

commit: the checked-out commit (`git rev-parse HEAD`); in CI it must equal
$GITHUB_SHA. modified: true if the working tree differs from that commit in
any way `git status --porcelain` reports – edited, staged, deleted or renamed
files and new files that are not ignored (build output, caches and this
build.json are in .gitignore). A local build with changes never claims to be
that exact commit. If the status cannot be determined, modified is unknown
(null) – never false – and a CI build stops. Without Git the commit stays
unknown. No paths, user or host names, no remote URLs.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "data" / "build.json"


def git(*args, cwd: Path = ROOT) -> str | None:
    """Output of a git command, or None if Git is missing or the command failed."""
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build_info(signed: bool, notarized: bool, ci: bool, root: Path = ROOT) -> dict:
    commit = git("rev-parse", "HEAD", cwd=root)
    if commit is None or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        commit = None
    expected = os.environ.get("GITHUB_SHA")
    if ci and expected and commit != expected:
        raise SystemExit(f"checked-out commit {commit} is not GITHUB_SHA {expected}")
    modified = None
    if commit:
        # untracked files count too (default --untracked-files=normal); ignored ones do not
        status = git("status", "--porcelain", "--untracked-files=normal", cwd=root)
        if status is None:
            if ci:
                raise SystemExit("git status failed: cannot tell whether the tree is unmodified")
        else:
            modified = bool(status)
    return {"signed": signed, "notarized": notarized, "ci": ci, "commit": commit, "modified": modified}


def main(argv: list[str]) -> int:
    pairs = [a for a in argv if a != "--ci"]
    opts = dict(zip(pairs[::2], pairs[1::2]))
    info = build_info(opts.get("--signed") == "true", opts.get("--notarized") == "true", "--ci" in argv)
    TARGET.write_text(json.dumps(info) + "\n", encoding="utf-8")
    print(f"{TARGET.relative_to(ROOT)}: {json.dumps(info)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
