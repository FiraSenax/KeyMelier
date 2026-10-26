"""How this copy of KeyMelier was built (data/build.json, written at build time
by tools/write_build_info.py – in CI and by the local build scripts).

Only what the app should say honestly about itself: whether the build is
signed (Windows: Authenticode via SignPath) or signed and notarized (macOS:
Developer ID), and the exact source revision – the full commit, and whether
the working tree had uncommitted changes. The app needs no Git at run time.
Missing or invalid values mean "unknown"; nothing is guessed.
"""

import json
import re
import sys
from pathlib import Path

ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
BUILD_FILE = ROOT_DIR / "data" / "build.json"
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")   # SHA-1 or SHA-256 object name


def valid_commit(value) -> str | None:
    return value if isinstance(value, str) and COMMIT.fullmatch(value) else None


def load(path: Path = BUILD_FILE) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    commit = valid_commit(data.get("commit"))
    return {"signed": data.get("signed") is True, "notarized": data.get("notarized") is True,
            "ci": data.get("ci") is True, "commit": commit,
            # a commit only counts as unmodified when the build said so explicitly
            "modified": None if commit is None else data.get("modified") is not False}
