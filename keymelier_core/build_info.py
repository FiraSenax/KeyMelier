"""How this copy of KeyMelier was built (data/build.json, written at build time
by tools/write_build_info.py – in CI and by the local build scripts).

Only what the app should say honestly about itself: whether the build is
signed (Windows: Authenticode) or signed and notarized (macOS:
Developer ID), and the exact source revision – the full commit, and whether
the working tree had uncommitted changes. The app needs no Git at run time.
Missing or invalid values mean "unknown"; nothing is guessed.
The optional release tag distinguishes RC builds with the same base version;
it must match this app version and name an unmodified, identified build.
"""

import json
import re
import sys
from pathlib import Path
from keymelier_core.version import __version__

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
    tag = data.get("release_tag")
    if not (isinstance(tag, str) and re.fullmatch(r"v" + re.escape(__version__) + r"(?:-rc\.[1-9]\d*)?", tag)
            and commit and data.get("modified") is False):
        tag = None
    return {"signed": data.get("signed") is True, "notarized": data.get("notarized") is True,
            "ci": data.get("ci") is True, "commit": commit, "release_tag": tag,
            # a commit only counts as unmodified when the build said so explicitly
            "modified": None if commit is None else data.get("modified") is not False}
