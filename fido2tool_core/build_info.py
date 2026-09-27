"""How this copy of KeyMelier was built (written by CI into data/build.json).

Only what the app should say honestly about itself: whether the build is
signed (Windows: Authenticode via SignPath) or signed and notarized (macOS:
Developer ID). A missing file means a local or unsigned build.
"""

import json
import sys
from pathlib import Path

ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
BUILD_FILE = ROOT_DIR / "data" / "build.json"


def load(path: Path = BUILD_FILE) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"signed": data.get("signed") is True, "notarized": data.get("notarized") is True,
            "ci": data.get("ci") is True}
