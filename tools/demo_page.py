"""Write the demo page (the real app page + demo bridge, no Python backend).

Prints the path of the HTML file. Used by tests/ui and tools/screenshots.py;
needs no GUI libraries: fido2tool_core.page builds the page like the app.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from screenshots import demo_page  # noqa: E402

if __name__ == "__main__":
    print(demo_page())
