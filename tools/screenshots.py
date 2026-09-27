#!/usr/bin/env python3
"""Documentation screenshots of the real UI with fictional demo data.

    venv/bin/python tools/screenshots.py

Builds the app page exactly like the app (app.build_html), swaps the Python
bridge for tools/docs_demo.js and renders each scene with headless Chrome
into docs/img/. No real keys or personal data are involved.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCENES = ["overview", "security", "pin", "passkeys", "oath", "openpgp", "openpgp-generate", "piv", "otp",
          "settings", "history", "details", "accounts", "backup", "lost", "replace", "sync"]
CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    shutil.which("chromium") or "", shutil.which("google-chrome") or "",
]


def demo_page() -> Path:
    import re
    from app import build_html
    html = build_html()
    html = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", html)  # demo scripts are inline too
    demo = (ROOT / "tools" / "docs_demo.js").read_text(encoding="utf-8")
    scenes = (ROOT / "tools" / "docs_scenes.js").read_text(encoding="utf-8")
    html = html.replace("<script>", f"<script>\n{demo}\n</script>\n<script>", 1)
    html = html.replace("</body>", f"<script>\n{scenes}\n</script>\n</body>", 1)
    out = ROOT / "build" / "docs-demo" / "demo.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def main():
    chrome = next((c for c in CHROME_CANDIDATES if c and Path(c).exists()), None)
    if not chrome:
        sys.exit("Chrome, Edge or Chromium is needed for the screenshots.")
    page = demo_page()
    target = ROOT / "docs" / "img"
    target.mkdir(parents=True, exist_ok=True)
    for scene in SCENES:
        png = target / f"{scene}.png"
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                        "--force-device-scale-factor=1.5", "--window-size=1360,820", "--lang=en-US",
                        "--virtual-time-budget=5000", f"--screenshot={png}", f"{page.as_uri()}#{scene}"],
                       check=True, capture_output=True, timeout=120)
        print("wrote", png.relative_to(ROOT))


if __name__ == "__main__":
    main()
