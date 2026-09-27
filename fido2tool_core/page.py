"""The app's single HTML document: static/ with CSS, scripts and icon inlined.

Kept free of GUI imports so tests and CI can build exactly the page the
app shows (tools/demo_page.py) without pywebview or smart card libraries.
"""

import base64
import hashlib
import sys
from pathlib import Path

ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
STATIC_DIR = ROOT_DIR / "static"

# Loaded in this order (classic scripts sharing one global scope)
SCRIPTS = ("i18n.js", "service-icons.js", "accounts.js", "ui-dialogs.js", "view-accounts.js", "view-sync.js",
           "view-replace.js", "onboarding.js", "view-keys.js", "app.js")


def build_html(static_dir: Path = STATIC_DIR) -> str:
    """Inline CSS, JS and the icon into one document (no server, no file URLs)."""
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    css = (static_dir / "style.css").read_text(encoding="utf-8")
    icon = base64.b64encode((static_dir / "icon.svg").read_bytes()).decode()
    html = html.replace('<link rel="stylesheet" href="style.css">', f"<style>\n{css}\n</style>")
    html = html.replace('src="icon.svg"', f'src="data:image/svg+xml;base64,{icon}"')
    hashes = []
    for name in SCRIPTS:
        tag = f'<script src="{name}"></script>'
        if tag not in html:
            raise ValueError(f"static/index.html does not load {name}")
        js = (static_dir / name).read_text(encoding="utf-8").replace("</script", "<\\/script")
        body = f"\n{js}\n"
        hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'")
        html = html.replace(tag, f"<script>{body}</script>")
    # Only our scripts may run: no inline handlers, no javascript: URLs,
    # no network, no framing. 'unsafe-eval' is needed by pywebview's bridge
    # stubs (new Function). Injected markup therefore cannot execute.
    csp = ("default-src 'none'; script-src " + " ".join(hashes) + " 'unsafe-eval'; "
           "style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; "
           "form-action 'none'; base-uri 'none'; frame-src 'none'; object-src 'none'")
    html = html.replace('<meta charset="UTF-8">',
                        f'<meta charset="UTF-8">\n  <meta http-equiv="Content-Security-Policy" content="{csp}">', 1)
    return html
