#!/usr/bin/env python3
"""Render static/icon.svg into the app icon files that are committed to the repo.

    python3 tools/make_icons.py

Produces static/icon.png (window/dock icon at runtime), static/menubar.png,
static/icon.ico
(Windows) and, on macOS, static/icon.icns. Needs cairosvg (with the cairo
library, e.g. `brew install cairo`) and Pillow. CI uses the committed files,
so the build machines don't need cairo.
"""

import shutil
import subprocess
import sys
import tempfile
from io import BytesIO
from pathlib import Path

import cairosvg
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SVG = ROOT / "static" / "icon.svg"


def render(px: int) -> Image.Image:
    png = cairosvg.svg2png(url=str(SVG), output_width=px, output_height=px)
    return Image.open(BytesIO(png)).convert("RGBA")


def main():
    render(512).save(ROOT / "static" / "icon.png")

    # Menu bar template image (black on transparent, 18 pt @2x)
    png = cairosvg.svg2png(url=str(ROOT / "static" / "menubar.svg"), output_width=36, output_height=36)
    (ROOT / "static" / "menubar.png").write_bytes(png)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [render(s) for s in sizes]
    frames[-1].save(ROOT / "static" / "icon.ico", format="ICO",
                    sizes=[(s, s) for s in sizes], append_images=frames[:-1])

    if sys.platform == "darwin":
        with tempfile.TemporaryDirectory() as tmp:
            iconset = Path(tmp) / "KeyMelier.iconset"
            iconset.mkdir()
            for size in (16, 32, 128, 256, 512):
                render(size).save(iconset / f"icon_{size}x{size}.png")
                render(size * 2).save(iconset / f"icon_{size}x{size}@2x.png")
            subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(ROOT / "static" / "icon.icns")], check=True)
    elif not (ROOT / "static" / "icon.icns").exists():
        print("Note: icon.icns can only be generated on macOS (iconutil).")

    print("Icons written to static/")


if __name__ == "__main__":
    main()
