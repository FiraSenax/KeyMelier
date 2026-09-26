#!/bin/bash
# KeyMelier — macOS build script
# Produces: dist/KeyMelier.app
# Requires: PyInstaller (installed automatically into the build venv)

set -e
cd "$(dirname "$0")"

VENV_DIR="build-venv"
PYTHON="$VENV_DIR/bin/python3"
PIP="$VENV_DIR/bin/pip"
PYINSTALLER="$VENV_DIR/bin/pyinstaller"

echo "=== KeyMelier — macOS build ==="

if [ ! -f "$PYTHON" ]; then
    echo "Creating build venv..."
    python3 -m venv "$VENV_DIR"
fi

echo "Installing dependencies..."
"$PIP" install -q --upgrade pip
"$PIP" install -q -r requirements.txt
"$PIP" install -q pyinstaller cairosvg

echo "Building app icon..."
ICONSET="build/KeyMelier.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
"$PYTHON" - <<'EOF'
import cairosvg
for size in (16, 32, 128, 256, 512):
    for scale in (1, 2):
        px = size * scale
        name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
        cairosvg.svg2png(url="static/icon.svg", write_to=f"build/KeyMelier.iconset/{name}",
                         output_width=px, output_height=px)
EOF
iconutil -c icns "$ICONSET" -o build/KeyMelier.icns
export KEYMELIER_ICON="build/KeyMelier.icns"

echo "Running PyInstaller..."
"$PYINSTALLER" --clean --noconfirm fido2tool.spec

# Extended attributes (Finder info, provenance) copied from the source tree
# break code signing; strip them and re-apply the ad-hoc signature.
# A Developer ID signature would replace "-" here.
xattr -cr dist/KeyMelier.app
codesign --force --deep --sign - dist/KeyMelier.app
codesign --verify --deep --strict dist/KeyMelier.app

echo ""
echo "Build complete: dist/KeyMelier.app"
echo "You can drag it to /Applications or distribute the .app directly."
