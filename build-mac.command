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
mkdir -p build
# The report records which files pip installed (SBOM hashes, tools/sbom.py);
# --force-reinstall so a rebuild records every package, not only new ones
rm -f build/pip-report*.json
"$PIP" install --require-hashes --force-reinstall -q -r requirements.txt -r requirements-build.txt \
    --report build/pip-report.json

echo "Using committed app icon..."
# Use the reviewed, committed icons; regeneration is a separate design task.
export KEYMELIER_ICON="static/icon.icns"

xattr -cr static data fido2tool_core

# Source commit (and whether the tree has uncommitted changes) for About/diagnostics
"$PYTHON" tools/write_build_info.py

echo "Running PyInstaller..."
"$PYINSTALLER" --clean --noconfirm fido2tool.spec

# Extended attributes (Finder info, provenance) copied from the source tree
# break code signing; strip them and re-apply the ad-hoc signature.
# A Developer ID signature would replace "-" here.
# macOS may re-attach attributes right after the build, so retry once.
for attempt in 1 2 3; do
    xattr -cr dist/KeyMelier.app
    if codesign --force --deep --sign - dist/KeyMelier.app 2>/dev/null \
        && codesign --verify --deep --strict dist/KeyMelier.app 2>/dev/null; then
        break
    fi
    [ "$attempt" = 3 ] && { echo "Code signing failed"; exit 1; }
    sleep 1
done

echo ""
echo "Build complete: dist/KeyMelier.app"
echo "Local test build only. Public distribution requires Developer ID signing and notarization."
