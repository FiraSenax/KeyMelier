#!/bin/bash
# KeyMelier — Linux build script
# Produces: dist/KeyMelier/ (PyInstaller bundle) and dist/KeyMelier-Linux-<arch>.AppImage
# Requires: Python 3.11–3.13 with venv, curl, squashfs-tools; the packages of
# the CI job build-linux (PC/SC headers, libraries Qt WebEngine links to).
#
# appimagetool is hash-pinned. The runtime is built from recorded sources in
# a pinned container; its static library inventory is included with the app.

set -euo pipefail
cd "$(dirname "$0")"

VENV_DIR="build-venv"
PYTHON="$VENV_DIR/bin/python3"
ARCH="$(uname -m)"

APPIMAGETOOL_VERSION="1.9.1"
case "$ARCH" in
    x86_64)
        APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0" ;;
    aarch64)
        APPIMAGETOOL_SHA256="f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "=== KeyMelier — Linux build ($ARCH) ==="

if [ ! -f "$PYTHON" ]; then
    echo "Creating build venv..."
    python3 -m venv "$VENV_DIR"
fi

echo "Installing dependencies..."
mkdir -p build
# The report records which files pip installed (SBOM hashes, tools/sbom.py);
# --force-reinstall so a rebuild records every package, not only new ones
rm -f build/pip-report*.json
"$PYTHON" -m pip install --require-hashes --force-reinstall -q -r requirements.txt -r requirements-build.txt \
    --report build/pip-report.json
"$PYTHON" tools/build_zxing.py
"$PYTHON" tools/build_runtime.py

# Source commit for About/diagnostics (CI writes it in its own step, with the signing state)
[ -n "${CI:-}" ] || "$PYTHON" tools/write_build_info.py

echo "Running PyInstaller..."
"$PYTHON" -m PyInstaller --clean --noconfirm keymelier.spec

"$PYTHON" tools/sbom.py --check build/keymelier-sbom.cdx.json --strict

echo "Assembling AppDir..."
APPDIR="build/AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps" \
    "$APPDIR/usr/share/keymelier"
cp -a dist/KeyMelier "$APPDIR/usr/lib/keymelier"
install -m 755 packaging/linux/AppRun "$APPDIR/AppRun"
install -m 644 packaging/linux/keymelier.desktop "$APPDIR/keymelier.desktop"
install -m 644 packaging/linux/keymelier.desktop "$APPDIR/usr/share/applications/keymelier.desktop"
install -m 644 static/icon.png "$APPDIR/keymelier.png"
install -m 644 static/icon.png "$APPDIR/usr/share/icons/hicolor/512x512/apps/keymelier.png"
install -m 644 packaging/linux/70-keymelier.rules "$APPDIR/usr/share/keymelier/70-keymelier.rules"
ln -sf keymelier.png "$APPDIR/.DirIcon"

fetch() {  # url sha256 target
    if [ ! -f "$3" ] || ! echo "$2  $3" | sha256sum -c --status; then
        curl -fsSL --retry 3 -o "$3" "$1"
    fi
    echo "$2  $3" | sha256sum -c --quiet || { echo "Checksum mismatch: $1"; rm -f "$3"; exit 1; }
}
TOOLS="build/appimage-tools"
mkdir -p "$TOOLS"
fetch "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$ARCH.AppImage" \
    "$APPIMAGETOOL_SHA256" "$TOOLS/appimagetool-$ARCH.AppImage"
"$PYTHON" -c 'import sys; sys.path.insert(0, "tools"); from build_runtime import verify_built; verify_built()'
# Unpack the (checked) tool instead of running the AppImage: needs no FUSE and
# also works under CPU emulation, where the AppImage magic in the ELF header
# confuses binfmt
OFFSET="$("$PYTHON" -c "import sys; sys.path.insert(0, 'tools'); import check_artifacts as c; \
print(c.appimage_offset(open('$TOOLS/appimagetool-$ARCH.AppImage', 'rb').read(4 << 20)))")"
rm -rf "$TOOLS/appimagetool"
unsquashfs -q -o "$OFFSET" -d "$TOOLS/appimagetool" "$TOOLS/appimagetool-$ARCH.AppImage" >/dev/null

echo "Building AppImage..."
OUT="dist/KeyMelier-Linux-$ARCH.AppImage"
rm -f "$OUT"
ARCH="$ARCH" "$TOOLS/appimagetool/AppRun" --no-appstream --runtime-file "$TOOLS/runtime-$ARCH" "$APPDIR" "$OUT"

echo ""
echo "Build complete: $OUT"
echo "Unsigned. Users verify it with SHA256SUMS.txt of the release."
