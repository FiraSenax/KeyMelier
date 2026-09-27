#!/bin/bash
# Disk image with KeyMelier.app and a link to /Applications on a neon
# background with an arrow: open it, drag the app over the old one.
# Signed (and later notarized) when an identity is set.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=dist/KeyMelier-macOS.dmg
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
# No extended attributes: they break strict signature checks ("detritus")
ditto --norsrc --noextattr --noqtn dist/KeyMelier.app "$STAGE/KeyMelier.app"
rm -f "$OUT"
# Styled window (background, icon positions) via dmgbuild; see dmg-settings.py
PYTHON=${PYTHON:-python3}
"$PYTHON" -m dmgbuild -s packaging/dmg-settings.py -D app="$STAGE/KeyMelier.app" "KeyMelier" "$OUT" >/dev/null
if [ -n "${KEYMELIER_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$KEYMELIER_SIGN_IDENTITY" --timestamp "$OUT"
fi
echo "$OUT"
