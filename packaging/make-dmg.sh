#!/bin/bash
# Disk image with KeyMelier.app and a link to /Applications: open it, drag
# the app over the old one. Signed (and later notarized) when an identity is set.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=dist/KeyMelier-macOS.dmg
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
# No extended attributes: they break strict signature checks ("detritus")
ditto --norsrc --noextattr --noqtn dist/KeyMelier.app "$STAGE/KeyMelier.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$OUT"
hdiutil create -volname "KeyMelier" -srcfolder "$STAGE" -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$OUT" >/dev/null
if [ -n "${KEYMELIER_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$KEYMELIER_SIGN_IDENTITY" --timestamp "$OUT"
fi
echo "$OUT"
