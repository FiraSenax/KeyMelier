#!/bin/bash
# Render packaging/dmg-background.svg to PNG (1x and 2x) with headless Chrome,
# which draws the SVG glow filters. The PNGs are committed; CI does not render.
set -euo pipefail
cd "$(dirname "$0")"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
HTML=$(mktemp -t dmgbg).html
printf '<!doctype html><html><body style="margin:0;background:#05020d;overflow:hidden">%s</body></html>' "$(cat dmg-background.svg)" > "$HTML"
for scale in 1 2; do
  out=dmg-background.png; [ "$scale" = 2 ] && out=dmg-background@2x.png
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=$scale \
    --window-size=760,480 --screenshot="$PWD/$out" "file://$HTML" >/dev/null 2>&1
  echo "wrote $out"
done
rm -f "$HTML"
