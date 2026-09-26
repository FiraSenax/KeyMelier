#!/bin/bash
# Run only on an ephemeral CI runner, after building with Developer ID.
set -euo pipefail
: "${APPLE_ID:?}" "${APPLE_TEAM_ID:?}" "${APPLE_APP_PASSWORD:?}"
codesign --verify --deep --strict --verbose=2 dist/KeyMelier.app
ditto -c -k --keepParent dist/KeyMelier.app dist/notarization.zip
xcrun notarytool submit dist/notarization.zip --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
xcrun stapler staple dist/KeyMelier.app
xcrun stapler validate dist/KeyMelier.app
spctl --assess --type execute --verbose=2 dist/KeyMelier.app
rm dist/notarization.zip
