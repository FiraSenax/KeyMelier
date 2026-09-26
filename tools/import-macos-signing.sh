#!/bin/bash
set -euo pipefail
: "${MACOS_CERTIFICATE_P12:?}" "${MACOS_CERTIFICATE_PASSWORD:?}" "${RUNNER_TEMP:?}"
keychain="$RUNNER_TEMP/keymelier-signing.keychain-db"
cert="$RUNNER_TEMP/keymelier-signing.p12"
password=$(openssl rand -hex 32)
printf '%s' "$MACOS_CERTIFICATE_P12" | base64 --decode > "$cert"
chmod 600 "$cert"
trap 'rm -f "$cert"' EXIT
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$cert" -P "$MACOS_CERTIFICATE_PASSWORD" -k "$keychain" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -k "$password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"
