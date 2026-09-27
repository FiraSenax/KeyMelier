# Changelog

## Unreleased

- **Account overview** (personal mode): every service across all keys – passkeys and authenticator codes together – with a recommendation each (only on a lost key, only on one key, codes only, well protected), search and a problems filter; free passkey slots per key.
- **"All keys belong to me"** setting: turn it off when managing keys for several people – cross-key overviews and backup hints are then hidden.
- The macOS disk image opens as a styled window: KeyMelier and Applications side by side with a "drag to install" arrow, in KeyMelier's colours (`packaging/dmg-background.svg`, built with dmgbuild).

## 1.3.1 — 2026-09-27

- **Disk image and installer:** macOS releases come as `KeyMelier-macOS.dmg` (drag to Applications, also to update), Windows releases as `KeyMelier-Windows-Setup.exe` (installs or updates, Start menu entry, uninstaller). The zips remain as portable versions. On Windows KeyMelier requests administrator rights at start.
- **Update download in the app:** the update notice downloads the disk image or installer for this system, verifies it against the release's SHA-256 checksums and opens it – installing stays with the user.
- Documentation with screenshots on the website; layout fixes.

## 1.3.0 — 2026-09-27

**Security review** (details in SECURITY_REVIEW.md):
- Critical: the page no longer receives a Python object through the pywebview bridge – only 11 wrapper functions – closing a path from page script to code execution.
- Content-Security-Policy, drops and navigation blocked; device-supplied values in markup coerced.
- Card operations can no longer hit another key (fresh serial per operation, refusal when ambiguous); FIDO reset bound to the serial.
- "OK" requires verified attestation; failed attestation is critical; attestation certificates must name the claimed model; fewer false "not genuine" results.
- Hardened history import, PIN-before-change for PIV generation, server-side confirmation for overwrites, fresher advisory requirement, safer file writes, workflow hardening.
- SBOM (CycloneDX 1.6) for each platform, in the app and attached to releases.

**New:**
- **OpenPGP key generation on the card:** signature, encryption and authentication keys (Ed25519/Cv25519, NIST P-256, RSA 2048/4096) are generated on the security key and self-signed by it; KeyMelier writes the OpenPGP public key and a revocation certificate (saved where you choose) and can import the key into GnuPG. Verified against Sequoia-PGP, including decrypting with the card.
- **Quantum safety** section per key: signature algorithms from getInfo, automatic detection of ML-DSA (COSE -48/-49/-50, RFC 9964), and what classical cryptography means for logins and for encryption.
- **History export and import** (JSON) to back up or move KeyMelier's knowledge about your keys; imports are validated and merged.

## 1.2.1 — 2026-09-27

- Third-party license notices: `THIRD_PARTY_LICENSES.txt` (generated at build time from the bundled packages, including source locations for LGPL/MPL components) ships inside the app and with every release; "Open-source licenses" opens it.
- Copying a PIV certificate no longer truncates it.

## 1.2.0 — 2026-09-27

- **Authenticator (OATH):** show TOTP/HOTP codes with countdown and one-click copy, add accounts from an otpauth:// link or by hand, rename, delete, set/remove the password, reset. Touch-protected accounts show their code after touching the key.
- **OpenPGP:** keys per slot (algorithm, fingerprint, creation date, generated/imported), signature counter, cardholder name and URL, PIN/admin PIN retries, change PIN/admin PIN, unblock PIN, signature PIN policy, touch policies (YubiKey), reset. Works with YubiKeys and other OpenPGP cards such as Token2.
- **What's on it:** the history remembers per key which passkey websites, authenticator accounts and OpenPGP keys it held (names only, never secrets) and when they were last read – on by default.
- **PIV:** certificates per slot with validity and expiry warnings, generate a key with a self-signed certificate, import, copy and delete certificates, change PIN/PUK, unblock the PIN, protect the management key with the PIN, warnings for factory defaults, reset.
- **YubiKey OTP slots:** which slots are used, static password, HMAC-SHA1 challenge-response (secret shown once for a backup key), swap, delete. On macOS KeyMelier asks for the Input Monitoring permission.
- **Applications per USB/NFC** for YubiKeys (FIDO2 over USB stays on so KeyMelier can always find the key again).
- Backup check and lost-key assistant include authenticator accounts, OpenPGP keys and PIV certificates.
- History shows the serial number and AAGUID of every key.
- Tabs for smart card applications only appear when the key offers them; while a key's smart card interface is in use, FIDO polling pauses for that key (fixes spurious errors on Token2).

## 1.1.3 — 2026-09-27

- After an offline start, metadata is re-verified as soon as revocation lists are reachable again (retried every 15 minutes while evidence is missing) instead of staying "Unknown" until restart.
- A cached revocation list that fails validation is discarded and downloaded again instead of blocking recovery.
- README privacy section matches the new default (history on).

## 1.1.2 — 2026-09-27

- FIDO metadata works offline: verified signer CRLs are stored locally and re-validated on every use.
- Without revocation evidence, model names and vendor icons are still shown, but no positive security assessment is made; a revoked signer is always rejected.
- Key history is on by default again; website recording remains opt-in.
- Release signing is optional: builds are signed/notarized when credentials are configured, otherwise published unsigned with the signing state and first-launch steps in the release notes.
- Privacy texts in all 11 languages; revocation state shown under Data freshness; fixed colours for the Unknown status.

## 1.1.1 — 2026-09-26

- Distinguish verified, unverified and failed attestation evidence.
- Show unknown security status when current trusted metadata is unavailable.
- Harden certificate paths, MDS expiry/revocation checks and advisory verification.
- Disable persistent history and website recording by default; remove automatic CSV exports.
- Add stateless mode, optional OS-keychain-backed history encryption and private atomic storage.
- Prevent CSV formula injection and preserve critical findings over lower-severity warnings.
- Lock dependencies with hashes and pin CI actions to reviewed commit IDs.
- Require signing and notarization for public versioned releases.

Local macOS builds are ad-hoc signed test builds. Publisher signing requires the
credentials documented in RELEASING.md. Windows and physical-key validation remain
separate from the automated regression suite.
