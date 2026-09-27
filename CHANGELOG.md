# Changelog

## Unreleased

- **Authenticator (OATH):** show TOTP/HOTP codes with countdown and one-click copy, add accounts from an otpauth:// link or by hand, rename, delete, set/remove the password, reset. Touch-protected accounts show their code after touching the key.
- **OpenPGP:** keys per slot (algorithm, fingerprint, creation date, generated/imported), signature counter, cardholder name and URL, PIN/admin PIN retries, change PIN/admin PIN, unblock PIN, signature PIN policy, touch policies (YubiKey), reset. Works with YubiKeys and other OpenPGP cards such as Token2.
- **What's on it:** the history remembers per key which passkey websites, authenticator accounts and OpenPGP keys it held (names only, never secrets) and when they were last read – on by default.
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
