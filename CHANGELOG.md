# Changelog

## Unreleased

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
