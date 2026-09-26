# Security remediation — 2026-09-26

Scope: findings from the supplied review, plus adjacent trust decisions, persistence,
exports and release workflow. This is an implementation review, not independent
certification or a complete penetration test.

| Severity | Finding | Resolution |
|---|---|---|
| High | Missing attestation evidence could pass | Explicit VERIFIED/UNVERIFIED/FAILED; UI, CSV and legacy history handling agree |
| High | Unknown metadata could appear safe | UNKNOWN unless current certified MDS and signed advisories are available |
| High | Partial certificate path validation | OpenSSL strict PKIX validation, validity dates, CA/key usage, path lengths and critical extensions |
| High | Signature algorithm/profile checks incomplete | Packed verification delegates to python-fido2; strict COSE key decoding and request binding |
| High | MDS signer revocation unchecked | Direct complete issuer-signed CRLs, expiry/signature checks and restricted download hosts; unavailable evidence fails closed |
| Medium | MDS expiry not enforced | Signed nextUpdate and certificate/CRL validity bound positive assessments |
| Medium | Advisory warning could mask revoked MDS | Highest severity wins; missing/failed advisory checks cannot produce OK |
| Medium | Bundled advisory bypassed signature check | Bundled and downloaded databases require valid Ed25519 signatures |
| Medium | Unknown firmware could miss bounded advisory | Conservatively flag matching model with unknown firmware |
| Medium | Device/website history and CSV written automatically | Persistence and websites opt-in; explicit exports; stateless mode; private atomic files; optional OS-keychain encrypted history |
| Medium | Spreadsheet formula injection | Formula prefixes neutralized and filenames independent of device-provided serials |
| Medium | Floating build dependencies/actions | Universal uv lock, hash-checked pip exports, pinned action commits, attached release evidence |
| Medium | Unsigned releases encouraged protection bypasses | Signed-release gates, notarization, Authenticode verification; bypass instructions and public unsigned nightly publishing removed |

Remaining external validation: physical hardware tests, Windows execution/ACLs,
real signing/notarization with provisioned publisher identities and CI runs.
Authenticator certificate CRL/OCSP beyond MDS status is not implemented. Offline
MDS verification requires current CRL evidence, so unavailable networking can
produce UNKNOWN/UNVERIFIED; this is intentional. Optional history encryption is
covered with a mocked credential store, not an interactive OS keychain write.
Old plaintext files/exports/backups are preserved and are not automatically erased.

## Maintainer decisions after the remediation (2026-09-26)

| Topic | Decision | Safeguard kept |
|---|---|---|
| Release signing | Optional: sign/notarize when credentials are configured, otherwise publish unsigned builds | Release notes state the actual signing state per platform; checksums, locks and source commit attached; first-launch steps documented |
| MDS revocation offline | Verified CRLs are persisted in `~/.keymelier/crl/` and re-validated (issuer, signature, validity) on every use. If revocation status cannot be established, signature- and path-verified metadata is used for display only | `is_current()` stays false without revocation evidence, so no "no known findings" assessment and no attestation chain verification; a CRL that lists the signer as revoked is never soft-failed (`RevokedError`) |
| Key history | On by default; websites remain opt-in | Stateless mode still disables all storage; turning history off keeps existing files |
