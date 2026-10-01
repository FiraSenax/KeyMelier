# Security review — 2026-09-27

Scope: the whole application after the smart card features (OATH, OpenPGP,
PIV, OTP, interfaces), in four parts: UI/bridge, trust and cryptographic
verification, key operations and secrets, persistence/build/supply chain.
Every finding was traced in the code; the critical one was reproduced.
This is an internal review, not an independent audit.

| Severity | Finding | Resolution |
|---|---|---|
| Critical | pywebview resolves `js_api` names as dotted attribute paths without filtering private members: page script could call `_window.gui.os.system` (reproduced: `_service.history_list` returned data) | The page gets no object any more (`js_api=None`); only 11 wrapper functions are exposed with `window.expose` |
| High | A malicious authenticator could inject markup via the fingerprint name-length field (`maxlength="…"`) | Device values coerced to small integers in Python and JS |
| High | Stale reader→serial cache and ambiguous product-name matching could send card operations (resets, key generation, PINs) to another key | Serial read fresh per operation; refuse when two readers claim a serial or several keys match; OTP refuses without a serial when several YubiKeys are present |
| Medium | No Content-Security-Policy; dropped links/files could navigate the window and receive the bridge | CSP with script hashes (no inline handlers, no network, no frames); drops swallowed; navigation away from the app document is reverted |
| Medium | Security status "OK" ignored attestation; a counterfeit of a certified model could show OK | FAILED attestation → CRITICAL; OK requires VERIFIED; recomputed after every attestation |
| Medium | Attestation chain was checked against the claimed model's roots only; vendors share roots | Packed: AAGUID extension must be present and match; fido-u2f: zero AAGUID and listed key identifier; otherwise UNVERIFIED |
| Medium | Genuine keys could be flagged "not genuine" (leaf without basicConstraints, intermediate anchors, strict profile rules) | PARTIAL_CHAIN, tolerant leaf profile for attestation; signature-valid chains with profile issues are UNVERIFIED, only broken signatures are FAILED |
| Medium | Imported history could forge "attestation passed/no advisories" for offline keys or break the UI with wrong types | Import keeps an allow-list of descriptive snapshot fields, validates inventory/events/lost-done, merges on a copy |
| Medium | PIV key generation replaced the key before the PIN was verified | PIN verified before anything changes |
| Medium | An armed FIDO reset fired on any key of the same model | Bound to the serial; without a serial, refused while another key of that model is connected |
| Medium | Destructive overwrites without server-side confirmation | OpenPGP key replacement, occupied PIV slots, configured OTP slots and PIV deletion require explicit flags |
| Low | Advisory database had no freshness bound | "No known vulnerabilities" needs a database or source contact within 45 days |
| Low | `save_text` followed symlinks and kept old file modes | `O_NOFOLLOW`, private files forced to 0600 |
| Low | Expired unlock tokens/OATH access keys stayed in memory | Purged on expiry, disconnect and lock |
| Low | Windows helpers resolved via search path while elevated | Absolute System32 paths |
| Low | Workflows persisted Git credentials; advisory job permissions broad; untrusted CVE text rendered as Markdown | `persist-credentials: false`, per-job permissions, CVE summary fenced |
| Low | CSV formula neutralisation missed some prefixes | Pipe and full-width forms covered |
| Info | UPX packing enabled in the spec | Disabled (never pack before signing) |

Open (documented, not changed in this pass):
- MDS cache and CRL rollback by someone who can write to the user's home
  directory (no persisted high-water mark for MDS serial / CRL number).
- `proxy-tools` is an sdist; its build backend is fetched without hashes.
- Attestation certificates are not revocation-checked.

Supply chain: every build writes a CycloneDX 1.6 SBOM (`tools/sbom.py`) and
third-party license notices; both ship in the app and with each release. The
SBOM lists Python packages (SPDX licenses, SHA-256 of the installed file from
pip's report, checked against the hash-pinned lock), the PyInstaller
bootloader, CPython, both OpenSSL builds and the Simple Icons data; CI rejects
a build whose SBOM is incomplete (`tools/sbom.py --check --strict`).

---

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
| Key history | On by default; contents (websites, authenticator accounts, OpenPGP fingerprints) remembered by default, names only | Stateless mode still disables all storage; turning history off keeps existing files |
| Diagnostic report (2026-09-27) | Built from an explicit list of fields, each passed through a type/enumeration filter (fido2tool_core/diagnostics.py); errors are recorded as bridge operation name + error code only, never their message; UI script errors only counted | No free text can enter it (names, serials, accounts, paths, URLs, host names, sync ids, passphrases, messages); unknown fields never copied; preview equals the saved text; saved only on an explicit click to a user-chosen file (owner-only); never transmitted. Tests inject synthetic secrets into settings, history, errors and data status |
| Links from company advisory sources (2026-09-27) | Besides the fixed hosts, the app opens exactly the `https://` reference URLs of loaded, signature-verified company sources (e.g. intranet pages) | Exact URL match, not the host; no spaces/control characters, at most 10 per finding; unsigned or invalid sources contribute nothing; opened only in the system browser, never in the app window |
| Linux page loading (2026-09-27) | Qt WebEngine cannot show the app page (over 2 MB as a data: URL) through `setHtml`, so on Linux the page is written to a file readable only by the user (`$XDG_RUNTIME_DIR/keymelier-*/`, mode 0600 in a 0700 folder) and loaded from there; the file is removed on exit | Same CSP as the inline page (script hashes, `connect-src 'none'`, no frames), so the file:// origin cannot fetch other files; navigation away from exactly this file is reverted; no local HTTP server |
| Linux credential store (2026-09-27) | The Secret Service (GNOME Keyring, KWallet, KeePassXC) counts as a native store; taken out of keyring's chain if several backends exist | keyring's plaintext, null and fail backends are still refused; without a Secret Service sync cannot be switched on and says why |
| Linux renderer sandbox (2026-09-27) | Qt WebEngine runs with Chromium's sandbox as shipped; KeyMelier does not set `--no-sandbox` or `QTWEBENGINE_DISABLE_SANDBOX`. Where the system forbids unprivileged user namespaces (containers; likely Ubuntu 24.04+ with its AppArmor restriction) Qt WebEngine continues with the seccomp-BPF layer only – observed via `chrome://sandbox` in an Ubuntu 24.04 container ("Layer 1 Sandbox: None", "Seccomp-BPF: Yes") | The renderer only ever shows KeyMelier's own page: no remote content, CSP with script hashes and `connect-src 'none'`, navigation reverted. Not yet checked on a Linux desktop; an AppArmor profile for the AppImage is not provided |
