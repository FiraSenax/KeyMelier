# RC8: RC7 external review follow-up — 2026-10-29

Base: `95247da` (`v1.8.7-rc.7`). Small compatibility and recovery corrections;
the previously accepted automatic-signing setup and open hardening work remain.

| Review item | Disposition |
|---|---|
| N1 — offline managed source | Keep the strict existing rule. ENTERPRISE.md now explicitly describes VPN loss: verified cached warnings survive, but an unreachable configured source cannot authorize `OK`. |
| N2 — unreadable revocation cache | Specific `update_revocation_state` error through check/download/open and all UI languages. Evidence stays intact; a known current-key marker still reports revocation. Recovery documented; no unsafe automatic reconstruction from incomplete evidence. |
| N3 — accidental repository stop | CI rejects the active fingerprint unless the document contains a matching explicit emergency acknowledgement and reason. Release signing still refuses the key. Prevention requires checks before merge; neither this guard nor the unsigned list protects against repository takeover. |
| N4 — three-digit firmware fallback | Regression coverage for 503 → 0.5.3 and known packed-byte vendors. No further decoding change or claim of physical-device validation. |
| N5 — local history normalization | Preserve local malformed/future timestamps and lost/replacement state across load, unrelated saves and empty sync. Normalize valid instants to UTC; compare strictly validated dates during merge so preserved future values cannot pin decisions. Incoming future timestamps and tombstones remain rejected. |

RC7 evidence was completed after the previous review text: publication run
[40844729678](https://github.com/FiraSenax/KeyMelier/actions/runs/40844729678)
passed all platform builds, signing/notarization, packaged smoke tests, Linux
compatibility checks and release rehearsal. The maintainer reported successful
Windows 11 use, including Bio-key unlock. This does not establish a manual
Linux hardware test or exhaustive destructive-device-operation validation.

RC8 local validation: 457 Python tests, no failures and two platform skips;
41 browser UI tests and 20 UI stress tests passed, including the new localized
revocation-error path.
Ruff, UI security/account/website checks, locked dependency exports, license
inputs and the 14-day advisory-signature gate passed. The UI test driver now
lets Chromium derive native keyboard codes instead of supplying Windows codes
as macOS native codes; the latter caused reproducible local Enter-key timeouts.

# RC7: RC4 external review follow-up on RC6 — 2026-10-29

Base: `7b47f14` (`v1.8.7-rc.6`). This follow-up is included in the
`v1.8.7-rc.7` candidate; the existing RC6 installers do not contain it. Findings were checked
against the implementation rather than accepted solely from the review.

| Review item | Current disposition |
|---|---|
| M1 — managed advisory fail-open | Fixed: all configured sources must be successful, complete and fresh before `OK`. Signed source caches preserve warnings and rollback floors across restart; redirects are rejected. Deferred loading remains asynchronous to avoid blocking startup on UNC/network paths, with `UNKNOWN` until completion. |
| M2 — poison sync files | Fixed: outer and authenticated inner JSON have byte/depth limits and parse errors become `sync_damaged`. Per-peer merge failures are isolated; a file is marked consumed only after a successful merge. A malformed own file is preserved and gets the existing device-ID recovery treatment. |
| M3 — future timestamps/removal marks | Fixed: merge times are validated and normalized to UTC, future values beyond one day are ignored, removal marks are bounded and previously stored future marks are cleaned on load/merge. Shared-passphrase authority and recovery are documented in SECURITY.md. |
| M4 — bundled advisory expiry | Already fixed in RC6: reviewed 29 October, 14-day release gate, 45-day client freshness. |
| M5 — signer and publishing in GitHub | Accepted deployment constraint: automatic builds/signing remain enabled as requested. Passkey login does not separate the signer from an account/CI compromise. |
| M6 — key revocation/rotation/backup | Partly addressed in RC6 by the sticky fingerprint emergency stop and manual recovery procedure. No independently authenticated automatic replacement-key protocol; owner-only PEM backup remains unencrypted. |
| M7 — imported attestation/test events | Fixed for new imports/sync: backend forces origin markers and timeline labels them in the existing UI languages. Local events retain their local presentation; no security verdict is imported. Origin cannot be reconstructed reliably for previously merged unmarked events. |
| L1 — positive assessment expiry / slow responses | Expiry fixed: polling and token reads also check advisory freshness and policy completeness. A hard total transfer deadline against trickling HTTP bodies remains open; current limits cover body size and per-read timeout. |
| L2 — four-digit decimal firmware | Fixed: 1203 decodes to 0.12.3, with a regression test. |
| L3 — obsolete certification wins | Fixed: certification follows effective date, ties prefer the less reassuring status, and compromise/bypass reports retain priority. Unknown/malformed status data cannot authorize `OK`. |
| L4 — MDS signer pin | Existing pinned GlobalSign R3 path validation, leaf-name check, JWT signature and issuer-signed CRLs verified in code. A separate leaf SPKI pin with its rotation path remains an optional strengthening, not implemented here. |
| L5 — native confirmations for destructive bridge actions | Open hardening: HTML confirmation/bridge arguments are not an independent native consent boundary against compromised renderer code. |
| L6 — navigation guard | Open: the current loaded-event guard is too late for a hard navigation boundary and permits data URLs. Needs native pre-navigation handling and tests on each supported backend. |
| L7 — URL parser ambiguity | Fixed: reject backslashes, control/whitespace characters, userinfo and invalid authorities before the existing host/exact-link allowlist. Valid custom HTTPS ports for managed links remain supported. |
| L8 — arbitrary JS-selected sync paths | Fixed at the exposed API: sync setup accepts the private native-dialog selection or existing stored configuration only. Deliberately selected NAS/UNC shares still work. |
| L9 — clipboard secret handling | Open: platform concealed-content markers and conditional auto-clear are not added in this change. |
| L10 — many distinct sync salts | Open: per-file parse/merge isolation is fixed, but per-round KDF budgets, fair batching and failed-file caching need a separate change. The existing session key cache is not a per-round work limit. |
| L11 — future advisory cache | Already fixed in RC6. |
| L12 — VC++ signer CN | Existing Windows Authenticode `Valid` check also validates trust; not merely a CN string comparison. Issuer-name pin remains intentionally absent. |
| L13 — locked encrypted history | Fixed: startup reports a blocked history, disables persistence/sync for it and preserves the encrypted file; no plaintext fallback. |
| I1 — broad PIN token permissions | Open hardening: narrower on-demand permissions require separate authenticator/UX compatibility testing. |
| I2 — minimum PIN length attribute | Fixed: bounded integer capability values and numeric UI construction; invalid device values disable that setting. |
| I3 — apostrophe escaping | Fixed in the shared HTML escaping helper. |
| I4 — device names in logs | Removed names from connect/disconnect log lines; the device label remains in the UI. |

The certification interpretation was cross-checked against the primary
[FIDO MDS 3.1 StatusReport definition](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#statusreport-dictionary).
This is not a blanket stable-release approval: the open hardening items above,
hardware reset/CTAP behavior, native Windows/Linux UI handling and the residual
shared-account signing risk remain distinct from the tested fixes. Large module
splits and broad C901 cleanup were deliberately kept outside these corrections.

Validation: the full local suite completed 445 tests with no failures and two
platform skips, including 20 new review regressions and the existing upgrade
fixtures. Ruff, UI security/account/website checks, JavaScript syntax checks,
dependency export verification and `git diff --check` passed. Legacy event
timestamps are compared by their normalized instant to avoid duplicate events
after sync. The `v1.8.7-rc.7` tag starts the signed artifact-only candidate build;
native Windows/Linux validation and the complete rehearsal are required before
shipping it. A tag build does not publish a GitHub Release.

# Update security follow-up — 2026-10-29

Follow-up review for RC5:

- The bundled review dated 2026-09-26 would cease supporting `OK` on
  2026-11-10 at 18:09:57 UTC. Reviewed and re-signed on 2026-10-29; release builds
  and publication now enforce a review younger than 14 days, with a 30-day daily
  warning gate. Offline copies still expire after 45 days by design.
- Future-dated documents are rejected before selection/cache writes and cannot
  act as an anti-rollback high-water mark. Official and managed sources recover
  from a previously loaded future document while retaining normal rollback checks.
- Update signing stays automatic in the existing GitHub environment, as requested.
  A passkey-secured login is not an independent artifact-signing approval. The
  owner-only private PEM backup remains unencrypted; account compromise and
  same-user workstation malware remain material limits.
- A best-effort, deny-only public-key-fingerprint list adds an emergency stop.
  Observed revocations persist locally, block downloads and installer opening,
  and cannot be undone by deleting the remote entry. It cannot protect a client
  before first observation if the repository is compromised, or authorize a new
  key. See [the recovery procedure](RELEASING.md#repository-emergency-stop).
- The VC++ helper already requires Authenticode status `Valid` as well as the
  exact Microsoft publisher name, product and version. The CN check is not its
  only signature check. No issuer-name pin was added: this remains dependent on
  Windows Authenticode trust rather than a separately pinned Microsoft CA.
- Complexity is quality debt, not evidence of an exploitable vulnerability:
  Ruff C901 identifies 24 core functions and 12 tooling functions above 10 on
  the RC4 tree. No broad security-sensitive refactor or bulk suppression is
  included in this release; existing E9/F correctness checks remain required.

Advisory content review: the 34-day NVD/vendor-keyword and signature/CRL-verified
FIDO MDS scan returned no new findings since 2026-09-25. A separate review of
[Yubico's advisory index](https://www.yubico.com/support/security-advisories/)
identified two historical omissions:
[CVE-2025-29991](https://www.yubico.com/support/security-advisories/ysa-2025-02/)
(PIN/UV Protocol Two, fixed in 5.7.4) and
[CVE-2024-35311](https://www.yubico.com/support/security-advisories/ysa-2024-02/)
(RP enumeration; separate ordinary/FIPS/Bio fixed versions). Added five entries
with affected model AAGUIDs checked against verified MDS sequence 292,
`nextUpdate=2026-11-01`, and vendor firmware boundaries; three boundary tests
cover affected, fixed and unrelated models. The existing
[EUCLEAK entries](https://www.yubico.com/support/security-advisories/ysa-2024-03/)
were retained. YSA-2026-01 affects host software, already covered by the locked
fido2 2.2.1 and yubikey-manager 5.9.2; YSA-2026-02 affects Java server software,
not authenticator hardware. The watch query alone is not treated as a complete
historical coverage audit.

RC5 local validation: 425 Python tests completed successfully (two platform
skips); Ruff, UI security/account/website checks, JavaScript syntax, workflow
YAML parsing, dependency export and license-input checks passed. Native CI
builds and installer tests are tracked by the RC5 tag run.
RC5's Windows run exposed two tests whose broad process mock intercepted the
real Windows ACL setup (`whoami`/`icacls`). RC6 narrows those mocks to the installer
launcher; application behavior is unchanged from RC5.

RC4 changes (retained in RC5):

- Advisory freshness previously trusted recent retrieval of any validly signed
  document, including rejected older copies. Replaying an old signed document
  could restore `OK` with a stale database. Freshness now depends solely on the
  signed review date (45 days); tests cover older/equal replays, newer-but-stale
  data, signature tampering and the scanner verdict. Existing warnings remain
  available when the database expires. Maintainers must review and re-sign it
  within 45 days even if entries do not change.
- A release host compromise could replace both the update binary and its unsigned
  checksum; download completion also opened the installer automatically. A
  separate Ed25519 key now authenticates the checksum bytes and exact release
  tag before binary download. Tests reject altered checksums, foreign keys and
  cross-release replay. Opening is a separate user action. The protected stable
  and RC publication jobs sign and verify checked artifacts. See
  [the key setup and compatibility procedure](RELEASING.md#independent-update-signatures).
- Linux PySide/Qt moves to 6.11.3 with coupled dependency and source evidence.
  The upstream HTTP/2 advisory motivated the patch; exploitability through
  KeyMelier's current network paths has not been established.
- Windows Setup offers prerequisite installation only when the checked x64
  runtime files are missing or below the minimum. Its helper requires valid
  Microsoft Authenticode, the x64 VC++ product and the minimum version, holds
  the downloaded file against replacement while starting it, and uses Microsoft's
  interactive installer. Cancellation/failure prevents app-file replacement;
  reboot requirements are propagated. Silent deployments retain their previous
  no-download behavior.

Local validation: 407 Python tests passed (two platform-specific skips), UI
security/account/website checks, PowerShell prerequisite safety tests with mocked
execution, Ruff, lock exports, license/source checks and strict macOS build
environment SBOM validation passed. The signing dependency bootstrap was also
installed in an isolated environment using the locked wheel hashes. The update
secret is provisioned in the tag-restricted `release-signing` environment; the
public key is included in this working tree. No release has been published.

These changes do not revoke already released clients or retroactively add
signature enforcement to them. A compromised signing key, a compromised trusted
build/review process, local administrator control and release withholding are
outside the new updater guarantee. Native Windows installation and Linux Qt
packaging still require their platform checks before release.

# Refactoring and security verification — 2026-10-26

The core package and PyInstaller spec now use the KeyMelier name throughout
imports, tests, build scripts, CI and documentation. The compatibility-fixture
generator retains one explicitly documented legacy package name to read old
release tags. Service helpers are private; the JS bridge still uses explicit
wrapper functions and an operation allow-list.

| Finding | Resolution |
|---|---|
| Attestation, smart card, enrollment, reset and export failures could expose exception messages; exception logging could include secrets | Fixed user-facing messages and exception types only in logs; UI error text is not logged |
| Previously positive device assessments could remain visible after MDS/CRL expiry until the next network refresh | Invalidate positive assessments when records are read and on the scanner's polling loop |
| Stateless mode did not cover every writer | Guard storage helpers, text export, downloads, GnuPG imports, keyring mutations and CRL cache deletion; Linux page loading uses an anonymous memory file |
| Encrypted history save errors were swallowed | Report failure without writing plaintext when the native credential store or encryption fails |
| Disabling content tracking while history was off left the saved copy intact; imports/sync could restore event details | Scrub the preserved history file and remove account/domain details from incoming events when tracking is off |
| Initial smart card serial discovery preceded the reader-to-FIDO mapping and could race polling | Hold all plausible FIDO interfaces during discovery, in a stable lock order; discard mappings on disconnect |

Regression coverage: `tests/test_audit_regressions.py`, plus the existing
certificate-path, CRL, diagnostics, device-identity and authorization suites.
Both registration tests explicitly request `rk=False`; management tokens remain
connection-scoped and expire at 300 seconds using monotonic time. CSV export
tests cover all requested formula/control-character prefixes. The SBOM checker
now accepts `--check --strict` using the default build output, as well as an
explicit file path.

Local verification: 322 Python tests completed successfully (one Linux-only
memory-file test skipped on macOS); UI security and account-model checks, Ruff,
requirements export consistency and strict SBOM validation passed. A fresh,
hash-pinned macOS build passed all 56 packaged startup checks. The initial
sandboxed launch aborted in macOS application registration; the same build
passed with desktop access and an isolated temporary home. The project venv's
outdated runtime packages were aligned with the existing requirements pins.

This is an implementation review using simulated devices. Physical USB/NFC
operations, Windows execution and the Linux Qt memory-page path require their
platform/hardware checks; existing limitations below still apply. Candidate
version: 1.8.6; stable publication remains subject to the release gates.

# Quality remediation — 2026-10-02

1.8.3 (released 2026-10-02) tightens management-token permissions and cancellation,
bridge error handling, async dialog ownership, function-test response binding,
download bounds/file creation and PIV read failure handling. It also rejects
contaminated pywebview build resources and adds artifact-only signed macOS RCs.
The follow-up also registers queued PIN requests for cancellation, separates
runtime device connections from reused HID paths, rechecks observable device
identity before CTAP access, and drops retired connection updates. PIV/OpenPGP
checks and generation now share a locked card connection; OTP occupancy checks
and programming share the operation locks. PIV slot aliases are canonicalized
before checking occupancy, and application-key generation excludes the reserved
attestation slot.
See [the candidate review](plans/1.8.3-quality-review.md) for evidence and limits,
and [the maintainer guide](ARCHITECTURE.md) for code ownership and invariants.
This is an internal implementation review, not independent certification. Earlier
review entries below are historical and are not a claim of fresh verification.

These guards have limits: serials/model identifiers are device-supplied, and
identical keys without serials can be exchanged between polls without detection.
The HID descriptor lookup/open race is not eliminated at the OS/library level.
Card/OTP locks serialize this process's operations, not other applications or a
physical unplug. Full cross-interface connection binding is not established here.
Older PIV firmware without slot metadata cannot reliably expose a private key
whose certificate has been removed. No claim of complete overwrite detection on
that firmware or cryptographic physical-device identification is made.

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
bootloader, CPython, both OpenSSL builds, individually reviewed brand assets and
native Linux package provenance. CI checks these records (`tools/sbom.py --check --strict`)
and corresponding source archives. This is not a claim that every statically linked
subcomponent is independently versioned or that automated checks prove legal compliance.

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

## MDS-Daten: was gespeichert/exportiert wird und warum

Prüfstand: 2026-10-27. Die Entfernung aller `mds_*`-Felder war eine
vorsichtige Implementierungsentscheidung, **kein belegtes allgemeines
Speicherverbot**. KeyMeliers eigener Code bleibt MIT; heruntergeladene
MDS-Inhalte erhalten dadurch keine MIT-Lizenz.

### Fundstellen und Grenzen

Die [Metadata Usage Terms für Entwickler](https://fidoalliance.org/metadata-usage-terms-for-developers/),
Abschnitte 1.1–1.3, beschränken die eingeräumte Nutzung auf FIDO-Authentifizierung.
Abschnitt 3.1(a) verlangt unveränderte Legal Headers; 3.1(b) erteilt keine
allgemeine Weitergabelizenz. Nach 3.1(c) sind Signaturen vor Nutzung zu prüfen;
ungültige BLOBs dürfen nicht verwendet werden. 3.1(d) verlangt die Entfernung
von Kopien zurückgezogener Statements. Abschnitt 1.4 betrifft Hinweise und
Schutzbedingungen für Drittnutzer. Diese Regeln betreffen BLOBs/Statements,
nicht ausdrücklich jede einzelne daraus gelesene Tatsache.

Die [Bedingungen für Nutzer/Relying Parties](https://fidoalliance.org/metadata-usage-terms-for-relying-parties-or-service-providers-2/),
Abschnitte 1 und 3.1, sind zusätzlich relevant. Der
[MDS Legal Terms-Einstieg](https://fidoalliance.org/metadata-legal-terms/)
ordnet die Vereinbarungen den Beteiligten zu. Ein Quellenlink allein erfüllt
weder die Bedingungen zur Verwendung noch die Pflege bereits verteilter Kopien.
Er ist keine zusätzliche Erlaubnis zur Weitergabe.

### Entscheidungen je Datenpfad

* **CSV (`exporter.py`):** Ein weitergegebenes CSV kann nicht aktualisiert oder
  zurückgerufen werden. Es enthält weder das signierte Statement noch dessen
  Gültigkeitsnachweise. `mds_description` bleibt deshalb leer. Das Entfernen der
  Spalten selbst war unnötig und wird korrigiert: beide bisherigen Spalten
  bleiben an derselben Position, als auslaufende Kompatibilitätsfelder.
* **Status:** `mds_status` stammt aus `statusReports`, nicht aus dem
  Modelltext/Icon im `metadataStatement` (siehe
  [MDS-Spezifikation, §3.1.1 Metadata BLOB Payload Entry](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#metadata-blob-payload-entry-dictionary)).
  Eine identische urheberrechtliche Behandlung von Text, Bild und kurzem
  Statuswert ist damit nicht belegt. Seine Entfernung wird **nicht** als
  zwingende Lizenzfolge behauptet. Der Status bleibt in der aktuellen,
  verifizierten Laufzeitanzeige erhalten. Ein möglicher späterer Export wäre
  ein ausdrücklich historischer Prüfbefund mit Zeitpunkt, BLOB-Seriennummer,
  Gültigkeit und Herkunft. Der bisherige nackte CSV-Wert besitzt diesen Kontext
  nicht; eine gesonderte Weitergabefreigabe ist ebenfalls nicht festgestellt.
  Deshalb bleibt auch diese CSV-Spalte vorerst leer, aus Vorsicht und gegen
  irreführende alte Zertifizierungsaussagen, nicht wegen eines behaupteten
  Verbots einzelner Fakten.
* **History (`history.py`, `_MDS_FIELDS`):** Abgetrennte Modelltexte, Icons,
  Versionen, Statuswerte und Legal Headers werden nicht dauerhaft kopiert.
  Die Migration entfernt sie aus geladenen Snapshots und schreibt diese
  bereinigte History zurück. So können zurückgezogene Statements nicht aus
  älteren Snapshots wieder erscheinen. Eigene Labels, Geräteangaben und
  Ereignisse bleiben erhalten. Bereits außerhalb der App liegende Exporte
  oder Backups werden nicht nachträglich gelöscht.
* **Sync (`_SNAPSHOT_TEXT`):** `mds_description` wird nicht importiert;
  Sicherheitsstatus wurde bereits unabhängig davon nicht als vertrauenswürdig
  importiert. Jeder Rechner beschafft seine aktuelle MDS-Evidenz selbst.
* **Hersteller (`scanner.py`):** Ein bloßer abgeleiteter Herstellername ist
  kein vollständiges Statement. Für seine Speicherung ist ebenfalls kein
  ausdrückliches Verbot nachgewiesen. Die bisherige Heuristik überschrieb aber
  das dauerhaft gespeicherte Feld `manufacturer` ohne Herkunft oder Ablauf.
  Sie bleibt deshalb für MDS-Text abgeschaltet; Hersteller aus Geräteangaben
  und USB-Zuordnung bleiben erhalten. Eine künftige MDS-Heuristik müsste ein
  separates, flüchtiges Anzeigefeld verwenden. Diese Entscheidung dient der
  Herkunftstrennung und ist keine zwingende Lizenzvorgabe.

### Laufzeit und Offline-Verhalten

KeyMelier verwendet aktuelle, verifizierte Metadaten zur lokalen Prüfung von
Authentifikatoren. Die [Metadata-Statement-Spezifikation, §4, `icon`](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1-ps-20250521.html#metadata-keys)
sieht die Darstellung des Gerätebilds zur Identifikation vor. Daraus folgt
keine allgemeine Erlaubnis für Werbung, gebündelte Logos oder beliebige
Inventardatenbanken. Die Einordnung der lokalen Authentifikatorprüfung als
zweckgebundene Nutzung ist unsere Implementierungsbewertung, keine allgemeine
rechtliche Freigabe für jede Verwendung der Daten.

Der ersetzbare lokale Cache bewahrt den signierten BLOB einschließlich seiner
Legal Headers. Ein neuer BLOB ersetzt die alten Statements. Einträge werden
nur angezeigt, solange Signatur-, Zertifikats-, Widerrufs- und `nextUpdate`-
Nachweise aktuell sind. Ein noch gültiger Cache funktioniert auch offline.
Fehlende aktuelle Widerrufsevidenz beweist nicht, dass ein Zertifikat widerrufen
ist: Das Unterdrücken der Anzeige ist eine bewusst strenge Sicherheitsregel.
Die Oberfläche unterscheidet fehlende aktuelle Evidenz von einer AAGUID,
die im aktuellen MDS nicht verzeichnet ist. Quellenhinweise und der erhaltene
Legal Header bleiben bei der Laufzeitanzeige zugänglich.

## Maintainer decisions after the remediation (2026-09-26)

| Topic | Decision | Safeguard kept |
|---|---|---|
| Release signing | Optional: sign/notarize when credentials are configured, otherwise publish unsigned builds | Release notes state the actual signing state per platform; checksums, locks and source commit attached; first-launch steps documented |
| MDS revocation offline | Verified CRLs are persisted in `~/.keymelier/crl/` and re-validated (issuer, signature, validity) on every use. Without current revocation evidence, MDS model data is withheld from display as well | `is_current()` gates lookup and display, positive assessments and attestation chain verification; distinguish stale/unavailable evidence from an AAGUID absent from current metadata |
| Key history | On by default; contents (websites, authenticator accounts, OpenPGP fingerprints) remembered by default, names only | Stateless mode still disables all storage; turning history off keeps existing files |
| Diagnostic report (2026-09-27) | Built from an explicit list of fields, each passed through a type/enumeration filter (keymelier_core/diagnostics.py); errors are recorded as bridge operation name + error code only, never their message; UI script errors only counted | No free text can enter it (names, serials, accounts, paths, URLs, host names, sync ids, passphrases, messages); unknown fields never copied; preview equals the saved text; saved only on an explicit click to a user-chosen file (owner-only); never transmitted. Tests inject synthetic secrets into settings, history, errors and data status |
| Links from company advisory sources (2026-09-27) | Besides the fixed hosts, the app opens exactly the `https://` reference URLs of loaded, signature-verified company sources (e.g. intranet pages) | Exact URL match, not the host; no spaces/control characters, at most 10 per finding; unsigned or invalid sources contribute nothing; opened only in the system browser, never in the app window |
| Linux page loading (2026-09-27) | Qt WebEngine cannot show the app page (over 2 MB as a data: URL) through `setHtml`, so on Linux the page is written to a file readable only by the user (`$XDG_RUNTIME_DIR/keymelier-*/`, mode 0600 in a 0700 folder) and loaded from there; the file is removed on exit | Same CSP as the inline page (script hashes, `connect-src 'none'`, no frames), so the file:// origin cannot fetch other files; navigation away from exactly this file is reverted; no local HTTP server |
| Linux credential store (2026-09-27) | The Secret Service (GNOME Keyring, KWallet, KeePassXC) counts as a native store; taken out of keyring's chain if several backends exist | keyring's plaintext, null and fail backends are still refused; without a Secret Service sync cannot be switched on and says why |
| Linux renderer sandbox (2026-09-27) | Qt WebEngine runs with Chromium's sandbox as shipped; KeyMelier does not set `--no-sandbox` or `QTWEBENGINE_DISABLE_SANDBOX`. Where the system forbids unprivileged user namespaces (containers; likely Ubuntu 24.04+ with its AppArmor restriction) Qt WebEngine continues with the seccomp-BPF layer only – observed via `chrome://sandbox` in an Ubuntu 24.04 container ("Layer 1 Sandbox: None", "Seccomp-BPF: Yes") | The renderer only ever shows KeyMelier's own page: no remote content, CSP with script hashes and `connect-src 'none'`, navigation reverted. Not yet checked on a Linux desktop; an AppArmor profile for the AppImage is not provided |
