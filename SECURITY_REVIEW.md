# RC2 hardening — 2026-10-31

RC1 was published at `a43b12c52d6c174a56a673c3607810edff92d32a` as
[v1.8.8-rc.1](https://github.com/FiraSenax/KeyMelier/releases/tag/v1.8.8-rc.1).
[Build 41016736648](https://github.com/FiraSenax/KeyMelier/actions/runs/41016736648)
passed after one Windows native-probe startup timeout and a rerun. Its packages
passed macOS signing/notarization, Windows signing and the signed-checksum gate.
Those results apply to RC1, not to subsequent source changes.

The five selected RC2 changes are:

1. **DOM rendering:** PIV, OpenPGP and OTP views, forms and generated-key results
   now insert device/imported strings through text nodes and attributes. The shared
   builders accept a restricted set of elements/attributes; no dynamic markup is
   parsed. Bundled SVG icons remain a reviewed parsing site. Production-CSP browser
   checks cover hostile attributes/text and all form variants/defaults.
2. **Sync work:** each peer round visits at most 32 files, derives at most four new
   salt keys and budgets 40 MB of peer data (each individual read remains capped at
   20 MB plus one size-check byte). Round-robin scheduling also applies to manual
   sync. Up to 128 unchanged failed files are retried after 60 seconds, immediately
   on a changed filesystem stamp or a manual check; failed merges are never
   acknowledged. Directory enumeration and filesystem latency are not time-bounded.
   The own-file read/write is additional constant work. Setup cannot validate a
   passphrase/empty folder from an incomplete batch: it fails before configuration
   if no peer could be opened. Back up and inspect damaged/unrelated files before
   retrying setup; nothing is automatically removed. Wire format/KDF parameters
   and mixed-version peers remain unchanged.
3. **HTTP deadlines:** a monotonic deadline covers headers and the streamed body
   (45 seconds per metadata request, 15 minutes per installer transfer), in addition
   to existing inactivity/size limits. A two-chunk queue and four-worker cap bound
   background work. Status/size/redirect checks precede body reads. Timed-out
   workers cannot write caches/installers. Socket shutdown wakes body reads;
   third-party DNS/header calls can outlive cancellation and occupy a slot until
   they return. Exhausted slots fail closed. This is not a promise to forcibly
   terminate OS DNS calls or a deadline for an entire multi-request refresh.
4. **Native regressions:** source probes cover all supported renderers; Windows
   and Qt tests exercise Enter, Escape and close on owned synthetic dialogs.
   macOS verifies the native Cancel default. Startup has a separate 60-second
   deadline and diagnostics, followed by a 30-second functional watchdog. No
   automatic retries hide failures; the earlier intermittent Windows startup
   failure has not been proven to have one specific cause.
5. **Clipboard:** OATH codes/OTP secrets expire after 30 seconds while the app runs.
   Native ownership generation plus a random marker prevent stale timers from
   clearing later copies, including identical text copied again. Windows checks
   and clears under the clipboard lock; macOS/Qt offer no atomic compare-and-clear,
   so an external replacement can race the final native check. Concealed/transient
   or history/cloud-suppression markers are hints, not a guarantee that clipboard
   managers comply. Already-read copies cannot be recalled. Exit, suspension or
   a busy clipboard can prevent best-effort expiry. Timers retain ownership tokens,
   not the secret text. Normal text/public-key/certificate copies do not expire.

Local validation: **511 Python tests passed (two platform skips), 44 browser UI
tests, 20 stress tests and 62 production-DOM checks passed**. Native macOS
navigation/default-cancel/private-clipboard probes and the static checks passed.
Windows/Linux execution and signed RC2 packages still require CI evidence; real hardware is still tracked
separately in [HARDWARE_TESTS.md](HARDWARE_TESTS.md). Windows UI/helper separation
is deferred to **1.9+**, including authenticated IPC and installer/update testing.
No broader renderer-isolation or secret-zeroization claim is made.

# Selected security changes — 2026-10-29

The maintainer selected five work areas from the triage below. They were implemented
for 1.8.8 RC1; publication evidence is recorded above:

1. **Native consent:** sensitive device writes, resets, deletions and sync-file
   removal require a native default-cancel dialog. Backend-owned labels and device
   identity describe a copied request; concurrent requests are rejected, each call
   needs its own decision, and disconnect/reconnect invalidates that decision.
   Existing device locks, PIN/touch, overwrite and reset guards remain in place.
2. **Renderer boundary:** native WKWebView, WebView2 and Qt callbacks reject foreign
   navigation before loading and prevent new WebView windows. Sidebar, passkey and
   OATH account values use DOM text/attributes. Existing HTML sites remain reviewed
   debt: the sink baseline detects new/changed sink lines, not arbitrary unsafe
   data flow. A separate test uses the production CSP; `unsafe-eval` remains for
   the pinned bridge and is not described as permitting inline event handlers.
3. **GnuPG/import:** known absolute executable locations precede absolute PATH
   entries; current/relative directories are excluded. Imports are bounded regular
   UTF-8 files (BOM accepted); errors return an explicit result before merging.
4. **Errors:** optional OpenPGP reads suppress only known unsupported/absent results;
   authentication/transport errors propagate. PIV certificate-deletion failure
   stops private-key deletion. Unexpected mapped errors record exception type and
   source-frame locations, never exception messages, source lines or arguments.
5. **History:** saved history is encrypted by default using the native credential
   store. The small migration verifies an encrypted copy and preserves the plaintext
   source unchanged. An existing encrypted file is authoritative; unavailable/wrong
   keys block persistence and sync. Explicit legacy opt-out, stateless behavior,
   export and sync formats remain available. Retained backups stay plaintext and
   can be stale; downgrade and recovery steps are documented in the README.

RC1 local validation at the time: the full Python suite passed (**497 tests, 2 platform skips**),
including real macOS navigation/default-cancel behavior. The final shared packaged
navigation probe and GnuPG path checks also passed targeted reruns. **44 browser UI
tests and 20 stress tests passed**, as did the production-CSP test, UI security and
account-model checks, Ruff, script syntax, native translation consistency, the HTML
sink baseline and `git diff --check`. Device operations and credential stores used
synthetic fixtures; no real key was changed. Actual Windows/Linux native execution,
physical keys and a signed release build remain release checks. No claim of a full
independent audit or complete renderer isolation is made.

# External 1.8.7 feedback triage

Reviewed on 2026-10-29 against `2237689` (1.8.7), the exact commit named in the
supplied feedback. This historical baseline records all thirteen criticism points
and the initial proposed follow-ups. The selected implementation is described above;
the observations in the following tables describe the original `2237689` code.
The numerical scores and comparison with other projects are subjective and are
not adopted as security evidence. No end-to-end exploit was demonstrated by the
feedback or this scoped review; that does not establish absence of vulnerabilities.

## Security findings

| ID / feedback | Verified behavior and assessment | Proposed disposition |
|---|---|---|
| S1 — CSP and 86 `innerHTML` assignments | Confirmed: [page.py](keymelier_core/page.py) includes `unsafe-eval`; there are 86 direct `.innerHTML =` assignments in `static/*.js`, including static icons and emptying containers. Installed, pinned pywebview 6.2.1 uses `new Function` in `webview/js/api.js`. This weakens protection against string evaluation, but does **not** itself authorize arbitrary inline scripts or event handlers. Escaping tests cover selected inputs, not every sink. | High priority: migrate renderers handling device/imported strings to DOM properties/`textContent` in small steps. Add a reviewed baseline/rule against new unsafe HTML sinks, covering alternatives such as `outerHTML` and `insertAdjacentHTML` too. Do not simply remove `unsafe-eval` until the real bridge works without it on every supported backend. |
| S2 — plaintext history by default | Confirmed in the actual application: [KeyService.__init__](keymelier_core/service.py) enables history unless settings explicitly disable it, although `History` alone defaults to disabled. [History.__init__](keymelier_core/history.py) selects encryption only with `KEYMELIER_ENCRYPT_HISTORY=1`. Account/site recording is also on by default. Native-keyring-only encryption and refusal to overwrite locked encrypted history already exist. | High priority design: encrypted history as the normal path, with an explicit migration and recovery policy. Flipping the environment-variable default alone selects a different filename and would make old entries appear missing. Preserve existing data, settings and stateless behavior. Protection is at rest; it does not isolate data from a compromised running user session. |
| S3 — flat bridge allowlist / destructive consent | The [allowlist](keymelier_core/bridge.py) is an exposure boundary, not a consent boundary. The feedback understates existing controls: OATH/OpenPGP/PIV resets and PIV deletion require literal `confirm=True`; PIV/OpenPGP generation and OTP writes have occupancy/replace guards, and FIDO reset requires arming/replug/touch. These JS-supplied flags still do not independently establish human consent. PIV import authenticates but can replace an existing certificate; it does not import a private key. | High priority: native confirmation for an inventoried set of destructive/security-changing operations, enforced before side effects. Show the backend-resolved operation, key and slot. Cover resets, deletion, replacement/import and changes to PIN/protection/interfaces as appropriate. Splitting `ALLOWED` into several lists alone would not close this gap. |
| S4 — sync passphrase retained in memory | Confirmed for an active session in [sync._SessionKeys](keymelier_core/sync.py). The cache already holds at most 32 derived keys and clears its references on close/reconfiguration. Each new session/file salt can require a fresh derivation, including after peer restart or cache eviction. Keeping only the keys known at setup would break existing v1 sync. | Design separately: fetch the passphrase from the native credential store only on a cache miss, or require explicit unlock, with short-lived references and a lock/expiry policy. Preserve the v1 KDF/header and mixed-version peers. Combine with the already-open KDF work budget; repeated unknown salts must not cause unbounded derivation/keyring prompts. No Python/JS zeroization guarantee. |
| S5 — GnuPG PATH precedence | Confirmed: [app._gpg](app.py) tries `shutil.which` before known installation paths. This is a local executable-selection risk requiring influence over PATH or a selected binary, not evidence of a remote exploit. The subprocess uses an argument array, without a shell. | Candidate for a small fix: prefer suitable known installations, validate the selected executable and define a safe fallback for custom installs. Preserve Homebrew, Gpg4win, Linux and Finder startup. Absolute paths alone do not make user-writable installations trustworthy. |
| S6 — lossy import decoding | Confirmed: [Api.open_text](app.py) uses UTF-8 with `errors="replace"`; invalid bytes inside a JSON string can silently change an account/label while leaving valid JSON. The file comes from a native picker, not an arbitrary JS path, and has a pre-read size check. | Candidate for a small fix: reject invalid encoding with a useful, redacted error before history merge; preserve valid UTF-8 exports and cancellation behavior. Bound the actual read as well as checking file size. Decide BOM/legacy-encoding behavior explicitly rather than guessing. |

The distinction between string evaluation and inline script permission follows
the [W3C CSP3 script-src definition](https://www.w3.org/TR/2026/WD-CSP3-20261027/#script-src).
The broad comment in `page.py` that injected markup cannot execute is not a proof
that every DOM data flow is safe. Native navigation remains a separate open
boundary: `app._lock_navigation` acts after loading and accepts data URLs on the
inline-page path, as already recorded under RC7 L6. Include that existing item
when selecting renderer/bridge work; do not count it as solved by CSP.

## Maintainability findings

| ID / feedback | Verified behavior and assessment | Proposed disposition |
|---|---|---|
| Q1 — oversized service and frontend | The line counts match: `service.py` 1,270; `app.js` 1,815. `KeyService` has 113 direct methods (124 function definitions in the whole file, including nested functions). Applet backend modules and `view-oath.js`, `view-piv.js`, `view-openpgp.js`, etc. already exist. Coordination/shared state remains concentrated. | Incremental extraction when touching a behavior, preserving public bridge names/envelopes, locks and device identity checks. A broad rewrite is not a prerequisite for the next security release. |
| Q2 — translations stored as JavaScript | `i18n.js` is 5,264 lines, about 958 KB, and contains dictionaries, helpers and later additions/overrides. JSON per language can improve editing but is not inherently a security fix. | Optional maintenance work: separate source data and generate the same offline, hashed bundle. Preserve final translation values, fallback/interpolation, all eleven languages and package inputs. Runtime fetching would conflict with the current `connect-src 'none'` design. |
| Q3 — broad exceptions hide bugs | Confirmed: 20 `except Exception` handlers in `piv_app.py`, 21 in `openpgp_app.py`. Some deliberately accommodate optional device capabilities; others map unexpected failures to a domain error or silently omit fields. The bridge already logs sanitized traceback locations for unexpected exceptions that reach it, but mapped errors can lose that context. | Narrow expected exceptions first around authentication, writes and occupancy detection. Keep redacted boundary envelopes; log unexpected failures with safe frame metadata. Do not add raw `logger.exception` everywhere: exception messages, source lines or locals may contain secrets/private paths. Unsupported capability and failed access must remain distinguishable. |
| Q4 — nested/repeated templates | Confirmed in `app.js:renderSidebar`, including duplicated subtitle expressions and nested conditionals. This makes escaping and event behavior harder to review; it is not itself an established exploit. | Address together with S1: compute plain values once and construct text/attributes through DOM APIs. Preserve selection, focus, keyboard behavior, scrolling and long translated labels. |
| Q5 — lazy imports and runtime import-path changes | Present, but not all equivalent. Optional smart-card/platform imports also support startup and GUI-free tests. `app.open_licenses` mutates `sys.path` in its source-run fallback; the newer [licenses._documents](keymelier_core/licenses.py) already uses `from tools import third_party_licenses` without that mutation. | Target the remaining source fallback when touched. Preserve the exposed callback, stateless behavior and frozen/source startup. Do not indiscriminately move platform/optional imports to module scope. No dependency upgrade is needed for this cleanup. |
| Q6 — large documentation and review-named tests | Sizes match approximately: changelog 41.7 KB, security review 42.9 KB before this entry, releasing guide 25.7 KB. Review-named test files exist, but their test methods mostly name concrete behavior. File length does not establish AI authorship or a vulnerability. | Keep one disposition record here and a roadmap link. Consolidate duplicates or split historical sections only with links and release evidence preserved. New tests should use behavior names; renaming working regressions is low priority. |
| Q7 — no typing/type-checker | Partly incorrect: 98 of the 113 direct `KeyService` methods have return annotations, with many annotated arguments and core dataclasses as well. Correct: [pyproject.toml](pyproject.toml) and the [build workflow](.github/workflows/build.yml) configure Ruff/tests, not mypy/pyright. Generic `dict` annotations do not express bridge payload contracts. | Extend the existing roadmap item: pinned type checking for a bounded module set and explicit request/response types, then expand. Do not manufacture a green result through blanket `Any` or ignore rules. |

## Proposed selection and acceptance gates

These were the initial recommendations. The five selected work areas and remaining
limits are recorded above; the remaining proposals are not release promises.

1. **Renderer and destructive operations (S1/S3, existing native-navigation item):**
   highest priority because a compromised renderer can invoke powerful methods.
   Native consent must be bound to the operation/target, default to cancel, be
   single-use and resist concurrent calls, replay and disconnect/reconnect races.
   Dialog failure must leave the device unchanged. Test real WKWebView, WebView2
   and Qt behavior; retain PIN, touch, overwrite and identity checks. DOM work
   needs malicious device/account/certificate strings in text and attributes,
   plus a CSP-enabled harness; the existing demo deliberately removes CSP.
2. **History encryption (S2):** decide new-install and upgrade behavior separately.
   Require a verified encrypted write/readback before switching storage; handle
   both filenames already present, keyring denial/unavailability, interrupted
   migration and restart. Document recovery and downgrade/export behavior;
   never silently delete plaintext originals or imply that retained copies and
   JSON/CSV exports became encrypted. Test old histories, lost/replacement state,
   account opt-outs and sync. A missing key must never trigger plaintext fallback.
3. **Small, bounded fixes (S5/S6/Q3):** candidates for an early patch once selected.
   Test executable precedence and custom installs without launching a fake binary;
   invalid UTF-8/cancel/oversized input without partial import; expected device
   failures versus injected programming errors without secrets in logs or UI.
4. **Sync lifetime (S4):** keep legacy v1 fixtures; test new peer/session salts,
   eviction, concurrent reads, wrong passphrases, unavailable keyring and disable
   during derivation. Evaluate memory exposure and denial-of-service together.
5. **Structural maintenance (Q1/Q2/Q4/Q5/Q6/Q7):** scope separately or accompany
   small changes where it lowers review complexity. Do not combine wholesale
   module, translation, packaging and type-system migrations into a security patch.

## Validation and limits

Local macOS validation for this review: **107 backend tests passed** across
`test_security`, `test_audit_regressions`, `test_overwrite_guards`, `test_sync`,
`test_sync_key_lifecycle`, `test_upgrade_compat`, `test_rc4_review` and
`test_diagnostics`; `node tests/ui_security.cjs` passed; **42/42 browser UI tests
passed**. The first sandboxed browser launch failed; the same suite passed with
an isolated headless browser outside the sandbox. Tests used simulated devices
and temporary data. The installed Python runtime dependencies matched the pinned
pywebview, cryptography, fido2 and yubikey-manager versions.

The positive feedback about allowlisting, authenticated sync, private storage
and regression coverage is supported by the inspected code and these checks.
The navigation guard needs the qualification above. Release signing, SBOM and
CI assertions remain the prior release evidence below; this review did not rerun
publication/signing, all platform builds, hardware resets or a full security audit.
The browser suite uses a demo bridge with CSP removed, so its successful escaping
checks do not certify native bridge isolation or production CSP enforcement.

# Stable 1.8.7 release preparation — 2026-10-29

The stable preparation changes only release documentation. Application code,
dependencies and release workflows match `v1.8.7-rc.9` (`39cb474`), merged into
protected main through PR #30. The stable tag will run the full signed pipeline
again; the evidence below describes the already published candidate.

RC9 publication run
[40872601879](https://github.com/FiraSenax/KeyMelier/actions/runs/40872601879)
passed the main-source gate, the 467-test Python suite on all three platforms,
42 browser UI tests, 20 stress tests, all platform builds, eleven Linux
compatibility jobs and release validation. Platform-specific skips apply.
Windows app, installer and uninstaller signatures were verified; macOS app and
DMG signing, notarization, stapling and Gatekeeper checks passed. Packaged
application start checks passed.

After publication, the public update signature and exact source commit were
verified independently, all 22 artifact metadata hashes matched the signed
checksums, and the downloaded Windows installer matched its signed hash.
RC8-to-RC9 update discovery passed, while the stable channel remained at 1.8.6.
No open GitHub Code Scanning alerts were returned during stable preparation.

Windows 11 including Bio unlock has been confirmed by the maintainer. Manual
Linux hardware testing remains open; automated container startup checks do not
replace it. The accepted shared-account signing limits and deferred hardening
items recorded below remain unchanged.

# RC9 preparation — 2026-10-29

The RC9 candidate includes the post-RC8 UI guidance and the main-ancestry gate
below. Publish it only after this branch has passed the protected PR path into
`main`; the tag's own workflow must then pass the source gate and the complete
signed release pipeline. The stable release remains separate.

Development run [40870687807](https://github.com/FiraSenax/KeyMelier/actions/runs/40870687807)
has passed the 467-test Python suite on Windows, macOS and Linux, all 42 browser
tests and 20 UI stress tests. These are checks of the unsigned development path,
not evidence of production signing or a manual Linux hardware test. The public
RC9 publication run supplies the separate signing and package evidence.
No open GitHub Code Scanning alerts were returned during RC9 preparation.

# After RC8: automatic RC publication follow-up — 2026-10-29

Review of `fd82d9a` and `6fa3f23` confirmed that automatic publication had no
main-ancestry gate. Builds still ran their tests, but a new tag on a development
branch could reach signing and the public RC channel without the main PR path.

A new `release-source` job has only read access and no production environment
or secrets. It fetches main, checks the exact tag/checkout/workflow commit match,
and requires that commit to be an ancestor of main. All builds and production
signing/publication jobs depend on it. Version tags and manually dispatched
signed builds require the gate; unsigned development builds remain available.
Missing refs/history, mismatched commits and off-main candidates fail closed.
Automatic public RCs remain enabled after this gate and the existing checks.

Local validation: 46 release/source/signing/artifact tests passed, including real
Git histories with annotated and lightweight tags, stale/mismatched refs and a
branch commit rejected before merge and accepted after merge. Ruff and workflow
YAML checks passed. No new tag or release was created for this follow-up.

**Authority remains a separate open issue.** The live tag ruleset was read via
GitHub API: `v*` tags cannot be updated or deleted, but new tag creation is not
restricted. The local CLI is authenticated as repository owner `FiraSenax` with
administration rights, so the agent technically can create tags using the same
identity as the maintainer. An owner-only exception cannot distinguish them.
The source gate is an accident guard, not a hard boundary against tagging an
older workflow without the gate or changing the workflow/rules. An enforceable
human/agent separation needs distinct credentials and restricted tag creation;
the existing automatic-signing setup was not represented as providing that.
See [tag authority](RELEASING.md#tag-authority-and-the-limit-of-the-source-check).

# After RC8: stable-candidate follow-up — 2026-10-29

The published `v1.8.7-rc.8` remains commit `3ec722f`. The following UI change
is on the development branch and requires a new build before distribution.

- The live GitHub `Protect main` ruleset initially blocked only deletion and
  force-push. It now also requires a pull request and the current
  `test (ubuntu-24.04)` check from GitHub Actions (integration 15368), with the
  branch up to date and no bypass actors. No second-person approval is required.
  The effective rules for `main` were read back through the GitHub API.
- The RC branch still needs to be merged into `main` before stable: the existing
  `main` workflow does not yet contain the emergency-stop check. Once merged,
  the required Linux job runs it before subsequent changes can reach `main`.
  These rules guard against accidents; a repository administrator can still
  alter the workflow or rules and they do not establish independent signing.
- Unreachable company sources are explained in the key overview and security
  details in all eleven languages, including VPN/update-check guidance. The
  hint updates when source results arrive or recover, escapes source names,
  and preserves known critical findings. VPN loss itself is not detected.
- This UI follow-up passed all 42 browser tests, the targeted UI security
  checks, JavaScript syntax checks and `git diff --check`. Backend policy and
  assessment rules are unchanged.

RC8's exact commit was built and tested in publication run
[40857341399](https://github.com/FiraSenax/KeyMelier/actions/runs/40857341399):
the 457-test Python suite, 41 UI tests, 20 stress tests, all platform builds,
signing/notarization, packaged start checks, eleven Linux compatibility jobs
and release validation passed. Public update signatures, all 22 artifact
metadata checksums, the downloaded Windows installer's hash and RC7-to-RC8
update detection were verified separately. Platform-specific skips apply;
these checks do not substitute for a manual Linux hardware test, which remains
open. Windows 11 including Bio unlock has been confirmed by the maintainer.
The previously accepted signing limits and deferred minor-release hardening
items below remain unchanged.

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
