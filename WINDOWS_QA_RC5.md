# Windows QA: 1.8.8 RC5

Date: 2026-11-05. Status: **IN PROGRESS — no stable release approval**.

Candidate: `v1.8.8-rc.5`, commit `3cd4a48976518ff9c8b92f0f5ed4f3508a3ddebe`.
Host: Windows 11 Pro, version 10.0.26300, x64. Source tests use Python 3.12;
the published package contains the release runtime. Evidence is local in
`build/qa-rc5/` (ignored by Git). No production history is included in this report.

## Observed results

| Check | Result | Evidence / scope |
|---|---|---|
| Exact candidate CI | Passed | Build run 41813218960: Windows/macOS/Linux tests, UI, builds, Linux compatibility and RC publication succeeded. Release job skipped as expected for RC. |
| ZIP and installer integrity | Passed | Download hashes match GitHub release digests and published checksums; SOURCE_COMMIT matches the candidate. |
| App and installer signing | Passed | Native Authenticode status Valid, same signer, Certum timestamp; file version 1.8.8. `signatures.json`. |
| Installed app identification | Passed | Installed EXE SHA-256 equals downloaded RC5 EXE; installed build metadata identifies the exact RC5 commit. |
| Installed uninstaller signing | Passed | `C:\Program Files\KeyMelier\unins000.exe`: native Authenticode status Valid. Uninstall not executed. |
| Published package startup | Passed | 63/63 checks, including WebView bridge, resources, QR decoder, blocked file/data navigation and synthetic 1.8.7 upgrade probe. `smoke-elevated/`, `smoke-elevated.log`. |
| UI interactions | Passed | 44/44 checks in Edge on Windows, demo backend. `ui_test.log`. |
| UI stress | Passed | 20/20 checks. `ui_stress.log`. |
| CSP / hostile values | Passed | Production CSP checks and 62 DOM checks. `csp_test.log`. |
| Sensitive forms | Passed | 41 production DOM checks, synthetic responses. `secret_forms.log`. |
| JS model/security/website tests | Passed | `accounts_model.log`, `ui_security.log`, `website_release.log`. |
| Runtime prerequisite safety | Passed | Signature/publisher/architecture/version/installer-result tests; mocked installer, no system runtime changes. `windows-runtime.log`. |
| Static checks | Passed | Ruff correctness, JS parsing, HTML sinks, native translations, locked exports and license inputs. |
| Advisory signature/freshness | Passed | Signature verified with 14-day maximum age. Review gate expires 2026-11-12 06:50:57 UTC. |
| Backend suite | Passed | Corrected elevated run: 524 tests, 511 passed, 13 skipped, no failures/errors (83.248 s). The Node-dependent upgrade account-model test skipped in the elevated environment passed separately (`upgrade-account-model.log`); the other 12 skips are platform-specific. Includes real native WebView navigation and synthetic Enter/Escape/close dialog probes. `unittest-elevated.log`, exit 0. |
| Real-key detection | Passed (partial) | Installed RC5 shows TOKEN2 PIN Plus Security Key Series, firmware 0.1.0. RC5 attestation reports an unverified chain; see the confirmed legacy-root finding and local correction below. |
| TOKEN2 reset and recovery | Passed (user-reported) | 2026-11-05: owner reports successful reset of the empty test key, then successful new PIN setup, unplug/replug and Read key with the new PIN. Per-application read results, cancellation and stale-confirmation rejection were not separately observed. |

## Windows acceptance still open

Additional key, 2026-11-05: owner identifies an older Feitian K33; native CTAP
getInfo identifies BioPassFIDO2 (AAGUID 12ded745-4bed-47d4-abaa-e713f51d6393),
FIDO_2_0/FIDO_2_1_PRE, resident keys, configured PIN and UV, credential-management
and biometric-management preview support. Firmware raw value is 0, so an actual
firmware version is not established. A non-PIN attestation probe returns
PUAT_REQUIRED, classified as inconclusive/needs_uv, not failed authenticity.
No credentials were read/deleted and no PIN/reset operation was performed by
the probe. This probe uses the local RC6 preparation source; it is not a
packaged RC5 UI pass.

Subsequent owner-reported installed RC5 result: PIN-assisted attestation Passed
(packed), with all seven displayed checks passing: makeCredential, format,
request binding/user presence, AAGUID consistency, signature, certificate chain
and certificate-to-model binding. The displayed chain contains two certificates,
leaf `FT BioPass FIDO2 0470` to `Feitian FIDO Root CA`. No certificate-chain fix
is indicated for this Feitian. The owner subsequently confirmed that Read key
with PIN reads the supported areas without errors; individual areas and account
contents were not recorded. Cancellation/reconnect and the fingerprint route
remain untested.

Code-level finding for the reported Feitian capabilities: the attestation UI
offers the fingerprint button based only on `options.uv`, whereas the backend
calls `ClientPin.get_uv_token`, which requires `pinUvAuthToken == true`. The
Feitian does not advertise that option. Unlike management unlock (which checks
both capabilities), this attestation button can therefore offer an unsupported
route. Confirm the visible behavior separately; do not classify this as a bad
certificate or broken sensor. No fingerprint verification attempt has been made
by this diagnostic probe.

All nine manual checklist rows in HARDWARE_TESTS.md require observations beyond
the automated checks above. Do not mark a complete manual row Passed based on a
synthetic probe.

- Native consent for actual operations and correct target; one-use authorization.
- Disconnect/reconnect while a confirmation is open; fresh request after rejection.
- Installed 1.8.7 → RC5 upgrade with native credential-store denial/recovery.
- Native rendering, selection/focus and navigation on real device values.
- Known/custom GnuPG and actual import dialogs, malformed/oversized imports.
- Actual 30-second clipboard expiry, another app copying different/identical text,
  public copies and clipboard-manager behavior. Local native CI clipboard probe is
  deliberately skipped outside disposable CI.
- Migration privacy with native persistence, unwritable legacy source and recovery.
- Sensitive forms with delayed real-device responses and device changes.
- Old/new app sync compatibility in a real desktop setup.

Also open: full installer upgrade, uninstall behavior, additional Windows versions
and key models. This Windows session cannot approve macOS/Linux hardware coverage.

## Environment findings

- Published EXE requires elevation: direct smoke launch returned Windows error
  740; the elevated isolated smoke test passed.
- `csp_test.cjs` and `secret_forms.cjs` need `PYTHON` pointing at the venv and
  `PYTHONUTF8=1` on this Windows/Python 3.12 host. Without these, Python alias and
  cp1252 encoding errors prevent test startup. Corrected runs passed.
- Activate the venv or add its Scripts directory to PATH so subprocess tests find uv.
- The symlink test needs elevated privileges on this host.
- Computer Use can observe the elevated installed app, but its lower-integrity
  helper cannot reliably click it. Hardware steps require user interaction.

## Confirmed RC5 finding: TOKEN2 legacy attestation trust anchor

On 2026-11-05, a dedicated live probe of the owner's test key reproduced the
reported UNVERIFIED chain result. Two initial touch requests timed out; a later
request succeeded. No PIN was supplied and no reset was performed by the probe.
The probe uses the application's non-resident synthetic attestation request.

Observed evidence:

- Current, signature-verified FIDO metadata lists a TOKEN2 X.509v1 trust anchor
  with no extensions, valid 2019-05-14 through 2072-05-20.
- The device supplies a distinct X.509v3 leaf, valid 2023-10-12 through 2043-10-07.
- Request binding, user presence, packed signature and AAGUID consistency pass.
- The leaf's AAGUID extension also matches the device model.
- KeyMelier rejects the root before OpenSSL validation with `ExtensionNotFound`
  for `BasicConstraints`. OpenSSL's full chain validation succeeds on the same
  two certificates. Thus this is a false-negative compatibility finding in
  KeyMelier, not an expired certificate or an observed bad device signature.

Local RC6 correction: for non-strict attestation validation only, accept missing
root BasicConstraints exclusively on an extension-free X.509v1 trust anchor with
a verified self-signature. The root still comes from the verified, current MDS
entry; the device cannot nominate its own trust anchor. Date, leaf, key-usage,
OpenSSL path and model-binding checks remain. Explicit CA=false is still rejected.
The strict MDS JWT validation path continues to reject this legacy case.

Validation: 52 targeted tests passed, including legacy-root acceptance and
rejection of expired root/leaf, invalid self-signature, wrong leaf signer,
missing v3 constraints, CA leaf and non-CA intermediate. Ruff passed. Re-evaluating
the captured evidence with corrected chain/model validation changes UNVERIFIED
to VERIFIED. This is an offline recheck of the successful live probe, not a new
packaged RC6 hardware test. Local evidence: `token2-diagnosis.json`,
`token2-offline-recheck.json`, `rc6-certificate-tests.log` in `build/qa-rc5/`.
No RC6 package has been built or published; the installed RC5 remains unchanged.

RC6 publication preparation, 2026-11-05: full Windows source suite after the
certificate changes passed (533 tests, 521 passed and 12 platform-specific
skips; 86.194 seconds). Both Ruff correctness checks, RC tag/version validation
and signed-advisory freshness check passed. Evidence: `build/qa-rc6/`.

Standards references:

- https://docs.openssl.org/3.6/man1/openssl-verification-options/#basic-constraints
- https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
- https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential

## Sources

- https://github.com/FiraSenax/KeyMelier/releases/tag/v1.8.8-rc.5
- https://github.com/FiraSenax/KeyMelier/actions/runs/41813218960
- TESTING.md and HARDWARE_TESTS.md at the candidate commit.
