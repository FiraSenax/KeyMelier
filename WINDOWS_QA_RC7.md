# Windows QA: 1.8.8 RC7 and managed-policy correction

Date: 2026-11-05. Host: Windows 11 Pro 10.0.26300 x64.
Status: **Stable acceptance remains open (#39).**

## Published RC7

Candidate: `v1.8.8-rc.7`, commit `e6b4217580f72a29931ba300cce2d8578db33363`.
Release: https://github.com/FiraSenax/KeyMelier/releases/tag/v1.8.8-rc.7
CI: https://github.com/FiraSenax/KeyMelier/actions/runs/42105490704

- Full release pipeline passed: three OS test jobs, browser UI, four package
  builds, eleven Linux compatibility jobs, rehearsal and prerelease publication.
- Published Windows ZIP, setup and SOURCE_COMMIT hashes match SHA256SUMS and
  GitHub digests. The source commit matches the tag.
- Native Authenticode validation: published app and setup both Valid with Certum
  timestamp. Installed app hash equals published RC7; installed metadata names
  the RC7 commit/tag. Installed uninstaller signature Valid.
- Local elevated packaged start test: **63/63 passed**, exit 0, isolated profile.
  Evidence: `build/qa-rc7/smoke/`, `smoke.stdout.log`, `signatures.json`.
- TOKEN2 PIN Plus attestation: **Passed (owner-reported actual RC7 UI result)**.
  All seven checks passed, packed format; AAGUID
  `eabb46cc-e241-80bf-ae9e-96fa6d2975cf` matches in getInfo and authData;
  signature/profile, request binding, presence and certificate model binding
  passed. Chain valid to `token2.com`. A preliminary failure report had no
  captured details; the requested repeat produced this complete passing result.
- TOKEN2 native reset consent: **Passed (owner-reported RC7)**. Correct action
  and target; Enter with default selection, Escape and window close each cancel
  without arming reset. Disconnect/reconnect while the dialog is open invalidates
  the old acceptance; fresh Read key succeeds with the unchanged PIN. A fresh
  accepted reset request was disarmed before unplugging; another request showed
  a new native confirmation. No actual reset was performed in these RC7 tests.

Earlier owner-reported TOKEN2 reset/PIN/read and Feitian K33 PIN-assisted
attestation/read results retain their RC5 scope; see WINDOWS_QA_RC5.md.

## Issue #38 correction

PR: https://github.com/FiraSenax/KeyMelier/pull/58

- Rejecting or failing to read managed policy now blocks OK independently of the
  accepted source list. Known warnings and critical findings remain available.
- Missing and explicitly empty policy remain valid. The source-list API and
  stored formats stay compatible. Configuration recovery requires IT correction
  and an application restart, explained in all eleven translations.
- Local focused policy/trust suite: 53 tests, 52 passed and one POSIX-only skip.
- Full Windows suite: 540 tests, 528 passed and 12 platform skips, exit 0.
- Browser UI: 45/45; production CSP and 62 DOM checks passed.
- Ruff correctness, HTML sink guard, signed-advisory 14-day gate passed.
- Subsequent compatibility adjustment retains previously supported HTTPS
  user-info URLs; 33 policy/configuration tests passed with one POSIX-only skip.
- Local evidence: `build/qa-188/`. Exact PR/candidate CI remains separate.

## Remaining stable acceptance

Update 2026-11-06: see [WINDOWS_QA_RC8.md](WINDOWS_QA_RC8.md) for the subsequently
completed installed upgrade/privacy tests, native Windows credential-denial
integration test and macOS observations. The environment limitations below
describe the earlier RC7 assessment; the packaged locked-store UI case remains
untested.

The nine manual rows in HARDWARE_TESTS.md are not automatically satisfied by CI.
Prioritize actual native consent cancellation/single-use/device-switch checks,
clipboard expiry and other-app ownership, and installed 1.8.7 upgrade/restart/
native credential-store denial/recovery/privacy checks. Windows Sandbox is not
installed on this host; the owner confirms no disposable Windows account or VM
is available for native credential-store denial testing. This part is blocked
on a separate test environment. No production credential-store changes
have been made for this test.

Actual GnuPG/import dialogs, real-device rendering and delayed sensitive forms,
mixed-version desktop sync, installer upgrade/uninstall behavior and macOS/Linux
manual coverage still need observations. Unsupported combinations must be
recorded explicitly. The advisory release freshness gate expires on
2026-11-12 06:50:57 UTC unless a genuine review and re-signing occurs first.
