# Hardware test matrix

Manual tests with real security keys. Automated checks are described in
[TESTING.md](TESTING.md); what they cannot do (real keys, unplugging, PIN
entry) is recorded here. The public page
[firasenax.github.io/KeyMelier/hardware.html](https://firasenax.github.io/KeyMelier/hardware.html)
is generated from this file (`python3 tools/make_hardware_page.py`).

**Rules**

- Every result is one of: **Passed**, **Failed**, **Not supported** (the key
  cannot do it), **Not tested**.
- Only enter results that were actually observed; say where they come from.
- No serial numbers, account names, PINs or other personal data – only
  model, firmware and the observed behaviour.
- Use test or spare keys. Do not reset keys, delete credentials or change a
  PIN for a test unless the test explicitly needs it and the key is a test key.
- Reports from the community arrive through the issue form
  *Tested with a security key* and are copied here.

## Procedure per row

1. **Detection:** plug the key in. Does it appear in the sidebar with model
   and firmware? Authenticity test (touch if asked)?
2. **Read functions:** *Read key* (enter the PIN). Which areas are read –
   passkeys (list, or search on FIDO 2.0 keys), authenticator (OATH),
   OpenPGP, PIV, OTP slots? Applications the key does not have are
   *Not supported* (see *What this key can do* in the overview).
3. **Cancel and reconnect:**
   a) Open the PIN dialog and close it with *Cancel*/Esc – no PIN attempt
      may be used up (check the counter in the PIN tab).
   b) Unplug the key while *Read key* runs – expected: the message that the
      key was removed while reading; known data stays.
   c) Plug it in again and read again – expected: works.
   d) FIDO 2.0 keys: start the passkey search and *Stop* – results found so
      far stay, sites not asked stay unknown.
4. Enter the **result** and anything unusual, with the date.

## 1.8.9 management permission checklist

Status (2026-11-14): **1.8.9 management-scope acceptance is in progress**.
RC2 is published at `c42768c68bc0434ec73a290e2bcda545e3e70605`. The local
checks and OTP recovery below are separate from firmware/management acceptance;
the remaining rows retain their untested status until observed.
Record exact commit/package, OS, model/firmware and date. Use expendable test
credentials and fingerprints; do not reset keys or alter production settings for
these checks. Preserve existing native confirmations and PIN retry limits.

| Check | Required observation | Status |
|---|---|---|
| Modern PIN unlock | Unlock Passkeys, Fingerprints and Key settings separately where supported. Each area works; switching areas requests confirmation again. A refused/failed operation does not consume an additional automatic PIN attempt. | Not tested |
| Built-in fingerprint | On representative fingerprint keys, passkey unlock succeeds; BIO_ENROLL/AUTHENTICATOR_CFG either work after their own verification or offer the existing PIN route. Refusal for one area does not disable a supported other area. | Not tested |
| Read after settings | After unlocking only settings/fingerprints, Read key requests the read unlock and updates supported content. After a passkey unlock, reading needs no new PIN while the token remains valid. | Not tested |
| Legacy firmware | Check credentialMgmtPreview and keys without pinUvAuthToken. PIN-based management still works through the library's legacy command. Device-level permission restriction is unavailable; local area checks still apply. | Passed: macOS 27.2, YubiKey 5 NFC 5.2.7, isolated RC2 source probe with owner-entered PIN; see below for limits. |
| Lifetime and cancellation | After five minutes or device-side expiry, re-unlock explicitly. Cancel a waiting fingerprint request; lock or unplug/reconnect during PIN/UV; no late result restores the unlock or carries over to another key. A fresh deliberate attempt works. | Not tested |
| Compatibility | Existing unscoped callers retain their original contract. History/settings, sync and import/export remain readable by supported old versions. No new persistent auth state is written. | Not tested |

Synthetic checks in `test_auth_scopes.py` cover permission separation, one PIN
attempt, actual python-fido2 modern/legacy command selection, replacement,
permission refusal and late-result invalidation. Browser checks in
`tests/ui/secret_forms.cjs` cover each area's request, duplicate suppression,
cleared PIN fields, read-after-settings and scoped UI cleanup. These do not
establish firmware compatibility or count as manual results above.

Separate OTP observation (2026-11-14): the installed, Developer ID signed and
notarized **v1.8.9-rc.1** (`a19dcba`) on macOS **27.2** showed an OTP permission
error with a **YubiKey 5 NFC, firmware 5.2.7**. Input Monitoring was visibly
enabled for KeyMelier in System Settings; a complete app quit/relaunch did not
restore access. The read-only Carbon API reported Secure Event Input active.
This establishes a failed OTP read in that system state, not a missing grant
or a proven sole cause. RC2 adds specific guidance for observed Secure Input.
RC2 follow-up: with Secure Input no longer active, the TCC log explicitly reported
that the stored Input Monitoring code requirement did not match KeyMelier. The
running process and installed RC2 both had the current signing identity; the
stored permission retained an older code hash. Only KeyMelier's `ListenEvent`
approval was reset. After the owner added the installed app again and restarted
it, the owner confirmed that both OTP slots were displayed and that the button
opened the correct permission pane: **Passed (owner observation)**. This confirms
recovery after re-granting Input Monitoring, not recovery through reboot alone.
No OTP slot was programmed, swapped or deleted. This does not accept the
management-scope checklist above.

### Additional local RC2 checks (2026-11-14)

On macOS 27.2, the installed, signed/notarized RC2 passed all **63 packaged
self-test checks** in a temporary profile with device scanning/network disabled.
A separate native probe at the same source commit passed bridge/script loading,
blocked file/data navigation, Cancel as the native default button (activated
programmatically), and four clipboard checks on a private pasteboard. This is
not a physical Enter-key test or a timed test of the user's clipboard manager.
Neither probe reads the user's history, changes
the real clipboard or supplies physical-device acceptance.

A separate isolated process used the original `v1.8.8` code (`630609d`) to write
encrypted fictional history/settings. RC2 reopened that profile with unchanged
history contents, labels, lost/replacement state and settings, then wrote an
export and v1 sync file. Original 1.8.8 reopened RC2's encrypted history/settings
and imported/merged its export/sync. It then wrote an update that RC2 reopened
and imported/merged successfully. **All four roundtrip stages passed.** Export
generation times differ normally; the original release's own restart behavior
provides the baseline for saved security verdicts. The credential backend was
simulated throughout; no native keychain or real sync folder was modified.
This verifies mixed-version data compatibility, not installer or native
credential-store denial/recovery acceptance.

### Real-device PIN probes (2026-11-14)

The probe uses the RC2 Python application/authentication code at `c42768c` with
real keys. The owner enters each PIN into a local secure text field. The test
adapter accepts only PIN retry/key-agreement/token commands and read-only
credential-management commands; PIN changes and credential deletion/update are
blocked by the adapter. Reports contain capabilities and boolean results, no
PINs, tokens, serial numbers, credential IDs or account names. This is a source
hardware probe, not acceptance of the packaged app's complete UI flow.

**YubiKey 5 NFC, firmware 5.2.7, macOS 27.2: Passed** for all 13 completed checks.
The actual legacy `getPINToken` command was used with credentialMgmtPreview;
passkey listing worked and the other management permissions were absent locally.
The PIN retry counter stayed at 8. A pre-cancelled request and unsupported
fingerprint/settings requests sent no additional PIN command. After the full
300-second local lifetime, the cached unlock expired and a new read was blocked
before any device command or automatic authentication retry. Device-side expiry,
waiting fingerprint cancellation and physical unplug/reconnect remain untested.

Two setup attempts preceded this successful run: a connection failure with the
normal app polling in parallel, and an argument-name error in the probe's
read-only adapter after a successful unlock. The normal app was closed and the
adapter fixed and checked before a fresh, owner-authorized PIN attempt. Neither
setup attempt is recorded as a KeyMelier application regression or a passed case.

## 1.8.8 security release checklist

Record the exact RC/commit, OS, key model/firmware, result and date for each check.
All new manual checks below are **Not tested** until observed. Use a temporary
profile and expendable test keys/accounts; preserve history backups. CI navigation,
dialog and clipboard probes use synthetic data and are not hardware sign-off.

| Check | Acceptance | macOS | Windows | Linux |
|---|---|---|---|---|
| Native consent | Reset, deletion, replacement and sync-file removal show the correct operation/target. Enter defaults to Cancel; Escape/window close cancel where offered. Cancellation changes no key/file. One acceptance authorizes only that request. | Not tested | Not tested | Not tested |
| Disconnect/reconnect | Disconnect while confirmation is open, reconnect the same or another key and accept: the old decision cannot authorize a write. Start a fresh request successfully afterward. | Not tested | Not tested | Not tested |
| Encrypted history upgrade | In a temporary profile with legacy plaintext history, verify equivalent encrypted history and unchanged backup. Restart successfully; with credential store locked/unavailable, block persistence/sync without plaintext fallback or file loss. | Not tested | Not tested | Not tested |
| Rendering/navigation | PIV/OpenPGP/OATH/OTP names and certificate values containing quotes/markup display literally. Forms, selection and focus still work. Foreign file/data/web navigation does not replace the app. | Not tested | Not tested | Not tested |
| GnuPG/import | Known/custom supported GnuPG installations work. A relative/current-directory executable is not chosen. Valid UTF-8/BOM imports work; malformed/oversized files do not partially merge. | Not tested | Not tested | Not tested |
| Clipboard | Copied test OATH code/OTP secret disappears after 30 seconds with app open. Copy different text (and the same text) in another app first: it remains. Certificate/public-key copies remain. Check desktop clipboard-manager behavior separately. | Not tested | Not tested | Not tested |
| Migration privacy | With a disposable old plaintext history, migrate, then disable “Remember websites/accounts”. Both history files lose site/account details, including with history disabled; key labels remain. A locked source produces a warning and can be retried. | Not tested | Passed (RC8, 2026-11-06; isolated synthetic profile, owner UI observations and file verification; WINDOWS_QA_RC8.md) | Not tested |
| Sensitive forms (RC5) | During delayed PIN/password/OATH/OTP requests, submitted secret fields are empty and a second submit starts no additional request. After failure, explicitly re-enter and retry. Cancel/key change clears fields. A late generated OTP secret does not appear on another key. | Not tested | Not tested | Not tested |
| Sync compatibility | Old/new app versions exchange v1 files; damaged peers do not block later healthy peers across rounds. Manual sync retries; repaired files merge. No file is deleted or acknowledged after a failed merge. | Not tested | Not tested | Not tested |

**Stable gate:** all automated checks and signing checks pass for the exact
candidate; supported real-key workflows above have no critical regressions, and
remaining unsupported/untested combinations are explicitly recorded. Verify
macOS notarization and Windows app/installer/uninstaller signing for the actual
RC assets. These checks alone do not turn untested hardware rows into Passed.

For 1.8.8 stable, prioritize native consent (Enter/Escape/close, disconnect and
single-use authorization) and conditional clipboard expiry on real Windows and
Linux desktops. Every new release must pass the signed advisory database's
14-day freshness gate. Review new vendor/MDS evidence before re-signing; do not
only advance the timestamp or relax the gate. Review evidence is recorded in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

### Final 1.8.7 → 1.8.8 desktop upgrade pass

Use a disposable OS user/profile with synthetic history and spare keys. Record
the exact installed candidate and OS for each observation; do not copy private
production history into a test report.

1. Install 1.8.7, create synthetic history, labels and settings, then close it.
2. Install the candidate over it. Verify labels/settings/sync identity, encrypted
   history and the retained plaintext original; close and reopen the app.
3. Lock or deny access to the **native** credential store. History/sync must be
   blocked visibly without overwriting either file or reverting to plaintext.
   Unlock the store and retry/restart; original entries must return.
4. Disable “Websites/accounts merken” with history enabled and disabled. Check
   both files, restart and re-enable history: removed account details stay gone.
5. Make the retained plaintext source non-writable in this test profile. An
   opt-out must show the cleanup warning; restore access and retry successfully.
6. Run native consent and clipboard checks above on Windows/Linux desktops,
   including identical text copied by another app. Use spare keys for destructive
   operations and record unsupported features separately.

The packaged RC5 upgrade probe automates the data transitions with a synthetic
credential store. It does not mark any manual row above as Passed.

## Matrix

| Operating system + version | KeyMelier (version/commit) | Key model | Firmware | Detection | Read functions | Cancel + reconnect | Result | Date, notes |
|---|---|---|---|---|---|---|---|---|
| macOS 27.2 (owner-reported), Apple M1 | 1.8.8-rc.8 / 8544da222f34db55a25e34c0e497d8485bf0e683 | YubiKey (exact variant not reported) | 5.2.7 | Passed (start and detection, owner-reported) | Passed (Read key, owner-reported; individual areas not recorded) | Passed (PIN cancellation preserves retries; native reset cancellation, reconnect invalidates stale consent, fresh Read key, new consent after disarming) | Passed (listed workflows only; partial coverage) | 2026-11-06 – owner also confirmed OATH clipboard expiry after 35 seconds and preservation of different/identical text recopied in TextEdit. Correct reset target/action; offered Enter/Escape/close paths cancel. No actual reset performed. Other clipboard managers and public certificate copies not tested. See WINDOWS_QA_RC8.md. |
| Windows 11 Pro 10.0.26300 (x64) | 1.8.8-rc.7 / e6b4217580f72a29931ba300cce2d8578db33363 | YubiKey 5 Series with NFC | 5.2.7 | Passed (model/firmware observed) | Passed (synthetic OATH account creation and code copy, owner-reported) | Not tested | Passed (OATH rendering, clipboard and test-account deletion; partial coverage) | 2026-11-05 – literal markup/quotes in the test name; code expiry after 35 seconds, different and identical Notepad recopy preserved, subsequent public AAGUID copy preserved. Native deletion identified the test account; only that account was removed. Other PIV/OpenPGP/OTP workflows not tested. |
| Windows 11 Pro 10.0.26300 (x64) | 1.8.8-rc.7 / e6b4217580f72a29931ba300cce2d8578db33363 | TOKEN2 PIN Plus Security Key Series | 0.1.0 (same test key as RC5) | Passed (owner-reported packed attestation, all seven checks; chain valid to token2.com) | Passed (Read key with existing PIN after rejected stale consent) | Passed (reset consent Enter/Escape/close; reconnect invalidates old consent; fresh request requires new confirmation) | Passed (listed workflows only; partial coverage) | 2026-11-05 – owner supplied complete attestation output. Native reset dialog names correct action/target, cancels safely, rejects acceptance after disconnect/reconnect, and requires a new confirmation after disarming. No actual RC7 reset performed. See WINDOWS_QA_RC7.md; other application/upgrade/clipboard checks remain separate. |
| Windows 11 Pro 10.0.26300 (x64) | 1.8.8-rc.5 / 3cd4a48976518ff9c8b92f0f5ed4f3508a3ddebe | Feitian K33 (owner identification); USB BioPassFIDO2 | Not reported (CTAP raw value 0) | Passed (CTAP detection; PIN-assisted attestation Passed) | Passed (Read key with PIN, owner-reported; individual areas not recorded) | Not tested | Passed (PIN-assisted attestation and reading; partial coverage) | 2026-11-05 – native getInfo observed; owner supplied installed app result: all seven attestation checks Passed, packed format, valid chain to Feitian FIDO Root CA and certificate AAGUID matches model. Owner also confirmed Read key with PIN completes without errors. No PIN/account data recorded. Fingerprint route and cancellation/reconnect remain untested. |
| Windows 11 Pro 10.0.26300 (x64) | 1.8.8-rc.5 / 3cd4a48976518ff9c8b92f0f5ed4f3508a3ddebe | TOKEN2 PIN Plus Security Key Series | 0.1.0 | Passed (model/firmware shown); RC5 attestation Unverified | Passed (Read key on empty key, owner-reported; individual areas not recorded) | Passed (reconnect only, owner-reported); cancellation Not tested | Passed (reset, new PIN, reconnect and read only; partial coverage) | 2026-11-05 – observed installed RC5 UI; EXE hash matches published RC5. Owner reports successful reset, new PIN setup, unplug/replug and Read key with new PIN. RC5 attestation reports an unverified chain; the legacy-root false negative is corrected for RC6 and passes an offline evidence recheck. Cancellation and stale-confirmation rejection remain untested. See WINDOWS_QA_RC5.md; no full hardware sign-off. |
| macOS (version not recorded) | 1.8.6 candidate (exact commit not reported) | Two keys, models not recorded | not recorded | Not tested | Not tested | Not tested | Passed (general use reported; individual checks not recorded) | 2026-10-26 – project owner reports running 1.8.6 on the Mac with two connected keys: looks good. No model, firmware or per-function results supplied; not a full hardware sign-off. |
| Windows (version not recorded) | 1.5.0 | not recorded | not recorded | Passed | Not tested | Not tested | Passed (installation and start only) | 2026-09-27 – reported by the project owner: Windows build installed with the installer and working. No details about key or functions recorded. |
| macOS + Windows (versions not recorded) | 1.6.0 | – | – | – | – | – | Passed (sync between two computers) | 2026-09-27 – reported by the project owner: sync Mac ↔ Windows set up and working. Not a key test. |
| macOS (version not recorded) | development state 1.3.1 | YubiKey with FIDO 2.0 (shown as "YubiKey OTP+FIDO+CCID") | not recorded | Passed | Passkey search: Passed (70 sites asked, 4 with passkeys) | Not tested | Passed (search) | 2026-09 – diagnostic run during development (local log). App version not exactly known; a hint only. |
| macOS 14/15 | 1.7.0 or newer | YubiKey 5 (FW 5.7) | | Not tested | Not tested | Not tested | Not tested | |
| macOS 14/15 | 1.7.0 or newer | YubiKey 5 (FW 5.1/5.2, FIDO 2.0) | | Not tested | Not tested | Not tested | Not tested | Passkeys by search only |
| macOS 14/15 | 1.7.0 or newer | YubiKey Bio | | Not tested | Not tested | Not tested | Not tested | Check fingerprint instead of PIN |
| macOS 14/15 | 1.7.0 or newer | Token2 (PIN+ / FIDO2.1) | | Not tested | Not tested | Not tested | Not tested | |
| macOS 14/15 | 1.7.0 or newer | Feitian (ePass/BioPass) | | Not tested | Not tested | Not tested | Not tested | |
| Windows 11 | 1.7.0 or newer | YubiKey 5 (FW 5.7) | | Not tested | Not tested | Not tested | Not tested | App starts with administrator rights |
| Windows 11 | 1.7.0 or newer | YubiKey 5 (FW 5.1/5.2, FIDO 2.0) | | Not tested | Not tested | Not tested | Not tested | |
| Windows 11 | 1.7.0 or newer | Token2 (PIN+ / FIDO2.1) | | Not tested | Not tested | Not tested | Not tested | |
| Windows 10 | 1.7.0 or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | |
| Containers: Ubuntu 24.04/26.04, Debian 13, Fedora 43, openSUSE Leap 16.0 (x86_64 + aarch64), Arch Linux (x86_64); Xvfb, no USB | 1.8.0 candidate | – | – | – | – | – | Passed (AppImage starts, self-test 46 checks, 11 of 11 combinations) | 2026-09-27 – automated start test on native CI runners (Build run 36342999686, CI job linux-compat), without a key, USB, Wayland or a real desktop. Not a hardware result. |
| Ubuntu 24.04 (GNOME, Wayland) | 1.8.0 or newer | YubiKey 5 (FW 5.7) | | Not tested | Not tested | Not tested | Not tested | AppImage; check access without the udev rules (systemd) |
| Ubuntu 24.04 (GNOME, Wayland) | 1.8.0 or newer | Token2 (PIN+ / FIDO2.1) | | Not tested | Not tested | Not tested | Not tested | Authenticator/OpenPGP/PIV need pcscd |
| Fedora (KDE Plasma) | 1.8.0 or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | Sync with KWallet (Secret Service) |
| Debian 12 / older distribution | 1.8.0 or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | Does the AppImage start at all (built on Ubuntu 24.04)? Udev rules from the AppImage |
| Raspberry Pi OS 64-bit (aarch64) | 1.8.0 or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | ARM64 AppImage |

Open combinations are all rows marked **Not tested**. Add rows for further
models; for an update test write "update from x.y" in the notes (procedure
in TESTING.md).
