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
| Sync compatibility | Old/new app versions exchange v1 files; damaged peers do not block later healthy peers across rounds. Manual sync retries; repaired files merge. No file is deleted or acknowledged after a failed merge. | Not tested | Not tested | Not tested |

**Stable gate:** all automated checks and signing checks pass for the exact
candidate; supported real-key workflows above have no critical regressions, and
remaining unsupported/untested combinations are explicitly recorded. Verify
macOS notarization and Windows app/installer/uninstaller signing for the actual
RC assets. These checks alone do not turn untested hardware rows into Passed.

## Matrix

| Operating system + version | KeyMelier (version/commit) | Key model | Firmware | Detection | Read functions | Cancel + reconnect | Result | Date, notes |
|---|---|---|---|---|---|---|---|---|
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
