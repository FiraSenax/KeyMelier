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

## Matrix

| Operating system + version | KeyMelier (version/commit) | Key model | Firmware | Detection | Read functions | Cancel + reconnect | Result | Date, notes |
|---|---|---|---|---|---|---|---|---|
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
| Ubuntu 24.04 container (aarch64, Xvfb, no USB) | development state after 1.7.1 | – | – | – | – | – | Passed (AppImage starts, self-test 46 checks) | 2026-09-27 – automated start test in Docker on macOS, not on a Linux desktop and without a key. Not a hardware result. |
| Ubuntu 24.04 (GNOME, Wayland) | first release with Linux or newer | YubiKey 5 (FW 5.7) | | Not tested | Not tested | Not tested | Not tested | AppImage; check access without the udev rules (systemd) |
| Ubuntu 24.04 (GNOME, Wayland) | first release with Linux or newer | Token2 (PIN+ / FIDO2.1) | | Not tested | Not tested | Not tested | Not tested | Authenticator/OpenPGP/PIV need pcscd |
| Fedora (KDE Plasma) | first release with Linux or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | Sync with KWallet (Secret Service) |
| Debian 12 / older distribution | first release with Linux or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | Does the AppImage start at all (built on Ubuntu 24.04)? Udev rules from the AppImage |
| Raspberry Pi OS 64-bit (aarch64) | first release with Linux or newer | any FIDO2 key | | Not tested | Not tested | Not tested | Not tested | ARM64 AppImage |

Open combinations are all rows marked **Not tested**. Add rows for further
models; for an update test write "update from x.y" in the notes (procedure
in TESTING.md).
