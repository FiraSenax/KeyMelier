# Local MSIX testing (no Store submission)

This is an experimental Windows distribution path, separate from the regular
EXE installer and the 1.8.6 RC. No Store account, product reservation, paid
certificate or Microsoft approval is needed to build and sideload these tests.
The package has the deliberately temporary identity `KeyMelier.LocalTest` and
appears as **KeyMelier (MSIX Test)** in Start. It is not a Store-approved app.

## Build and automated test

On an x64 Windows 10 (build 19041+) or Windows 11 test machine, with Windows SDK
MakeAppx/SignTool, Python and the hash-pinned build dependencies installed:

```powershell
python tools/write_build_info.py --signed false
$env:KEYMELIER_ICON = 'static\icon.ico'
python -m PyInstaller --clean --noconfirm keymelier.spec
powershell -NoProfile -File tools/build_msix.ps1
# Run the following in an elevated Windows PowerShell session:
powershell -NoProfile -File tools/test_msix.ps1
```

`build_msix.ps1` uses full MakeAppx validation and builds two package revisions
(`1.8.6.0` and `1.8.6.1` for application 1.8.6). Both contain the same app; the
second revision exists to exercise the package upgrade path. The script creates
a non-exportable test signing key, exports only its PUBLIC `.cer`, signs both
packages, and removes its private key in `finally`. The certificate expires in
14 days. No production certificate, SignPath or Store API is used.

The **MSIX local test** Actions workflow runs the same process on Windows.
It only has read permissions and retains the `msix-local-test` artifact for
7 days. It never publishes a release, contacts Partner Center or submits an app.
The normal signed macOS RC and GitHub installer workflow remain separate.

The installation test refuses to overwrite an existing `KeyMelier.LocalTest`
installation. It temporarily trusts the public test certificate, installs the
first MSIX, and runs the actual installed executable with a real GUI and an
isolated temporary user-data directory. It verifies:

- The running process really has Windows package identity.
- All existing packaged startup checks, including the UI/backend bridge, pass.
- The MSIX app does not query GitHub for application updates or offer an EXE
  installer. FIDO metadata, CRLs and vulnerability data still refresh normally.
- A synthetic credential can be written, read and deleted through the native
  Windows Credential Manager.
- Synthetic user data can be written, read and deleted through the app's storage
  helpers under the temporary home.
- The higher package revision installs with the same identity; a synthetic marker
  in the package's `LocalState` survives the upgrade; the installed GUI passes
  the checks again.
- The package and any certificate trust added by the test are removed afterwards.

`TEST-PACKAGE.json` records source/build provenance, versions, certificate
thumbprint/expiry and SHA-256 checksums. `INSTALL-TEST.json` and the per-version
startup reports record results. The tests neither enumerate nor modify keys.

## Manual installation for real hardware tests

Use a Windows test account/VM with a snapshot and USB passthrough if needed.
Check the workflow commit and `TEST-PACKAGE.json` before trusting its certificate.
In **elevated Windows PowerShell**, from the downloaded artifact folder:

```powershell
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path .\KeyMelier-Test.cer).Path)
$cert.Thumbprint  # compare with TEST-PACKAGE.json
Import-Certificate -FilePath .\KeyMelier-Test.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
Add-AppxPackage -Path .\KeyMelier-Test-1.8.6.0-x64.msix
```

Launch **KeyMelier (MSIX Test)** from Start and accept its normal UAC prompt.
Use the versions actually listed in `TEST-PACKAGE.json` if they differ.
Install the `.1` package later with `Add-AppxPackage` to test an upgrade.

The test package has a separate Windows identity, but the application currently
uses the existing `~/keymelier` data location and `KeyMelier` credential namespace.
A normal launch can therefore share data with a regular EXE installation. Do not
run both at once; use a disposable Windows account or back up data first. The
CI self-tests isolate their data and use a unique synthetic credential name.

Record these manual results before considering Store submission:

| Check | Required observation | Current evidence |
|---|---|---|
| Start menu and UAC | Correct app starts; admin account consent and standard-user credential prompts behave as expected | Manual test pending |
| FIDO/HID | Keys appear; metadata, touch, PIN/UV unlock and read-only credential listing work | Real hardware pending |
| PC/SC | OATH, PIV and OpenPGP information can be read; unplug/replug recovers cleanly | Real hardware pending |
| Existing data | Settings/history and encrypted history remain readable after package upgrade | Real user-data migration pending |
| User scope | Elevation with another admin account does not silently use the wrong account's data/keyring | Manual test pending |
| Update UI | Application updates refer to Store/package management; security data still refreshes | Unit/CI coverage plus manual check |
| Removal | No test app/certificate remains after cleanup; required exported/backed-up user data remains available | Automated cleanup plus manual review |

Do not test resets, PIN changes, key deletion or key generation on a production
security key. Any destructive hardware test needs an explicitly selected spare
key and the usual in-app confirmation.

Cleanup of a manual installation:

```powershell
Get-AppxPackage -Name KeyMelier.LocalTest | Remove-AppxPackage
# Remove only this certificate, and only if you added it for this test:
Remove-Item "Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)"
```

## What a passing test does not establish

The manifest declares `runFullTrust` and `allowElevation` because the existing
Windows executable requires administrator rights for raw FIDO HID access.
Sideloading these capabilities does not require Store approval; Store use of
`allowElevation` requires Microsoft's separate review. Windows S mode cannot be
claimed as supported. Run the Windows App Certification Kit on a Windows client
and obtain the required capability approval before any Store submission.

Before a real Store build, replace the local identity with the exact Partner
Center identity/publisher, decide and test data migration/coexistence, provide
Store artwork/listing/privacy information, and test Store-managed updates through
an appropriate Store test distribution. The local package upgrade test does not
exercise Microsoft's Store delivery service. The Store signs MSIX packages on
publication; this local certificate is only for temporary testing.

Sources: [Microsoft local MSIX testing](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-debug),
[MakeAppx](https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool),
[testing signatures](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide),
[capability approval](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations).
