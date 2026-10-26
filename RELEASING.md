# Release setup

macOS signing follows the configured Apple credentials. Windows signing is an
explicit opt-in until the real Certum signing probe succeeds. Once enabled, any
missing credential, failed login or invalid signature fails the Windows job;
it cannot silently publish an unsigned Windows build. Release notes and the
website use the verified build outputs, not merely the presence of credentials.

The repository provides the workflow; the maintainer must obtain identities and
configure the GitHub `release-signing` environment. Stable releases (including
1.8.6) are blocked until both macOS and Windows jobs report verified signing.
Use artifact-only RC tags while Certum setup is pending. Never commit certificates,
private keys, app passwords or cloud credentials. Restrict that environment to
reviewed version tags and configure appropriate environment protection rules.

## macOS

Enroll in the [Apple Developer Program](https://developer.apple.com/programs/).
Create a [Developer ID Application certificate](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
with its private key and export it as a password-protected P12 from Keychain Access.
Configure these GitHub environment secrets:

- `MACOS_CERTIFICATE_P12`: base64-encoded P12 including the private key.
- `MACOS_CERTIFICATE_PASSWORD`: its export password.
- `MACOS_SIGN_IDENTITY`: exact Developer ID Application identity.
- `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`: notarytool credentials.

PyInstaller signs nested binaries with the Developer ID and hardened runtime.
The workflow verifies the bundle, submits it to Apple's notary service, staples
and validates the ticket, then assesses Gatekeeper acceptance. A temporary signing
keychain is removed even on failure. The hardened runtime runs without entitlements
(`data/macos-entitlements.plist` is empty); keep it that way when changing packaging.

## Windows

The previous SignPath integration has been removed after the application was
not accepted. Certum Open Source Code Signing in the Cloud (SimplySign) has been
issued on 26 October 2026. The [real provider probe](https://github.com/FiraSenax/KeyMelier/actions/runs/40378787279)
passed that day using the exact certificate thumbprint, with a trusted timestamp,
native Authenticode validation and completed session cleanup. Previously built
unsigned packages remain unchanged; the first signed candidate is 1.8.6 RC5.

The workflow uses the official SimplySign Desktop 9.4.4.92 MSI, pinned by SHA-256
and verified against its Asseco Authenticode signature before installation. A
reviewed, commit-pinned [community login action](https://github.com/jay0lee/certum-cloud-code-sign/tree/a3324503499c49090869856eeeecfe95fb613d87)
connects the desktop client on a disposable GitHub-hosted Windows runner. This is
desktop login automation, not an official Certum CI API. Debug screenshots and
client log capture are disabled. Review updates to the action and MSI together.
The private signing key remains in Certum's cloud.

After issuance, activate SimplySign and verify the name/address in the issued
certificate. Configure the existing protected `release-signing` environment:

| Type | Name | Value |
|---|---|---|
| Secret | `CERTUM_USERNAME` | SimplySign account email |
| Secret | `CERTUM_TOTP_SECRET` | Base32 token seed from SimplySign setup, not the six-digit current code |
| Variable | `CERTUM_CERT_SHA1` | Exact 40-character thumbprint of the issued code-signing certificate, without spaces |
| Variable | `WINDOWS_SIGNING_ENABLED` | Leave unset or `false` until the provider probe passes; then set `true` |

If the public certificate download is unavailable, the first probe can obtain
its thumbprint from SimplySign. Leave `CERTUM_CERT_SHA1` unset and configure
`CERTUM_CERT_SERIAL` and `CERTUM_CERT_COMMON_NAME` from the verified issuance
notice and CertManager. This probe requires exactly one matching serial, the
exact publisher common name, a trusted Certum chain, current validity, code-signing
usage and access to the cloud private key before signing. It reports only public
certificate metadata. Copy the verified thumbprint into `CERTUM_CERT_SHA1` after
the probe succeeds. Release builds never use this bootstrap path.

The TOTP seed grants access to signing and belongs only in that protected
GitHub environment. Do not put it in chat, repository files, workflow inputs,
logs or artifacts. The login expects SHA-256, six digits and a 30-second period;
verify these settings against the issued account before enabling CI. If setup
does not provide an exportable token seed, keep CI signing disabled and use the
local connected-session method below until an approved login method is available.
Old `SIGNPATH_*` secrets and variables are no longer read and can be removed.
Keep the existing reviewed `v*` tag restriction on `release-signing`.

Before enabling production signing, push a fresh reviewed probe tag, for example
`vsigncheck-win-20261026-1`. **Signing check** then compiles, signs and verifies a
tiny probe with the real certificate and RFC3161 timestamp. It publishes no
release or downloadable binary and does not run macOS notarization. Build ignores
all `vsigncheck-*` tags. Delete the probe tag after inspecting the result. The
probe works before `WINDOWS_SIGNING_ENABLED` is set; missing credentials fail.

After the probe succeeds, set `WINDOWS_SIGNING_ENABLED=true` and build a **new**
RC tag. Do not reuse RC2: it remains the unsigned Windows candidate. Verify the
actual publisher on Windows and test install, start, update and uninstall before
a stable release. Signing does not guarantee immediate SmartScreen reputation.

The signed path signs the app first, then Inno Setup signs both its embedded
uninstaller and the final installer. Every signature must match the configured
certificate, pass Windows Authenticode and SignTool validation and include a
trusted timestamp. Third-party binaries retain their existing signatures. The
SimplySign process is stopped and its local certificate reference removed even
on failure, before the app's start test. Signing jobs are serialized. Credentials
are supplied only to the connection action, never to the app or packaging tests.

For local signing on a Windows machine with SimplySign Desktop already connected
and the Windows SDK/Inno Setup installed, use PowerShell 7 from a clean checkout:

```powershell
$env:CERTUM_CERT_SHA1 = 'THUMBPRINT_OF_THE_ISSUED_CERTIFICATE'
python tools/write_build_info.py --signed true
pyinstaller --clean --noconfirm keymelier.spec
./tools/sign-windows.ps1 -Path dist/KeyMelier/KeyMelier.exe
$version = python -c "from keymelier_core.version import __version__; print(__version__)"
./tools/build-windows-installer.ps1 -AppVersion $version -Signed
python tools/smoke_packaged.py
```

The separate **Windows signing tests** workflow needs no production secrets. It
uses a temporary, non-exportable test key on a disposable runner to exercise
signing, trusted timestamp verification, installer/uninstaller integration and
rejection of unsigned, tampered, wrong-signer, expired and untimestamped inputs.
A second job verifies installation of the official client without logging in.
These tests do not prove that the real SimplySign account can authenticate.

A separate [local MSIX test workflow](packaging/windows-msix/TESTING.md) builds,
test-signs, installs, starts and upgrades packages without a Store account or
submission. It uses a temporary test identity and exports only a public test
certificate. Store distribution still requires a real Partner Center identity,
review of `allowElevation`, hardware/client testing and certification. Microsoft's
Store signature applies to the Store MSIX, not to the GitHub EXE installer.

## Signed release candidates without publication

RCs use reviewed tags **`v<version>-rc.N`**, for example `v1.8.3-rc.1`.
They use the existing `release-signing` environment (its `v*` tag restriction
stays in force), the same builds, macOS Developer ID signing, notarization of
both app and DMG, stapling, Gatekeeper checks, smoke tests and final package
verification as a release. A signed RC fails if the Apple credentials are missing;
it never silently falls back to an unsigned macOS candidate.

After reviewing and committing a candidate (including this workflow):

```bash
git tag v1.8.3-rc.1
git push origin v1.8.3-rc.1
```

A tag push starts the workflow even when the candidate commit is on a review
branch. Do not move an existing RC tag; use `rc.2`, `rc.3`, etc. for fixes.
The packaged application version remains `1.8.3`; the RC tag, source commit,
Actions run and `RC-MANIFEST.json` identify the candidate. Installing the later
stable build with the same version is manual: the normal updater compares
release versions, not RC run numbers.

The output is the **`release-rehearsal` artifact**, retained for 30 days, with
packages, checksums, source commit, dependency locks, SBOMs and a check report:

```bash
python3 tools/fetch_rc.py RUN_ID
```

No GitHub Release is created, no tag is marked latest, and nothing writes to
GitHub Pages. The normal `/releases/latest` update check cannot discover these
artifacts. **Artifact-only does not mean confidential:** tags and workflow
metadata in this public repository remain visible, and artifact access follows
GitHub's repository permissions.

You can also repeat a reviewed tag via **Actions → Build → Run workflow** with
**`signed_rc` enabled**. Select a tag permitted by `release-signing`; arbitrary
branches are intentionally blocked by the environment. The default manual branch run
remains the unsigned rehearsal. Existing environment protection rules
still apply. Windows signing runs when explicitly enabled; Linux
remains unsigned. Apple notarization applies only to macOS.

Only the separate stable tag `v1.8.3` publishes a normal release. The RC tag
condition explicitly excludes RCs from that publishing job.

## Clean build environments

Before collecting files, the PyInstaller spec verifies pywebview's JavaScript
against its installed wheel manifest. Missing, modified or extra scripts stop
the build. In particular, copied files such as `customize 2.js` are loaded by
pywebview and can cause a native Cocoa abort (`KeyError: text_select`).

If this check fails, preserve the old environment for diagnosis and create a
new virtual environment, then install `requirements.txt` and
`requirements-build.txt` with `--require-hashes`. `pip --force-reinstall` in the
old environment does not remove files absent from the package manifest. Do not
suppress the check or manually alter the packaged scripts. Always run
`tools/smoke_packaged.py` on the rebuilt application before distributing it.

## Release

1. Review changes; the automatic checks (see [TESTING.md](TESTING.md)) must pass in CI. Test with
   physical supported keys on macOS and Windows (and Linux when possible) and record the results in
   [HARDWARE_TESTS.md](HARDWARE_TESTS.md).
   Also inspect the actual open Code Scanning alerts for the candidate commit:
   a successful CodeQL job only means the scan ran. Review and resolve findings;
   record any narrowly justified test-only dismissal rather than excluding tests
   or disabling a query. Scan completion alone is not a clean security result.
2. Bump `keymelier_core/version.py` and `pyproject.toml` consistently; refresh the lock.
3. Run the **release rehearsal** on the candidate (*Actions → Build → Run workflow*): the same builds,
   artifact transfer and checks as the release, without publishing. It must be green; its report
   (artifact `release-rehearsal`) names the commit, the version and every file with its SHA-256.
   `python3 tools/fetch_rc.py RUN_ID` puts exactly the checked packages of that run into
   `dist/rc-<version>-<commit>/` with `RC-MANIFEST.json` (version, commit, run link, SHA-256 of every
   file) – verified, never overwriting an existing candidate.
4. Commit and push the reviewed version tag (`vX.Y.Z`) on that commit.
5. Verify successful signing/notarization and the attached source/dependency evidence.

Before Windows signing is enabled, Windows RC and development builds remain
unsigned and are labelled as such; the stable publishing job is blocked. After enablement, missing Windows credentials stop the build. macOS
without credentials is ad-hoc signed, except for signed RCs which require Apple signing. The Linux AppImages
(x86_64, aarch64) are always unsigned; the release notes say so and
`SHA256SUMS.txt` covers them. The signing branches
require their first real CI run after provisioning; they cannot be validated with
ad-hoc certificates.

## Website signing status

The prepared website reads a `keymelier-signing` marker from the latest stable
GitHub release notes. The release workflow creates that marker from the verified
platform-job outputs, and checks the release notes before publication. Only a
published stable release with a Windows installer can switch the website to the
Windows signed state. RCs, certificate purchase/issuance, a missing marker and
network failures never do. The static fallback refers readers to the release
notes. Merge/deploy these website changes with the signed release preparation;
no separate hand-edited "signed" claim is required at certificate issuance.
