# Release setup

macOS signing follows the configured Apple credentials. Windows signing is an
explicit opt-in until the real Certum signing probe succeeds. Once enabled, any
missing credential, failed login or invalid signature fails the Windows job;
it cannot silently publish an unsigned Windows build. Release notes and the
website use the verified build outputs, not merely the presence of credentials.

The repository provides the workflow; the maintainer must obtain identities and
configure the GitHub `release-signing` environment. Stable releases (including
1.8.6) are blocked until both macOS and Windows jobs report verified signing.
Public RCs require both verified signatures too. Never commit certificates,
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

## Signed release candidates

RCs use reviewed tags **`v<version>-rc.N`**, for example `v1.8.3-rc.1`.
They use the existing `release-signing` environment (its `v*` tag restriction
stays in force), the same builds, macOS Developer ID signing, notarization of
both app and DMG, stapling, Gatekeeper checks, smoke tests and final package
verification as a release. A signed RC fails if the Apple credentials are missing;
it never silently falls back to an unsigned macOS candidate.

After reviewing and merging a candidate (including this workflow) into protected
`main`, tag the exact merged commit, for example:

```bash
git fetch origin main
git tag v1.8.3-rc.1 origin/main
git push origin v1.8.3-rc.1
```

A version tag starts a source check without production secrets. It requires the
tag, workflow SHA and checkout to identify the same commit, already reachable
from freshly fetched `origin/main`. Missing history or a failed fetch stops the
run. The builds and signing jobs wait for this check; off-main tags cannot pass
this workflow, including manually dispatched signed rehearsals. Ordinary PR and
unsigned branch builds remain available.

An eligible RC tag automatically publishes a public GitHub prerelease after
all checks pass. No second manual build is required. Do not move an existing RC tag; use
`rc.2`, `rc.3`, etc. for fixes.
The native package version remains numeric, for example `1.8.7`. New builds also
record the verified RC tag in `data/build.json`, so the app can compare
`1.8.7-rc.2 < 1.8.7-rc.3 < 1.8.7`. The source commit, Actions run and
`RC-MANIFEST.json` identify the exact candidate. Older RCs without this metadata
or the update-channel setting need one manual upgrade.

The workflow also keeps the **`release-rehearsal` artifact** for 30 days, with
packages, checksums, source commit, dependency locks, SBOMs and a check report:

```bash
python3 tools/fetch_rc.py RUN_ID
```

For a signed **artifact-only rehearsal**, repeat a reviewed tag via
**Actions → Build → Run workflow** with **`signed_rc` enabled** and
**`publish_rc` disabled**. This manual run creates no GitHub Release, does not
mark anything latest and does not write to GitHub Pages. The updater cannot
discover Actions artifacts. **Artifact-only does not mean confidential:** tags
and workflow metadata in this public repository remain visible, and artifact
access follows GitHub's repository permissions.

Select a tag already contained in `main` and permitted by `release-signing`; arbitrary
branches are intentionally blocked by the environment. The default manual branch run
remains the unsigned rehearsal. Existing environment protection rules
still apply. Windows signing runs when explicitly enabled; Linux
remains unsigned. Apple notarization applies only to macOS.

Only the separate stable tag `v1.8.3` publishes a normal release. The RC tag
condition explicitly excludes RCs from that publishing job.

## Public release candidates for the optional update channel

Pushing a reviewed new `vX.Y.Z-rc.N` tag on a commit in `main` automatically builds and publishes the
RC in the same run. Do not start a second manual publication run for that tag.
The manual fallback remains available for an older, unpublished candidate:
select its tag in **Actions → Build → Run workflow** and enable both
**`signed_rc`** and **`publish_rc`**. It requires the same main-ancestry gate,
rebuilds and verifies all packages. Older tagged workflow versions do not gain
new safeguards retroactively; use a new reviewed tag after merging this workflow.

The separate `release-candidate` job requires a successful complete rehearsal,
matching RC tag and verified macOS/Windows signing. It downloads only that run's
checked artifact, verifies the source commit and checksums again, creates a draft
with all files and then publishes it with `prerelease=true` and latest disabled.
It never replaces an existing release. If an upload fails, inspect the draft
before retrying; it remains invisible to the app's updater.

In the app, **Settings → Updates → Include release candidates** is off by default.
Enabling it includes public RCs in the normal update check. The final stable
version follows its RCs even if the option is switched off; older stable versions
are never offered as a downgrade. MSIX installations retain package-managed
updates. Neither the website's latest stable download nor stable-only users are
switched to RCs.

### Tag authority and the limit of the source check

On 2026-10-29, the active `Protect release tags` ruleset for `v*` prohibited
updates, force-push and deletion, with no bypass actors. It did **not** restrict
new tag creation. The local GitHub CLI used the repository owner's `FiraSenax`
identity, including administration rights. GitHub cannot distinguish a person
from an agent using the same credentials; an owner-only tag rule would therefore
not remove that agent's tag authority.

The source check prevents mistakes when using this workflow. It is not an
independent security boundary: a writer can tag an older workflow without this
check, and an administrator can change rules or workflow code. To enforce
separate release authority, use a distinct agent identity without release-tag
creation or repository-administration rights and a separately controlled release
identity. Restrict creation in a separate tag ruleset so an allowed creator does
not also gain a bypass of the existing immutable-tag rules. GitHub's creation
restriction allows only its configured bypass actors; adding it with no allowed
actor blocks everyone. Do not claim human-only tagging while both use the owner
credentials. No credentials, tag rules or signing-environment approvals were
changed by this follow-up.

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
4. Merge the reviewed candidate through the protected `main` PR path, then
   push the version tag (`vX.Y.Z`) on that exact commit. The source gate also
   applies to stable signing and publication.
5. Verify successful signing/notarization and the attached source/dependency evidence.

Before Windows signing is enabled, Windows RC and development builds remain
unsigned and are labelled as such; the stable publishing job is blocked. After enablement, missing Windows credentials stop the build. macOS
without credentials is ad-hoc signed, except for signed RCs which require Apple signing. The Linux AppImages
(x86_64, aarch64) are always unsigned; the release notes say so and
`SHA256SUMS.txt` covers them. The signing branches
require their first real CI run after provisioning; they cannot be validated with
ad-hoc certificates.

## Independent update signatures

The publication jobs also require `KEYMELIER_UPDATE_SIGNING_KEY`, an Ed25519 PEM
stored only as a secret of the existing `release-signing` environment. This is
separate from the advisory key and from the paid Windows/macOS certificates.
Ed25519 keys have no certificate expiry and need no scheduled renewal.
Builds and signing remain fully automatic: no per-build hardware interaction or
required reviewer is introduced. A passkey protects the GitHub account login;
it does not cryptographically authorize each CI artifact. Account/environment
compromise remains outside the protection of a secret stored in that account.

One-time setup, from the project environment with `gh` authenticated:

```sh
python tools/update_signing.py setup
```

The command checks that the GitHub environment restricts deployment refs,
generates an owner-only private backup at
`~/.config/keymelier/update-signing-key.pem`, sends it to GitHub through stdin,
and writes only the public key to `data/update-public-key.txt`. Keep a secure
backup of the private file. Review and commit the public file with the updater
and workflow changes **before building the next release**. Re-running setup
reuses the backup; it refuses mismatched keys or replacement of an existing
remote key whose local backup is missing. It publishes nothing.
The local PEM is unencrypted (owner-only `0600`); that permission is not
encryption and does not protect against malware running as the same user. Keep
an encrypted offline backup and protect the workstation. No password is added
to the unattended GitHub signing job.

After the normal artifact checks, the protected publication job signs the exact
release tag and `SHA256SUMS.txt`, with a dedicated protocol prefix. The extra
`SHA256SUMS.txt.sig` is uploaded alongside the unchanged checksum list. The
signing step rechecks every file and the source commit, requires the secret to
match the embedded public key, and verifies its result before publication. A
missing or mismatched key fails the release. PR jobs and artifact-only rehearsals
do not receive this secret or generate production update signatures. Windows
Authenticode and macOS notarization remain required independently.

New clients authenticate the signed checksums before downloading an executable
and require a separate Open action after verifying the download. Old clients
continue to read the existing checksum format; the new signature file is
additive. New clients keep the release-page link for older unsigned stable
releases but do not download them in-app. RCs without the complete signed asset
set are not offered. This deliberately fails closed; there is no checksum-only
fallback. Artifact-only RCs can still be obtained with the existing rehearsal
workflow. To validate downloaded published artifacts, include the exact tag:

```sh
python tools/update_signing.py verify artifacts --tag v1.8.7-rc.4 --commit COMMIT
```

Do not replace the key on a timer: installed clients trust the key embedded in
their app. A planned rotation needs an explicitly reviewed transition release
and support for clients still trusting the old key. The following emergency stop
does not implement automatic key rotation or independent compromise recovery.

### Repository emergency stop

`data/revoked-update-keys.json` contains SHA-256 hashes of the **raw 32-byte public
keys**, lower-case hexadecimal, in `{"version":1,"revoked":["FINGERPRINT"]}`.
Never put a private key, its hash, or a replacement public key in this list.
Obtain the currently pinned public-key fingerprint without reading its private key:

```sh
python tools/update_signing.py fingerprint
```

CI runs `python tools/check_update_revocation.py` on every normal build and PR.
If the currently embedded key is listed, the same document must also contain an
explicit acknowledgement, for example:

```json
"emergency_stop": {
  "fingerprint": "THE_SAME_64_CHARACTER_PUBLIC_KEY_FINGERPRINT",
  "reason": "Confirmed incident; automatic updates intentionally stopped."
}
```

The reason must be 10–1000 characters and public. The acknowledgement is only an
accident guard; the release signer still refuses a revoked key. Require the
Build checks before merging changes to `main` for this check to prevent an
accidental publication. A check that runs only after a direct push cannot stop
clients from observing that push. It does not defend against an attacker who
can change both the list and the acknowledgement or workflow.

On 2026-10-29, the live `Protect main` ruleset was configured to require a pull
request and the up-to-date `test (ubuntu-24.04)` check from GitHub Actions
(integration 15368), without bypass actors. No second-person approval is required.
Keep the emergency-stop check in that required job and merge this RC branch
before stable so the rule protects subsequent list changes. Verify the effective
rules before release; this documented snapshot is not enforcement by itself:

```sh
gh api repos/FiraSenax/KeyMelier/rules/branches/main
```

To stop a compromised key, append its fingerprint and publish the reviewed file
on `main`. Clients fetch that fixed HTTPS URL during update checks, before a
download, and immediately before opening a downloaded installer. Bundled and
previously observed revocations also apply offline. The aggregate cache and a
separate marker for the installed key make the stop persistent across restarts,
remote list rollback/removal and concurrent app processes. Stateless sessions
only remember downloaded notices within the process. A malformed local cache
blocks the automatic update path. The normal app and device operations remain
available. The release signer also refuses keys revoked by the checked-out list.

The remote list is an additional, unsigned **deny-only signal**: it can disable
updates but cannot enable a new key, bypass an update signature or undo a known
revocation. Missing/offline/invalid remote responses leave existing trust and
known revocations unchanged. A repository attacker can withhold the first notice
or cause denial of service. Older clients without this feature cannot apply it.
The online endpoint becomes available when this file reaches `main`; a test
branch alone does not activate the remote list.

Incident recovery: stop publication, secure the GitHub account/environment and
runner access, publish the fingerprint stop, and assess other signing credentials
exposed to the same environment. Generate a replacement update key in a clean
environment and build a reviewed recovery installer embedding it. Announce the
incident and verify the recovery download through a separately authenticated
channel. Affected installations must install that recovery version manually;
do not remove the old fingerprint or disable signature checks to resume updates.
This project does not yet implement a signed multi-key transition for planned
rotation. Do not overwrite the current key as a routine maintenance step.

### Unreadable local revocation state

`update_revocation_state` means the local revocation evidence cannot be read.
The app shows a specific message and blocks update checks, downloads and opening
installers; normal key operations remain available. An existing revocation
marker takes precedence and continues to report the key as revoked.

Close KeyMelier and preserve a backup of
`~/.keymelier/revoked-update-keys.json` and every
`~/.keymelier/revoked-update-key-*` marker before investigating filesystem access
or damaged content. Do not delete them or replace the list with an empty one.
Restore access permissions if that is the cause. For damaged JSON, restore a
verified backup only after checking that it retains all previously observed
revocations; keep every marker. If that evidence cannot be recovered, use the
maintainer-reviewed manual incident recovery path above. Bundle data and the
current-key marker alone cannot reconstruct all previously observed revoked
keys, so the app deliberately does not rebuild the aggregate cache automatically.

### Signed advisory review before releases

Review vendor advisories and verified FIDO MDS evidence before running
`python tools/advisories_sign.py sign`. Never refresh the date solely to make
CI green. Release-tag builds and publication require
`python tools/advisories_sign.py verify --max-age-days 14`; publication repeats
the check even if earlier CI jobs were completed on a previous day. The daily
Advisory watch job uses 30 days, leaving time to review before the app's 45-day
positive-verdict window expires. Dates more than one day in the future are
rejected, with the same bounded clock tolerance as the client.

## Website signing status

The prepared website reads a `keymelier-signing` marker from the latest stable
GitHub release notes. The release workflow creates that marker from the verified
platform-job outputs, and checks the release notes before publication. Only a
published stable release with a Windows installer can switch the website to the
Windows signed state. RCs, certificate purchase/issuance, a missing marker and
network failures never do. The static fallback refers readers to the release
notes. Merge/deploy these website changes with the signed release preparation;
no separate hand-edited "signed" claim is required at certificate issuance.
