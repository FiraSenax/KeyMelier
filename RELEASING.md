# Release setup

Signing is optional. When the credentials below are configured, version-tag builds
are signed (and notarized on macOS); without them the builds are published unsigned
and the release notes say so, including first-launch instructions.

The repository provides the workflow; the maintainer must obtain identities and
configure the GitHub `release-signing` environment. Never commit certificates,
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

Windows builds are signed through the [SignPath Foundation](https://signpath.org)
program for open-source projects (free; the certificate is issued to SignPath
Foundation, which appears as the publisher). Azure Artifact Signing is not
available to individuals in the EU.

1. Apply at <https://signpath.org/apply>. Requirements: OSI license, public
   repository, automated build (GitHub Actions), released project, the policy in
   `CODE_SIGNING.md` linked from the README, MFA on GitHub and SignPath.
2. After approval, in SignPath: create the project (GitHub trusted build
   system), paste `.signpath/artifact-configuration.xml` as the artifact
   configuration, create a `release-signing` signing policy with manual approval,
   and create a CI user with an API token.
3. In the GitHub environment `release-signing` configure:
   - Secret `SIGNPATH_API_TOKEN`.
   - Variables `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_SIGNING_POLICY_SLUG`.

On a version tag the workflow uploads the unsigned build, submits it to
SignPath, waits for approval and signing, verifies the Authenticode signature
of `KeyMelier.exe` and publishes the signed folder. Signing does not guarantee
immediate SmartScreen reputation.

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
remains the unsigned rehearsal. Existing environment/SignPath approval rules
still apply. Windows signing runs when its credentials are configured; Linux
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
2. Bump `fido2tool_core/version.py` and `pyproject.toml` consistently; refresh the lock.
3. Run the **release rehearsal** on the candidate (*Actions → Build → Run workflow*): the same builds,
   artifact transfer and checks as the release, without publishing. It must be green; its report
   (artifact `release-rehearsal`) names the commit, the version and every file with its SHA-256.
   `python3 tools/fetch_rc.py RUN_ID` puts exactly the checked packages of that run into
   `dist/rc-<version>-<commit>/` with `RC-MANIFEST.json` (version, commit, run link, SHA-256 of every
   file) – verified, never overwriting an existing candidate.
4. Commit and push the reviewed version tag (`vX.Y.Z`) on that commit.
5. Verify successful signing/notarization and the attached source/dependency evidence.

Without the credentials above, version-tag builds are published unsigned (macOS
ad-hoc signed) and labelled as such in the release notes. The Linux AppImages
(x86_64, aarch64) are always unsigned; the release notes say so and
`SHA256SUMS.txt` covers them. The signing branches
require their first real CI run after provisioning; they cannot be validated with
ad-hoc certificates.
