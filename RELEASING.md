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
keychain is removed even on failure. The library-validation entitlement supports
the bundled Python/native modules; review it when changing packaging.

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

## Release

1. Review changes; the automatic checks (see [TESTING.md](TESTING.md)) must pass in CI. Test with
   physical supported keys on macOS and Windows (and Linux when possible) and record the results in
   [HARDWARE_TESTS.md](HARDWARE_TESTS.md).
2. Bump `fido2tool_core/version.py` and `pyproject.toml` consistently; refresh the lock.
3. Run the **release rehearsal** on the candidate (*Actions → Build → Run workflow*): the same builds,
   artifact transfer and checks as the release, without publishing. It must be green; its report
   (artifact `release-rehearsal`) names the commit, the version and every file with its SHA-256.
4. Commit and push the reviewed version tag (`vX.Y.Z`) on that commit.
5. Verify successful signing/notarization and the attached source/dependency evidence.

Without the credentials above, version-tag builds are published unsigned (macOS
ad-hoc signed) and labelled as such in the release notes. The Linux AppImages
(x86_64, aarch64) are always unsigned; the release notes say so and
`SHA256SUMS.txt` covers them. The signing branches
require their first real CI run after provisioning; they cannot be validated with
ad-hoc certificates.
