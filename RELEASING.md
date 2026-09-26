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

Set up [Azure Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
with a Public Trust certificate profile and completed identity validation.
Use a GitHub OIDC federated identity scoped to the `release-signing` environment
and assign the Artifact Signing Certificate Profile Signer role on the required
profile. Configure:

- Secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.
- Variables: `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE`.

The workflow signs EXE, DLL and PYD files with SHA-256 and RFC3161 timestamps,
then checks their Authenticode status. Alternative CA/hardware-backed signing
requires adapting this step to that provider; do not export a hardware-protected
key merely to fit this workflow. Signing does not guarantee immediate SmartScreen
reputation.

## Release

1. Review changes and run the tests. Test with physical supported keys on both OSes.
2. Bump `fido2tool_core/version.py` and `pyproject.toml` consistently; refresh the lock.
3. Commit and push the reviewed version tag (`vX.Y.Z`).
4. Verify successful signing/notarization and the attached source/dependency evidence.

Without the credentials above, version-tag builds are published unsigned (macOS
ad-hoc signed) and labelled as such in the release notes. The signing branches
require their first real CI run after provisioning; they cannot be validated with
ad-hoc certificates.
