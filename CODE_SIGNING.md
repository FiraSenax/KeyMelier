# Code signing policy

> **Status (October 2026):** from version 1.8.2 the macOS app is signed with
> the maintainer's Apple Developer ID and notarized by Apple. Windows builds
> are still **unsigned**: the SignPath Foundation application was not accepted.
> Each release's notes state the actual signing state per platform.

Windows: GitHub installers remain unsigned. The experimental MSIX path uses a
temporary, self-signed test certificate and has no Store approval. See the
[local test guide](packaging/windows-msix/TESTING.md). A future Store MSIX would
be signed by Microsoft during publication; that does not sign the GitHub EXE.

macOS: signed with the maintainer's Apple Developer ID and notarized by Apple.

## What is signed

- Production macOS packages built from this repository by GitHub Actions on
  reviewed version tags are Developer ID signed and notarized.
- Local MSIX test packages are signed by a temporary test key; only the public
  certificate is retained with the packages. These signatures are not production
  publisher verification. The workflow deletes its private key after signing.
- Bundled third-party libraries are not re-signed.
- Every release lists the source commit, the dependency locks, SHA-256
  checksums, an SBOM and third-party licenses.

Signed RC tags (`vX.Y.Z-rc.N`) use the same signing policy and approvals, but
keep checked packages as Actions artifacts only. They do not create a public
release or change the latest release. See [RELEASING.md](RELEASING.md).

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [Sven Frank (@FiraSenax)](https://github.com/FiraSenax) |
| Approvers | [Sven Frank (@FiraSenax)](https://github.com/FiraSenax) |

Changes from contributors outside this list are reviewed by a committer before
they are merged. Production signing follows the GitHub environment's protection
rules. The maintainer uses multi-factor authentication for GitHub. Temporary
MSIX test signing is automated and cannot publish a Store app.

## Privacy

KeyMelier does not transfer any information about you, your computer or your
security keys to other networked systems. It only downloads public data:

- FIDO Alliance metadata (`mds3.fidoalliance.org`) and the certificate
  revocation lists of its signer (GlobalSign),
- KeyMelier's signed vulnerability database (`raw.githubusercontent.com`),
- the latest release number (`api.github.com`), to show an update notice.

These requests carry no key data; like any web request they reveal your IP
address to the server. Everything KeyMelier stores (history, settings) stays on
your computer. `--stateless` disables all storage. Details: see "Privacy and security"
in the README.

## Reporting a problem

If a signed KeyMelier binary behaves unexpectedly or you suspect a compromised
release, please open an issue or contact the maintainer via GitHub.
