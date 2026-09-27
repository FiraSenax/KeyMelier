# Code signing policy

> **Status (September 2026):** releases so far are **unsigned**; each
> release's notes state the actual signing state. KeyMelier has applied to
> the SignPath Foundation program for Windows, and Apple Developer ID
> signing is being set up for macOS. This policy describes how signing works
> once active.

Windows (once accepted): free code signing provided by
[SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

macOS: signed with the maintainer's Apple Developer ID and notarized by Apple.

## What is signed

- Only `KeyMelier.exe`, built from this repository by GitHub Actions
  (`.github/workflows/build.yml`) on a version tag. The unsigned build is
  handed to SignPath directly from the workflow run; nothing is built or
  modified on a personal machine.
- Bundled third-party libraries are not re-signed.
- Every release lists the source commit, the dependency locks, SHA-256
  checksums, an SBOM and third-party licenses.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [Sven Frank (@FiraSenax)](https://github.com/FiraSenax) |
| Approvers | [Sven Frank (@FiraSenax)](https://github.com/FiraSenax) |

Changes from contributors outside this list are reviewed by a committer before
they are merged. Every signing request is approved manually. All team members
use multi-factor authentication for GitHub and SignPath.

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
