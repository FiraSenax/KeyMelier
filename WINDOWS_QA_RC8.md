# 1.8.8 RC8 acceptance and follow-up correction

Date: 2026-11-06. Stable acceptance remains open in #39.
Published candidate: `v1.8.8-rc.8`,
`8544da222f34db55a25e34c0e497d8485bf0e683`.
Windows host: Windows 11 Pro 10.0.26300 x64.

## Published packages

Release pipeline 42119877769 passed. Published Windows ZIP and setup matched
SHA256SUMS, GitHub digests and the locally tested CI artifacts. Installed app,
setup and uninstaller signatures were Valid. Isolated packaged startup passed
63/63 checks. The pipeline also passed macOS notarization and Linux package
compatibility checks; these are not manual desktop observations.

## Installed 1.8.7 upgrade and privacy

The owner installed signed 1.8.7. A separate profile was populated with the
release's synthetic compatibility fixture; normal user history was not copied.
The published RC8 setup upgraded the installation successfully (exit 0).

- Owner confirmed labels/details in 1.8.7, after upgrade, and after restart.
- Real Windows Credential Manager encryption worked without mocks. All baseline
  entries, settings and sync identity survived; the four synthetic entries were
  equivalent, and the legacy source stayed byte-for-byte unchanged at migration.
- Turning off website/account memory scrubbed both legacy and encrypted files
  while preserving key labels, including when history was disabled.
- A real Windows sharing lock on the synthetic legacy file prevented cleanup.
  The owner observed the warning; the source stayed intact. Releasing the lock
  and retrying cleared the warning and cleaned both files.
- The owner deliberately re-enabled both settings before closing. On the final
  restart, removed account details stayed gone. The initial report of returned
  details was clarified: the owner meant the intentionally retained key labels.

Local ignored evidence: `build/qa-upgrade-187-rc8-20261106/`, including installer
log, migration and privacy result JSON files. The test file lock was released.

## Native Windows credential denial and recovery

A separate process used Windows `CreateRestrictedToken` to disable its user SID
and impersonated that restricted token for the test only. This produced an
actual `CredRead` access denial (WinError 5) through `keyring.backends.Windows`.
No OS account, production credential or credential-store permission was changed.
Reverting the thread token restored access.

The test used synthetic history and an existing native encryption key without
printing or modifying that key. Its isolated history files remained readable
under the restriction, so the failure was specifically the credential API.
With the RC8 history/service code:

- History reported `history_locked` and disabled persistence.
- Sync was unavailable; enabling it returned `sync_unavailable`.
- An attempted history import wrote neither history nor settings; no sync file
  was created. File hashes remained identical.
- After reverting the restriction, all four synthetic entries loaded normally;
  file hashes remained identical after recovery.

Local evidence: `build/qa-native-denial.py` and
`build/qa-native-denial-20261106/result.json`. This is a real native-backend
integration test, not an observation of a locked-store warning in the packaged
desktop UI. That UI case remains untested.

## GnuPG follow-up correction

Real custom-path GnuPG 2.4.9 from Git for Windows imported a generated public-only
test key into an isolated `GNUPGHOME`. RC8 then skipped its intended smart-card
daemon release: it looked for a sibling `gpgconf`, although Windows installed
`gpgconf.exe`. This can leave GnuPG holding the smart-card interface.

The follow-up selects `gpgconf.exe` on Windows and keeps `gpgconf` on macOS/Linux.
The real import repeated successfully and invoked the Windows companion with
`--kill scdaemon`. A regression test covers Windows/macOS/Linux companion names.
The generated private key existed only in process memory; only a synthetic
public key was imported. Cleanup stopped only the isolated GnuPG home's daemons.

Local evidence: `build/qa-gpg-real-20261106/` (before/after command traces).
This source correction is not present in the published RC8 binaries.

## macOS owner observations

Apple M1, macOS 27.2 as reported by the owner; YubiKey firmware 5.2.7; RC8.
Start, detection and Read key passed. Cancelling the PIN dialog left the retry
counter unchanged. OATH clipboard expiry after 35 seconds passed; different
text copied in TextEdit and identical text copied again in TextEdit both survived
the original expiry timer. Other clipboard managers were not tested.

## Additional integration and regression checks

The unchanged RC8 sync code and the tagged 1.8.7 source ran in separate Windows
processes against an isolated shared folder. Real scrypt/AES-GCM v1 files were
written and consumed in both directions. After four exchange rounds both sides
contained both synthetic entries, without sync errors. This is source-level
compatibility evidence, not a two-desktop or cloud-provider observation.
Local evidence: `build/qa-sync-mixed-20261106/result.json`.

For the GnuPG follow-up, the full elevated Windows suite passed: 541 tests,
529 passed and 12 platform skips. Ruff and diff whitespace checks passed.
An initial non-elevated run lacked `uv` on PATH and symlink privileges; the
configured elevated runner resolved these environment failures without changing
tests or weakening assertions.

## Remaining scope

Record pending native import and macOS consent observations separately. Do not
turn the native credential integration test into a packaged UI pass. GnuPG's
standard-install path, other real smart-card workflows, delayed sensitive forms,
mixed-version real-desktop sync and Linux manual coverage remain untested unless
explicitly recorded. The follow-up correction needs exact-commit CI/package
validation before stable. RC7 hardware observations retain their original scope.
