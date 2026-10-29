# Security policy

## Reporting a vulnerability

Public security reports are welcome. Open a
[GitHub issue](https://github.com/FiraSenax/KeyMelier/issues/new)
with a descriptive title. Public discussion of suspected vulnerabilities and
reproducible findings is accepted; prior private disclosure is not required.
GitHub's private vulnerability reporting remains an optional alternative if you
prefer to share a report privately.

Please include:

- KeyMelier version or commit, operating system and installation type.
- The affected feature, expected behavior and observed behavior.
- Reproduction steps, prerequisites and the security impact you observed.
- A minimal example using a test key and fictional data, where possible.

You can attach **About KeyMelier → Diagnostic report → Save**. The JSON preview
shows exactly what will be saved: selected app/system details, metadata status
and recent operation/error codes. It is not a complete application log and is
never uploaded automatically.

Keep PINs, passwords, OTP seeds, private keys, recovery codes and signing
credentials out of reports. Check logs and screenshots for account names,
serial numbers and other personal data before attaching them. Use a spare key
for destructive reproduction steps; describe such steps clearly.

## Supported versions

Security fixes target the latest stable release. Reports against `main` and
release candidates are also welcome. Older release branches do not receive
separate security backports; users should upgrade to the corrected stable
release when available.

## Handling reports

Reports are reviewed on a best-effort basis. Confirmed issues are tracked through
their fix and validation, with relevant security changes described in the
changelog or release notes. Please distinguish a suspected issue from an
observed exploit and include enough detail to reproduce it safely.

This policy covers KeyMelier and its distribution/build process. Vulnerabilities
in authenticator firmware or third-party services should also be reported to the
respective vendor. KeyMelier reports may still be useful when its handling of
such a vulnerability is affected.

[SECURITY_REVIEW.md](SECURITY_REVIEW.md) records implementation reviews and known
limitations; it is not an independent security certification.

## Sync trust and recovery

Everyone who knows a sync passphrase has equal authority over the shared history,
including labels, account inventories, loss/replacement decisions and removals.
AES-GCM authenticates possession of that shared secret, not an individual
computer. Model/device security verdicts are assessed locally; imported test
events are historical claims marked with their import/sync origin.

Incoming merge timestamps must be ISO dates/times and are normalized to UTC
(legacy dates and naive times mean UTC). Timestamps more than one day in the
future are ignored, including previously stored future removal marks. A peer
with a badly wrong clock must correct it before resending its changes. Removal
marks are limited to 5,000 per input and retained state; ordinary histories and
the version-1 encrypted sync format remain supported.

If a passphrase or computer is compromised, turn sync off on every trusted
computer, review/restore the trusted local histories, and configure a **new,
empty sync folder with a new passphrase** on those computers. Remove the old
folder's sharing permissions and the compromised computer's access separately.
Keep any old files needed for recovery outside the new sync folder. Changing a
passphrase cannot revoke access to copies already obtained with the old one.
