---
id: keymelier-security-and-compatibility
---

# Review KeyMelier for security and compatibility

Apply the root `AGENTS.md` compatibility requirements. Prioritize reproducible
regressions and security findings, with the affected caller or data flow and a
concrete failure scenario. Distinguish confirmed behavior from assumptions.
Keep proposed fixes focused; avoid unrelated refactors or dependency upgrades.

- In `app.py` and `keymelier_core/`, preserve existing bridge/Python callers,
  supported firmware and macOS, Windows and Linux behavior. Check unsupported
  operations, platform fallbacks and partial device reads as well as happy paths.
- For authentication and operations, check permission-scoped tokens, expiry,
  cancellation, disconnect/reconnect and stale asynchronous results. Scope
  changes replace tokens rather than unioning permissions. Do not add implicit
  PIN retries, broader unlocks or renderer-controlled native approval.
- For history, settings, import/export and sync, preserve existing data and
  formats. Check input validation, non-destructive merges and recovery. An
  unavailable OS credential store must not overwrite encrypted history or
  silently fall back to plaintext. Never expose PINs, seeds, private keys or
  authentication tokens in logs or UI.
- For `static/`, check that device/import strings stay untrusted text, CSP and
  navigation restrictions remain effective, duplicate submissions are blocked,
  and cancelled or superseded responses cannot restore stale sensitive state.
  Check user-visible changes in all eleven supported languages.
- For update, packaging, dependency and `.github/` changes, preserve signature,
  digest, trust-anchor, revocation, source provenance and release-signing gates.
  Retain pinned/hash-verified dependencies and existing installation/update
  compatibility; do not solve CI failures by skipping security checks.
- For tests and hardware/release documentation, require evidence appropriate to
  the claim. Synthetic tests and demo UI checks do not establish physical-key
  acceptance, installed-package behavior or a completed Windows/Linux test.
  Keep untested cases explicit rather than treating an RC publication as proof.

Use the existing checks in `.github/workflows/build.yml` to assess coverage for
the changed behavior. Report missing meaningful regression coverage, not a
request for tests that merely duplicate implementation or exercise prose.
