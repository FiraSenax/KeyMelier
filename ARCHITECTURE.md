# Maintainer guide

This map describes the 1.8.3 quality candidate. Keep changes focused on existing
behaviour, and test failure and cancellation paths before broad refactoring.

## Boundaries

| Area | Owner | Contract |
|---|---|---|
| Desktop lifecycle, exposed callbacks | `app.py` | Own the window; expose only the intended bridge wrappers |
| Operation dispatch | `fido2tool_core/bridge.py` | Allow-list methods; validate argument shape/signature before execution; unexpected exceptions never expose their message |
| Device orchestration | `fido2tool_core/service.py` | Acquire device sessions, coordinate cancellation, delegate protocol work |
| Management authorization | `fido2tool_core/auth.py` | Expiring tokens with explicit permissions; lock/disconnect revokes active authorization attempts |
| Cancellable work | `fido2tool_core/operations.py` | One registered PIN/UV unlock per device, including queued requests; duplicate calls cannot replace its cancellation event |
| Connection lifecycle | `fido2tool_core/scanner.py` | Fresh runtime ID for each observed connection/replacement; recheck observable identity before CTAP operations; discard retired connection updates |
| Protocol operations | `passkeys.py`, `fingerprints.py`, `key_config.py`, `piv_app.py`, other protocol modules | Check authorization at the operation boundary; never interpret an unexpected read error as an empty slot |
| Network input | `network.py`, `mds3.py`, `updates.py`, `app_update.py` | Bound downloaded data; preserve signature/trust checks; verify updates before exposing a completed download |
| Page assembly | `fido2tool_core/page.py`, `static/index.html` | Keep script order consistent in packaged and development pages |

## Frontend ownership

`static/app.js` retains app initialization, selection, shared rendering and event
coordination. Feature dialogs and operations live in `view-passkeys.js`,
`view-fingerprints.js`, `view-function-test.js`, `view-oath.js`,
`view-openpgp.js`, `view-piv.js`, `view-otp.js` and `view-key-settings.js`.
`view-unlock.js` owns the unlock/probe dialogs; `ui-forms.js` holds shared form
helpers. Existing account/history/advisory modules keep their previous roles.

These are ordered classic scripts sharing globals, not isolated ES modules.
The extraction reduces editing scope but does not eliminate coupling. A new
script must be included in both page definitions. Avoid top-level execution that
depends on a later script; bind dialog events during initialization.

Async UI requests must retain the identity of the dialog/operation they started
in. Check that identity after every awaited operation before modifying shared
UI state. Closing or replacing a dialog invalidates its old result. Do not use
the presence of any open dialog as proof that a response still belongs to it.

## Invariants to preserve

- A scoped unlock token cannot authorize a different management operation.
- The scanner owns each HID transport from opening through construction and use;
  failed device construction must still close the transport and release its lock.
- Lock/disconnect cannot be undone by a late result from an already active
  authorization attempt. UI stale-result guards do not replace backend checks.
- Register PIN/UV cancellation before waiting for the device lock. Cancelling an
  in-flight PIN request discards its result; it cannot undo a PIN attempt already
  sent to the authenticator.
- Runtime connection IDs are not history identities. A reused HID path must not
  revive old requests, authorization or attestation. Identical anonymous keys
  exchanged between polls remain indistinguishable; serials are not cryptographic
  proof of physical identity.
- Publish disconnect/connect/update callbacks in order without holding the
  scanner state lock during callbacks. Ignore updates for a retired connection.
- A transport/permission/parse error is not evidence that a PIV slot is empty.
- PIV/OpenPGP occupancy checks and generation share one locked card connection.
  OTP checks and programming share the OTP/device locks. Normalize PIV slot names
  before checking occupancy; do not generate application keys in the attestation
  slot. Do not automatically retry a write after an error.
- Device data and unexpected exception messages must not leak into diagnostics.
- Function tests bind responses to the requested RP, credential and presence/
  verification requirements, and verify the assertion signature.
- An updater must not overwrite an existing file or follow a pre-created output
  symlink. Partial output is removed on failure; the final path is returned only
  after successful copy and sync. This is not an atomic rename protocol.
- Build from a clean, hash-pinned environment. The pywebview manifest check is
  an additional contamination guard, not a substitute for trusted dependencies.
- RC packaging uses release validation but cannot invoke public release creation.

## Verification

Use [TESTING.md](TESTING.md) for commands and
[RELEASING.md](RELEASING.md) for release/RC gates. Add regression tests around
observable failures, not implementation layout alone. Native packaging tests
are required after changes to the window, pywebview or bundled resources;
browser-only tests cannot detect a Cocoa startup crash.
