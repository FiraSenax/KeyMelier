# Roadmap

Planned work after 1.8.0. Nothing here is implemented yet.

## 1.9 – Tell apart keys of the same model without a serial number

### Problem

The history identifies a key by `hash(AAGUID | USB serial)` (`fido2tool_core/history.py`,
`key_id`); YubiKeys add the serial read via yubikit. FIDO itself exposes no unique serial,
and many keys report no USB serial either. Two such keys of the same model and firmware
batch therefore share **one** history entry: their passkeys, accounts, lost/replacement
state and sync data are mixed. The attestation certificate does not help – by FIDO
Alliance rules it is shared by at least 100,000 devices; enterprise attestation (CTAP 2.1)
would be unique but is only released for vendor-approved relying parties.

### Approach

**1. Silent recognition credential (all FIDO2 keys).**

- The authenticity test already creates a *non-discoverable* credential (`rk: false`,
  `fido2tool_core/attestation.py`), with the user's touch. Keep its credential ID in the
  history entry (`recognition: {credential_id, rp_id, created}`) instead of discarding it.
  No extra touch, no passkey slot used.
- Only the key that created a non-discoverable credential can unwrap its ID. On connect,
  for every history entry of the same AAGUID that has a recognition ID, send
  `getAssertion(rp_id, allowList=[id], options={up: false})` – no touch, no PIN on most
  keys. Success = this is that key; `CTAP2_ERR_NO_CREDENTIALS` = not this one.
- The RP ID stays KeyMelier-internal and can never collide with a real website: use a
  reserved name (`keymelier.invalid`) – and the same one as the authenticity test from
  then on.
- The credential ID is not secret (useless without the key) and is synced with the
  history, so the other computers recognise the key as well.

**2. Smart-card serials as a second source (no touch).** Keys with an OpenPGP applet carry
a manufacturer serial in the AID (e.g. Nitrokey 3, many Feitian models); PIV often has a
card serial too. KeyMelier reads these for the OpenPGP/PIV views already; use them for the
identity when the USB serial is missing.

### Design details to settle

- **Stable entry IDs:** do not derive the history `key_id` from the recognition ID (that
  would rename existing entries and break sync merges). New entries get a random,
  permanent ID; recognition maps a connected key to it. Existing IDs stay.
- **Migration:** an existing shared entry keeps its data; the first key recognised after
  the upgrade (by its first authenticity test) is linked to it, a second key of the same
  model then gets its own entry ("<Model> (2)"). Entries already mixed cannot be split
  retroactively – say so in the UI and the changelog.
- **Keys with `alwaysUv`:** they refuse a silent assertion. Recognise them after unlocking
  (PIN token with `getAssertion` permission for the recognition RP ID); until then show
  them as "not yet recognised" instead of guessing.
- **Keys that ignore `up: false`** (some older FIDO 2.0 firmware waits for a touch): short
  timeout, cancel, remember per model that silent recognition does not work, fall back to
  the current behaviour. Must never make a key blink unexpectedly more than once.
- **Factory reset:** the credential is gone, the key no longer matches – it becomes a new
  entry. That is correct (it is empty); mention it in the lost/replace hints.
- **Several candidates:** one silent assertion per candidate entry of that model (a
  handful at most); run once on connect, never in the polling loop.
- **Privacy:** only the credential ID and the fixed RP ID are stored; the diagnostic report
  gets at most "recognition: yes/no/unsupported" per key, never the ID.

### Tests

- Automated: a simulated CTAP2 authenticator (wraps its own credential IDs, answers
  `up: false`, can require UV, can ignore `up: false`, can be reset); two keys of one
  AAGUID get two entries; migration of a shared entry; sync of recognition IDs between
  computers; `alwaysUv` path; timeout path; reset path; upgrade tests with the 1.8.0
  fixtures.
- Hardware (HARDWARE_TESTS.md, new rows): two identical keys **without** USB serial (e.g.
  2 × Token2 or 2 × Feitian) – separate entries, recognised on a second computer via sync;
  per tested model: does `up: false` stay silent (no blinking)?; a key with `alwaysUv`;
  a reset key.

### Out of scope for 1.9

Splitting entries that are already mixed; recognising keys without FIDO2 (U2F-only).
