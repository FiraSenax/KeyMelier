# KeyMelier

*The sommelier for your security keys.*

A desktop app (macOS + Windows) for inspecting and managing FIDO2 security keys. Plug in a key and see what it is, its attestation evidence and known vulnerability findings — and manage it: PIN, passkeys, fingerprints, factory reset. Key history is opt-in; the default session keeps key metadata in memory.

## Features

- **Inspect:** model and vendor (via FIDO Alliance MDS3, with the vendor's official icon), firmware, AAGUID, capabilities, FIDO versions; for YubiKeys also serial number, real firmware and form factor (via Yubico's yubikit)
- **Security check:** per-key checklist with direct links to fix issues (PIN, vulnerabilities, authenticity, fingerprints, backups)
- **Security:** attestation evidence (verified / unverified / failed), certification status, known vulnerabilities from a curated advisory database
- **PIN:** status and remaining attempts, set or change the PIN (incl. keys that require a first PIN change, e.g. pre-registered YubiKey as a Service keys)
- **Passkeys:** list discoverable credentials per website, rename and delete them
- **Backup & loss:** which websites are on which key (names only, local recording disabled by default), sites without a second key are highlighted; a lost-key assistant lists the accounts to remove the key from
- **Function test:** register, sign in and verify a signature like a real website – nothing is stored on the key
- **Key settings:** minimum PIN length, always require PIN/fingerprint, force a PIN change
- **Fingerprints** (bio keys): enroll with live guidance, rename, delete
- **Factory reset:** guided flow (re-plug, touch)
- **History:** keys seen before stay in the sidebar with their last known state, a custom name and an activity timeline
- **Languages:** 11 languages following the OS (de, en, es, fr, it, nl, pl, pt, ja, ko, zh), light and dark mode
- **macOS menu bar:** connected keys with status at a glance; illustrations of each key's form factor
- Explicit CSV export of connected keys to `~/keymelier/exports/`

## Download

Release builds must be Developer ID signed and notarized on macOS, and Authenticode
signed on Windows. Older releases and CI test artifacts may be unsigned. Do not
bypass Gatekeeper or SmartScreen to run an unverified download. Use a reviewed
source checkout for local testing, or wait for a signed release.

After extracting a signed release, verify the expected publisher before opening it.
Windows direct CTAP2 HID management can require elevation; build/install dependencies
without administrator privileges, then elevate only the reviewed application when
needed. Managed devices require your organization's approval.

## Build it yourself

### macOS app

```bash
./build-mac.command          # produces dist/KeyMelier.app
cp -R dist/KeyMelier.app /Applications/
```

The local build is ad-hoc signed for testing, without a verified publisher identity. No drivers are needed (macOS uses IOKit HID).

### From source

```bash
git clone https://github.com/FiraSenax/KeyMelier
cd KeyMelier
python3 -m venv venv && venv/bin/pip install --require-hashes -r requirements.txt
venv/bin/python3 app.py
```

Or double-click `run.command` (macOS) / `run.bat` (Windows).

### Windows

> On Windows 10 1903 and later, direct CTAP2 HID access requires elevated privileges. Right-click `run.bat` → **Run as administrator**. `build-windows.bat` builds `dist\KeyMelier\KeyMelier.exe`.

## Privacy and security

- KeyMelier is a native window (pywebview). The UI talks to Python directly — there is **no local web server or open port**, so browser extensions, websites and other programs cannot reach it.
- PINs are only held in memory for the single operation that needs them and are never logged or stored. Unlocking for passkey/fingerprint management keeps a short-lived, key-scoped token (5 minutes) in memory only.
- Network: the app contacts the FIDO Alliance (metadata), GlobalSign (signer certificate revocation lists), `raw.githubusercontent.com` (signed advisory database) and `api.github.com` (is a newer KeyMelier release available?). It never sends information about your keys.
- History is disabled by default. Enable it explicitly in the backup view to persist key models, serials and events. Website recording is a separate opt-in, disabled by default; enabling it can reveal accounts and internal domains. Disabling it removes site lists and account details from history events.
- CSV files are created only using the export button; exported metadata is plaintext. Formula-like cells are neutralized.
- `python app.py --stateless` (or `KEYMELIER_STATELESS=1`) skips persistent settings, history, caches, the lock file and exports. Metadata remains in process memory. OS/browser runtime files are outside this application-level guarantee.
- Optional encrypted history: start with `KEYMELIER_ENCRYPT_HISTORY=1` and enable history. `history.encrypted` uses authenticated encryption with its key held in macOS Keychain or Windows Credential Manager. There is no plaintext-keyring fallback. Existing plaintext history is not migrated or deleted automatically; remove/archive it separately if required. CSV exports remain plaintext. Losing the OS-stored key prevents recovery.
- Local data when enabled: `~/keymelier/history.json` (or `history.encrypted`), `~/keymelier/settings.json`, explicitly generated `~/keymelier/exports/`, and public caches under `~/.keymelier/`. Writes are atomic with owner-only POSIX permissions or Windows user ACLs. Disabling history preserves existing files; it does not securely erase old copies or backups.

## Limitations

- Only passkeys stored **on** the key (discoverable credentials) can be listed. Classic two-factor registrations (U2F / "security key as second factor") are not stored on the key and cannot be listed by any tool.
- FIDO keys expose no unique serial number over FIDO. Two keys of the same model and firmware batch share one history entry.
- A factory reset deletes passkeys, PIN and fingerprints but does not fix firmware vulnerabilities.

## FIDO Alliance MDS3

On first launch the app downloads the [FIDO Alliance Metadata Service](https://mds.fidoalliance.org/) blob and caches it for 24 hours. It is used to resolve the AAGUID to model name and vendor icon, check certification status, and verify attestation certificate chains.

The MDS JWT is checked against the pinned root using PKIX path validation and
current, issuer-signed CRLs. Unavailable, expired or unsupported revocation evidence
fails closed. Metadata past its signed `nextUpdate` cannot produce a positive assessment.

`VERIFIED` attestation requires a valid supported signature, matching AAGUID and
request binding, user presence, and a valid certificate path to the current MDS roots.
`none`, self-attestation, unsupported formats or missing metadata are `UNVERIFIED`.
`FAILED` means a performed evidence check failed; a transport error alone is not proof
of a counterfeit key. Authenticator attestation certificates do not currently get
individual online CRL/OCSP checks; MDS security status is shown separately. A verified
attestation is not an unconditional safety guarantee or enterprise certification.

`OK` means current certified MDS status and an available signed advisory database,
with no matching findings. Missing evidence produces `UNKNOWN`; known warnings and
critical findings take priority. The curated advisory database is not exhaustive.

## Security advisories

`data/advisories.json` maps vulnerabilities to affected AAGUIDs and firmware ranges. Only entries verified against the vendor advisory and the MDS3 metadata (AAGUID + authenticatorVersion) are included:

| ID | Severity | Affected | Condition |
|---|---|---|---|
| CVE-2024-45678 (EUCLEAK, YSA-2024-03) | Medium (CVSS 4.9) | YubiKey 5 (incl. FIPS), Security Key Series | firmware < 5.7.0 |
| CVE-2024-45678 (EUCLEAK, YSA-2024-03) | Medium (CVSS 4.9) | YubiKey Bio Series | firmware < 5.7.2 |

When adding entries, derive the AAGUIDs from MDS3 rather than by hand and include a `references` link to the official advisory.

## Dependencies and releases

Python 3.11–3.13 is supported. `uv.lock` pins runtime/build dependencies across
platforms. `requirements.txt` and `requirements-build.txt` include hashes; scripts
and CI install them with `--require-hashes`. To intentionally update dependencies,
review the lock diff and regenerate exports with uv:

```bash
uv lock
uv export --frozen --no-dev --no-emit-project -o requirements.txt
uv export --frozen --only-group build --no-emit-project -o requirements-build.txt
```

CI actions are pinned to commit IDs. The build uses committed icons. Dependency
locking improves traceability; it does not promise bit-for-bit identical binaries
across different operating systems, SDKs or signing timestamps.

See [RELEASING.md](RELEASING.md) for the signing setup. Version tags publish only
after tests, signing and platform signature verification succeed. Pushes to main
produce CI test artifacts, not public unsigned nightly releases. Releases include
checksums, the source commit and dependency lockfiles.

Run the regression suite with:

```bash
venv/bin/python -m unittest discover -s tests -v
node tests/ui_security.cjs
```

## Project structure

```
app.py                   # Entry point — native window + JS bridge (pywebview)
fido2tool_core/
  service.py             # All app logic the UI can call (UI-agnostic)
  scanner.py             # USB polling, per-device locking, CTAP2 info
  attestation.py         # makeCredential attestation test + chain verification
  pin.py / auth.py       # PIN handling, unlock tokens
  passkeys.py            # Credential management
  fingerprints.py        # Bio enrollment
  reset.py               # Factory reset flow
  history.py             # Persistent key history
  mds3.py / advisories.py / exporter.py
static/                  # UI (HTML/CSS/JS, inlined into the window at start)
data/advisories.json     # Curated advisory database
fido2tool.spec           # PyInstaller spec (.app / .exe)
```

## License

KeyMelier is released under the [MIT License](LICENSE).

It builds on open-source libraries under their own licenses, among them
[python-fido2](https://github.com/Yubico/python-fido2) (BSD-2-Clause),
[pywebview](https://github.com/r0x0r/pywebview) (BSD-3-Clause),
[cryptography](https://github.com/pyca/cryptography) (Apache-2.0 / BSD) and
[requests](https://github.com/psf/requests) (Apache-2.0),
[yubikey-manager / yubikit](https://github.com/Yubico/yubikey-manager) (BSD-2-Clause); app bundles are built with
[PyInstaller](https://pyinstaller.org) (GPL with bootloader exception, which permits this use).
FIDO metadata is downloaded at runtime from the FIDO Alliance Metadata Service; vendor
icons shown in the app come from that service. Product names are trademarks of their owners.
