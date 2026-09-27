# KeyMelier

*The sommelier for your security keys.*

KeyMelier is a desktop app (macOS + Windows) that **checks, rates and keeps track of your security keys** – across vendors. Managing a PIN or deleting a passkey is something Chrome can do too; KeyMelier answers the questions around it:

- **Is this key genuine and safe?** Attestation verified up to the FIDO Alliance root, a curated and signed vulnerability database that updates itself, certification and revocation status – summed up in a per-key security check with concrete fixes.
- **What is on which key – and what if one is lost?** KeyMelier remembers every key it has seen and what was on it, shows which accounts exist on only one key, and walks you through a lost key.
- **Does it actually work?** A function test registers, signs in and verifies a signature like a real website, without storing anything on the key.

And it manages everything on the key: PIN, passkeys, fingerprints and key settings – plus authenticator codes (OATH), OpenPGP, PIV certificates, YubiKey OTP slots and which applications are enabled over USB/NFC.

## What makes it different

| | KeyMelier | Browser (Chrome) | Vendor apps |
|---|---|---|---|
| Works with keys from any vendor | ✓ | ✓ | usually own keys only |
| Vulnerability check with self-updating, signed database | ✓ | – | – |
| Attestation verified to the FIDO root, revocation checked | ✓ | – | – |
| Remembers keys and what was on them; backup overview across keys | ✓ | – | – |
| Lost-key assistant | ✓ | – | – |
| PIN, passkeys, fingerprints, reset | ✓ | ✓ | ✓ |
| Authenticator codes, OpenPGP, PIV, OTP slots | ✓ | – | ✓ (own keys) |

## Features

- **Inspect:** model and vendor (via FIDO Alliance MDS3, with the vendor's official icon), firmware, AAGUID, capabilities, FIDO versions; for YubiKeys also serial number, real firmware and form factor (via Yubico's yubikit)
- **Security check:** per-key checklist with direct links to fix issues (PIN, vulnerabilities, authenticity, fingerprints, backups)
- **Security:** attestation evidence (verified / unverified / failed), certification status, known vulnerabilities from a curated advisory database
- **PIN:** status and remaining attempts, set or change the PIN (incl. keys that require a first PIN change, e.g. pre-registered YubiKey as a Service keys)
- **Passkeys:** list discoverable credentials per website, rename and delete them
- **Backup & loss:** which websites and authenticator accounts are on which key, those without a second key are highlighted; a lost-key assistant lists the accounts to remove the key from, the authenticator accounts to re-enroll, the OpenPGP keys to revoke and the PIV certificates to have revoked
- **Function test:** register, sign in and verify a signature like a real website – nothing is stored on the key
- **Key settings:** minimum PIN length, always require PIN/fingerprint, force a PIN change
- **Fingerprints** (bio keys): enroll with live guidance, rename, delete
- **Authenticator (OATH):** TOTP/HOTP codes with countdown and copy, add via `otpauth://` link or by hand, rename, delete, password, reset
- **OpenPGP:** keys per slot with fingerprint and algorithm, signature counter, cardholder data, PIN/admin PIN (change, unblock, retries), signature PIN policy, touch policies, reset – YubiKey and other OpenPGP cards (e.g. Token2)
- **PIV:** certificates per slot with validity, generate a key with a self-signed certificate, import/copy/delete certificates, PIN/PUK, protect the management key with the PIN, warnings for factory defaults, reset
- **YubiKey OTP slots:** see which slots are used, static password, HMAC-SHA1 challenge-response (e.g. KeePassXC), swap, delete. On macOS this needs the "Input Monitoring" permission for KeyMelier
- **Applications per USB/NFC** (YubiKey): turn off what you don't use
- **Factory reset:** guided flow (re-plug, touch)
- **History:** keys seen before stay in the sidebar with their last known state, serial number, AAGUID, a custom name, what was on them and an activity timeline
- **Languages:** 11 languages following the OS (de, en, es, fr, it, nl, pl, pt, ja, ko, zh), light and dark mode
- **macOS menu bar:** connected keys with status at a glance; illustrations of each key's form factor
- Explicit CSV export of connected keys to `~/keymelier/exports/`

## License

KeyMelier is MIT licensed (see `LICENSE`). The app bundles the Python runtime and open-source packages under their own licenses (MIT, BSD, Apache-2.0, PSF, MPL-2.0 for certifi, LGPL-2.1+ for pyscard, which ships as separate replaceable files). Their notices are in `THIRD_PARTY_LICENSES.txt` inside the app ("Open-source licenses" in the app) and attached to every release; `tools/third_party_licenses.py` generates it during the build.

## Download

Ready-made builds are attached to the [latest release](https://github.com/FiraSenax/KeyMelier/releases/latest).
Each release states whether its macOS build is Developer ID signed and notarized
and whether its Windows build is Authenticode signed. Checksums (`SHA256SUMS.txt`),
dependency locks and the source commit are attached to every release.

### First launch of an unsigned macOS build

1. Unzip `KeyMelier-macOS.zip` and move **KeyMelier.app** to **Applications**.
2. Open it. macOS says it "cannot verify" the app – click **Done** (not "Move to Trash").
3. Open **System Settings → Privacy & Security**, click **Open Anyway** next to the
   message about KeyMelier and confirm.

Or in Terminal: `xattr -dr com.apple.quarantine /Applications/KeyMelier.app`.
Only do this for a download from this repository whose checksum matches `SHA256SUMS.txt`.

### First launch on Windows

1. Unzip `KeyMelier-Windows.zip` and open the `KeyMelier` folder.
2. Right-click **KeyMelier.exe** → **Run as administrator** (Windows only allows
   direct FIDO access to elevated programs).
3. For an unsigned build SmartScreen may show "Windows protected your PC":
   click **More info** → **Run anyway**.

Managed devices may require your organization's approval.

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
- History is enabled by default: key models, serial numbers and events are saved locally so previously seen keys stay in the sidebar. Turn it off in the "Backup & loss" view (existing files are kept) or use stateless mode. Remembering what is on each key (passkey websites, authenticator account names, OpenPGP key fingerprints — never secrets or codes) is also on by default so you know what is affected when a key is lost; it can reveal accounts and internal domains, so turn it off in the same view if needed. Disabling it removes these lists and account details from history events.
- CSV files are created only using the export button; exported metadata is plaintext. Formula-like cells are neutralized.
- `python app.py --stateless` (or `KEYMELIER_STATELESS=1`) skips persistent settings, history, caches, the lock file and exports. Metadata remains in process memory. OS/browser runtime files are outside this application-level guarantee.
- Optional encrypted history: start with `KEYMELIER_ENCRYPT_HISTORY=1` and enable history. `history.encrypted` uses authenticated encryption with its key held in macOS Keychain or Windows Credential Manager. There is no plaintext-keyring fallback. Existing plaintext history is not migrated or deleted automatically; remove/archive it separately if required. CSV exports remain plaintext. Losing the OS-stored key prevents recovery.
- Local data when enabled: `~/keymelier/history.json` (or `history.encrypted`), `~/keymelier/settings.json`, explicitly generated `~/keymelier/exports/`, and public caches under `~/.keymelier/`. Writes are atomic with owner-only POSIX permissions or Windows user ACLs. Disabling history preserves existing files; it does not securely erase old copies or backups.

## Limitations

- Only passkeys stored **on** the key (discoverable credentials) can be listed. Classic two-factor registrations (U2F / "security key as second factor") are not stored on the key and cannot be listed by any tool.
- FIDO keys expose no unique serial number over FIDO. YubiKeys are told apart by the serial read via yubikit; for other vendors, two keys of the same model and firmware batch share one history entry.
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
