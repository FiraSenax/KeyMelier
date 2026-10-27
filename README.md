# KeyMelier

*The sommelier for your security keys.*

Website: https://firasenax.github.io/KeyMelier/

KeyMelier is a desktop app (macOS, Windows and Linux) that **checks, rates and keeps track of your security keys** – across vendors. Managing a PIN or deleting a passkey is something Chrome can do too; KeyMelier answers the questions around it:

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

- **Inspect:** model and vendor (via FIDO Alliance MDS3, with the vendor's official icon), firmware, AAGUID, capabilities, FIDO versions; for YubiKeys also serial number, real firmware and form factor (via Yubico's yubikit). The overview and technical details let you copy the AAGUID directly, without unlocking the key. It identifies the authenticator model; disconnected keys show their saved value.
- **Quantum safety:** shows which signature algorithms a key offers and detects ML-DSA (RFC 9964) automatically once keys support it; explains where classical cryptography is a real risk (encryption) and where not yet (logins)
- **Security check:** per-key checklist with direct links to fix issues (PIN, vulnerabilities, authenticity, fingerprints, backups)
- **Security:** attestation evidence (verified / unverified / failed), certification status, known vulnerabilities from a curated advisory database
- **PIN:** status and remaining attempts, set or change the PIN (incl. keys that require a first PIN change, e.g. pre-registered YubiKey as a Service keys)
- **Passkeys:** list discoverable credentials per website, rename and delete them; view and copy full credential IDs and user IDs
- **Account overview:** every service across all your keys with what to improve – only on one key, only on a lost key, codes only (for people whose keys all belong to them; can be turned off when managing keys for several people)
- **Backup & loss:** which websites and authenticator accounts are on which key, those without a second key are highlighted; a lost-key assistant lists the accounts to remove the key from, the authenticator accounts to re-enroll, the OpenPGP keys to revoke and the PIV certificates to have revoked
- **Function test:** register, sign in and verify a signature like a real website – nothing is stored on the key
- **Key settings:** minimum PIN length, always require PIN/fingerprint, force a PIN change
- **Fingerprints** (bio keys): enroll with live guidance, rename, delete
- **Authenticator (OATH):** TOTP/HOTP codes with countdown and copy, add via `otpauth://` link, a local PNG/JPEG QR image, or by hand; review imported fields before saving, including algorithm, digits, period and HOTP counter; rename, delete, password, reset. QR images are decoded locally and never uploaded; one account per image (no bulk exports yet).
- **OpenPGP:** generate keys directly on the security key (Ed25519/Cv25519, NIST P-256, RSA 2048/4096) with the public key for GnuPG and a revocation certificate, optional import into GnuPG; keys per slot with fingerprint and algorithm, signature counter, cardholder data, PIN/admin PIN (change, unblock, retries), signature PIN policy, touch policies, reset – YubiKey and other OpenPGP cards (e.g. Token2)
- **PIV:** certificates per slot with validity, generate a key with a self-signed certificate, import/copy/delete certificates, PIN/PUK, protect the management key with the PIN, warnings for factory defaults, reset
- **YubiKey OTP slots:** see which slots are used, static password, HMAC-SHA1 challenge-response (e.g. KeePassXC), swap, delete. On macOS this needs the "Input Monitoring" permission for KeyMelier
- **Applications per USB/NFC** (YubiKey): turn off what you don't use
- **Factory reset:** guided flow (re-plug, touch)
- **History:** keys seen before stay in the sidebar with their last known state, serial number, AAGUID, a custom name, what was on them and an activity timeline; export and import (backup, move to another computer; imports are merged)
- **Languages:** 11 languages following the OS (de, en, es, fr, it, nl, pl, pt, ja, ko, zh), light and dark mode
- **macOS menu bar:** connected keys with status at a glance; illustrations of each key's form factor
- Explicit CSV export of connected keys to `~/keymelier/exports/`

## Code signing

From version 1.8.2 the **macOS app is signed** with an Apple Developer ID and **notarized** by Apple. Windows releases published before Certum setup remain **unsigned**; the real SimplySign signing probe passed on 26 October 2026, and subsequent candidates must pass signature checks before publication. Each release's notes state its actual signing status. Linux packages remain unsigned. An experimental [MSIX testing path](packaging/windows-msix/TESTING.md) uses temporary test certificates; Microsoft Store approval and distribution are not yet established. See [CODE_SIGNING.md](CODE_SIGNING.md) for the policy, team roles and privacy statement.

## Download

Ready-made builds are attached to the [latest release](https://github.com/FiraSenax/KeyMelier/releases/latest).

- **macOS:** `KeyMelier-macOS.dmg` – open it and drag KeyMelier to Applications (also to update).
- **Windows:** `KeyMelier-Windows-Setup.exe` – installs or updates KeyMelier.
- **Linux:** `KeyMelier-Linux-x86_64.AppImage` (ARM64: `…-aarch64.AppImage`) – `chmod +x` and start it. Unsigned; needs glibc 2.39 or newer (Ubuntu 24.04, Debian 13, Fedora 40 or later). Device access (udev rules), `pcscd` for the smart card functions and the keyring for sync: see [Linux](https://firasenax.github.io/KeyMelier/guide.html#linux) in the documentation.
- Portable alternatives: `KeyMelier-macOS.zip`, `KeyMelier-Windows.zip`.

When a newer version exists, KeyMelier offers to download it, verifies it against the release's SHA-256 checksums and opens it; installing stays with you.
Each release states whether its macOS build is Developer ID signed and notarized
and whether its Windows build is Authenticode signed. Checksums (`SHA256SUMS.txt`),
dependency locks and the source commit are attached to every release.

### First launch of an unsigned macOS build (before 1.8.2)

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

Windows 10/11 x64 requires the [Microsoft Visual C++ v14 x64 runtime](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
(14.44.35211.0 or later), installed directly from Microsoft. Setup checks for it
and offers to open Microsoft's download page if it is missing; ZIP users must
install it first. Setup never accepts Microsoft's terms for the user. Windows
provides UCRT and API libraries. Packaging excludes VC/UCRT/MFC/API-set DLLs from
every collected directory, and the final ZIP check rejects accidental inclusion.
The WebView2 SDK/loader remains bundled under its own BSD-style terms; the Edge
WebView2 Runtime is a separate system prerequisite.

### Linux

```bash
./build-linux.sh             # produces dist/KeyMelier-Linux-<arch>.AppImage
```

Needs Python 3.11–3.13 with `venv`, the PC/SC headers for pyscard (`libpcsclite-dev`, `swig`) and, so that PyInstaller can bundle them, the libraries Qt WebEngine links to (`libminizip1t64 libopus0 libsnappy1v5` on Ubuntu 24.04); the CI job `build-linux` lists every package. The web view is Qt (PySide6, LGPL-3.0), bundled in the AppImage. `appimagetool` and the AppImage runtime are downloaded at fixed versions and checked against pinned SHA-256 sums. The udev rules are in [`packaging/linux/70-keymelier.rules`](packaging/linux/70-keymelier.rules).

## Privacy and security

- KeyMelier is a native window (pywebview). The UI talks to Python directly — there is **no local web server or open port**, so browser extensions, websites and other programs cannot reach it.
- PINs are used for the operation that needs them and are not logged or written to storage by KeyMelier. Unlocking for passkey/fingerprint management keeps a short-lived, key-scoped token (5 minutes) in memory only. Inputs pass through JavaScript, the bridge and Python: these runtimes can retain immutable copies until memory is reused. KeyMelier does not guarantee that PINs or other secrets are erased from a RAM/crash dump; copying them into a wipeable buffer would not erase the earlier copies.
- Network: the app contacts the FIDO Alliance (metadata), GlobalSign (signer certificate revocation lists), `raw.githubusercontent.com` (signed advisory database) and `api.github.com` (is a newer KeyMelier release available?). It never sends information about your keys.
- History is enabled by default: key models, serial numbers and events are saved locally so previously seen keys stay in the sidebar. Turn it off in the "Backup & loss" view (existing files are kept) or use stateless mode. Remembering what is on each key (passkey websites, authenticator account names, OpenPGP key fingerprints — never secrets or codes) is also on by default so you know what is affected when a key is lost; it can reveal accounts and internal domains, so turn it off in the same view if needed. Disabling it removes these lists and account details from history events.
- CSV files are created only using the export button; exported metadata is plaintext. Formula-like cells are neutralized.
- `python app.py --stateless` (or `KEYMELIER_STATELESS=1`) skips persistent settings, history, caches, the lock file and exports; update downloads, GnuPG imports and credential-store writes are disabled too. Metadata remains in process memory. On Linux the UI page uses anonymous memory instead of a temporary disk file. OS/browser runtime files are outside this application-level guarantee.
- Optional encrypted history: start with `KEYMELIER_ENCRYPT_HISTORY=1` and enable history. `history.encrypted` uses authenticated encryption with its key held in macOS Keychain, Windows Credential Manager or the Linux Secret Service. There is no plaintext-keyring fallback. Existing plaintext history is not migrated or deleted automatically; remove/archive it separately if required. CSV exports remain plaintext. Losing the OS-stored key prevents recovery.
- Local data when enabled: `~/keymelier/history.json` (or `history.encrypted`), `~/keymelier/settings.json`, explicitly generated `~/keymelier/exports/`, and public caches under `~/.keymelier/`. Writes are atomic with owner-only POSIX permissions or Windows user ACLs. Disabling history preserves existing files; it does not securely erase old copies or backups.

## Limitations

- Only passkeys stored **on** the key (discoverable credentials) can be listed. Classic two-factor registrations (U2F / "security key as second factor") are not stored on the key and cannot be listed by any tool.
- Standard FIDO does not expose a unique serial number. Besides USB serials and YubiKey management serials, RC3 reads vendor identifiers over the same HID connection: Token2's `0x41` GET_INFO channel and the Trussed admin UUID on Solo 2, Nitrokey 3 and Nitrokey Passkey. Support depends on firmware and needs hardware confirmation. When a newly supported identifier is found, an older no-serial history entry is kept separate rather than assigned to that key. Keys that expose no usable identifier can still share a history entry; the broader [recognition project](ROADMAP.md) is separate work.
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

Python 3.11–3.13 is supported. `uv.lock` pins runtime, build and quality-tool
dependencies across platforms. The three `requirements*.txt` files are generated
exports with hashes; scripts and CI install them with `--require-hashes`.
Quality tools remain separate from application and package-build environments.
To intentionally update dependencies, install the pinned tools, edit
`pyproject.toml` or select a transitive package with `uv lock --upgrade-package`,
then regenerate every export:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements-quality.txt
uv lock
python tools/export_requirements.py
python tools/export_requirements.py --check
```

**Automated updates:** Dependabot opens weekly pull requests for the Python lock (minor and
patch grouped) and the pinned GitHub Actions, plus security updates as soon as an advisory
appears. Generated requirements files are excluded from independent updates:
related packages such as PySide6 and Shiboken must resolve together. Every PR runs
the full build. Linux uses the upstream `PySide6` package as the single version
pin for Essentials, Addons and Shiboken. For Python updates, regenerate the exports on the PR branch,
review the manifest, lock and export diffs together, then commit and push them.
CI checks their consistency offline before running tests. Pull requests are also
checked by *Dependency review* (no dependency with a known moderate-or-higher vulnerability),
and CodeQL, secret scanning with push protection and private vulnerability reporting are on.

CI actions are pinned to commit IDs. The build uses committed icons. Dependency
locking improves traceability; it does not promise bit-for-bit identical binaries
across different operating systems, SDKs or signing timestamps.

Which security keys were tested, and how to report yours: [tested keys](https://firasenax.github.io/KeyMelier/hardware.html) (from [HARDWARE_TESTS.md](HARDWARE_TESTS.md); report with the *Tested with a security key* issue form).
How the app is tested (automatically and with real keys): [TESTING.md](TESTING.md) and
[HARDWARE_TESTS.md](HARDWARE_TESTS.md). Organisations can add their own signed advisory sources: [ENTERPRISE.md](ENTERPRISE.md). See [RELEASING.md](RELEASING.md) for the signing setup. Version tags publish only
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
keymelier_core/
  service.py             # All app logic the UI can call (UI-agnostic)
  scanner.py             # USB polling, per-device locking, CTAP2 info
  attestation.py         # makeCredential attestation test + chain verification
  pin.py / auth.py       # PIN handling, unlock tokens
  passkeys.py            # Credential management
  fingerprints.py        # Bio enrollment
  reset.py               # Factory reset flow
  history.py             # Persistent key history
  mds3.py / advisories.py / exporter.py
  policy.py              # Managed configuration (ENTERPRISE.md)
  desktop.py             # Browser, clipboard, page file (Linux specifics)
  diagnostics.py         # Diagnostic report from allow-listed fields
static/                  # UI (HTML/CSS/JS, inlined into the window at start)
data/advisories.json     # Curated advisory database
keymelier.spec           # PyInstaller spec (.app / .exe / Linux bundle)
packaging/linux/         # AppImage entry point, desktop entry, udev rules
```

## License

KeyMelier is released under the [MIT License](LICENSE).

The app bundles the Python runtime and open-source packages under their own licenses (MIT, BSD, Apache-2.0, PSF, MPL-2.0 for certifi, LGPL-2.1+ for pyscard, which ships as separate replaceable files). **About → Licenses & notices** opens an offline reader with the complete original texts, literal search, document export, the KeyMelier MIT license, and the matching source manifest. It is also available from the macOS application menu and app settings. The documents are in `THIRD_PARTY_LICENSES.txt` inside the app and attached to every release; `tools/third_party_licenses.py` generates them from the collected build components. Windows Setup also displays the complete notices. Microsoft system prerequisites are installed separately from Microsoft under its terms.

A CycloneDX SBOM (`keymelier-sbom.cdx.json` in the app, `KeyMelier-<platform>.cdx.json` in each release) inventories collected Python packages, the PyInstaller bootloader, CPython, OpenSSL, reviewed artwork and native Linux packages. Python archive hashes come from pip's installation report and are checked against the lock file. Brand assets retain their individual usage terms; native package notices are preserved from their distribution. Not every statically linked subcomponent is independently versioned in this inventory.

`KeyMelier-Sources-<platform>.tar` accompanies the binaries with corresponding source archives, the application source and library replacement instructions. `THIRD_PARTY_SOURCES.json` records exact versions and checksums. See [library replacement and rebuild instructions](packaging/licenses/LIBRARY-REPLACEMENT.txt). The build excludes unused GNU Readline and collects pyscard's Python modules as external, replaceable files.

It builds on open-source libraries under their own licenses, among them
[python-fido2](https://github.com/Yubico/python-fido2) (BSD-2-Clause),
[pywebview](https://github.com/r0x0r/pywebview) (BSD-3-Clause),
[cryptography](https://github.com/pyca/cryptography) (Apache-2.0 / BSD) and
[requests](https://github.com/psf/requests) (Apache-2.0),
[yubikey-manager / yubikit](https://github.com/Yubico/yubikey-manager) (BSD-2-Clause); app bundles are built with
[PyInstaller](https://pyinstaller.org) (GPL with bootloader exception, which permits this use).
FIDO metadata and authenticator icons are downloaded at runtime from the FIDO Alliance Metadata Service for local authenticator checks. They are separate from the app's MIT license and governed by the [FIDO usage terms](https://fidoalliance.org/metadata-usage-terms-for-relying-parties-or-service-providers-2/); see the [MDS notice](packaging/licenses/FIDO-METADATA-NOTICE.txt). Icons are displayed from current verified statements and are not bundled or retained in history/sync exports. Product names and logos belong to their owners; no endorsement is implied. Separately bundled service logos and the assessed usage conditions are documented in [the brand review](packaging/brands/review.json).
