# KeyMelier

A desktop app (macOS + Windows) for inspecting and managing FIDO2 security keys. Plug in a key and see what it is, whether it is genuine and affected by known vulnerabilities — and manage it: PIN, passkeys, fingerprints, factory reset. KeyMelier remembers every key it has seen, with an activity history.

## Features

- **Inspect:** model and vendor (via FIDO Alliance MDS3, with the vendor's official icon), firmware, AAGUID, capabilities, FIDO versions
- **Security:** attestation test (is the key genuine?), certification status, known vulnerabilities from a curated advisory database
- **PIN:** status and remaining attempts, set or change the PIN (incl. keys that require a first PIN change, e.g. pre-registered YubiKey as a Service keys)
- **Passkeys:** list discoverable credentials per website and delete them
- **Fingerprints** (bio keys): enroll with live guidance, rename, delete
- **Factory reset:** guided flow (re-plug, touch)
- **History:** keys seen before stay in the sidebar with their last known state, a custom name and an activity timeline
- **Languages:** German and English, light and dark mode
- CSV export of every connected key to `~/keymelier/exports/`

## Download

Ready-made builds are attached to the [latest release](https://github.com/FiraSenax/KeyMelier/releases/tag/latest) (built automatically from `main`).

### First launch on macOS

The app is not notarized by Apple, so macOS blocks it the first time:

1. Unzip `KeyMelier-macOS.zip` and move **KeyMelier.app** to **Applications**.
2. Open it. macOS says it "cannot verify" the app – click **Done** (not "Move to Trash").
3. Open **System Settings → Privacy & Security**, scroll down to the message about KeyMelier and click **Open Anyway**, then confirm with your password or Touch ID.

This is needed only once. Alternatively, in Terminal: `xattr -dr com.apple.quarantine /Applications/KeyMelier.app`

### First launch on Windows

1. Unzip `KeyMelier-Windows.zip` and open the `KeyMelier` folder.
2. Right-click **KeyMelier.exe** → **Run as administrator** (Windows only allows FIDO access to elevated programs).
3. If SmartScreen shows "Windows protected your PC", click **More info** → **Run anyway**.

## Build it yourself

### macOS app

```bash
./build-mac.command          # produces dist/KeyMelier.app
cp -R dist/KeyMelier.app /Applications/
```

The app is not signed; a locally built copy opens normally. No drivers are needed (macOS uses IOKit HID).

### From source

```bash
git clone https://github.com/FiraSenax/KeyMelier
cd KeyMelier
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python3 app.py
```

Or double-click `run.command` (macOS) / `run.bat` (Windows).

### Windows

> On Windows 10 1903 and later, direct CTAP2 HID access requires elevated privileges. Right-click `run.bat` → **Run as administrator**. `build-windows.bat` builds `dist\KeyMelier\KeyMelier.exe`.

## Privacy and security

- KeyMelier is a native window (pywebview). The UI talks to Python directly — there is **no local web server or open port**, so browser extensions, websites and other programs cannot reach it.
- PINs are only held in memory for the single operation that needs them and are never logged or stored. Unlocking for passkey/fingerprint management keeps a short-lived, key-scoped token (5 minutes) in memory only.
- Local data: `~/keymelier/history.json` (keys seen, events), `~/keymelier/settings.json` (language), `~/keymelier/exports/` (CSV), `~/.keymelier/mds3_cache.json` (FIDO metadata cache).

## Limitations

- Only passkeys stored **on** the key (discoverable credentials) can be listed. Classic two-factor registrations (U2F / "security key as second factor") are not stored on the key and cannot be listed by any tool.
- FIDO keys expose no unique serial number over FIDO. Two keys of the same model and firmware batch share one history entry.
- A factory reset deletes passkeys, PIN and fingerprints but does not fix firmware vulnerabilities.

## FIDO Alliance MDS3

On first launch the app downloads the [FIDO Alliance Metadata Service](https://mds.fidoalliance.org/) blob and caches it for 24 hours. It is used to resolve the AAGUID to model name and vendor icon, check certification status, and verify attestation certificate chains.

## Security advisories

`data/advisories.json` maps vulnerabilities to affected AAGUIDs and firmware ranges. Only entries verified against the vendor advisory and the MDS3 metadata (AAGUID + authenticatorVersion) are included:

| ID | Severity | Affected | Condition |
|---|---|---|---|
| CVE-2024-45678 (EUCLEAK, YSA-2024-03) | Medium (CVSS 4.9) | YubiKey 5 (incl. FIPS), Security Key Series | firmware < 5.7.0 |
| CVE-2024-45678 (EUCLEAK, YSA-2024-03) | Medium (CVSS 4.9) | YubiKey Bio Series | firmware < 5.7.2 |

When adding entries, derive the AAGUIDs from MDS3 rather than by hand and include a `references` link to the official advisory.

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
