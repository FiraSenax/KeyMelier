# Testing KeyMelier

What is checked automatically, how to run it yourself, and what still needs
a person with real keys. Nothing here touches real security keys or real
user data: tests use fictional demo data, temporary folders and simulated
devices.

## Automatic checks

| Check | What it proves | Where it runs |
|---|---|---|
| `python -m unittest discover -s tests` | Backend logic: PIN/probe handling (wrong PIN sent once, never retried), history, sync (encryption, merge, shared ids, broken files), key replacement, upgrade from published releases, failure cases, update download | CI job `test` (macOS, Windows, Ubuntu) |
| `node tests/accounts_model.cjs` | Account model: identity rules, search coverage, filters, replacement plan | CI job `test` |
| `node tests/ui_security.cjs` | Attestation classification in the UI | CI job `test` |
| `node --check static/*.js` | Every UI script parses | CI job `test` |
| `node tests/ui/ui_test.cjs` | The real UI page on demo data in headless Chrome, driven with **real keyboard and mouse input** (DevTools protocol): navigation, filters, search, menus, dialogs and focus, guided replacement, error message when a key is pulled out while reading, no page errors | CI job `ui` (Ubuntu) – required for the builds |
| `python tools/smoke_packaged.py` | The **built app** from `dist/` starts its real window in a temporary home (no key access, no network) and checks runtime libraries, bundled data, translations, icons, CSS and the page ↔ backend bridge (46 checks); on Linux the AppImage itself under Xvfb with a D-Bus session and an unlocked Secret Service | CI jobs `build-macos`, `build-windows`, `build-linux` (x86_64, aarch64) after building/signing |
| `python tools/sbom.py --check … --strict` | The shipped SBOM is complete: SPDX licenses, the SHA-256 of every installed file (from pip's report, allowed by the lock), bootloader, CPython, OpenSSL, Simple Icons | CI jobs `build-macos`, `build-windows`, `build-linux` (also at the end of `build-linux.sh`) |
| `python tools/check_artifacts.py macos\|windows dist` | Packages exist and are not empty, ZIP/DMG structure, version in Info.plist and in the Windows version resources (app and installer), signing state as reported (ad-hoc / not signed while unsigned), SBOM, licence notices | CI jobs `build-macos`, `build-windows` |
| `python tools/check_artifacts.py linux dist --arch …` | The AppImage is an executable type 2 AppImage for the architecture; its file system holds the app, the page, the signed advisories, the udev rules and the right version (read with `unsquashfs`); SBOM, licence notices | CI job `build-linux` |
| `python tools/check_artifacts.py restore-exec artifacts` | After the artifact download (which drops the execute bit): exactly the two AppImages are executable again, no other file changes, a missing AppImage fails | CI job `release`, before the checksums |
| `python tools/check_artifacts.py release artifacts …` | Everything to be published: no file missing or extra, source commit, locks equal the repository's, versions, SBOMs, `SHA256SUMS.txt` lists exactly the files and every hash verifies, release notes state the real signing state | CI job `release` before publishing |
| `python -m unittest tests.test_release_metadata` | One version in `version.py`, `pyproject.toml`, `uv.lock`, app bundle and installer sources, and a changelog entry for it; the workflows are valid YAML | CI job `test` |
| `python tools/advisories_sign.py verify` | The bundled vulnerability database is validly signed | CI job `test`, daily *Advisory watch* |

A failure in any of these stops the release: the builds need `test` and
`ui`, the release needs both builds.

On failure CI keeps evidence as artifacts: `ui-test-artifacts`
(screenshot, browser log, failed checks) and `smoke-artifacts-macos` /
`smoke-artifacts-windows` / `smoke-artifacts-linux-<arch>` (self-test report, app log, output, the page's
text and markup when page checks fail, a screenshot when the start hangs).

## Running them locally

```bash
venv/bin/python -m unittest discover -s tests       # backend
node tests/accounts_model.cjs && node tests/ui_security.cjs
node tests/ui/ui_test.cjs                          # needs Chrome/Chromium/Edge; CHROME=/path to choose
./build-mac.command && venv/bin/python tools/smoke_packaged.py   # the packaged app (macOS)
```

On Windows: build with `build-windows.bat`, then
`python tools\smoke_packaged.py` (the app asks for administrator rights).

On Linux (or in an Ubuntu 24.04 container, with the packages of the CI job
`build-linux`):

```bash
./build-linux.sh
xvfb-run -a dbus-run-session -- bash -c 'echo -n test | gnome-keyring-daemon --unlock --components=secrets >/dev/null;
  python3 tools/smoke_packaged.py dist/KeyMelier-Linux-$(uname -m).AppImage'
```

Useful switches: `UI_TIMEOUT_MS`, `UI_ARTIFACTS`, `SMOKE_TIMEOUT`,
`SMOKE_ARTIFACTS`. The packaged app can also be started by hand with
`KeyMelier --self-test result.json`; it quits by itself and writes
`result.json` and `result.log`.

## Upgrade compatibility

`tests/fixtures/compat/<tag>/` holds `history.json` and `settings.json`
written **by the code of that release** (v1.4.0, v1.5.0, v1.6.0, v1.6.1, v1.7.0) with
fictional keys: labels, listed and searched passkeys, authenticator
accounts, a lost key with a ticked service, a running key replacement with
progress, settings and (1.6+) a sync id. `tests/test_upgrade_compat.py`
checks that the current code keeps their meaning, that load/save/load is
stable, and that stateless mode and a switched-off history leave the files
untouched. No data migration is needed today.

After a release, add its data: `venv/bin/python tools/make_compat_fixtures.py v1.8.0`
(or without arguments for the default list) and commit the new folder.

This covers the **data**. Installing a new version over an old one is a
separate, manual check:

### Installer update – manual procedure

Use a test user account or a computer without important KeyMelier data.

**macOS**
1. Install the previous release from its DMG (drag to Applications).
2. Start it; name a key, mark a key as lost, start a key replacement and
   tick one entry; switch the language; if you use sync, set it up.
3. Quit KeyMelier. Download the new DMG (or use *About → Check for updates*),
   drag the app over the old one and choose **Replace**.
4. Start it. Check: version under *About*, key names, the lost key, the
   running replacement and its tick, the language, sync status (*Settings*).
5. First launch of an unsigned build: *System Settings → Privacy & Security
   → Open Anyway* (until notarization is available).

**Windows**
1. Install the previous `KeyMelier-Windows-Setup.exe`.
2. Same data as above.
3. Quit KeyMelier, run the new installer (it updates in place).
4. Same checks as above; also: Start menu entry, uninstaller present,
   SmartScreen hint for unsigned builds.

Record the result in [HARDWARE_TESTS.md](HARDWARE_TESTS.md) (column
*Result*, note "update from x.y").

## Limits of the automatic checks

- **Browser engine:** UI tests run in Chrome on Linux. The app uses WebKit
  (macOS), WebView2 (Windows) and Qt WebEngine (Linux); the packaged start
  test covers loading, resources and the bridge there, but not every
  interaction.
- **Linux:** built and start-tested in Ubuntu 24.04 containers (aarch64
  natively, x86_64 emulated) on 2026-09-27; not yet run in CI or on a Linux
  desktop, and no key has been used on Linux yet (containers on macOS get no
  USB). Wayland sessions, other distributions and the udev rules are open
  rows in [HARDWARE_TESTS.md](HARDWARE_TESTS.md).
- **Windows start test in CI** runs on the hosted runner (desktop session,
  WebView2, app with administrator rights) – first verified on 2026-09-27
  (43 checks, run 36321724829). If a future runner image cannot show
  windows, the job fails visibly; run the check on a Windows PC instead.
- **No security keys in CI:** detection, reading, PIN entry, unplugging and
  reconnecting real keys are covered by [HARDWARE_TESTS.md](HARDWARE_TESTS.md).
- **Not tested automatically:** screen readers, high-contrast modes,
  installer updates (manual procedure above), notarized/signed builds
  (signing credentials are not configured yet).
