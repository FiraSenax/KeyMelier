# Testing KeyMelier

What is checked automatically, how to run it yourself, and what still needs
a person with real keys. Nothing here touches real security keys or real
user data: tests use fictional demo data, temporary folders and simulated
devices.

## Automatic checks

| Check | What it proves | Where it runs |
|---|---|---|
| `python -m unittest discover -s tests` | Backend logic: PIN/probe handling (wrong PIN sent once, never retried), history, sync (encryption, merge, shared ids, broken files), key replacement, upgrade from published releases, failure cases, update download | CI job `test` (macOS, Windows) |
| `node tests/accounts_model.cjs` | Account model: identity rules, search coverage, filters, replacement plan | CI job `test` |
| `node tests/ui_security.cjs` | Attestation classification in the UI | CI job `test` |
| `node --check static/*.js` | Every UI script parses | CI job `test` |
| `node tests/ui/ui_test.cjs` | The real UI page on demo data in headless Chrome, driven with **real keyboard and mouse input** (DevTools protocol): navigation, filters, search, menus, dialogs and focus, guided replacement, error message when a key is pulled out while reading, no page errors | CI job `ui` (Ubuntu) – required for the builds |
| `python tools/smoke_packaged.py` | The **built app** from `dist/` starts its real window in a temporary home (no key access, no network) and checks runtime libraries, bundled data, translations, icons, CSS and the page ↔ backend bridge (43 checks) | CI jobs `build-macos`, `build-windows` after building/signing |
| `python tools/advisories_sign.py verify` | The bundled vulnerability database is validly signed | CI job `test`, daily *Advisory watch* |

A failure in any of these stops the release: the builds need `test` and
`ui`, the release needs both builds.

On failure CI keeps evidence as artifacts: `ui-test-artifacts`
(screenshot, browser log, failed checks) and `smoke-artifacts-macos` /
`smoke-artifacts-windows` (self-test report, app log, output).

## Running them locally

```bash
venv/bin/python -m unittest discover -s tests       # backend
node tests/accounts_model.cjs && node tests/ui_security.cjs
node tests/ui/ui_test.cjs                          # needs Chrome/Chromium/Edge; CHROME=/path to choose
./build-mac.command && venv/bin/python tools/smoke_packaged.py   # the packaged app (macOS)
```

On Windows: build with `build-windows.bat`, then
`python tools\smoke_packaged.py` (the app asks for administrator rights).

Useful switches: `UI_TIMEOUT_MS`, `UI_ARTIFACTS`, `SMOKE_TIMEOUT`,
`SMOKE_ARTIFACTS`. The packaged app can also be started by hand with
`KeyMelier --self-test result.json`; it quits by itself and writes
`result.json` and `result.log`.

## Upgrade compatibility

`tests/fixtures/compat/<tag>/` holds `history.json` and `settings.json`
written **by the code of that release** (v1.5.0, v1.6.1, v1.7.0) with
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
*Ergebnis*, note "Update von x.y").

## Limits of the automatic checks

- **Browser engine:** UI tests run in Chrome on Linux. The app uses WebKit
  (macOS) and WebView2 (Windows); the packaged start test covers loading,
  resources and the bridge there, but not every interaction.
- **Windows start test in CI** runs on the hosted runner (desktop session,
  WebView2, app with administrator rights) – first verified on 2026-09-27
  (43 checks, run 36321724829). If a future runner image cannot show
  windows, the job fails visibly; run the check on a Windows PC instead.
- **No security keys in CI:** detection, reading, PIN entry, unplugging and
  reconnecting real keys are covered by [HARDWARE_TESTS.md](HARDWARE_TESTS.md).
- **Not tested automatically:** screen readers, high-contrast modes,
  installer updates (manual procedure above), notarized/signed builds
  (signing credentials are not configured yet).
