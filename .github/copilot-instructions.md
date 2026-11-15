# Working on KeyMelier

Read the root `AGENTS.md` first, including compatibility, device-safety and review
rules. Use Copilot primarily to implement, explain and test changes. CodeRabbit
is the default PR reviewer; request a second Copilot review only when the owner
explicitly asks for one.

## Architecture and compatibility

- KeyMelier is a Python 3.11–3.14 desktop application for macOS, Windows and
  Linux. `app.py` hosts pywebview; `keymelier_core/` handles devices, operations,
  storage, sync and updates; `static/` contains the JavaScript/CSS/HTML UI.
- The frontend calls the Python bridge directly. There is no local HTTP server.
  Retain existing bridge callers, stored data/settings, import/export and sync
  formats, update paths, older supported key firmware and all three platforms.
- Preserve native confirmation, deliberate PIN attempts, token permission scopes,
  expiry, cancellation and disconnect handling. Never fix a failure by silently
  retrying authentication, broadening permissions or using plaintext storage.
- Keep untrusted device/import content as text, maintain CSP protections and
  update all eleven supported UI languages for user-visible changes.
- Use synthetic devices and temporary data in tests. Do not access physical keys,
  personal history, the OS credential store or release-signing credentials unless
  that specific action has been authorized. Keep hardware/package acceptance
  separate from source tests; consult `HARDWARE_TESTS.md` and `CODE_SIGNING.md`.

## Environment and checks

Create an isolated environment with `python3 -m venv .venv` on macOS/Linux or
`py -3 -m venv .venv` on Windows, using a supported interpreter, then activate it
for your shell. Commands below assume its `python`, `ruff` and other executables
are on PATH; Windows uses `.venv\Scripts`, macOS/Linux use `.venv/bin`.
CI runtime versions, OS prerequisites and the full check matrix are defined in
`.github/workflows/build.yml`. Keep dependency pins and hashes intact.

```sh
python -m pip install --require-hashes -r requirements.txt
python -m pip install --require-hashes --only-binary=:all: -r requirements-quality.txt
python -m unittest discover -s tests -v
ruff check app.py keymelier_core tools
ruff check tools tests --select E9,F63,F7,F82
```

Choose checks for the change; a documentation/instruction-only change normally
needs `git diff --check`, link/path verification and configuration validation.
For Python changes, run the relevant regression tests and the backend suite.
Useful existing checks for UI changes are:

```sh
node --check static/CHANGED_FILE.js
node tests/ui_security.cjs
python tools/check_html_sinks.py
node tools/export_native_text.cjs --check
node tests/accounts_model.cjs
node tests/website_release.cjs
```

Replace `CHANGED_FILE.js` with each edited script. Browser tests in
`tests/ui/` require Chrome/Chromium (`CHROME` can select the executable):
`ui_test.cjs`, `csp_test.cjs`, `secret_forms.cjs` and `ui_stress.cjs`.
For dependency changes, also run `python tools/export_requirements.py --check`
and `python tools/license_inputs.py`. For hardware-result documentation, run
`python tools/make_hardware_page.py --check`. Run `git diff --check` before
finishing and report unavailable checks without claiming they passed.

## Review handoff

Keep PRs focused and explain the concrete behavior change and validation.
Batch related commits before pushing. Follow the CodeRabbit review loop in
`AGENTS.md`, including checking the latest reviewed commit and respecting manual
review/rate-limit requirements. Reviews do not authorize merging or publishing
a release, changing billing or enabling CodeRabbit Agent/Autofix.
