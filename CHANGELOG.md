# Changelog

## Unreleased

## 1.8.8 — 2026-10-29

Security release candidate; hardware validation is ongoing.

- Require a native, default-cancel confirmation for sensitive key changes, resets, deletions and sync-file removal, bound to the selected device and one request. Existing PIN, touch and overwrite checks remain in force.
- Block foreign WebView navigation before loading, including local files and data URLs. Render sidebar, passkey and OATH account values through DOM text/attribute APIs; add an HTML-sink review guard and a production-CSP browser test.
- Prefer known GnuPG installations and exclude relative/current-directory executable lookup. Reject invalid UTF-8 and oversized history imports without merging partial data.
- Distinguish unsupported smart-card features from access failures, stop PIV deletion if certificate deletion fails, and retain sanitized error locations without logging secrets.
- Encrypt saved history by default using the OS credential store. Automatically verify an encrypted copy of legacy history and preserve its plaintext original as a backup; no plaintext fallback when the store is locked or unavailable. Export and sync formats remain unchanged.

## 1.8.7 — 2026-10-29

Stable release of the reviewed RC9 application code, including the security and compatibility fixes below.
License distribution, metadata freshness, macOS menu responsiveness and build dependency maintenance.

- Authenticate updates with a separate Ed25519 signature bound to the exact release tag, retain observed signing-key revocations locally and require an explicit action to open a downloaded installer. Production tags must identify a commit already merged into main before signing and publication.
- Bind advisory freshness to a signed review date, reject future-dated data and require every managed source to be valid and reachable before showing `OK`. Explain unavailable company sources and VPN requirements in the app while preserving known warnings.
- Isolate damaged sync files, validate incoming timestamps and deletion marks, preserve local history when the computer clock was wrong, and distinguish imported test events from local tests. Unreadable encrypted history remains intact without a plaintext fallback.
- Correct firmware decoding and effective certification selection, tighten link and sync-folder handling, and clarify that an authenticity-test touch does not unlock key management.
- Update the Linux Qt runtime to 6.11.3. Windows Setup now offers Microsoft's verified runtime installer when its prerequisite is missing or too old and resumes after successful installation.
- Fix a macOS UI deadlock when using the native About, Check for Updates or key-selection menu actions. Run their JavaScript calls off the AppKit thread and exercise all three actions in a native regression test.
- Add an optional release-candidate update channel in Settings, with numeric RC ordering, final-release upgrades and no automatic downgrade. Record the RC tag in build metadata and allow explicit publication of a verified signed RC as a GitHub prerelease.
- Show the AAGUID in a compact header line with a copy button instead of a separate overview card; keep saved-value and all-zero explanations in Technical Details.
- Update the build dependency setuptools to 84.2.1, including the archive and legacy wheel path traversal fixes from 84.1.0; refresh its reviewed licenses and source evidence together.
- Reduce service logos to individually reviewed assets for licensing reasons; other services use a letter avatar.
- Include complete third-party notices, source archives and build provenance. Check reviewed dependency versions, licenses and embedded sources on upgrades; retain KeyMelier’s MIT license.
- Use the separately installed Microsoft Visual C++ runtime on Windows; the installer checks the prerequisite and portable downloads explain how to install it.
- Keep the existing CSV header and column order. The deprecated `mds_description` and `mds_status` columns now contain empty values and are planned for removal in a future format change.
- Explain expired or unverified FIDO MDS data separately from an AAGUID absent from current metadata, in all supported languages. A still-valid cache works offline; otherwise model text, icon and certification status are withheld until verification succeeds. Device operations remain available.
- Remove detached MDS fields from saved history and sync; existing history snapshots are migrated. Manufacturer inference uses device information, without copying MDS descriptions into persistent identity fields.
- Add an offline, searchable license reader under About, with complete document export, including the macOS About entry.
- Document public security reporting and the existing diagnostic report export in SECURITY.md.

## v1.8.7-rc.9 — 2026-10-29

- Require version tags to match the workflow checkout and a commit already contained in main before production signing or publication; unsigned branch builds remain available. This workflow guard does not separate a human from an agent sharing owner credentials.
- Explain unreachable company advisory sources directly in the key overview and security details, with VPN/update-check guidance in every supported language; retain all known security findings.
- Automatically publish reviewed RC tag pushes as public, signed GitHub prereleases after all release checks; retain manual artifact-only rehearsals and the separate stable update channel.

## v1.8.7-rc.8 — 2026-10-29

- Preserve local history timestamps and lost/replacement state when the computer clock was wrong; keep strict validation for imports and sync and prevent preserved future dates from pinning merge decisions.
- Show a specific, localized error for unreadable update revocation data and preserve all evidence; known revocation markers still take precedence. Document recovery without deleting the emergency stop.
- Check accidental revocation of the active update key in CI; require an explicit matching emergency acknowledgement while keeping the release signer's unconditional rejection of revoked keys.
- Document intranet/VPN offline behavior and cover three-digit decimal firmware fallback separately from known vendor encodings.
- Clarify in every supported language that touching a key for the authenticity test does not unlock it for management; the sidebar lock reflects the separate management unlock.

## v1.8.7-rc.7 — 2026-10-29

- Require every managed advisory source to be current and valid before showing `OK`; retain signed warnings and rollback protection across restarts and reject source redirects.
- Isolate damaged sync files, consume peer files only after successful merging, normalize timestamps to UTC and reject future-dated changes/removal marks. Preserve the existing sync format and prevent duplicate legacy events after normalization.
- Label imported or synced test events by their origin; correct decimal firmware decoding and use the latest effective certification status while retaining compromise warnings.
- Check advisory expiry during normal device polling, restrict sync-folder setup to native selections or existing configuration, harden browser links and PIN-length display, and omit device names from connection logs.
- Keep the app usable when encrypted history cannot be opened, preserving the encrypted file and reporting the blocked history without a plaintext fallback.

- Fix the blurry sidebar logo on macOS by using the existing high-resolution PNG instead of the filtered SVG at small display sizes.
- Bind advisory freshness to its signed review timestamp; replaying old signed data no longer restores a positive security verdict. Reviewed advisory data must be re-signed within 45 days.
- Reject future-dated official and managed advisory files before caching/comparing dates, and recover from such caches. Require a signed review less than 14 days old for release builds and publication; the daily check flags reviews at 30 days.
- Review and re-sign the advisory database on 2026-10-29; add CVE-2025-29991 and CVE-2024-35311 with vendor-specific firmware boundaries and verified FIDO model identifiers.
- Authenticate update checksums with a separate, pinned Ed25519 key and the exact release tag. Automate protected release signing and one-time key setup; require an explicit Open action after downloading.
- Add a repository emergency stop by public-key fingerprint. Once observed, a revocation persists locally and blocks update downloads and installer opening, including offline. This deny-only mechanism cannot establish trust in a replacement key or defeat a repository attacker withholding the initial notice.
- Update the Linux PySide/Qt runtime to 6.11.3 with matching source/license evidence and the library replacement probe.
- When the Windows C++ runtime is missing or too old, offer its official Microsoft download, verify its signature, open Microsoft's installer and resume KeyMelier setup after success. Existing runtimes skip this step; silent installations still require prior provisioning.

## 1.8.6 — 2026-10-26

Signed Windows releases, security hardening and easier access to key and account details.

- Import one authenticator QR code from a local PNG/JPEG image. Review and edit the decoded account before saving; preserve the hash algorithm, digits, TOTP period and HOTP counter. No screenshot capture, upload or automatic key write. Multi-account exports are not supported in this release.
- Show and copy complete passkey credential IDs and user IDs, with wrapping for long values.
- Read additional device identifiers directly over FIDO HID on supported Token2, Solo 2, Nitrokey 3 and Nitrokey Passkey devices. Recheck before operations; unsupported or malformed replies do not become identities. Previously shared history without a serial stays separate for review. These new vendor reads still need model-specific hardware confirmation; this is not the full serial-less recognition project.

- Show the AAGUID in the key overview and let users copy it from there or from technical details without unlocking the key. Mark saved offline values and explain an all-zero AAGUID.
- Sign the Windows app, installer and uninstaller with Certum SimplySign, replacing SignPath. Verify the publisher and trusted timestamp with native Windows checks. macOS remains Developer ID signed and notarized; Linux remains unsigned. Website signing status follows verified stable-release metadata.
- Prepare a separate Windows MSIX test package with local test signing, installation and upgrade checks. Packaged installations defer application updates to their package manager. This is preparation only; no Microsoft Store submission or approval.

- Rename the core package and build spec to KeyMelier, update imports and build tooling, and consolidate the license documentation. Upgrade fixtures still support historical releases with the former package name.
- Stop displaying previously verified authenticity results when the supporting metadata or revocation information expires.
- Keep unexpected exception messages out of UI responses and logs, including desktop callbacks, smart card operations and background tasks.
- Extend stateless mode to storage helpers, exports, update downloads, GnuPG imports and credential-store writes. The Linux UI page uses anonymous memory instead of a temporary file in this mode.
- Report encrypted-history save failures without falling back to plaintext. Disabling account tracking also clears saved account details when history is disabled; imports and sync honor that setting.
- Serialize initial smart card discovery with FIDO access before a reader-to-key mapping is available, and discard reader mappings on disconnect.
- Add regression coverage for these guarantees, non-resident test credentials, connection-scoped authorization expiry and CSV formula neutralization. Check build tools with Ruff and support the documented strict SBOM command.

## 1.8.5 — 2026-10-22

Security and dependency maintenance release. No new application features.
Upgrade from 1.8.4 and earlier to receive the corrected HTTPS certificate bundle.

- **Security (application):** update certifi to 2026.10.19 to remove the emSign ECC Root CA - G3 trust anchor affected by compromised intermediate CA keys (GHSA-6q48-6c7w-9gw2). Rebuild the applications with the corrected HTTPS CA bundle; add a regression check against the removed root's fingerprint.
- **Security (development/CI):** update uv to 0.13.4 to remove trust in the affected emSign root (GHSA-hq85-5cpj-mr62). uv remains isolated from the application and package-build dependencies.
- Update pycparser to 3.11, pythonnet to 3.2.1 and Ruff to 0.17.1. Keep the Linux Qt libraries at 6.11.2 under the single upstream PySide6 package, so future updates resolve Essentials, Addons and Shiboken together; include its license and SBOM metadata.
- Restore build dependency consistency after automated updates: keep the project manifest, lockfile and all three hash-pinned requirements exports in sync. Resolve Qt and Shiboken together, isolate quality tools in their own dependency group, and check exports offline on every CI platform.

## 1.8.4 — 2026-10-02

Fixes for 1.8.3. No new features.

- **Keys seemed to be unplugged and plugged in again** (YubiKeys whose serial number is not in the USB descriptor, which is most of them): 1.8.3 re-read the serial number through the management application on every poll, once a second, and a single failed read made the key look like a different device – the unlock was lost, the authenticity test ran again and the selection jumped. The serial is now re-checked at most every 10 seconds, including after failed reads. A failed read never counts as another device, and a swapped key of the same model is still noticed. Before an action, the serial is still checked afresh; a failed read is tried once more and then reported as "busy, try again" instead of "key no longer connected".
- **A click beside the unlock dialog** closed it while a passkey search or a PIN check was running – the search went on invisibly and its result was lost. Such a click is ignored now (like Escape); waiting for a finger can still be left that way.
- **"Enter PIN instead"** could fail with "busy" when the key took a moment to end the fingerprint wait; the PIN request now waits for it. Closing the dialog or locking the key cancels waiting PIN requests immediately too, before they reach the device or can restore the unlock.
- **A wrong PIN after closing the dialog** used up an attempt without telling you; it is now reported.
- **PIV:** one unreadable certificate no longer stops the whole PIV page – that slot shows "Certificate unreadable" and can be deleted or set up again (it still counts as occupied, so nothing is overwritten by accident).
- Unexpected errors are logged with file, line and function again (no messages, values or paths), so reports can be diagnosed.
- The update check reads GitHub's answer with a size limit, like the other downloads.

## 1.8.3 — 2026-10-02

Quality, stability and security release. No new product features.

macOS builds are Developer ID signed and notarized. Windows and Linux builds remain unsigned.

- Remove the global fast hash of the sync passphrase. Derived keys are cached per sync session by salt and released on reconfiguration/disable; existing encrypted sync files remain compatible.
- Close HID connections even when the initial device handshake fails; retain the original error and release the device lock if cleanup also fails.
- Split the UI into focused view modules and keep dialog event handling with its state. Extract the service bridge and cancellable-operation registry into independently testable modules.
- Ignore late PIN/UV/search responses belonging to a closed or replaced dialog; prevent duplicate PIN submissions. Correct the function test's initial PIN prompt and prevent a previous key's result from replacing the selected key's result.
- Clear fingerprint permission hints on disconnect, check token scopes before management operations, and prevent a late unlock from restoring a locked/cancelled session. A second fingerprint wait cannot replace the first wait's cancellation target.
- Register queued PIN requests for cancellation too; closing their dialog or locking the key prevents a late result from restoring access.
- Give each observed device connection a fresh runtime ID. Check observable identity again before CTAP access, treat replacements as disconnect/reconnect, and discard late updates from disconnected keys.
- Keep occupancy checks and key generation under the same locks for PIV, OpenPGP and OTP. Normalize PIV slot aliases before overwrite checks and reject application-key generation in the reserved attestation slot.
- Verify RP binding, user presence, required user verification and credential identity in the existing function test in addition to its signature.
- Download updates through private random temporary files; exclusively create the verified destination without overwriting existing files or following pre-existing symlinks. Require exact checksum filenames, matching release URLs and successful HTTP responses.
- Bound downloaded metadata, advisories and checksum bodies before parsing/verification. Reject malformed bridge calls and keep unexpected exception text out of UI responses and bridge logs.
- Treat PIV certificate/metadata read failures as errors instead of empty slots, preserving overwrite protection.
- Reject stale or modified pywebview scripts before packaging; a fresh build environment fixes the reproduced local Cocoa startup crash.
- Support signed/notarized macOS RC tags (`vX.Y.Z-rc.N`) with checked Actions artifacts only, without publishing a release or updating the website.
- Add regression tests for these failure cases. Platform builds, signing and physical hardware checks remain release gates; local automated checks are recorded in `plans/1.8.3-quality-review.md`.

## 1.8.2 — 2026-10-02

The first release since 1.8.0 (1.8.1 was tagged but never published: in CI the signing keychain was removed before the disk image was signed; its changes are included here).

**macOS: signed and notarized.** The first release whose macOS app is signed with the maintainer's Apple Developer ID and notarized by Apple – it opens without the "cannot verify" warning. The hardened runtime now runs without exceptions (the `disable-library-validation` entitlement is gone). Windows and Linux builds are still unsigned.

**Changed**

- **Unlocking a key with a fingerprint:** for a key with an enrolled fingerprint the unlock dialog now asks for the finger first – the key waits for it as soon as the dialog opens. *Enter PIN instead* and *Cancel* stop that wait on the key (no attempt is used up). A finger that is not recognised offers *Try again* – a new attempt never starts by itself; after too many unrecognised fingers the dialog switches to the PIN. Keys without a fingerprint (or that cannot unlock with one) still ask for the PIN.

**Fixed**

- **Fingerprint unlock on a YubiKey Bio** failed with "UNAUTHORIZED_PERMISSION": the key grants fingerprint and settings management only with the PIN. The fingerprint unlock now asks for passkey management alone when the key refuses more (it refuses before asking for the finger, so no attempt is used); the *Fingerprints* and *Settings* tabs then ask for the PIN.
- **What this key can do** on a YubiKey without a smart card interface (YubiKey Bio): Authenticator, OpenPGP, PIV and OTP now say *no* instead of *not checked yet* forever; the card has space above it and the count sits on the right.
- **Small windows:** the sidebar scrolls as one, so key rows are no longer cut off; version, status and language stay at the bottom; the tabs stay on one line with faded edges; the *Advanced* menu stays inside the window.

## 1.8.0 — 2026-09-27

The first release since 1.7.0 (1.7.1 was prepared but never published; its changes are included here).

**New**

- **Linux:** AppImage for x86-64 and ARM64 (`KeyMelier-Linux-<arch>.AppImage`, unsigned, in `SHA256SUMS.txt`). Qt web view (PySide6, LGPL-3.0) bundled; the sync passphrase goes to the desktop keyring (Secret Service – GNOME Keyring, KWallet, KeePassXC), and without one sync says so instead of failing; udev rules for key access on systems without systemd's own rule (inside the AppImage and in `packaging/linux/`); smart card functions via `pcscd`; clipboard via `wl-copy`/`xclip`/`xsel`; system language from `LANGUAGE`/`LANG`; update check offers the AppImage for your processor and opens its folder. The introduction and the empty screen explain device access on Linux. CI builds and start-tests both AppImages under Xvfb and checks their contents. See *Linux* in the documentation.
- **Additional advisory sources for organisations** (no setting in the app; machine-wide only: Windows `HKLM\SOFTWARE\Policies\KeyMelier`, macOS managed preferences, Linux `/etc/keymelier/policy.json`): signed with the organisation's own key, file or https URL. They can only add findings – the official database always stays active and official entries cannot be removed or changed. Each such finding shows *Source: company policy (name)*; the state of each source is listed under *Data freshness*. Unsigned or invalid sources are ignored and logged. Links in such findings (e.g. to the intranet) open in the browser – exactly those links, nothing else on that server. Every field of such a source is checked against a whitelist (ids, AAGUID format, firmware versions, CVSS, https links without quotes or brackets, no control characters; unreadable firmware bounds skip the entry instead of matching every firmware). See [ENTERPRISE.md](ENTERPRISE.md).
- **All keys at once** (sidebar, with two or more keys): status table of every key; re-check all plugged-in keys; read them one after another; change the PIN on several keys – each key confirmed on its own, stop at the first error, never an automatic retry, the new PIN is not kept afterwards.
- **Transparency about key support:** the overview says *What this key can do* (full, partly – e.g. passkeys by search only on FIDO 2.0 –, not, not checked yet); "this key cannot do that" errors now name the reason; a public [tested keys](https://firasenax.github.io/KeyMelier/hardware.html) page is generated from HARDWARE_TESTS.md; community reports through the *Tested with a security key* issue form.
- **Inventory export** (Settings): keys with passkeys, authenticator, OpenPGP, PIV, OTP and the account rating as JSON or CSV, filterable by key and account category; names only, saved readable only by you, spreadsheet formulas in CSV neutralised.
- **Account overview easier to read:** rows are tinted by risk with a coloured edge and a symbol (✕ ! ? i ✓, always with text), and cells where a key in use lacks a risky account are marked as backup gaps; a legend explains both.
- **Introduction on first start:** what KeyMelier does; remember history or nothing at all; why Windows needs administrator rights; what the warnings for unsigned / not yet notarized builds mean (from the real build state) and how to check the checksum; how to begin. Skippable, reopen under About.
- **Diagnostic report** (About → *Diagnostic report…*): for bug reports, built only from a fixed list of technical fields (version, build, system, GUI, settings switches, counts, data status, recent operation names with error codes) – no key names, serial numbers, accounts, paths, URLs, host names, sync ids, passwords or error texts. Shown in full before saving; saved only where you choose; never sent.

**Fixed**

- **Files held by another program:** settings and history that cannot be read at start because another program holds them are left unchanged – not set aside, not overwritten in that session; only damaged content is set aside. One locked sync file no longer stops the others from being read.
- **Windows sync:** writing or reading a sync file no longer fails while another program (a cloud sync client, the other computer, a virus scanner) is using it at that moment – Windows' sharing violation is retried for up to two seconds; a file that stays locked is still reported, one that was just renamed is read in the next round.
- **Account overview:** the window no longer scrolls sideways (hidden screen-reader texts in the table widened the page); at the minimum window size long key names in the table header take at most two lines, so the matrix stays usable; buttons reached with the keyboard are no longer hidden under the fixed header and first column.
- **Reading a key tells the truth:** if the key is pulled out while reading, KeyMelier says so and what to do next instead of reporting success; parts that could not be read are named; known data is kept.
- **Unreadable data files are never overwritten:** a damaged `history.json` or `settings.json` (e.g. after an interrupted save) is kept as `*.unreadable-<time>`; KeyMelier starts with defaults and says so.
- The lock/search icons in the sidebar now work with Enter and Space.

**Quality and release checks**

- **SBOM complete and checked:** also lists the PyInstaller bootloader, both OpenSSL builds and the Simple Icons data; SPDX licenses for every component; the SHA-256 of each file actually installed (pip report, checked against the lock). Every CI build rejects an incomplete SBOM.
- Quality: UI tests with real keyboard input in CI, a start test of the packaged app on macOS and Windows, upgrade tests with data written by earlier releases, failure-case tests, `app.js` split into view modules, [TESTING.md](TESTING.md) and a hardware test matrix.
- **Source revision in every build:** About shows the commit the app was built from ("modified" for a local build with uncommitted changes, "unknown" without one); the diagnostic report contains the full commit; the release checks require it to match SOURCE_COMMIT.txt in every package.
- Release checks: the release job restores the AppImages' execute bit after the artifact transfer; a manual **release rehearsal** in CI runs the same builds, transfer and checks as a release without publishing, and keeps the checked packages and a report. The AppImages are start-tested unchanged in clean containers of the supported distributions on x86-64 and ARM64. UI load tests with 12 keys and 300+ accounts (search/filter speed, focus, sticky headers, dialogs at 1280×800 and 820×560, light/dark). The build workflow is valid YAML again and checked by a test.

**Known limitations**

- **Unsigned:** macOS builds are not notarized, Windows builds are not code-signed, the Linux AppImages are unsigned – compare the checksums in `SHA256SUMS.txt`.
- **Linux:** needs glibc 2.39 or newer. The AppImages are start-tested automatically in containers (Ubuntu 24.04 and 26.04, Debian 13, Fedora 43, openSUSE Leap 16.0 on x86-64 and ARM64, Arch Linux on x86-64) – without a security key, USB, Wayland or a real desktop. Key access on Linux has not been tested with hardware yet.
- **Automated tests** use demo data and synthetic keys; UI tests run in Chrome, not in each platform's web view. Results with real keys are recorded in [HARDWARE_TESTS.md](HARDWARE_TESTS.md).

## 1.7.0 — 2026-09-27

UI revision – what needs attention and what to do next:

- **Backup & loss** starts with account coverage (**Review accounts**), then **Lost a key?** and **Replace an old key**, plus a one-line sync status. Storage, history, "All keys belong to me", history export/import and sync setup moved to the new global **Settings** (app settings); a key's own settings are now called **Key settings**.
- **Account overview:** the summary cards are filters (keyboard accessible), combined with the search, with a match count, "Reset filter" and an empty state. Header row and account column stay visible while scrolling; the legend sits above the table; **Next step** explains what to do for problem accounts – without promising any automatic transfer.
- **Key check vs. account coverage:** the header, overview and checks keep "Key check" (the device) and "Account coverage" (accounts depending on the key) apart, so a flawless key can still show accounts without a backup. Unknown and stale data stay marked.
- **Key overview** leads with passkeys, authenticator accounts and open tasks ("Not read" instead of an empty count); missing optional hardware is one compact line; **Read key** reuses the unlock dialog / passkey search (no automatic PIN attempts); CSV export moved into the **⋯** menu.
- **Passkeys:** compact groups per service with search, labelled Rename/Delete and details on demand.
- **Replacing a key** is a guided view in four steps (choose, compare, test & confirm, summary) with "Open entries only"; "found on the new key" and "confirmed by you" stay separate, a tick never counts as technical proof.
- A running key replacement can be **cancelled** from Backup & loss (asks first; only the progress is forgotten, nothing changes on the keys).
- **Check for updates** lives in **About KeyMelier** (bottom of the sidebar) and, on macOS, in the KeyMelier menu.
- Readability: stronger contrast for hint and status text in light and dark mode, visible keyboard focus, larger click targets, focus kept in dialogs and returned on close, long explanations behind "Details", sync shown compactly ("last synced locally").

## 1.6.1 — 2026-09-27

Bug fixes only.

- **Sync: no data loss when two computers share a sync id.** A computer that took over another's sync id (e.g. settings copied to a new computer) skipped the existing file and overwrote it on its first write; a third computer then lost the first computer's data if that one stayed offline. Now every computer first reads and merges a file under its own id before writing. Who wrote it is recognised by an anonymous machine hash inside the encrypted file: another computer means a real collision and this one moves to a new, stored sync id; a normal restart keeps its id. An own file that cannot be read (incomplete, damaged, other passphrase) is never overwritten – the computer moves to a new id, keeps the file and shows a notice.
- Account overview: service logos and letters are centred in their tile.
- Website: the download buttons link the macOS disk image and the Windows installer instead of the ZIPs.

## 1.6.0 — 2026-09-27

- **About KeyMelier inside the app** (bottom of the sidebar) – also on Windows, which has no app menu: version, what KeyMelier does, privacy, links, open-source licenses and "check for updates".
- Sync: a file that is still arriving through the cloud is read again instead of showing an error; an error appears only if it persists. Two computers with the same sync id (e.g. settings copied to a new Mac) are detected and one takes a new id.
- **Check for updates** on request: at the bottom of the sidebar (with the installed version), in the macOS app menu below "About KeyMelier" and in the menu bar icon. It says clearly whether KeyMelier is up to date, a new version is available (then the usual download-and-install banner appears), or GitHub could not be reached.
- **Sync between your computers** (Backup & loss): pick a folder you already sync (iCloud Drive, OneDrive, Dropbox, Syncthing, NAS) on each computer. KeyMelier writes one file per computer, encrypted with a passphrase (scrypt + AES-256-GCM; the passphrase stays in the Keychain / Credential Manager), and merges the others: key names, history, what is on each key, lost and replacement status – the newest decision wins, also "no longer lost" and "removed". No server, no network service; the cloud provider only sees random ids. Security ratings are never taken over. Needs the saved history; off in stateless mode.
- **Display names no longer match accounts:** a passkey is assigned to an account only by the account name the service stored; entries with only a display name (e.g. "Administrator") stay "assignment unclear" and are never counted as each other's backup – in the account overview, backup rating, lost-key assistant and key replacement. The display name is still shown.
- **"About KeyMelier" says more** (macOS): what KeyMelier does, that everything stays on the Mac, and links to the website, source code and issue tracker – in all 11 languages.
- **Search coverage per website:** a passkey search now records its result and time for every website it asked. "Not there" is shown only for a website the key explicitly answered "no credentials" for; websites not asked, errors, unsupported or PIN-required answers and incompletely listed accounts stay "unknown". A finished search is no longer treated like a complete list of the key. Older or imported search data without per-site results is treated as unknown.

## 1.5.0 — 2026-09-27

- **Account ratings are strict:** accounts are identical only with the same service (rpId) and the same account name; nameless passkeys are never assigned to a named account ("assignment unclear"); only keys not marked as lost count; "passkey on two keys", "passkey plus code", "codes only" and "unclear" are distinguished. Account overview, backup view, lost-key assistant and security check share one model (`static/accounts.js`).
- **Passkey search results per site:** found, no credentials, not supported, PIN required, technical error; a stopped or failed search never removes known entries, partial results are marked, the search can be cancelled, a wrong PIN stops it at once without retrying, and a hit is explained as "credentials on the key", not a sign-in.
- **Provenance and freshness:** every entry shows whether it was read directly, found by search or imported, and when; keys that were not (fully) read show "?" instead of "not there"; stale data is flagged; the limits of the rating are explained.
- Regression tests for the account model and the passkey search.
- **Replace an old key** (Backup & loss): pick old and new key, see every passkey, authenticator account, OpenPGP key, certificate and OTP slot of the old key with two separate marks – "found on the new key" (checked from what the new key showed) and "confirmed by you". Guidance per type (passkeys are registered anew, never copied; codes set up again; OpenPGP only from your own backup; certificates reissued). Progress is kept with the history (session-only with history off); neither key is ever reset or changed.
- Removing a key from the history also ends a key replacement that pointed to it.
- **Simpler tab bar:** everyday areas stay direct; OpenPGP, PIV, OTP, key settings and technical details are in an "Advanced" menu (keyboard: arrows, Home/End, Esc). Tabs and the key header wrap in narrow windows instead of being cut off.

## 1.4.0 — 2026-09-27

- Service logos in the account overview, passkey and authenticator lists for brands that allow it (bundled from Simple Icons, CC0 icon data; nothing is fetched from the network). Brands that restrict logo use keep the letter.
- **Find passkeys on older keys** (FIDO 2.0, e.g. YubiKey 5.1): they cannot list passkeys, so KeyMelier asks them website by website – silently, for your known sites, common passkey services and your own domains; with the PIN including account names.
- **Account names (UPNs)** are remembered with the passkeys; the account overview rates every account separately (e.g. several Microsoft Entra accounts of one domain).
- Keys without passkey management (FIDO 2.0, e.g. YubiKey firmware 5.1) get a "read" action instead of the unlock, a clear explanation instead of "This key does not support that", and "passkeys not readable" in the account overview.
- Serial numbers in the sidebar, the key header and the account overview – usually printed on the key.
- Quick unlock: a lock next to each key in the sidebar asks for the PIN and reads everything on the key at once (passkeys, authenticator, OpenPGP, certificates).
- **Account overview** (personal mode): every service across all keys – passkeys and authenticator codes together – with a recommendation each (only on a lost key, only on one key, codes only, well protected), search and a problems filter; free passkey slots per key.
- **"All keys belong to me"** setting: turn it off when managing keys for several people – cross-key overviews and backup hints are then hidden.
- The macOS disk image opens as a styled window: KeyMelier and Applications side by side with a "drag to install" arrow, in KeyMelier's colours (`packaging/dmg-background.svg`, built with dmgbuild).

## 1.3.1 — 2026-09-27

- **Disk image and installer:** macOS releases come as `KeyMelier-macOS.dmg` (drag to Applications, also to update), Windows releases as `KeyMelier-Windows-Setup.exe` (installs or updates, Start menu entry, uninstaller). The zips remain as portable versions. On Windows KeyMelier requests administrator rights at start.
- **Update download in the app:** the update notice downloads the disk image or installer for this system, verifies it against the release's SHA-256 checksums and opens it – installing stays with the user.
- Documentation with screenshots on the website; layout fixes.

## 1.3.0 — 2026-09-27

**Security review** (details in SECURITY_REVIEW.md):
- Critical: the page no longer receives a Python object through the pywebview bridge – only 11 wrapper functions – closing a path from page script to code execution.
- Content-Security-Policy, drops and navigation blocked; device-supplied values in markup coerced.
- Card operations can no longer hit another key (fresh serial per operation, refusal when ambiguous); FIDO reset bound to the serial.
- "OK" requires verified attestation; failed attestation is critical; attestation certificates must name the claimed model; fewer false "not genuine" results.
- Hardened history import, PIN-before-change for PIV generation, server-side confirmation for overwrites, fresher advisory requirement, safer file writes, workflow hardening.
- SBOM (CycloneDX 1.6) for each platform, in the app and attached to releases.

**New:**
- **OpenPGP key generation on the card:** signature, encryption and authentication keys (Ed25519/Cv25519, NIST P-256, RSA 2048/4096) are generated on the security key and self-signed by it; KeyMelier writes the OpenPGP public key and a revocation certificate (saved where you choose) and can import the key into GnuPG. Verified against Sequoia-PGP, including decrypting with the card.
- **Quantum safety** section per key: signature algorithms from getInfo, automatic detection of ML-DSA (COSE -48/-49/-50, RFC 9964), and what classical cryptography means for logins and for encryption.
- **History export and import** (JSON) to back up or move KeyMelier's knowledge about your keys; imports are validated and merged.

## 1.2.1 — 2026-09-27

- Third-party license notices: `THIRD_PARTY_LICENSES.txt` (generated at build time from the bundled packages, including source locations for LGPL/MPL components) ships inside the app and with every release; "Open-source licenses" opens it.
- Copying a PIV certificate no longer truncates it.

## 1.2.0 — 2026-09-27

- **Authenticator (OATH):** show TOTP/HOTP codes with countdown and one-click copy, add accounts from an otpauth:// link or by hand, rename, delete, set/remove the password, reset. Touch-protected accounts show their code after touching the key.
- **OpenPGP:** keys per slot (algorithm, fingerprint, creation date, generated/imported), signature counter, cardholder name and URL, PIN/admin PIN retries, change PIN/admin PIN, unblock PIN, signature PIN policy, touch policies (YubiKey), reset. Works with YubiKeys and other OpenPGP cards such as Token2.
- **What's on it:** the history remembers per key which passkey websites, authenticator accounts and OpenPGP keys it held (names only, never secrets) and when they were last read – on by default.
- **PIV:** certificates per slot with validity and expiry warnings, generate a key with a self-signed certificate, import, copy and delete certificates, change PIN/PUK, unblock the PIN, protect the management key with the PIN, warnings for factory defaults, reset.
- **YubiKey OTP slots:** which slots are used, static password, HMAC-SHA1 challenge-response (secret shown once for a backup key), swap, delete. On macOS KeyMelier asks for the Input Monitoring permission.
- **Applications per USB/NFC** for YubiKeys (FIDO2 over USB stays on so KeyMelier can always find the key again).
- Backup check and lost-key assistant include authenticator accounts, OpenPGP keys and PIV certificates.
- History shows the serial number and AAGUID of every key.
- Tabs for smart card applications only appear when the key offers them; while a key's smart card interface is in use, FIDO polling pauses for that key (fixes spurious errors on Token2).

## 1.1.3 — 2026-09-27

- After an offline start, metadata is re-verified as soon as revocation lists are reachable again (retried every 15 minutes while evidence is missing) instead of staying "Unknown" until restart.
- A cached revocation list that fails validation is discarded and downloaded again instead of blocking recovery.
- README privacy section matches the new default (history on).

## 1.1.2 — 2026-09-27

- FIDO metadata works offline: verified signer CRLs are stored locally and re-validated on every use.
- Without revocation evidence, model names and vendor icons are still shown, but no positive security assessment is made; a revoked signer is always rejected.
- Key history is on by default again; website recording remains opt-in.
- Release signing is optional: builds are signed/notarized when credentials are configured, otherwise published unsigned with the signing state and first-launch steps in the release notes.
- Privacy texts in all 11 languages; revocation state shown under Data freshness; fixed colours for the Unknown status.

## 1.1.1 — 2026-09-26

- Distinguish verified, unverified and failed attestation evidence.
- Show unknown security status when current trusted metadata is unavailable.
- Harden certificate paths, MDS expiry/revocation checks and advisory verification.
- Disable persistent history and website recording by default; remove automatic CSV exports.
- Add stateless mode, optional OS-keychain-backed history encryption and private atomic storage.
- Prevent CSV formula injection and preserve critical findings over lower-severity warnings.
- Lock dependencies with hashes and pin CI actions to reviewed commit IDs.
- Require signing and notarization for public versioned releases.

Local macOS builds are ad-hoc signed test builds. Publisher signing requires the
credentials documented in RELEASING.md. Windows and physical-key validation remain
separate from the automated regression suite.
