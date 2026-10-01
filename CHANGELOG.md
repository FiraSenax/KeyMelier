# Changelog

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
