# Dependency upgrades and distribution evidence

KeyMelier's code remains MIT. Dependencies keep their original terms. This
procedure prevents a version upgrade from silently retaining older source or
license evidence; it does not automatically approve new legal terms.

1. Update the intended pins in `pyproject.toml`, then run `uv lock` (or select a
   transitive package with `uv lock --upgrade-package NAME`).
2. Run `python tools/export_requirements.py` and
   `python tools/license_inputs.py --refresh`. The latter derives every available
   Python source archive, size and SHA-256 directly from `uv.lock`. It is offline.
3. Review the diff. For a changed parent in `embedded-sources.json`, inspect its
   sources/build requirements and update the exact embedded archives and notices.
   For a changed manual SPDX mapping, inspect the original license, then update
   `license-overrides.json`; do not just copy the old permission assumption.
   If the expression itself changes, update its mapping in `tools/sbom.py` too.
   `license-policy.json` also fixes the reviewed versions and license expression for each
   Python component, including nested vendors. A newly collected package or a
   new version or different expression fails validation even when it is a recognized SPDX ID.
   Inspect the actual grant and distribution obligations before updating it;
   `--refresh` deliberately never approves this file automatically.
   A package and Setuptools' nested copy can have different versions; both need
   explicit entries in the reviewed version list, never an unrestricted range.
   Qt sources and their module selection must match the new PySide version.
4. Run `python tools/license_inputs.py` and the Python tests. CI repeats the check
   on every platform before packaging, including dependency-update PRs.
5. Build all platforms. The normal build scripts and CI rebuild zxing-cpp from its
   checked sdist against checked nanobind source. Implicit CMake dependency
   downloads and pip build isolation are disabled. Build tools are hash-locked.
   The generated proof records source versions/hashes, the recipe hash, wheel
   hash and installed native file hashes. PyInstaller rejects a substituted wheel.
6. On Linux, Docker builds the runtime from `runtime-build.json`. The container
   base is pinned by digest. Toolchain package versions/source commits are checked;
   library sources are downloaded/hash-checked before the offline compile step.
   Unknown static libraries stop the build. Review package source recipes, patches
   and notices when updating the runtime/toolchain; then update their pins together.
7. Check CI's packaged startup tests, library replacement checks, source archive
   hashes and strict SBOM validation. The final AppImage's runtime must match the
   build evidence (only its documented MD5 metadata slot may change during assembly).
   Test QR import and normal launch on Windows, macOS and both Linux architectures.

The release source tar includes the application/build recipes, matching upstream
archives and, on Linux, the complete Alpine package database and linker map.
The offline About license reader receives the newly generated notices and source
manifest automatically. No manual copying into frontend strings is necessary.

The earlier upstream zxing and AppImage binaries cannot gain missing historical
build evidence retroactively. Controlled builds replace those inputs in new
packages. Nothing in this procedure rewrites a published release.

## 1.8.9 build/quality patch review (2026-11-10)

PRs #61/#62 update the pinned release action to 3.0.4 and build/quality tools to
scikit-build-core 1.1.2, Ruff 0.17.4 and uv 0.13.7. Runtime dependencies, Python
requirements, platform baselines and application data formats are unchanged.
The release action retains its inputs/runtime and changes bundled dependencies;
it is used by the stable publishing job. RC publication still uses the existing
checked rehearsal and GitHub CLI path. The action remains pinned by commit SHA.

The original old/new Python source archives were downloaded from the lock URLs
and verified against their recorded SHA-256 hashes. All LICENSE/COPYING/NOTICE/
AUTHORS/COPYRIGHT files, including vendored notices present in these sources,
are byte-identical. License expressions remain unchanged. The scikit-build-core
source's build-system requirements are unchanged; its pyproject diff only adds
a development lint exception. Matching requirements exports, source manifest
and exact reviewed policy versions accompany the new lock.

New source hashes:

- scikit-build-core 1.1.2: `7893709119c5ab1be75cd10442383132c9433b9f104dacef5185949efbea7974`
- Ruff 0.17.4: `f32d178b50e826e00f6c6c1be3f56333068acb9b67fe167143527fa9b81e890d`
- uv 0.13.7: `5e766791cb825d7a07e2ef9e622d307b48754fb682a31ba7bc5f272fab9ea395`

Upstream changes: [scikit-build-core](https://github.com/scikit-build/scikit-build-core/releases/tag/v1.1.2),
[Ruff](https://github.com/astral-sh/ruff/releases/tag/0.17.4),
[uv](https://github.com/astral-sh/uv/releases/tag/0.13.7),
[release action](https://github.com/softprops/action-gh-release/releases/tag/v3.0.4).
Required validation remains export/source/license checks, tests and actual
controlled builds/packaged startup on all four targets. Synthetic or CI results
do not constitute new hardware acceptance or update a published RC retroactively.
Local validation passed all 554 backend tests (two platform skips), export and
source/license checks, and both Ruff correctness checks. The controlled zxing-cpp
3.1.1 build with scikit-build-core 1.1.2 completed and verified its installed
binary hashes; QR decoding and controlled-build/release regression checks passed.

## Setuptools 84.2.1 review (2026-10-27)

The upgrade from 84.0.0 includes the archive extraction and legacy wheel namespace
path traversal fixes introduced in 84.1.0. The version, wheel hashes, exported
build requirements and matching source archive are updated together. Review used
the original PyPI wheels and source archives, verified against `uv.lock`:

- Wheel SHA-256: `ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2`.
- Source SHA-256: `3ff8b3b5492a0aa66960f4419365a86b84e013070d4313e4d4a6894f5d64d6bc`.

All 17 license/notice files are byte-identical to 84.0.0 after accounting for the
vendored packaging directory's version change from 26.0 to 26.3. The remaining
vendored distributions retain their versions. Packaging 26.3 already has an exact
reviewed policy entry. The parent license expression and individual vendor terms
remain unchanged; only the reviewed Setuptools version is advanced. Upstream
changes are documented in the source archive's `NEWS.rst` and
[release notes](https://github.com/pypa/setuptools/releases/tag/v84.2.1).

## PySide/Qt 6.11.3 review (2026-10-29)

The Linux runtime advances from 6.11.2 to the 6.11.3 patch release. Qt documents
the QNetworkAccessManager HTTP/2 fix in
[CVE-2026-95620](https://www.qt.io/blog/security-advisory-cve-2026-95620).
This is dependency maintenance; no reachable exploit in KeyMelier was established.
The four PySide/Shiboken pins, wheel hashes, exported requirements, eight Qt
module source pins and version-specific library replacement probe are updated
together. No unrelated dependency versions are changed.

Source archive sizes and SHA-256 values come from each official Qt Metalink.
Both PySide source archives were downloaded and checked against their pinned
hashes. All 15 LICENSE/COPYING files, including the LGPL/GPL grants and the
PySide/Shiboken notices, are byte-identical between 6.11.2 and 6.11.3. The
reviewed license expressions therefore remain unchanged. New PySide source:
`050819cb05e14d6689f42b56e4fa9c8ff63be2bb339e0c094c45b990b7cabde1`.
Linux packaging must still download/hash-check the matching module archives
and run the existing startup/replacement checks on both architectures.

## Latest compatible stable review (2026-11-01)

The maintainer requested major as well as patch updates. `uv lock --upgrade`
refreshes every transitive dependency; direct build/quality pins advance to
nanobind 3.1.0, wheel 0.48.0, Ruff 0.17.3 and uv 0.13.6. Runtime changes include
certifi 2026.10.23, PyObjC 13.0, pyscard 2.3.2 and python-dateutil 4.0.0.
The new tzdata 2026.6 dependency replaces dateutil's embedded timezone database;
six is no longer required by dateutil. Python 3.11 source support remains.
Dateutil now rejects malformed numeric ISO fields and removes pre-3.11 helpers;
KeyMelier does not call these helpers or the removed mutable timezone path API.

All changed Python source archives were downloaded and checked against the old
and new lock hashes. Their LICENSE/COPYING/NOTICE texts are byte-identical;
new tzdata carries Apache-2.0 grants. Dateutil's complete original license still
contains both Apache-2.0 and BSD-3-Clause terms despite its new narrower metadata;
the reviewed combined expression is retained. PyObjC's missing wheel notice is
supplied from the checked 13.0 source. Nanobind's vendored robin-map remains 1.4.0;
its file hash and the controlled build input are checked. No independent upgrade
is made to code embedded by cryptography/Pillow: their current upstream wheels
and embedded SBOMs remain the authority for those builds.

Release Python is pinned to 3.14.10 across macOS, Windows and Linux, including
the Oct 25 SSL/security fixes. Qt stays at 6.11.3: the latest PySide 6.12.0 is
affected by CVE-2026-105924, while 6.11.3 contains the fix. PySide 6.11.3 requires
Python below 3.15. Reassess when fixed PySide 6.12.1 wheels become available.

The AppImage runtime uses immutable type2-runtime commit
`fedfad51acc2860b2916a1eef32ba4a500ff31ef`, FUSE 3.18.3, squashfuse 0.6.5,
zstd 1.5.7, zlib 1.3.2 and mimalloc 3.6.1. Alpine 3.24.3 is pinned by its
multiarch digest. Both architectures' package indexes agree on musl 1.2.6-r3
and GCC 15.2.0-r5 and their source commits. The musl recipe includes upstream
security backports through CVE-2026-107891. Aports recipes/patches accompany
the source evidence. Native license terms are unchanged; zlib and mimalloc
copyright years are refreshed from their exact sources, as are GCC notices.
The versioned appimagetool 1.9.1 remains latest stable; its moving continuous
build is deliberately not selected.

`libfuse-appimage.patch` ports the existing AppImage helper selection to
libfuse's posix_spawn implementation. Only the non-setuid runtime library is
built; FUSE utilities, custom I/O and io_uring are not enabled. The selected
helper must exist in the environment; failure does not choose a different one.
The patch is included in the recipe hash and corresponding source bundle.
Mimalloc's new ARMv8.1 default is disabled to retain ARMv8.0 compatibility; its
new five-digit runtime version encoding is read correctly. Unknown static link
inputs and mismatched compiled versions still fail the build.

CI uses Node 26.13.0 stable and setup-python 7.1.0 by immutable SHA; all artifact
downloads use the verified 8.0.2 SHA. Already-current Actions remain pinned.
Local validation includes Python 3.14.10 tests, the controlled QR decoder build,
strict SBOM validation and the source/license/export checks. Platform packaging,
Linux compatibility and signed release evidence must be checked for the final
commit; local tests do not constitute hardware approval.
