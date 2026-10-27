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
