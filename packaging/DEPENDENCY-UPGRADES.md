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
   `license-policy.json` also fixes the reviewed version and license expression for each
   Python component, including nested vendors. A newly collected package or a
   new version or different expression fails validation even when it is a recognized SPDX ID.
   Inspect the actual grant and distribution obligations before updating it;
   `--refresh` deliberately never approves this file automatically.
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
