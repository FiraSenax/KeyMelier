#!/usr/bin/env python3
"""CycloneDX 1.6 inventory of collected application dependencies.

    python3 tools/sbom.py [output]                  write (as the build does)
    python3 tools/sbom.py --check [FILE] [--strict] validate a written SBOM

Called by the PyInstaller spec next to third_party_licenses.py, so each
platform's build describes exactly what is installed and bundled there:

- Python distributions identified from PyInstaller's collected files, with version, package URL
  and an SPDX license expression;
- the SHA-256 of the artifact pip actually installed, from pip's
  installation report (build/pip-report*.json, written by CI and the build
  scripts with `pip install --report`); without a report, the hashes the
  lock file allows are listed as properties instead;
- the PyInstaller bootloader inside the executable;
- CPython and the OpenSSL builds bundled with CPython and with cryptography;
- reviewed original brand assets, UI icon attribution, native Linux packages
  and the AppImage runtime.

Known limit: not every statically linked Rust/C++ or runtime dependency is
individually versioned. License notices/source archives complement this inventory.
"""

import glob
import hashlib
import json
import os
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from third_party_licenses import requirement_names  # noqa: E402

# SPDX license expressions verified against the license files each package
# ships, for packages whose metadata has no SPDX License-Expression.
SPDX_OVERRIDES = {
    "fido2": "BSD-2-Clause AND Apache-2.0 AND MPL-2.0",   # COPYING (BSD 2-clause) + COPYING.APLv2 + COPYING.MPLv2
    "pywebview": "BSD-3-Clause",
    "pyscard": "LGPL-2.1-or-later",                        # "version 2.1 … or any later version"
    "python-pskc": "LGPL-2.1-or-later",
    "python-dateutil": "Apache-2.0 AND BSD-3-Clause",      # Apache-2.0 since 2017-12, BSD-3-Clause before
    "yubikey-manager": "BSD-2-Clause",
    "pyopenssl": "Apache-2.0",
    "requests": "Apache-2.0",
    "certifi": "MPL-2.0",
    "proxy-tools": "BSD-3-Clause",  # source header, not the conflicting PyPI classifier
    "setuptools": "MIT AND BSD-3-Clause AND MPL-2.0",  # includes _validate_pyproject
    "backports-tarfile": "MIT",
    "jaraco-text": "MIT",
    # Windows / Linux only (not installed on every build machine)
    "clr-loader": "MIT",
    "pythonnet": "MIT",
    "pywin32": "PSF-2.0 AND BSD-3-Clause",
    "pywin32-ctypes": "BSD-3-Clause",
    "jeepney": "MIT",
    "secretstorage": "BSD-3-Clause",
    "qtpy": "MIT",
    "pyside6": "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
    "pyside6-essentials": "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",   # METADATA License field
    "pyside6-addons": "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
    "shiboken6": "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
}
# Unambiguous license classifiers
CLASSIFIER_SPDX = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "ISC License (ISCL)": "ISC",
}
# Identifiers and exceptions an expression may use (checked by validate())
SPDX_IDS = {"MIT", "MIT-0", "MIT-CMU", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "PSF-2.0", "ISC",
            "LGPL-2.1-or-later", "LGPL-3.0-or-later", "GPL-2.0-or-later",
            "LGPL-3.0-only", "GPL-2.0-only", "GPL-3.0-only", "CC0-1.0", "Unlicense", "0BSD"}
SPDX_EXCEPTIONS = {"Bootloader-exception"}
SPDX_IDS.add('Zlib')
SPDX_IDS.add('GPL-3.0-or-later')
SPDX_EXCEPTIONS.add('GCC-exception-3.1')


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def spdx_expression(dist) -> str | None:
    """SPDX expression for an installed distribution, or None if unknown."""
    name = _norm(dist.metadata["Name"])
    if name in SPDX_OVERRIDES:
        reviews = json.loads((ROOT / 'packaging/license-overrides.json').read_text())
        if name in reviews and (reviews[name]['version'] != dist.version or reviews[name]['expression'] != SPDX_OVERRIDES[name]):
            raise ValueError('Review the original license before reusing the SPDX override for ' + name)
        return SPDX_OVERRIDES[name]
    expr = (dist.metadata.get("License-Expression") or "").strip()
    if expr:
        return expr
    classifiers = [c.split("::")[-1].strip() for c in dist.metadata.get_all("Classifier") or []
                   if c.startswith("License ::")]
    mapped = {CLASSIFIER_SPDX.get(c) for c in classifiers}
    if classifiers and None not in mapped:
        return " AND ".join(sorted(mapped))
    legacy = (dist.metadata.get("License") or "").strip()   # older metadata: "License: MIT"
    if legacy and "\n" not in legacy and expression_ok(legacy):
        return legacy
    return None


def _licenses(expr: str | None) -> list[dict]:
    if not expr:
        return []
    return [{"license": {"id": expr}}] if expr in SPDX_IDS else [{"expression": expr}]


def lock_hashes(*files: str) -> dict[str, list[str]]:
    """Package name -> allowed sha256 hashes from the hash-pinned lock files."""
    hashes: dict[str, list[str]] = {}
    for file in files or ("requirements.txt", "requirements-build.txt"):
        current = None
        for line in (ROOT / file).read_text().splitlines():
            m = re.match(r"^([A-Za-z0-9_.-]+)==", line)
            if m:
                current = _norm(m.group(1))
            for h in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
                if current:
                    hashes.setdefault(current, []).append(h)
    return hashes


def installed_artifacts(pattern: str | None = None) -> dict[str, dict]:
    """Package name -> {sha256, url} of the artifact pip installed (pip --report)."""
    found: dict[str, dict] = {}
    for path in sorted(glob.glob(pattern or os.environ.get("KEYMELIER_PIP_REPORTS") or str(ROOT / "build" / "pip-report*.json"))):
        try:
            report = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for item in report.get("install", []):
            info = item.get("download_info") or {}
            sha = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256")
            name = (item.get("metadata") or {}).get("name")
            if sha and name:
                found[_norm(name)] = {"sha256": sha, "url": info.get("url", ""),
                                      "version": (item.get("metadata") or {}).get("version")}
    return found


def _package(name: str, allowed: dict, artifacts: dict, component_type="library") -> dict | None:
    try:
        dist = distribution(name)
    except PackageNotFoundError:
        return None  # other platform
    norm = _norm(dist.metadata["Name"])
    purl = f"pkg:pypi/{norm}@{dist.version}"
    component = {"type": component_type, "bom-ref": purl, "name": dist.metadata["Name"], "version": dist.version,
                 "purl": purl, "licenses": _licenses(spdx_expression(dist))}
    art = artifacts.get(norm)
    if norm == 'zxing-cpp' and art:
        from build_zxing import PROOF, verify_installed
        if PROOF.is_file():
            proof = verify_installed()
            component['hashes'] = [{'alg': 'SHA-256', 'content': proof['wheel_sha256']}]
            component['properties'] = [{'name': 'keymelier:controlled-build', 'value': json.dumps(proof, sort_keys=True)}]
            return component
    if art and art.get("version") == dist.version:
        # the file pip actually installed; it must be one the lock file allows
        component["hashes"] = [{"alg": "SHA-256", "content": art["sha256"]}]
        if art["url"]:
            component["externalReferences"] = [{"type": "distribution", "url": art["url"]}]
    elif allowed.get(norm):
        component["properties"] = [{"name": "keymelier:lock:sha256", "value": h} for h in allowed[norm]]
    return component


def _openssl_components() -> list[dict]:
    out = []
    try:
        import ssl
        m = re.match(r"OpenSSL (\S+)", ssl.OPENSSL_VERSION)
        if m:
            out.append({"type": "library", "bom-ref": f"openssl@{m.group(1)}#cpython", "name": "OpenSSL",
                        "version": m.group(1), "purl": f"pkg:generic/openssl@{m.group(1)}",
                        "licenses": _licenses("Apache-2.0"),
                        "properties": [{"name": "keymelier:bundled-in", "value": "CPython (ssl)"}]})
    except ImportError:
        pass
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        m = re.match(r"OpenSSL (\S+)", backend.openssl_version_text())
        if m:
            out.append({"type": "library", "bom-ref": f"openssl@{m.group(1)}#cryptography", "name": "OpenSSL",
                        "version": m.group(1), "purl": f"pkg:generic/openssl@{m.group(1)}",
                        "licenses": _licenses("Apache-2.0"),
                        "properties": [{"name": "keymelier:bundled-in", "value": "cryptography (statically linked)"}]})
    except Exception:
        pass
    return out


def _brand_components():
    from make_service_icons import reviewed_brands, asset_bytes
    components = []
    for name, info in sorted(reviewed_brands().items()):
        if info["status"] != "enabled":
            continue
        purl = f"pkg:generic/keymelier-brand-{name}@{info['reviewed']}"
        components.append({"type": "data", "bom-ref": purl, "name": f"brand:{name}",
            "version": info["reviewed"], "purl": purl,
            "licenses": [{"license": {"name": "Brand usage terms", "url": info["terms_url"]}}],
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(asset_bytes(name, info)).hexdigest()}],
            "properties": [{"name": "keymelier:asset", "value": "packaging/brands/" + info["asset"]}],
            "externalReferences": [{"type": "distribution", "url": info["asset_url"]}]})
    return components


def _native_components(packages):
    from urllib.parse import quote
    out = []
    for package in packages:
        purl = f"pkg:deb/ubuntu/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}"
        out.append({"type": "library", "bom-ref": purl, "name": package["name"], "version": package["version"],
            "purl": purl, "licenses": [{"license": {"name": "Debian copyright file (included in THIRD_PARTY_LICENSES.txt)"}}],
            "properties": [{"name": "keymelier:copyright:sha256", "value": package["copyright_sha256"]},
                           {"name": "keymelier:source-package", "value": package["source_package"]},
                           {"name": "keymelier:source-version", "value": package["source_version"]},
                           *({"name": "keymelier:bundled-file", "value": f} for f in package["files"])]})
    return out


def _runtime_components():
    from build_runtime import LOCK, PROOF, verify_built
    lock = json.loads(LOCK.read_text())
    proof = verify_built() if PROOF.is_file() else None
    version = next(s['version'] for s in lock['sources'] if s['component'] == 'type2-runtime')
    root = {'type': 'application', 'bom-ref': 'pkg:generic/appimage-type2-runtime@' + version,
            'name': 'AppImage type2 runtime', 'version': version,
            'purl': 'pkg:generic/appimage-type2-runtime@' + version,
            'licenses': [{'license': {'name': 'AppImage runtime and static dependency notices'}}]}
    if not proof:
        return [root]  # Development inventory; strict release validation rejects missing proof.
    root['hashes'] = [{'alg': 'SHA-256', 'content': proof['sha256']}]
    root['properties'] = [{'name': 'keymelier:runtime-build', 'value': json.dumps(proof, sort_keys=True)}]
    components = [root]
    licenses = {'libfuse': 'LGPL-2.1-or-later', 'squashfuse': 'BSD-2-Clause',
                'zstd': 'BSD-3-Clause', 'zlib': 'Zlib', 'mimalloc': 'MIT', 'musl': 'MIT'}
    for source in lock['sources']:
        name = source['component']
        if name not in licenses:
            continue
        version = lock['toolchain_packages']['musl-dev'] if name == 'musl' else source['version']
        purl = f'pkg:generic/{name}@{version}'
        components.append({'type': 'library', 'bom-ref': purl + '#appimage', 'name': name,
            'version': version, 'purl': purl, 'licenses': _licenses(licenses[name]),
            'properties': [{'name': 'keymelier:bundled-in', 'value': root['bom-ref']},
                           {'name': 'keymelier:source-sha256', 'value': source['sha256']}],
            'externalReferences': [{'type': 'source-distribution', 'url': source['url']}]})
    version = lock['toolchain_packages']['gcc']
    components.append({'type': 'library', 'bom-ref': f'pkg:generic/gcc-runtime@{version}#appimage',
        'name': 'GCC runtime', 'version': version, 'purl': f'pkg:generic/gcc-runtime@{version}',
        'licenses': _licenses('GPL-3.0-or-later WITH GCC-exception-3.1'),
        'properties': [{'name': 'keymelier:bundled-in', 'value': root['bom-ref']}]})
    return components


def build(app_version: str, report_glob: str | None = None, names=None, native_packages=(), vendors=(), upstream_sboms=()) -> dict:
    allowed = lock_hashes()
    artifacts = installed_artifacts(report_glob)
    components = [c for c in (_package(n, allowed, artifacts) for n in (requirement_names() if names is None else names)) if c]
    bootloader = _package("pyinstaller", allowed, artifacts, component_type="application")
    if bootloader:
        # only the bootloader ends up in the app; its own license, not PyInstaller's GPL
        bootloader["licenses"] = [{"expression": "GPL-2.0-or-later WITH Bootloader-exception"}]
        bootloader["properties"] = bootloader.get("properties", []) + [
            {"name": "keymelier:bundled-part", "value": "bootloader (executable stub)"}]
        components.append(bootloader)
    components.append({
        "type": "platform", "bom-ref": f"python@{platform.python_version()}", "name": "CPython",
        "version": platform.python_version(), "purl": f"pkg:generic/cpython@{platform.python_version()}",
        "licenses": _licenses("PSF-2.0"),
    })
    components += _openssl_components()
    components += _brand_components() + _native_components(native_packages)
    for evidence in upstream_sboms:
        parent = next(c for c in components if _norm(c["name"]) == evidence["parent"])
        serial = evidence.get("serialNumber", "")
        if serial and serial.startswith("urn:uuid:"):
            parent.setdefault("externalReferences", []).append({"type": "bom",
                "url": "urn:cdx:" + serial.removeprefix("urn:uuid:") + "/" + str(evidence["bom_version"]),
                "hashes": [{"alg": "SHA-256", "content": evidence["sha256"]}],
                "comment": evidence["path"] + "; " + evidence["scope"]})
        parent.setdefault("properties", []).append({"name": "keymelier:upstream-sbom", "value": evidence["path"]})
    for name, license_file, expr in (("Lucide", "lucide-LICENSE.txt", "ISC AND MIT"),
                                     ("Feather", "feather-LICENSE.txt", "MIT")):
        purl = f"pkg:generic/{name.lower()}-icons@embedded"
        components.append({"type": "data", "bom-ref": purl, "name": name, "version": "embedded", "purl": purl,
            "licenses": _licenses(expr),
            "properties": [{"name": "keymelier:license-file", "value": "packaging/licenses/" + license_file},
                           {"name": "keymelier:license-sha256", "value": hashlib.sha256(
                               (ROOT / "packaging/licenses" / license_file).read_bytes()).hexdigest()}]})
    for dist in vendors:
        name = _norm(dist.metadata["Name"])
        purl = f"pkg:pypi/{name}@{dist.version}"
        components.append({"type": "library", "bom-ref": purl + "#setuptools-vendor", "name": dist.metadata["Name"],
            "version": dist.version, "purl": purl, "licenses": _licenses(spdx_expression(dist)),
            "properties": [{"name": "keymelier:bundled-in", "value": "setuptools wheel; see parent artifact hash"}]})
    if sys.platform == "win32":
        purl = "pkg:nuget/Microsoft.Web.WebView2@1.0.3856.49"
        components.append({"type": "library", "bom-ref": purl, "name": "Microsoft.Web.WebView2", "version": "1.0.3856.49",
            "purl": purl, "licenses": _licenses("BSD-3-Clause")})
    if sys.platform.startswith("linux"):
        components.extend(_runtime_components())
    for component in list(components):
        evidence = next((p['value'] for p in component.get('properties', [])
                         if p.get('name') == 'keymelier:controlled-build'), None)
        if evidence:
            proof = json.loads(evidence)
            version = proof['inputs']['nanobind']['version']
            nested = [('nanobind', version, 'BSD-3-Clause')]
            nested += [(name, info['version'], info['license']) for name, info in proof['vendored_components'].items()]
            for name, version, license_expr in nested:
                purl = f'pkg:generic/{name}@{version}'
                components.append({'type': 'library', 'bom-ref': purl, 'name': name,
                    'version': version, 'purl': purl, 'licenses': _licenses(license_expr),
                    'properties': [{'name': 'keymelier:bundled-in', 'value': component['bom-ref']}]})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "keymelier-sbom"}]},
            "component": {
                "type": "application", "bom-ref": f"keymelier@{app_version}", "name": "KeyMelier",
                "version": app_version, "licenses": [{"license": {"id": "MIT"}}],
                "purl": f"pkg:github/FiraSenax/KeyMelier@v{app_version}",
            },
            "properties": [{"name": "keymelier:platform", "value": f"{sys.platform}-{platform.machine()}"},
                           {"name": "keymelier:hashes",
                            "value": "installed artifacts (pip report)" if artifacts else "allowed by lock file"}],
        },
        "components": components,
        "dependencies": [{"ref": f"keymelier@{app_version}", "dependsOn": [c["bom-ref"] for c in components]}],
    }


# ── Validation ───────────────────────────────────────────────────────────────

_EXPR_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9.+-]+")


def expression_ok(expr: str) -> bool:
    """Only known SPDX ids/exceptions, joined by AND/OR/WITH (and parentheses)."""
    tokens = _EXPR_TOKEN.findall(expr)
    if "".join(tokens) != re.sub(r"\s+", "", expr):
        return False
    prev_with = False
    for tok in tokens:
        if tok in "()":
            continue
        if tok in ("AND", "OR", "WITH"):
            prev_with = tok == "WITH"
            continue
        if (tok not in SPDX_EXCEPTIONS) if prev_with else (tok not in SPDX_IDS):
            return False
        prev_with = False
    return True


def validate(bom: dict, app_version: str | None = None, strict: bool = False) -> list[str]:
    """Problems with an SBOM (empty list = fine). strict: a release build –
    the bootloader must be listed and every package must carry the hash of
    the artifact that was installed, and that hash must be allowed by the lock."""
    problems = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        problems.append("not a CycloneDX 1.6 document")
    if not re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", str(bom.get("serialNumber", ""))):
        problems.append("missing serialNumber")
    app = (bom.get("metadata") or {}).get("component") or {}
    if app.get("name") != "KeyMelier" or (app_version and app.get("version") != app_version):
        problems.append(f"metadata.component is {app.get('name')} {app.get('version')}, expected KeyMelier {app_version}")
    comps = bom.get("components") or []
    refs = [c.get("bom-ref") for c in comps]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-ref")
    allowed = lock_hashes()
    for c in comps:
        label = f"{c.get('name')} {c.get('version')}"
        if not c.get("name") or not c.get("version") or not c.get("purl"):
            problems.append(f"{label}: name, version and purl are required")
        lic = c.get("licenses") or []
        if not lic:
            problems.append(f"{label}: no license")
        for entry in lic:
            expr = entry.get("expression") or (entry.get("license") or {}).get("id")
            custom = (entry.get("license") or {}).get("name")
            documented_asset = c.get("name", "").startswith("brand:") and custom == "Brand usage terms"
            documented_native = c.get("purl", "").startswith("pkg:deb/") and custom == "Debian copyright file (included in THIRD_PARTY_LICENSES.txt)"
            documented_runtime = c.get('purl', '').startswith('pkg:generic/appimage-type2-runtime@') and custom == "AppImage runtime and static dependency notices"
            if not (documented_asset or documented_native or documented_runtime) and (not expr or not expression_ok(expr)):
                problems.append(f"{label}: license is not a known SPDX expression: {entry}")
            if documented_native and not any(p.get("name") == "keymelier:copyright:sha256" and re.fullmatch(r"[0-9a-f]{64}", p.get("value", "")) for p in c.get("properties", [])):
                problems.append(f"{label}: missing bundled native copyright proof")
        for h in c.get("hashes") or []:
            if h.get("alg") != "SHA-256" or not re.fullmatch(r"[0-9a-f]{64}", h.get("content", "")):
                problems.append(f"{label}: malformed hash")
        purl = c.get("purl", "")
        if purl.startswith('pkg:generic/appimage-type2-runtime@'):
            evidence = next((p['value'] for p in c.get('properties', [])
                             if p.get('name') == 'keymelier:runtime-build'), None)
            try:
                from build_runtime import validate_proof
                if evidence:
                    proof = json.loads(evidence)
                    validate_proof(proof)
                    if c.get('hashes') != [{'alg': 'SHA-256', 'content': proof['sha256']}]:
                        raise ValueError('Runtime artifact hash differs from its build proof')
                elif strict:
                    raise ValueError('Runtime build proof missing')
            except (ValueError, KeyError, TypeError) as error:
                problems.append(f'{label}: {error}')
        if purl.startswith("pkg:pypi/"):
            name = _norm(c["name"])
            controlled = next((p['value'] for p in c.get('properties', [])
                               if p.get('name') == 'keymelier:controlled-build'), None)
            controlled_hash = None
            if controlled:
                try:
                    from build_zxing import validate_proof
                    proof = json.loads(controlled)
                    validate_proof(proof)
                    if name != 'zxing-cpp' or c['version'] != proof['inputs']['zxing-cpp']['version']:
                        raise ValueError('Controlled build does not match this package')
                    controlled_hash = proof['wheel_sha256']
                    if c.get('hashes') != [{'alg': 'SHA-256', 'content': controlled_hash}]:
                        raise ValueError('Controlled wheel hash differs from SBOM artifact')
                except (ValueError, KeyError, TypeError) as error:
                    problems.append(f'{label}: invalid controlled build proof: {error}')
            if strict and name == 'zxing-cpp' and not controlled_hash:
                problems.append(f'{label}: controlled source build proof missing')
            vendored = any(p.get("value") == "setuptools wheel; see parent artifact hash" for p in c.get("properties", []))
            if not vendored and not allowed.get(name):
                problems.append(f"{label}: collected package is not pinned in the dependency lock")
            if strict and not c.get("hashes") and not vendored:
                problems.append(f"{label}: no hash of the installed artifact (pip report missing?)")
            for h in c.get("hashes") or []:
                if allowed.get(name) and h["content"] not in allowed[name] and h['content'] != controlled_hash:
                    problems.append(f"{label}: installed artifact hash is not allowed by the lock file")
    names = {c.get("name") for c in comps}
    for required in ("CPython", "OpenSSL", "Lucide", "Feather") + (("pyinstaller",) if strict else ()):
        if required not in names:
            problems.append(f"missing component: {required}")
    for expected in _brand_components():
        actual = next((c for c in comps if c.get("bom-ref") == expected["bom-ref"]), None)
        if actual != expected:
            problems.append(f"{expected['name']}: missing or different reviewed asset/terms")
    deps = {d.get("ref"): d.get("dependsOn", []) for d in bom.get("dependencies") or []}
    if set(deps.get(app.get("bom-ref"), [])) != set(refs):
        problems.append("dependencies do not list every component")
    return problems


def write(path: Path, app_version: str, names=None, native_packages=(), vendors=(), upstream_sboms=()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    bom = build(app_version, names=names, native_packages=native_packages, vendors=vendors, upstream_sboms=upstream_sboms)
    problems = validate(bom, app_version)
    if problems:
        raise SystemExit("SBOM incomplete:\n  " + "\n  ".join(problems))
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return path


def _version() -> str:
    ns: dict = {}
    exec((ROOT / "keymelier_core" / "version.py").read_text(), ns)
    return ns["__version__"]


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=ROOT / "build" / "keymelier-sbom.cdx.json")
    parser.add_argument("--check", action="store_true", help="Validate the SBOM (default: build/keymelier-sbom.cdx.json)")
    parser.add_argument("--strict", action="store_true", help="Require installed artifact hashes and PyInstaller")
    args = parser.parse_args(argv)
    if args.strict and not args.check:
        parser.error("--strict requires --check")
    if args.check:
        try:
            found = validate(json.loads(args.path.read_text(encoding="utf-8")), _version(), strict=args.strict)
        except (OSError, ValueError) as e:
            print(f"SBOM could not be read: {e}", file=sys.stderr)
            return 1
        for p in found:
            print("SBOM:", p)
        print(f"{args.path}: {'OK' if not found else f'{len(found)} problem(s)'}")
        return 1 if found else 0
    print(write(args.path, _version()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
