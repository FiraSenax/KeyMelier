#!/usr/bin/env python3
"""CycloneDX 1.6 SBOM of everything shipped in the app bundle.

    python3 tools/sbom.py [output]                  write (as the build does)
    python3 tools/sbom.py --check FILE [--strict]   validate a written SBOM

Called by the PyInstaller spec next to third_party_licenses.py, so each
platform's build describes exactly what is installed and bundled there:

- every runtime Python package (requirements.txt) with version, package URL
  and an SPDX license expression;
- the SHA-256 of the artifact pip actually installed, from pip's
  installation report (build/pip-report*.json, written by CI and the build
  scripts with `pip install --report`); without a report, the hashes the
  lock file allows are listed as properties instead;
- the PyInstaller bootloader inside the executable;
- CPython and the OpenSSL builds bundled with CPython and with cryptography;
- the Simple Icons data in static/service-icons.js (hash of the shipped file).

Known limit: further native libraries inside CPython (zlib, libffi, expat …)
are covered by the CPython component, not listed one by one.
"""

import glob
import hashlib
import json
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
    "proxy-tools": "MIT",
    # Windows / Linux only (not installed on every build machine)
    "clr-loader": "MIT",
    "pythonnet": "MIT",
    "pywin32": "PSF-2.0",
    "pywin32-ctypes": "BSD-3-Clause",
    "jeepney": "MIT",
    "secretstorage": "BSD-3-Clause",
    "qtpy": "MIT",
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
SPDX_IDS = {"MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "PSF-2.0", "ISC",
            "LGPL-2.1-or-later", "LGPL-3.0-or-later", "GPL-2.0-or-later",
            "LGPL-3.0-only", "GPL-2.0-only", "GPL-3.0-only", "CC0-1.0", "Unlicense", "0BSD"}
SPDX_EXCEPTIONS = {"Bootloader-exception"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def spdx_expression(dist) -> str | None:
    """SPDX expression for an installed distribution, or None if unknown."""
    name = _norm(dist.metadata["Name"])
    if name in SPDX_OVERRIDES:
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
    for path in sorted(glob.glob(pattern or str(ROOT / "build" / "pip-report*.json"))):
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


def _simple_icons() -> dict | None:
    path = ROOT / "static" / "service-icons.js"
    if not path.exists():
        return None
    m = re.search(r"Simple Icons (\d+\.\d+\.\d+)", path.read_text(encoding="utf-8")[:500])
    version = m.group(1) if m else "unknown"
    return {"type": "data", "bom-ref": f"pkg:npm/simple-icons@{version}", "name": "simple-icons", "version": version,
            "purl": f"pkg:npm/simple-icons@{version}", "licenses": _licenses("CC0-1.0"),
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(path.read_bytes()).hexdigest()}],
            "properties": [{"name": "keymelier:file", "value": "static/service-icons.js"}]}


def build(app_version: str, report_glob: str | None = None) -> dict:
    allowed = lock_hashes()
    artifacts = installed_artifacts(report_glob)
    components = [c for c in (_package(n, allowed, artifacts) for n in requirement_names()) if c]
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
    icons = _simple_icons()
    if icons:
        components.append(icons)
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
            if not expr or not expression_ok(expr):
                problems.append(f"{label}: license is not a known SPDX expression: {entry}")
        for h in c.get("hashes") or []:
            if h.get("alg") != "SHA-256" or not re.fullmatch(r"[0-9a-f]{64}", h.get("content", "")):
                problems.append(f"{label}: malformed hash")
        purl = c.get("purl", "")
        if purl.startswith("pkg:pypi/"):
            name = _norm(c["name"])
            if strict and not c.get("hashes"):
                problems.append(f"{label}: no hash of the installed artifact (pip report missing?)")
            for h in c.get("hashes") or []:
                if allowed.get(name) and h["content"] not in allowed[name]:
                    problems.append(f"{label}: installed artifact hash is not allowed by the lock file")
    names = {c.get("name") for c in comps}
    for required in ("CPython", "OpenSSL", "simple-icons") + (("pyinstaller",) if strict else ()):
        if required not in names:
            problems.append(f"missing component: {required}")
    icons = next((c for c in comps if c.get("name") == "simple-icons"), None)
    shipped = ROOT / "static" / "service-icons.js"
    if icons and shipped.exists() and icons.get("hashes", [{}])[0].get("content") != hashlib.sha256(shipped.read_bytes()).hexdigest():
        problems.append("simple-icons: hash does not match static/service-icons.js")
    deps = {d.get("ref"): d.get("dependsOn", []) for d in bom.get("dependencies") or []}
    if set(deps.get(app.get("bom-ref"), [])) != set(refs):
        problems.append("dependencies do not list every component")
    return problems


def write(path: Path, app_version: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    bom = build(app_version)
    problems = validate(bom, app_version)
    if problems:
        raise SystemExit("SBOM incomplete:\n  " + "\n  ".join(problems))
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return path


def _version() -> str:
    ns: dict = {}
    exec((ROOT / "fido2tool_core" / "version.py").read_text(), ns)
    return ns["__version__"]


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        found = validate(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")), _version(),
                         strict="--strict" in sys.argv)
        for p in found:
            print("SBOM:", p)
        print(f"{sys.argv[2]}: {'OK' if not found else f'{len(found)} problem(s)'}")
        sys.exit(1 if found else 0)
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "keymelier-sbom.cdx.json"
    print(write(target, _version()))
