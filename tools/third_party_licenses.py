#!/usr/bin/env python3
"""Collect original notices for the application's identified dependencies.

    python3 tools/third_party_licenses.py [output]

Called after PyInstaller Analysis, using the collected distribution inventory.
MIT/BSD/Apache require their notices in binary distributions; pyscard is
LGPL and certifi MPL, so their source locations are named as well.
"""

import hashlib
import json
import re
import sys
import sysconfig
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Missing files are supplied only from reviewed upstream sources, never by
# inventing an author/copyright notice from package metadata.
EXTRA_TEXTS = {
    "pyside6": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-essentials": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-addons": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "shiboken6": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "proxy-tools": ["proxy-tools-NOTICE.txt", "werkzeug-0.9.4-LICENSE.txt"],
}
LABELS = {"yubikey-manager": "BSD-2-Clause", "proxy-tools": "BSD-3-Clause (source header; PyPI metadata differs)",
          "setuptools": "MIT; bundled components have additional licenses (see nested notices)",
          "pywin32": "PSF-2.0 and BSD-3-Clause (bundled modules)"}

LICENSE_NAMES = re.compile(r"(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", re.I)


def requirement_names() -> list[str]:
    names = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==", line)
        if m:
            names.append(m.group(1))
    return sorted(set(names), key=str.lower)


def license_texts(dist) -> list[tuple[str, str]]:
    texts = []
    for f in dist.files or []:
        if LICENSE_NAMES.search(Path(str(f)).name) and Path(str(f)).suffix.lower() not in {".py", ".pyc", ".so", ".dll"}:
            try:
                texts.append((str(f).replace("\\", "/"), Path(dist.locate_file(f)).read_text(errors="replace").strip()))
            except OSError as error:
                raise ValueError(f"Original license file cannot be read: {f}") from error
    name = dist.metadata["Name"].lower().replace("_", "-")
    extras = EXTRA_TEXTS.get(name, [])
    if name.startswith("pyobjc-") and not texts:
        if dist.version != "12.2.2":
            raise ValueError(f"Review the upstream PyObjC license for {dist.version}")
        extras = ["pyobjc-12.2.2-LICENSE.txt"]
    if name == "proxy-tools" and dist.version != "0.1.0":
        raise ValueError("Review the proxy-tools source license for this version")
    for filename in extras:
        texts.append((filename, (ROOT / "packaging" / "licenses" / filename).read_text().strip()))
    return texts


def license_label(dist) -> str:
    meta = dist.metadata
    name = meta["Name"].lower().replace("_", "-")
    if name in LABELS:
        return LABELS[name]
    label = meta.get("License-Expression") or ""
    if not label:
        classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License")]
        label = ", ".join(classifiers)
    if not label:
        label = (meta.get("License") or "").splitlines()[0] if meta.get("License") else ""
    return label or "see license text"


def python_license() -> str:
    for candidate in (Path(sysconfig.get_paths()["stdlib"]) / "LICENSE.txt",
                      Path(sys.base_prefix) / "LICENSE.txt"):
        if candidate.exists():
            return candidate.read_text(errors="replace").strip()
    raise ValueError("CPython LICENSE.txt missing: use a Python distribution with its original license")


def build(names=None, native_notices=()) -> str:
    rule = "=" * 78
    out = [
        "KeyMelier – licenses and notices",
        rule,
        "",
        "KeyMelier itself:",
        "",
        (ROOT / "LICENSE").read_text().strip(),
        "",
        "KeyMelier bundles the Python runtime and the open-source packages listed",
        "below. Each is used under its own license, reproduced here.",
        "The application is built with PyInstaller, whose bootloader is GPL-2.0",
        "with an exception that explicitly allows distributing built applications.",
        "",
    ]
    missing = []
    for name in (requirement_names() if names is None else names):
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            if names is not None:
                raise ValueError(f"Collected distribution is missing: {name}") from None
            continue  # other platform (requirements.txt has markers)
        out += [rule, f"{dist.metadata['Name']} {dist.version} – {license_label(dist)}"]
        home = dist.metadata.get("Home-page") or next(
            (u.split(",", 1)[1].strip() for u in dist.metadata.get_all("Project-URL") or []
             if u.lower().startswith(("source", "homepage", "repository"))), "")
        if home:
            out.append(home)
        out.append(f"Exact package release: https://pypi.org/project/{name}/{dist.version}/#files")
        out.append(rule)
        texts = license_texts(dist)
        if not texts:
            missing.append(name)
        for filename, text in texts:
            out += ["", f"--- {filename} ---", "", text]
        out.append("")
    try:
        bootloader = distribution("pyinstaller")
    except PackageNotFoundError:
        if names is not None:
            raise ValueError("PyInstaller bootloader license is missing") from None
    else:
        texts = license_texts(bootloader)
        if not texts:
            missing.append("PyInstaller bootloader")
        out += [rule, f"PyInstaller {bootloader.version} bootloader — GPL-2.0-or-later WITH Bootloader-exception", rule]
        for filename, text in texts:
            out += ["", f"--- {filename} ---", "", text]
    for filename in ("lucide-LICENSE.txt", "feather-LICENSE.txt", "FIDO-METADATA-NOTICE.txt",
                     "LIBRARY-REPLACEMENT.txt"):
        out += [rule, filename, rule, "", (ROOT / "packaging" / "licenses" / filename).read_text().strip(), ""]
    if __package__:
        from .make_service_icons import reviewed_brands, asset_bytes
    else:
        from make_service_icons import reviewed_brands, asset_bytes
    for name, info in sorted(reviewed_brands().items()):
        if info["status"] != "enabled":
            continue
        asset_bytes(name, info)  # fails if the reviewed original was changed
        out += [rule, info["title"] + " – original brand asset", rule, info["attribution"],
                "Used only to identify the corresponding account; no affiliation or endorsement.",
                "Usage terms: " + info["terms_url"], "Original asset: " + info["asset_url"],
                "These trademarks are not licensed under KeyMelier's MIT license or CC0.", ""]
    if sys.platform == "win32":
        out += [rule, "Microsoft system prerequisites (not bundled)", rule,
                "The Visual C++ x64 runtime must be installed separately from Microsoft.",
                "Windows 10/11 provide the Universal CRT and Windows API libraries.",
                "KeyMelier does not bundle VC, UCRT or Windows API-set DLLs.",
                "Microsoft's installer supplies the applicable terms for that separate software.",
                "https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist", ""]
        for filename in ("webview2-1.0.3856.49-LICENSE.txt", "webview2-1.0.3856.49-NOTICE.txt"):
            out += [rule, "Microsoft WebView2 SDK 1.0.3856.49 – " + filename, rule,
                    (ROOT / "packaging" / "licenses" / filename).read_text(), ""]
    if sys.platform.startswith("linux"):
        for filename in ("appimage-runtime-LICENSE.txt", "gcc-14.2.0-COPYING3.txt",
                         "gcc-14.2.0-RUNTIME-EXCEPTION.txt"):
            out += [rule, "AppImage runtime / static dependency — " + filename, rule,
                    (ROOT / "packaging/licenses" / filename).read_text(), ""]
    for name, text in native_notices:
        out += [rule, name, rule, text, ""]
    out += [rule, f"Python {sys.version.split()[0]} – PSF License", rule, "", python_license(), ""]
    if missing:
        raise ValueError("Missing original license texts: " + ", ".join(missing))
    return "\n".join(out)


def write(path: Path, names=None, native_notices=()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Check all vendored notices against the reviewed originals.
    provenance = json.loads((ROOT / "packaging/licenses/provenance.json").read_text())
    for name, info in provenance.items():
        raw = (ROOT / "packaging/licenses" / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != info["sha256"]:
            raise ValueError(f"Vendored license changed: {name}")
    path.write_text(build(names, native_notices), encoding="utf-8")
    return path


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "THIRD_PARTY_LICENSES.txt"
    print(write(target))
