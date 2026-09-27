#!/usr/bin/env python3
"""Collect the licenses of everything shipped in the app bundle.

    python3 tools/third_party_licenses.py [output]

Called by the PyInstaller spec, so each platform's build lists exactly the
runtime packages installed there (requirements.txt carries platform markers).
MIT/BSD/Apache require their notices in binary distributions; pyscard is
LGPL and certifi MPL, so their source locations are named as well.
"""

import re
import sys
import sysconfig
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Copyleft packages: where their source code is available (LGPL/MPL)
SOURCE = {
    "pyscard": "https://github.com/LudovicRousseau/pyscard (LGPL-2.1-or-later; the library is shipped "
               "as separate, replaceable files inside the app)",
    "certifi": "https://github.com/certifi/python-certifi (MPL-2.0)",
    "python-pskc": "https://github.com/arthurdejong/python-pskc (LGPL-2.1-or-later)",
}

# Packages whose metadata has no usable license label
LABELS = {"yubikey-manager": "BSD-2-Clause"}

MIT_TEXT = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

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
        if LICENSE_NAMES.search(Path(str(f)).name) and ".dist-info" in str(f):
            try:
                texts.append((Path(str(f)).name, Path(dist.locate_file(f)).read_text(errors="replace").strip()))
            except OSError:
                pass
    return texts


def license_label(dist) -> str:
    meta = dist.metadata
    if meta["Name"].lower() in LABELS:
        return LABELS[meta["Name"].lower()]
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
    return "Python Software Foundation License Version 2 – https://docs.python.org/3/license.html"


def build() -> str:
    rule = "=" * 78
    out = [
        "KeyMelier – third-party licenses",
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
    for name in requirement_names():
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue  # other platform (requirements.txt has markers)
        out += [rule, f"{dist.metadata['Name']} {dist.version} – {license_label(dist)}"]
        home = dist.metadata.get("Home-page") or next(
            (u.split(",", 1)[1].strip() for u in dist.metadata.get_all("Project-URL") or []
             if u.lower().startswith(("source", "homepage", "repository"))), "")
        if home:
            out.append(home)
        if name.lower() in SOURCE:
            out.append(f"Source code: {SOURCE[name.lower()]}")
        out.append(rule)
        texts = license_texts(dist)
        if not texts and "MIT" in license_label(dist):
            author = (dist.metadata.get("Author") or dist.metadata.get("Author-email") or "the authors").strip()
            texts = [("MIT License (package ships no license file)", f"Copyright (c) {author}\n\n{MIT_TEXT}")]
        if not texts:
            missing.append(name)
            out.append(f"License: {license_label(dist)} (no license file in the package)")
        for filename, text in texts:
            out += ["", f"--- {filename} ---", "", text]
        out.append("")
    out += [rule, f"Python {sys.version.split()[0]} – PSF License", rule, "", python_license(), ""]
    if missing:
        print("Note: no license file shipped by: " + ", ".join(missing), file=sys.stderr)
    return "\n".join(out)


def write(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build(), encoding="utf-8")
    return path


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "THIRD_PARTY_LICENSES.txt"
    print(write(target))
