"""Identify collected Python distributions and native Linux package notices.

Run after PyInstaller Analysis and its platform filters. Installed-but-unused
requirements are not evidence of distribution. Conversely build dependencies
whose modules are collected must be documented too.
"""

import hashlib
import json
import re
import subprocess
import sys
from importlib.metadata import distributions, distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def collected_packages(entries):
    sources = {Path(src).resolve() for _dest, src, _kind in entries if src and Path(src).is_file()}
    found = []
    for dist in distributions():
        if any(Path(dist.locate_file(f)).resolve() in sources for f in dist.files or []):
            name = dist.metadata["Name"]
            if name.lower() != "pyinstaller":  # its bootloader is documented separately
                found.append(name)
    return sorted(set(found), key=str.lower)


def linux_packages(binaries):
    """Exact distro package/source versions and original Debian copyright files."""
    packages = {}
    for dest, src, _kind in binaries:
        source = Path(src).resolve()
        # Wheel/CPython libraries have separate provenance; only query system ELF files.
        if not source.as_posix().startswith(("/usr/lib/", "/lib/")):
            continue
        candidates = [str(source), str(source).replace("/usr/lib/", "/lib/", 1)]
        owner = None
        for candidate in candidates:
            query = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True)
            if query.returncode == 0:
                owner = query.stdout.split(": ", 1)[0].strip()
                break
        if not owner:
            raise ValueError(f"No Debian package provenance for {dest}")
        if owner not in packages:
            query = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}", owner],
                                   capture_output=True, text=True, check=True)
            binary, version, source_name, source_version = query.stdout.split("\t")
            copyright_file = Path("/usr/share/doc") / owner.split(":")[0] / "copyright"
            if not copyright_file.is_file():
                raise ValueError(f"Missing original copyright file for {owner}")
            notice = copyright_file.read_text()
            # Debian may refer to standard license texts instead of embedding them.
            for license_name in sorted(set(re.findall(r"/usr/share/common-licenses/([A-Za-z0-9_.+-]+)", notice))):
                path = Path("/usr/share/common-licenses") / license_name.rstrip(".")
                if not path.is_file():
                    raise ValueError(f"Missing common license {path}")
                notice += "\n\n--- " + str(path) + " ---\n" + path.read_text()
            packages[owner] = {"name": binary, "version": version, "source_package": source_name,
                               "source_version": source_version, "files": [], "notice": notice,
                               "copyright_sha256": hashlib.sha256(notice.encode()).hexdigest()}
        packages[owner]["files"].append(dest)
    return list(packages.values())


def collect(analysis):
    from license_inputs import check
    problems = check()
    if problems:
        raise ValueError('\n'.join(problems))
    entries = list(analysis.pure) + list(analysis.binaries) + list(analysis.datas)
    names = collected_packages(entries)
    from build_zxing import verify_installed
    zxing_build = verify_installed() if 'zxing-cpp' in names else None
    if any("libreadline" in dest.lower() for dest, _src, _kind in analysis.binaries):
        raise ValueError("GNU Readline is not needed by KeyMelier and must not be bundled")
    if sys.platform == "win32":
        from check_artifacts import pe_info
        webview = [(dest, src) for dest, src, _kind in entries
                   if dest.replace("\\", "/").rsplit("/", 1)[-1].lower() in {"microsoft.web.webview2.core.dll", "microsoft.web.webview2.winforms.dll", "webview2loader.dll"}]
        if not webview:
            raise ValueError("WebView2 SDK inventory missing")
        for dest, src in webview:
            if pe_info(Path(src).read_bytes())["file_version"] != (1, 0, 3856, 49):
                raise ValueError(f"Review the WebView2 SDK notices/version: {dest}")
    natives = linux_packages(analysis.binaries) if sys.platform.startswith("linux") else []
    from wheel_evidence import collect as wheel_evidence
    evidence, pillow, evidence_datas = wheel_evidence(names, analysis.binaries)
    analysis.datas.extend(evidence_datas)
    # Paths describe the build input, not a claim that a license grant follows
    # from the path. In particular, System32 and VS redist copies differ.
    binary_inputs = []
    for dest, src, kind in analysis.binaries:
        path = Path(src)
        if kind == "SYMLINK" or not path.is_file():
            continue
        item = {"file": dest, "source": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        if sys.platform == "win32" and path.suffix.lower() in {".dll", ".pyd", ".exe"}:
            item["file_version"] = list(pe_info(path.read_bytes()).get("file_version") or ())
        binary_inputs.append(item)
    vendors = []
    if "setuptools" in names:
        sources = {Path(src).resolve() for _dest, src, _kind in entries if src}
        vendor_dir = distribution("setuptools").locate_file("setuptools/_vendor")
        vendors = [d for d in distributions(path=[str(vendor_dir)])
                   if any(Path(d.locate_file(f)).resolve() in sources for f in d.files or [])]
    inventory = {"schema": 1, "python_packages": names,
                 "setuptools_vendors": [{"name": d.metadata["Name"], "version": d.version} for d in vendors],
                 "native_packages": [{k: v for k, v in p.items() if k != "notice"} for p in natives],
                 "binary_inputs": binary_inputs, "upstream_sboms": evidence, "pillow": pillow,
                 "zxing_build": zxing_build}
    target = ROOT / "build" / "BUNDLE_INVENTORY.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(inventory, indent=2) + "\n")
    return names, natives, vendors, target
