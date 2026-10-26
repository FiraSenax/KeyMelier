"""Select Microsoft redistributables from their documented deployment folders.

PyInstaller's PATH search can otherwise collect copies from unrelated JDKs.
VS 2022's licensed VC redist and the Windows SDK's UCRT redist are explicit
build prerequisites. No debug, preview or arbitrary PATH fallback is used.
"""
import os
import re
import subprocess
from pathlib import Path


def family(filename):
    name = filename.lower()
    if name == "ucrtbase.dll" or name.startswith("api-ms-win-") and name.endswith(".dll"):
        return "ucrt"
    if re.fullmatch(r"(?:vcruntime|msvcp|concrt|vcomp)140(?:_[a-z0-9_]+)?\.dll", name):
        return "vc"
    return None


def latest(paths, version_index):
    valid = [p for p in paths if re.fullmatch(r"\d+(?:\.\d+)+", p.parts[version_index])]
    if not valid:
        raise ValueError("Install the VS 2022 C++ and Windows SDK redistributables before building")
    return max(valid, key=lambda p: tuple(map(int, p.parts[version_index].split("."))))


def locations():
    program_files = Path(os.environ["ProgramFiles(x86)"])
    vswhere = program_files / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-version", "[17.0,18.0)",
                                  "-property", "installationPath"], text=True).strip()
    if not vs:
        raise ValueError("Visual Studio 2022 is required for documented runtime redistribution")
    vc = latest((Path(vs) / "VC/Redist/MSVC").glob("*/x64/Microsoft.VC143.CRT"), -3)
    sdk = latest((program_files / "Windows Kits/10/Redist").glob("*/ucrt/DLLs/x64"), -4)
    return {"vc": vc, "ucrt": sdk}


def select(binaries, roots=None):
    roots = locations() if roots is None else roots
    replacements = {kind: {p.name.lower(): p for p in root.glob("*.dll")} for kind, root in roots.items()}
    out, used = [], set()
    for dest, src, kind in binaries:
        name = dest.replace("\\", "/").rsplit("/", 1)[-1]
        group = family(name)
        if group:
            source = replacements[group].get(name.lower())
            if source is None:
                raise ValueError("Runtime missing from Microsoft's redist directory: " + name)
            out.append((dest, str(source), kind))
            used.add(name.lower())
        else:
            out.append((dest, src, kind))
    # Include each selected redist's companion DLLs, rather than mixing versions
    # or omitting dependencies introduced by a serviced runtime.
    for files in replacements.values():
        for name, source in sorted(files.items()):
            if name not in used:
                out.append((source.name, str(source), "BINARY"))
                used.add(name)
    return out
