"""Use Microsoft's system runtimes; do not redistribute VC/UCRT/API DLLs.

The Windows installer checks for the x64 Visual C++ runtime and directs users
to Microsoft's own installer when it is missing. Windows 10/11 supply UCRT.
This filter applies to every destination, including nested wheel directories.
"""
import re


def family(filename):
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in {"ucrtbase.dll", "ucrtbased.dll"} or name.startswith(("api-ms-win-", "ext-ms-win-")) and name.endswith(".dll"):
        return "ucrt"
    if re.fullmatch(r"(?:vcruntime|msvcr|msvcp|concrt|vcomp|mfc|mfcm)\d+[a-z0-9_]*\.dll", name):
        return "vc"
    return None


def select(binaries):
    return [entry for entry in binaries if family(entry[0]) is None]
