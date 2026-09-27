#!/usr/bin/env python3
"""CycloneDX 1.6 SBOM of everything shipped in the app bundle.

    python3 tools/sbom.py [output]

Called by the PyInstaller spec next to third_party_licenses.py, so each
platform's build describes exactly the runtime packages installed there.
Each component carries its package URL, license and the SHA-256 hashes the
lock file allows for it (requirements.txt is installed with --require-hashes).
"""

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

from third_party_licenses import license_label, requirement_names  # noqa: E402


def lock_hashes() -> dict[str, list[str]]:
    """Package name -> allowed sha256 hashes from requirements.txt."""
    hashes: dict[str, list[str]] = {}
    current = None
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==", line)
        if m:
            current = _norm(m.group(1))
        for h in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
            if current:
                hashes.setdefault(current, []).append(h)
    return hashes


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _license(dist) -> list[dict]:
    label = license_label(dist)
    if label == "see license text":
        return []
    spdx_like = re.fullmatch(r"[A-Za-z0-9.+-]+(?: (?:OR|AND) [A-Za-z0-9.+-]+)*", label)
    if spdx_like and " " in label:
        return [{"expression": label}]
    key = "id" if spdx_like else "name"
    return [{"license": {key: label}}]


def build(app_version: str) -> dict:
    hashes = lock_hashes()
    components = []
    for name in requirement_names():
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue  # other platform
        norm = _norm(dist.metadata["Name"])
        component = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{norm}@{dist.version}",
            "name": dist.metadata["Name"],
            "version": dist.version,
            "purl": f"pkg:pypi/{norm}@{dist.version}",
        }
        licenses = _license(dist)
        if licenses:
            component["licenses"] = licenses
        if hashes.get(norm):
            # the artifact actually installed is one of these (hash-pinned install)
            component["properties"] = [{"name": "keymelier:lock:sha256", "value": h} for h in hashes[norm]]
        components.append(component)
    components.append({
        "type": "platform", "bom-ref": f"python@{platform.python_version()}", "name": "CPython",
        "version": platform.python_version(), "licenses": [{"license": {"id": "PSF-2.0"}}],
    })
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
            "properties": [{"name": "keymelier:platform", "value": f"{sys.platform}-{platform.machine()}"}],
        },
        "components": components,
        "dependencies": [{"ref": f"keymelier@{app_version}", "dependsOn": [c["bom-ref"] for c in components]}],
    }


def write(path: Path, app_version: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(app_version), indent=2), encoding="utf-8")
    return path


if __name__ == "__main__":
    ns: dict = {}
    exec((ROOT / "fido2tool_core" / "version.py").read_text(), ns)
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "keymelier-sbom.cdx.json"
    print(write(target, ns["__version__"]))
