"""Preserve wheel authors' SBOMs without treating optional features as shipped.

The original documents remain separate: Pillow describes optional/build-only
dependencies as well as compiled modules. Flattening that list into our runtime
SBOM would falsely declare libimagequant (GPL) on wheels built without it.
"""
import base64
import hashlib
import json
from importlib.metadata import distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {"cryptography": ("50.0.2", 2), "pillow": ("13.0.0", 1)}


def collect(names, binaries):
    collected = {n.lower() for n in names}
    evidence, datas = [], []
    for name, (version, count) in EXPECTED.items():
        if name not in collected:
            continue
        dist = distribution(name)
        if dist.version != version:
            raise ValueError("Review upstream wheel evidence for " + name)
        files = [f for f in dist.files or [] if "/sboms/" in str(f).replace("\\", "/") and str(f).endswith(".json")]
        if len(files) != count:
            raise ValueError("Missing upstream wheel SBOM: " + name)
        for file in files:
            path = Path(dist.locate_file(file))
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).digest()
            record = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            if not file.hash or file.hash.mode != "sha256" or file.hash.value != record:
                raise ValueError("Wheel RECORD hash mismatch: " + str(file))
            bom = json.loads(raw)
            if bom.get("bomFormat") != "CycloneDX":
                raise ValueError("Unexpected upstream SBOM format")
            dest = f"THIRD_PARTY_SBOMS/{name}/{Path(file).name}"
            datas.append((dest, str(path), "DATA"))
            evidence.append({"parent": name, "version": version, "path": dest,
                             "sha256": digest.hex(), "serialNumber": bom.get("serialNumber"),
                             "bom_version": bom.get("version", 1),
                             "scope": "upstream build inventory; optional/excluded entries are not proof of runtime inclusion"})
    pillow = {}
    if "pillow" in collected:
        from PIL import features
        pillow = {"collected_native_files": sorted({Path(dest).name for dest, _src, _kind in binaries
                    if dest.replace("\\", "/").startswith("PIL/")}),
                  "installed_wheel_features": {f: features.version(f) for f in features.get_supported()},
                  "note": "Installed features may belong to extensions not collected into the app."}
    return evidence, pillow, datas
