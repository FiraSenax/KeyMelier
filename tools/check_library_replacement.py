"""Run a COPY of the packaged app with changed external LGPL libraries.

pyscard: change Python source. Linux Qt: replace the NUL-terminated qVersion
string in libQt6Core and require the changed result at runtime. This is a
binary replacement test, not a claim that Qt was rebuilt from source.
No publisher keys are used; the copied macOS app gets an ad-hoc signature.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = "keymelier-library-replacement-1"


def modify_pyscard(path):
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open("a", encoding="utf-8") as out:
        out.write(f"\n__keymelier_replacement_probe__ = {PROBE!r}\n")
    shutil.rmtree(path.parent / "__pycache__", ignore_errors=True)
    return {"file": "smartcard/System.py", "before": before,
            "after": hashlib.sha256(path.read_bytes()).hexdigest()}


def modify_qt(path):
    raw = path.read_bytes()
    old, new = b"6.11.2\0", b"6.11.3\0"
    if old not in raw:
        raise ValueError("Review the Qt replacement probe for this version")
    modified = raw.replace(old, new)
    path.write_bytes(modified)
    return {"file": path.name, "before": hashlib.sha256(raw).hexdigest(),
            "after": hashlib.sha256(modified).hexdigest(), "expected_qVersion": "6.11.3"}


def main():
    supplied = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / ("KeyMelier.app" if sys.platform == "darwin" else "KeyMelier")
    original = supplied.resolve()
    output = Path(os.environ.get("SMOKE_ARTIFACTS", ROOT / "build/smoke-artifacts")) / "replacement"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="km-replacement-") as tmp:
        copy = (Path(tmp) / original.name).resolve()
        shutil.copytree(original, copy, symlinks=True)
        base = copy / "Contents/Resources" if sys.platform == "darwin" else copy / "_internal"
        if not (base / "smartcard/System.py").resolve().is_relative_to(copy):
            raise ValueError("Replacement target escapes the disposable copy")
        modifications = [modify_pyscard(base / "smartcard/System.py")]
        expected = {"pyscard": PROBE}
        if sys.platform.startswith("linux"):
            qt = base / "PySide6/Qt/lib/libQt6Core.so.6"
            if not qt.resolve().is_relative_to(copy):
                raise ValueError("Replacement target escapes the disposable copy")
            modifications.append(modify_qt(qt.resolve()))
            expected["qt"] = "6.11.3"
        if sys.platform == "darwin":
            subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(copy)], check=True)
            app = copy
        else:
            app = copy / ("KeyMelier.exe" if sys.platform == "win32" else "KeyMelier")
        (output / "modified-libraries.json").write_text(json.dumps(modifications, indent=2) + "\n")
        env = {**os.environ, "KEYMELIER_LIBRARY_PROBE": json.dumps(expected), "SMOKE_ARTIFACTS": str(output.resolve())}
        subprocess.run([sys.executable, str(ROOT / "tools/smoke_packaged.py"), str(app)], env=env, check=True)
        report = json.loads((output / "self-test.json").read_text())
        passed = {c["name"] for c in report["checks"] if c["ok"]}
        for name in expected:
            if "replacement: " + name not in passed:
                raise ValueError("Modified library was not confirmed at runtime: " + name)
    print("Modified LGPL libraries loaded; packaged application start test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
