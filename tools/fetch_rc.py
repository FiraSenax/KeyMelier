#!/usr/bin/env python3
"""Put the packages of one checked CI run into their own release-candidate folder.

    python3 tools/fetch_rc.py RUN_ID [--dest dist]

Takes ONLY the artifact "release-rehearsal" of that GitHub Actions run (the
packages the release checks passed), never older local files. Before anything
is placed it checks: the run finished successfully; the rehearsal report says
passed and names the run's commit; SOURCE_COMMIT.txt is that commit; every
expected file is there and nothing else; every SHA-256 in SHA256SUMS.txt and
in the report matches. Then it writes dist/rc-<version>-<commit12>/ with the
packages, the report, the release notes and RC-MANIFEST.json (version, commit,
run id and link, files with SHA-256, check result).

An existing candidate folder is never overwritten: identical content is left
as it is, anything different is an error. Nothing outside the new folder is
touched. Needs the GitHub CLI (gh), logged in.
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_artifacts  # noqa: E402

REPO = "FiraSenax/KeyMelier"
ARTIFACT = "release-rehearsal"
EXTRA = ("release-check.md", "release-notes.md")   # evidence kept next to the packages


class RCError(Exception):
    pass


def gh(*args) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_info(run_id: str) -> dict:
    info = json.loads(gh("run", "view", run_id, "-R", REPO, "--json", "headSha,status,conclusion,url,event"))
    if info.get("status") != "completed" or info.get("conclusion") != "success":
        raise RCError(f"run {run_id} is {info.get('status')}/{info.get('conclusion')}, not a successful run")
    return info


def download(run_id: str, target: Path) -> None:
    gh("run", "download", run_id, "-R", REPO, "-n", ARTIFACT, "-D", str(target))


def verify(folder: Path, run_id: str, head_sha: str) -> dict:
    """Checks the downloaded rehearsal (packages in folder/artifacts); returns the manifest."""
    packages = folder / "artifacts"
    report_path = folder / "release-check.md"
    if not packages.is_dir() or not report_path.is_file():
        raise RCError("the rehearsal artifact has no packages or no report")
    report = report_path.read_text(encoding="utf-8")
    commit = re.search(r"- Commit: `([0-9a-f]{40})`", report)
    version = re.search(r"- Version: (\d+\.\d+\.\d+)\s*$", report, re.M)
    if not re.search(r"- Result: \*\*passed\*\*", report):
        raise RCError("the release check in the report did not pass")
    if not commit or commit.group(1) != head_sha:
        raise RCError(f"report commit {commit.group(1) if commit else None} is not the run's commit {head_sha}")
    if not version:
        raise RCError("the report names no version")
    source = (packages / "SOURCE_COMMIT.txt").read_text().strip() if (packages / "SOURCE_COMMIT.txt").exists() else ""
    if source != head_sha:
        raise RCError(f"SOURCE_COMMIT.txt is {source or 'missing'}, the run built {head_sha}")
    present = {p.name for p in packages.iterdir() if p.is_file()}
    expected = set(check_artifacts.RELEASE_FILES)
    if present != expected:
        raise RCError(f"artifact list differs – missing {sorted(expected - present)}, extra {sorted(present - expected)}")
    sums = {}
    for line in (packages / "SHA256SUMS.txt").read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line.strip())
        if m:
            sums[m.group(2)] = m.group(1)
    if set(sums) != expected - {"SHA256SUMS.txt"}:
        raise RCError("SHA256SUMS.txt does not list exactly the released files")
    files = {}
    for name in sorted(expected):
        digest = sha256(packages / name)
        if name in sums and digest != sums[name]:
            raise RCError(f"checksum of {name} does not match SHA256SUMS.txt")
        listed = re.search(rf"\| {re.escape(name)} \| [^|]+ \| `([0-9a-f]{{64}})` \|", report)
        if not listed or listed.group(1) != digest:
            raise RCError(f"checksum of {name} does not match the checked report")
        files[name] = digest
    return {"version": version.group(1), "commit": head_sha, "run_id": str(run_id),
            "run_url": f"https://github.com/{REPO}/actions/runs/{run_id}", "release_check": "passed",
            "files": files}


def place(folder: Path, manifest: dict, dest: Path) -> tuple[Path, bool]:
    """Copy into dest/rc-<version>-<commit12>; (path, created). Never overwrites anything different."""
    target = dest / f"rc-{manifest['version']}-{manifest['commit'][:12]}"
    if target.exists():
        existing = target / "RC-MANIFEST.json"
        try:
            old = json.loads(existing.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise RCError(f"{target} exists but has no readable RC-MANIFEST.json – left untouched")
        if old != manifest:
            raise RCError(f"{target} exists with different content – left untouched")
        for name, digest in manifest["files"].items():
            if not (target / name).is_file() or sha256(target / name) != digest:
                raise RCError(f"{target}/{name} was changed – left untouched")
        return target, False
    dest.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".rc-", dir=dest))
    try:
        for name in manifest["files"]:
            shutil.copy2(folder / "artifacts" / name, staging / name)
        for name in EXTRA:
            if (folder / name).is_file():
                shutil.copy2(folder / name, staging / name)
        for name, digest in manifest["files"].items():   # verify the copies, too
            if sha256(staging / name) != digest:
                raise RCError(f"copy of {name} differs")
        (staging / "RC-MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
        staging.rename(target)   # appears complete or not at all
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target, True


def main(argv: list[str]) -> int:
    if not argv or not argv[0].isdigit():
        print(__doc__)
        return 2
    run_id = argv[0]
    dest = Path(argv[argv.index("--dest") + 1]) if "--dest" in argv else ROOT / "dist"
    try:
        info = run_info(run_id)
        with tempfile.TemporaryDirectory() as tmp:
            download(run_id, Path(tmp))
            manifest = verify(Path(tmp), run_id, info["headSha"])
            target, created = place(Path(tmp), manifest, dest)
    except (RCError, subprocess.CalledProcessError) as e:
        print(f"FAIL {e}")
        return 1
    print(f"{'Created' if created else 'Already present, unchanged:'} {target}")
    print(f"  version {manifest['version']}, commit {manifest['commit']}, run {manifest['run_url']}")
    for name, digest in manifest["files"].items():
        print(f"  {digest}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
