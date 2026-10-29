#!/usr/bin/env python3
"""Require the exact release checkout to be reachable from freshly fetched main.

The workflow fetches origin/main before calling this tool, without signing
secrets. This is an accident guard in the workflow, not an independent trust
boundary against someone who can change the workflow or repository rules.
"""
import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_REF = "refs/remotes/origin/main"
RELEASE_REF = re.compile(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?")


def validate(ref: str, expected_sha: str, repo: Path = ROOT) -> str:
    if not RELEASE_REF.fullmatch(ref):
        raise ValueError("Production signing requires a version tag (vX.Y.Z or vX.Y.Z-rc.N)")
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", expected_sha):
        raise ValueError("Expected source commit must be a full Git object id")

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                       stderr=subprocess.PIPE).strip()

    try:
        head = git("rev-parse", "--verify", "HEAD^{commit}")
        tag = git("rev-parse", "--verify", ref + "^{commit}")
        main = git("rev-parse", "--verify", MAIN_REF + "^{commit}")
        if head != expected_sha.lower() or tag != head:
            raise ValueError("Release tag, checked-out commit and workflow source do not match")
        git("merge-base", "--is-ancestor", head, main)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Release commit must be contained in origin/main; missing history fails closed") from error
    return head


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        commit = validate(args.ref, args.sha)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    print(f"Release source {commit} is contained in origin/main")
