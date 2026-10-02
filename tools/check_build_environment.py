#!/usr/bin/env python3
"""Reject stale/modified pywebview scripts before they enter a signed bundle.

pywebview loads every .js file under webview/js, including stray copies such as
'customize 2.js'. pip --force-reinstall does not remove files absent from RECORD.
Those copies can crash Cocoa during navigation before Python can report an error.
"""
import base64
import hashlib
from importlib.metadata import distribution
from pathlib import Path


def verify_scripts(root: Path, expected: dict[str, str]) -> list[str]:
    actual = {p.relative_to(root).as_posix(): p for p in root.rglob('*.js')}
    problems = []
    for name in sorted(actual.keys() - expected.keys()):
        problems.append(f'unexpected pywebview script: {name}')
    for name, digest in sorted(expected.items()):
        path = actual.get(name)
        if path is None:
            problems.append(f'missing pywebview script: {name}')
        elif path.is_symlink() or base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode().rstrip('=') != digest:
            problems.append(f'modified pywebview script: {name}')
    return problems


def check() -> None:
    dist = distribution('pywebview')
    expected = {}
    for file in dist.files or ():
        name = str(file).replace('\\', '/')
        if name.startswith('webview/js/') and name.endswith('.js'):
            if not file.hash or file.hash.mode != 'sha256':
                raise SystemExit('pywebview has no SHA-256 script manifest; use a clean wheel installation')
            expected[name.removeprefix('webview/js/')] = file.hash.value
    if not expected:
        raise SystemExit('pywebview script manifest missing; use a clean wheel installation')
    problems = verify_scripts(Path(dist.locate_file('webview/js')), expected)
    if problems:
        raise SystemExit('Build environment is not clean:\n  ' + '\n  '.join(problems)
                         + '\nCreate a NEW virtual environment and install the hash-pinned requirements. '
                         'Reinstalling over the old environment does not remove stray copies.')


if __name__ == '__main__':
    check()
    print('pywebview scripts match their installed wheel manifest')
