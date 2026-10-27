#!/usr/bin/env python3
"""Keep source manifests coupled to dependency upgrades (offline).

After uv lock / export_requirements.py, run --refresh and review the diff.
Special embedded dependencies still require a deliberate source/notice review;
refresh never guesses a new vendored version or relaxes a license grant.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def source_pins(root=ROOT):
    packages = tomllib.loads((root / 'uv.lock').read_text())['package']
    out = {}
    for package in packages:
        source = package.get('sdist')
        if not source:
            continue
        out[package['name']] = {'version': package['version'], 'url': source['url'],
            'filename': source['url'].rsplit('/', 1)[-1],
            'sha256': source['hash'].removeprefix('sha256:'), 'size': source['size'], 'modified': False}
    return dict(sorted(out.items()))


def check(root=ROOT):
    problems = []
    expected = source_pins(root)
    if json.loads((root / 'packaging/python-sources.json').read_text()) != expected:
        problems.append('Python source manifest is stale: run python tools/license_inputs.py --refresh')
    versions = {p['name']: p['version'] for p in tomllib.loads((root / 'uv.lock').read_text())['package']}
    for name, review in json.loads((root / 'packaging/license-policy.json').read_text()).items():
        if name in versions and versions[name] not in review['versions']:
            problems.append('Review dependency license/source changes before approving ' + name + ' ' + versions[name])
    for name, review in json.loads((root / 'packaging/license-overrides.json').read_text()).items():
        if versions.get(name) != review['version']:
            problems.append('Review original license terms before reusing the SPDX override for ' + name)
    for item in json.loads((root / 'packaging/embedded-sources.json').read_text()):
        if versions.get(item['parent']) != item['parent_version']:
            problems.append('Review embedded sources/notices after upgrading ' + item['parent'])
        if item['component'] == 'nanobind' and versions.get('nanobind') != item['version']:
            problems.append('Controlled nanobind source differs from the build dependency lock')
    qt = versions['pyside6']
    for filename, item in json.loads((root / 'packaging/linux-sources.json').read_text()).items():
        if '-everywhere' in filename and item['version'] != qt:
            problems.append('Review Qt module sources/notices: ' + filename)
    runtime = json.loads((root / 'packaging/runtime-build.json').read_text())
    runtime_source = next(s for s in runtime['sources'] if s['component'] == 'type2-runtime')
    if not runtime_source['url'].endswith('/' + runtime['runtime_commit']):
        problems.append('Runtime source commit and build version disagree')
    for filename, item in json.loads((root / 'packaging/licenses/provenance.json').read_text()).items():
        if hashlib.sha256((root / 'packaging/licenses' / filename).read_bytes()).hexdigest() != item['sha256']:
            problems.append('Original license text differs from its recorded provenance: ' + filename)
    return sorted(set(problems))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    if args.refresh:
        (ROOT / 'packaging/python-sources.json').write_text(json.dumps(source_pins(), indent=2) + '\n')
    problems = check()
    if problems:
        print('\n'.join(problems))
        return 1
    print('Dependency sources and original license checksums match the reviewed inputs.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
