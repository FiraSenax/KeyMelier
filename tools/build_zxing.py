#!/usr/bin/env python3
"""Build zxing from checked source with locked nanobind, without dependency downloads."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from importlib.metadata import distribution

from corresponding_sources import fetch
from license_inputs import check

ROOT = Path(__file__).resolve().parent.parent
PROOF = ROOT / 'build/zxing-build.json'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inputs():
    items = json.loads((ROOT / 'packaging/embedded-sources.json').read_text())
    return [s for s in items if s['parent'] == 'zxing-cpp']


def recipe_hash():
    return digest(__file__)


def validate_proof(proof):
    expected = {s['component']: {'version': s['version'], 'sha256': s['sha256']} for s in inputs()}
    if proof.get('inputs') != expected or proof.get('recipe_sha256') != recipe_hash():
        raise ValueError('zxing build proof has stale sources or recipe; rebuild with tools/build_zxing.py')
    vendors = next(s for s in inputs() if s['component'] == 'nanobind')['vendored_components']
    if proof.get('vendored_components') != vendors:
        raise ValueError('Missing/stale nanobind vendored component evidence')
    for field in ('wheel_sha256',):
        if len(proof.get(field, '')) != 64:
            raise ValueError('Missing controlled zxing build artifact hash')


def verify_installed():
    proof = json.loads(PROOF.read_text())
    validate_proof(proof)
    dist = distribution('zxing-cpp')
    if dist.version != proof['inputs']['zxing-cpp']['version']:
        raise ValueError('Installed zxing version differs from its controlled build')
    actual = {str(f).replace('\\', '/'): digest(dist.locate_file(f)) for f in dist.files or []
              if str(f).endswith(('.so', '.pyd', '.dll', '.dylib'))}
    if not actual or actual != proof['installed_binaries']:
        raise ValueError('Installed zxing binaries differ from the controlled source build')
    return proof


def main():
    problems = check()
    if problems:
        raise SystemExit('\n'.join(problems))
    sources = {s['component']: s for s in inputs()}
    nanobind = distribution('nanobind')
    if nanobind.version != sources['nanobind']['version']:
        raise SystemExit('Install the locked build requirements before compiling zxing')
    source = fetch(sources['zxing-cpp'])
    vendors = sources['nanobind']['vendored_components']
    nanobind_source = ROOT / 'build/controlled-nanobind'
    shutil.rmtree(nanobind_source, ignore_errors=True)
    nanobind_source.mkdir(parents=True)
    with tarfile.open(fetch(sources['nanobind'])) as archive:
        for vendor in vendors.values():
            member = archive.getmember('nanobind-' + nanobind.version + '/' + vendor['file'])
            raw = archive.extractfile(member).read()
            if hashlib.sha256(raw).hexdigest() != vendor['sha256']:
                raise ValueError('Vendored nanobind header differs from the reviewed source')
        archive.extractall(nanobind_source, filter='data')
    nanobind_cmake = nanobind_source / ('nanobind-' + nanobind.version) / 'cmake'
    folder = ROOT / 'build/controlled-wheels'
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    env = {**os.environ, 'PIP_NO_INDEX': '1', 'CMAKE_BUILD_PARALLEL_LEVEL': '4'}
    if sys.platform == 'darwin':
        import platform
        env['MACOSX_DEPLOYMENT_TARGET'] = '11.0' if platform.machine() == 'arm64' else '10.15'
    elif sys.platform == 'win32':
        # A VS generator finds the installed compiler/SDK without requiring the
        # caller to launch a special Developer Command Prompt first.
        env['CMAKE_GENERATOR'] = 'Visual Studio 17 2022'
        env['CMAKE_GENERATOR_PLATFORM'] = 'x64'
    # LOCAL disallows CMake's implicit GitHub fallback; nanobind_DIR selects the
    # checked source, independently of a host installation or CMake search path.
    command = [sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
               '--no-index', '--no-cache-dir', '--wheel-dir', str(folder), str(source),
               '-Ccmake.define.ZXING_DEPENDENCIES=LOCAL',
               '-Ccmake.define.FETCHCONTENT_FULLY_DISCONNECTED=ON',
               '-Ccmake.define.nanobind_DIR=' + str(nanobind_cmake)]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    wheels = list(folder.glob('zxing_cpp-*.whl'))
    if len(wheels) != 1:
        raise SystemExit('Expected exactly one locally compiled zxing wheel')
    wheel = wheels[0]
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps',
                    '--force-reinstall', str(wheel)], check=True, env=env)
    dist = distribution('zxing-cpp')
    proof = {'schema': 1, 'recipe_sha256': recipe_hash(),
             'vendored_components': vendors,
             'inputs': {k: {'version': v['version'], 'sha256': v['sha256']} for k, v in sources.items()},
             'wheel_sha256': digest(wheel), 'wheel_filename': wheel.name,
             'build_tools': {name: distribution(name).version for name in
                             ('scikit-build-core', 'cmake', 'ninja', 'nanobind', 'wheel')},
             'installed_binaries': {str(f).replace('\\', '/'): digest(dist.locate_file(f))
                 for f in dist.files or [] if str(f).endswith(('.so', '.pyd', '.dll', '.dylib'))}}
    PROOF.write_text(json.dumps(proof, indent=2) + '\n')
    verify_installed()
    print('Controlled zxing build verified:', json.dumps(proof['inputs']))


if __name__ == '__main__':
    main()
