#!/usr/bin/env python3
"""Build AppImage's runtime offline and retain exact inputs and linker evidence."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import struct

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'packaging/runtime-build.json'
PROOF = ROOT / 'build/runtime-build.json'


def architecture():
    return {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recipe_hash():
    return hashlib.sha256(Path(__file__).read_bytes() +
        (ROOT / 'packaging/linux/runtime-build.sh').read_bytes()).hexdigest()


def normalized_hash(raw):
    """appimagetool writes only .digest_md5 in our unsigned/no-update build."""
    data = bytearray(raw)
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected a 64-bit little-endian runtime')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, string_index = struct.unpack_from('<HHH', data, 58)
    end = offset + size * count
    if size != 64 or end > len(data) or string_index >= count:
        raise ValueError('Invalid runtime ELF section table')
    strings_offset, strings_size = struct.unpack_from('<QQ', data, offset + string_index * size + 24)
    strings = data[strings_offset:strings_offset + strings_size]
    found = False
    for i in range(count):
        entry = offset + i * size
        name = struct.unpack_from('<I', data, entry)[0]
        if bytes(strings[name:]).split(b'\0', 1)[0] == b'.digest_md5':
            start, length = struct.unpack_from('<QQ', data, entry + 24)
            if length != 16 or start + length > end:
                raise ValueError('Invalid AppImage digest section')
            data[start:start + length] = b'\0' * length
            found = True
    if not found:
        raise ValueError('AppImage digest section missing')
    return hashlib.sha256(data[:end]).hexdigest()


def validate_proof(proof):
    lock = json.loads(LOCK.read_text())
    if proof.get('inputs_sha256') != digest(LOCK) or proof.get('recipe_sha256') != recipe_hash():
        raise ValueError('Stale AppImage runtime source/build evidence; run tools/build_runtime.py')
    if proof.get('container') != lock['container'] or proof.get('toolchain_packages') != lock['toolchain_packages']:
        raise ValueError('Unreviewed AppImage runtime toolchain')
    if proof.get('toolchain_commits') != lock['toolchain_commits']:
        raise ValueError('Runtime toolchain package source commits differ')
    versions = {s['component']: s['version'] for s in lock['sources']
                if s['component'] in {'zlib', 'zstd', 'mimalloc', 'libfuse', 'squashfuse'}}
    if proof.get('component_versions') != versions:
        raise ValueError('Actually compiled runtime component versions differ from the source lock')
    if not proof.get('linked_files') or len(proof.get('sha256', '')) != 64:
        raise ValueError('Missing AppImage runtime linker/artifact evidence')
    known = {'libc.a', 'libgcc.a', 'libgcc_eh.a', 'libssp_nonshared.a', 'libsquashfuse.a', 'libsquashfuse_ll.a',
             'libzstd.a', 'libz.a', 'libfuse3.a', 'libmimalloc.a',
             'rcrt1.o', 'crti.o', 'crtn.o', 'crtbeginS.o', 'crtendS.o', 'crtbeginT.o', 'crtend.o'}
    for item in proof['linked_files']:
        if Path(item['file']).name not in known or len(item['sha256']) != 64:
            raise ValueError('Review newly linked runtime input: ' + item['file'])
    if not {'libc.a', 'libfuse3.a', 'libsquashfuse.a'} <= {Path(i['file']).name for i in proof['linked_files']}:
        raise ValueError('Incomplete runtime static link inventory')


def verify_built():
    proof = json.loads(PROOF.read_text())
    validate_proof(proof)
    runtime = ROOT / 'build/appimage-tools' / ('runtime-' + architecture())
    if digest(runtime) != proof['sha256'] or proof['architecture'] != architecture():
        raise ValueError('AppImage runtime differs from controlled build')
    return proof


def main():
    from corresponding_sources import fetch
    lock = json.loads(LOCK.read_text())
    work = ROOT / 'build/runtime-controlled'
    shutil.rmtree(work, ignore_errors=True)
    sources = work / 'sources'
    output = work / 'out'
    sources.mkdir(parents=True)
    output.mkdir()
    # Build recipes/toolchain-source records are retained in the source bundle;
    # only the inputs compiled here enter the offline container.
    for source in lock['sources']:
        if source['component'] not in {'musl', 'alpine-musl-build', 'alpine-gcc-build'}:
            shutil.copyfile(fetch(source), sources / source['filename'])
    packages = ' '.join(name + '=' + version for name, version in lock['toolchain_packages'].items())
    dockerfile = work / 'Dockerfile'
    dockerfile.write_text('FROM ' + lock['container'] + '\nRUN apk add --no-cache '
        'bash build-base clang binutils file autoconf automake libtool meson ninja cmake '
        'linux-headers python3 pkgconf ' + packages + '\n')
    tag = 'keymelier-runtime-build:' + digest(LOCK)[:16]
    subprocess.run(['docker', 'build', '--tag', tag, str(work)], check=True)
    subprocess.run(['docker', 'run', '--rm', '--network=none',
        '-e', 'RUNTIME_COMMIT=' + lock['runtime_commit'],
        '-v', str(sources) + ':/sources:ro', '-v', str(output) + ':/out',
        '-v', str(ROOT / 'packaging/linux/runtime-build.sh') + ':/build-runtime.sh:ro',
        tag, 'sh', '/build-runtime.sh'], check=True)
    if 'NEEDED' in (output / 'elf-dynamic.txt').read_text():
        raise ValueError('AppImage runtime unexpectedly links a shared library')
    installed, commits = {}, {}
    for block in (output / 'alpine-installed.txt').read_text().split('\n\n'):
        fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        if fields.get('P') in lock['toolchain_packages']:
            installed[fields['P']] = fields['V']
            commits[fields['P']] = fields.get('c')
    if installed != lock['toolchain_packages']:
        raise ValueError('Installed runtime toolchain differs from reviewed versions')
    proof = {'schema': 1, 'architecture': architecture(), 'inputs_sha256': digest(LOCK),
             'recipe_sha256': recipe_hash(), 'container': lock['container'],
             'toolchain_packages': installed, 'sha256': digest(output / 'runtime'),
             'toolchain_commits': commits,
             'component_versions': json.loads((output / 'component-versions.json').read_text()),
             'normalized_sha256': normalized_hash((output / 'runtime').read_bytes()),
             'linked_files': json.loads((output / 'linked-files.json').read_text()),
             'link_map_sha256': digest(output / 'runtime.map')}
    validate_proof(proof)
    target = ROOT / 'build/appimage-tools' / ('runtime-' + architecture())
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output / 'runtime', target)
    PROOF.write_text(json.dumps(proof, indent=2) + '\n')
    verify_built()
    print('Controlled AppImage runtime build verified:', proof['sha256'])


if __name__ == '__main__':
    main()
