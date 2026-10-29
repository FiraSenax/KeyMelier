#!/usr/bin/env python3
"""Set up the independent update key, or sign/verify a prepared release.

setup creates a private backup outside the repository and sends the PEM to an
existing, protected GitHub environment via gh's stdin. Only the public key is
written into data/. Re-running setup reuses the key; it never silently rotates.
No command prints private key material. No command publishes a release.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from keymelier_core import update_auth  # noqa: E402

SECRET = 'KEYMELIER_UPDATE_SIGNING_KEY'
ENVIRONMENT = 'release-signing'
REPOSITORY = 'FiraSenax/KeyMelier'
DEFAULT_PRIVATE = Path.home() / '.config/keymelier/update-signing-key.pem'


def _load_key(pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('An Ed25519 private key is required.')
    return key


def _public_text(key):
    return base64.b64encode(key.public_key().public_bytes_raw()).decode('ascii')


def _gh(*args, input=None):
    result = subprocess.run(['gh', *args], input=input, capture_output=True, check=True)
    return result.stdout


def setup(private_path=DEFAULT_PRIVATE, public_path=update_auth.PUBLIC_KEY_FILE):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.is_symlink() or private_path.resolve().is_relative_to(ROOT):
        raise ValueError('The private backup must be a regular file outside the repository.')
    environment = json.loads(_gh('api', f'repos/{REPOSITORY}/environments/{ENVIRONMENT}'))
    if not environment.get('deployment_branch_policy'):
        raise ValueError('Restrict release-signing to reviewed release tags before setup.')
    secrets = json.loads(_gh('secret', 'list', '--repo', REPOSITORY, '--env', ENVIRONMENT, '--json', 'name'))
    existing_public = public_path.read_text(encoding='ascii').strip() if public_path.exists() else ''
    if private_path.exists():
        if os.name != 'nt' and private_path.stat().st_mode & 0o077:
            raise ValueError('The private backup must be readable only by its owner (0600).')
        pem = private_path.read_bytes()
        key = _load_key(pem)
    else:
        if existing_public or any(item['name'] == SECRET for item in secrets):
            raise ValueError('An update key already exists. Restore its backup; do not replace it silently.')
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(pem)
            stream.flush()
            os.fsync(stream.fileno())
    public = _public_text(key)
    if existing_public and existing_public != public:
        raise ValueError('Backup and pinned public key differ; refusing an unplanned key rotation.')
    # gh encrypts the secret for GitHub; stdin keeps the PEM out of argv/logs.
    _gh('secret', 'set', SECRET, '--repo', REPOSITORY, '--env', ENVIRONMENT, input=pem)
    public_path.write_text(public + '\n', encoding='ascii')
    print(f'Update secret installed in {REPOSITORY}/{ENVIRONMENT}.')
    print(f'Private backup: {private_path}; keep a secure backup of this file.')
    print(f'Public key: {public_path}; include it in the reviewed release commit.')


def checked_sums(folder: Path, commit: str) -> bytes:
    if not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', commit):
        raise ValueError('An exact source commit is required.')
    if (folder / 'SOURCE_COMMIT.txt').read_text().strip() != commit:
        raise ValueError('Source commit differs from the reviewed build.')
    sums_path = folder / 'SHA256SUMS.txt'
    if sums_path.stat().st_size > update_auth.MAX_CHECKSUM_BYTES:
        raise ValueError('Checksum file is too large.')
    data = sums_path.read_bytes()
    listed = set()
    for line in data.decode('utf-8').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if not match or match[2] in listed:
            raise ValueError('Malformed or duplicate checksum entry.')
        digest, name = match.groups()
        path = folder / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Checksum entry is not a regular release file.')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise ValueError('Release file differs from its checksum.')
        listed.add(name)
    expected = {p.name for p in folder.iterdir() if p.name not in ('SHA256SUMS.txt', update_auth.SIGNATURE_FILE)}
    if not listed or listed != expected:
        raise ValueError('Checksums must cover exactly the prepared release files.')
    return data


def sign(folder: Path, tag: str, commit: str):
    from keymelier_core import update_revocation
    update_revocation.ensure_allowed()
    pem = os.environ.get(SECRET, '').encode('ascii')
    if not pem:
        raise ValueError(f'Missing {SECRET} in the protected release environment.')
    key = _load_key(pem)
    if key.public_key().public_bytes_raw() != update_auth.public_key().public_bytes_raw():
        raise ValueError('Signing secret does not match the public key embedded in this release.')
    data = checked_sums(folder, commit)
    signature = base64.b64encode(key.sign(update_auth.signing_payload(tag, data)))
    update_auth.verify(tag, data, signature)
    with (folder / update_auth.SIGNATURE_FILE).open('xb') as stream:
        stream.write(signature + b'\n')


def verify(folder: Path, tag: str, commit: str):
    data = checked_sums(folder, commit)
    update_auth.verify(tag, data, (folder / update_auth.SIGNATURE_FILE).read_bytes())


def requirements():
    """Only the locked signing library and its two dependencies, without Qt/UI."""
    packages = tomllib.loads((ROOT / 'uv.lock').read_text())['package']
    selected = {p['name']: p for p in packages if p['name'] in {'cryptography', 'cffi', 'pycparser'}}
    if set(selected) != {'cryptography', 'cffi', 'pycparser'}:
        raise ValueError('Signing dependencies are missing from uv.lock.')
    for name, package in sorted(selected.items()):
        hashes = sorted({wheel['hash'] for wheel in package['wheels']})
        if not hashes or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in hashes):
            raise ValueError('Signing dependency has no valid wheel hashes.')
        print(name + '==' + package['version'] + ' ' + ' '.join('--hash=' + value for value in hashes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('requirements')
    sub.add_parser('fingerprint')
    create = sub.add_parser('setup')
    create.add_argument('--private-file', type=Path, default=DEFAULT_PRIVATE)
    for name in ('sign', 'verify'):
        command = sub.add_parser(name)
        command.add_argument('folder', type=Path)
        command.add_argument('--tag', required=True)
        command.add_argument('--commit', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'requirements':
            requirements()
        elif args.command == 'fingerprint':
            from keymelier_core.update_revocation import fingerprint
            print(fingerprint())
        elif args.command == 'setup':
            setup(args.private_file)
        else:
            globals()[args.command](args.folder, args.tag, args.commit)
            print('Release-bound update signature verified.')
    except subprocess.CalledProcessError:
        parser.exit(1, 'GitHub operation failed. Check gh authentication and environment access; no private key was printed.\n')
    except (OSError, ValueError) as error:
        # Cryptography/IO errors can include input fragments or paths. Keep the
        # external error generic; tests exercise the detailed internal failures.
        parser.exit(1, f'Update signing {args.command} failed ({type(error).__name__}); no release was published.\n')


if __name__ == '__main__':
    main()
