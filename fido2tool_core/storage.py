"""Private atomic local writes; no device metadata is written in stateless mode."""
import os
import tempfile
from pathlib import Path


def stateless():
    return os.environ.get("KEYMELIER_STATELESS") == "1"


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ValueError("Storage directory must not be a symbolic link")
    if os.name != "nt":
        path.parent.chmod(0o700)
    else:
        import csv
        import re
        import subprocess
        options = {"creationflags": subprocess.CREATE_NO_WINDOW}
        # Absolute paths: the app runs elevated, and a bare name would also be
        # searched for in the app and current directory
        system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        identity = subprocess.check_output([os.path.join(system32, 'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
                                           text=True, **options)
        sid = next(csv.reader([identity.strip()]))[-1]
        if not re.fullmatch(r'S-1-\d+(?:-\d+)+', sid):
            raise ValueError("Could not determine Windows user SID")
        subprocess.run([os.path.join(system32, 'icacls.exe'), str(path.parent), '/inheritance:r', '/grant:r', f'*{sid}:(OI)(CI)F'],
                       check=True, stdout=subprocess.DEVNULL, **options)
    fd, name = tempfile.mkstemp(prefix=".keymelier-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def history_cipher(create=True):
    """Use only native OS credential stores, never a plaintext fallback backend."""
    import keyring
    from cryptography.fernet import Fernet
    backend = keyring.get_keyring()
    if type(backend).__module__ not in {'keyring.backends.macOS', 'keyring.backends.Windows'}:
        raise RuntimeError('Encrypted history requires macOS Keychain or Windows Credential Manager')
    key = backend.get_password('KeyMelier', 'history-encryption-v1')
    if key is None:
        if not create:
            raise RuntimeError('History encryption key is missing from the OS credential store')
        key = Fernet.generate_key().decode('ascii')
        backend.set_password('KeyMelier', 'history-encryption-v1', key)
    return Fernet(key.encode('ascii'))
