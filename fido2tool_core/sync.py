"""Sync what KeyMelier knows between the user's own computers.

No server and no network service: the user picks a folder they already sync
(iCloud Drive, OneDrive, Dropbox, Syncthing, a NAS share). Every computer
writes one file there, KeyMelier-<device>.kmsync, holding everything it knows
(the history, including which keys were removed), and merges the files of
the other computers (History.merge_sync).

The files are encrypted with a passphrase the user sets on every computer:
scrypt (n=2^17, r=8, p=1) derives an AES-256-GCM key; the plaintext header
(format, version, random device id, salt) is bound as associated data. The
folder's owner (e.g. the cloud provider) only sees random device ids, sizes
and times. The computer's name travels inside the encrypted part only.

The passphrase is kept in the OS credential store (macOS Keychain, Windows
Credential Manager) – never in a plain file.

Concurrency: a computer only ever writes its own file, atomically (temporary
file + rename), and only reads the others. A file that is still arriving
through the cloud fails authentication and is simply read again later; it is
reported only if it stays unreadable (ERROR_AFTER checks).

Before its first write – and whenever its own file changed behind its back –
a computer reads the file under its own device id and merges it, so nothing
is lost. The file names the computer that wrote it (a hash of the OS machine
id, inside the encrypted part). If that is another computer (same device id,
e.g. settings copied by a migration tool), this computer takes a new device
id, which the caller stores. A file at its own path that it cannot read
(incomplete, damaged, other passphrase) is never overwritten: the computer
moves to a new device id as well, and the old file stays for inspection.
A normal restart finds its own machine hash and keeps the id.
"""

import base64
import hashlib
import json
import logging
import os
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

FORMAT = "keymelier-sync"
VERSION = 1
MIN_PASSPHRASE = 10
MAX_FILE = 20_000_000
FILE_RE = re.compile(r"^KeyMelier-([0-9a-f]{16})\.kmsync$")
SCRYPT = {"n": 2 ** 17, "r": 8, "p": 1}
INTERVAL = 30          # seconds between checks of the folder
ERROR_AFTER = 2        # report an unreadable file only after this many checks in a row
KEYRING_NAME = "sync-passphrase-v1"


class SyncError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def new_device_id() -> str:
    return secrets.token_hex(8)


def machine_id(fallback) -> str:
    """Stable, anonymous id of this computer (hash of the OS machine id).
    fallback() supplies a stored random id where the OS has none."""
    raw = None
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r'"IOPlatformUUID" = "([0-9A-Fa-f-]+)"', out)
            raw = m.group(1) if m else None
        elif os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                raw = str(winreg.QueryValueEx(key, "MachineGuid")[0])
        else:
            raw = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    except Exception as e:
        logger.info("No OS machine id (%s); using a stored one", e)
    raw = raw or fallback()
    return hashlib.sha256(f"keymelier-sync|{raw}".encode()).hexdigest()[:16]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text) -> bytes:
    if not isinstance(text, str) or len(text) > 2 * MAX_FILE:
        raise SyncError("Damaged sync file.", "sync_damaged")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise SyncError("Damaged sync file.", "sync_damaged") from None


_key_cache: dict[tuple[str, bytes], bytes] = {}


def _derive(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    tag = (hashlib.sha256(passphrase.encode()).hexdigest(), salt)
    if tag not in _key_cache:
        if len(_key_cache) > 32:
            _key_cache.clear()
        _key_cache[tag] = Scrypt(salt=salt, length=32, **SCRYPT).derive(passphrase.encode())
    return _key_cache[tag]


def _aad(header: dict) -> bytes:
    return json.dumps({k: header[k] for k in ("format", "v", "device", "salt")}, sort_keys=True).encode()


def seal(payload: dict, passphrase: str, device: str, salt: bytes | None = None) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = salt or os.urandom(16)
    header = {"format": FORMAT, "v": VERSION, "device": device, "salt": _b64(salt)}
    nonce = os.urandom(12)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, json.dumps(payload).encode(), _aad(header))
    return json.dumps({**header, "nonce": _b64(nonce), "ct": _b64(ct)}).encode()


def unseal(data: bytes, passphrase: str) -> tuple[str, dict]:
    """Returns (device id, payload). Raises SyncError (sync_damaged,
    sync_passphrase) – a wrong passphrase and a manipulated file look the same."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        header = json.loads(data)
    except ValueError:
        raise SyncError("Damaged sync file.", "sync_damaged") from None
    if not isinstance(header, dict) or header.get("format") != FORMAT or header.get("v") != VERSION \
            or not isinstance(header.get("device"), str) or not re.fullmatch(r"[0-9a-f]{16}", header["device"]):
        raise SyncError("Not a KeyMelier sync file of this version.", "sync_damaged")
    salt, nonce, ct = _unb64(header.get("salt")), _unb64(header.get("nonce")), _unb64(header.get("ct"))
    if len(salt) != 16 or len(nonce) != 12:
        raise SyncError("Damaged sync file.", "sync_damaged")
    try:
        plain = AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, _aad(header))
    except InvalidTag:
        raise SyncError("Wrong passphrase, or the file was changed.", "sync_passphrase") from None
    payload = json.loads(plain)
    if not isinstance(payload, dict):
        raise SyncError("Damaged sync file.", "sync_damaged")
    return header["device"], payload


# ── The folder ───────────────────────────────────────────────────────────────

def _read_regular(path: Path) -> bytes | None:
    """Read a plain file (no symlink, no device, not too large)."""
    import stat
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        return f.read(MAX_FILE + 1)


class SyncFolder:
    def __init__(self, folder: Path, device: str, passphrase: str, machine: str = ""):
        self.folder = Path(folder)
        self.device = device
        self.machine = machine
        self._passphrase = passphrase
        self._salt = os.urandom(16)        # one salt per session: derive once
        self.instance = secrets.token_hex(8)   # this run of KeyMelier
        self._written_hash = None
        self._own_stamp = None             # (mtime, size) of our file when we last wrote or read it
        self._last_written = ""
        self._seen: dict[str, tuple] = {}  # file name -> (mtime, size) already merged

    @property
    def own_path(self) -> Path:
        return self.folder / f"KeyMelier-{self.device}.kmsync"

    def check(self):
        if not self.folder.is_dir():
            raise SyncError("The sync folder is not available.", "sync_folder")

    def write(self, history_state: dict, force=False) -> bool:
        """Write this computer's file if its content changed."""
        self.check()
        digest = hashlib.sha256(json.dumps(history_state, sort_keys=True).encode()).hexdigest()
        if digest == self._written_hash and not force and self.own_path.exists():
            return False
        self._last_written = datetime.now(timezone.utc).isoformat()
        payload = {"device_name": platform.node()[:80], "written": self._last_written,
                   "instance": self.instance, "machine": self.machine, "history": history_state}
        data = seal(payload, self._passphrase, self.device, self._salt)
        if self.own_path.is_symlink():
            raise SyncError("The sync file must not be a symbolic link.", "sync_folder")
        fd, tmp = tempfile.mkstemp(prefix=".KeyMelier-", suffix=".tmp", dir=self.folder)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.own_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self._written_hash = digest
        st = os.lstat(self.own_path)
        self._own_stamp = (st.st_mtime_ns, st.st_size)
        return True

    def own_changed(self) -> bool:
        """Is there a file at our path we have not seen yet (first run) or that
        changed since we last wrote or read it?"""
        try:
            st = os.lstat(self.own_path)
        except OSError:
            return False
        return (st.st_mtime_ns, st.st_size) != self._own_stamp

    def read_own(self) -> tuple[str, str | None, dict | None]:
        """Read the file at our path: ("ok", None, payload) or ("unreadable", code, None)."""
        st = os.lstat(self.own_path)
        self._own_stamp = (st.st_mtime_ns, st.st_size)
        data = _read_regular(self.own_path)
        if data is None:
            return "unreadable", "sync_damaged", None
        try:
            device, payload = unseal(data, self._passphrase)
        except SyncError as e:
            return "unreadable", e.code, None
        if device != self.device:
            return "unreadable", "sync_damaged", None
        return "ok", None, payload

    def change_device(self, device: str) -> None:
        self.device = device
        self._written_hash = self._own_stamp = None
        self._seen.clear()   # the old file is read as another computer's from now on

    def read_others(self, only_new=True) -> tuple[list[dict], list[dict]]:
        """Files of the other computers: ([{device, name, written, history}], [{file, code}])."""
        self.check()
        found, errors = [], []
        for path in sorted(self.folder.iterdir()):
            m = FILE_RE.match(path.name)
            if not m or m.group(1) == self.device:
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            stamp = (st.st_mtime_ns, st.st_size)
            if only_new and self._seen.get(path.name) == stamp:
                continue
            data = _read_regular(path)
            if data is None:
                errors.append({"file": path.name, "code": "sync_damaged"})
                continue
            try:
                device, payload = unseal(data, self._passphrase)
            except SyncError as e:
                errors.append({"file": path.name, "code": e.code})
                continue
            if device != m.group(1):
                errors.append({"file": path.name, "code": "sync_damaged"})  # renamed/copied file
                continue
            self._seen[path.name] = stamp
            found.append({"device": device, "name": str(payload.get("device_name") or "")[:80],
                          "written": str(payload.get("written") or "")[:40],
                          "history": payload.get("history") if isinstance(payload.get("history"), dict) else {}})
        return found, errors


# ── Background syncing ───────────────────────────────────────────────────────

class Syncer:
    """Checks the folder every INTERVAL seconds and after local changes."""

    def __init__(self, history, emit, keep_contents, on_new_device=None):
        self._history = history
        self._on_new_device = on_new_device or (lambda device: None)
        self._fails: dict[str, int] = {}
        self._emit = emit
        self._keep_contents = keep_contents
        self._folder: SyncFolder | None = None
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread = None
        self._last_revision = None
        self.devices: dict[str, dict] = {}
        self.errors: list[dict] = []
        self.notice: dict | None = None    # this computer took a new device id, and why
        self.last_sync: str | None = None

    def configure(self, folder: Path | None, device: str | None, passphrase: str | None, machine: str = ""):
        with self._lock:
            self._folder = SyncFolder(folder, device, passphrase, machine) if folder and device and passphrase else None
            self._last_revision = None
            self.devices, self.errors, self.notice, self.last_sync = {}, [], None, None
        self._history.track_forgotten = self._folder is not None
        if self._folder is not None:
            self.start()
            self.trigger()

    @property
    def active(self) -> bool:
        return self._folder is not None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="keymelier-sync", daemon=True)
            self._thread.start()

    def trigger(self):
        self._wake.set()

    def _loop(self):
        while True:
            self._wake.wait(INTERVAL)
            self._wake.clear()
            try:
                self.run_once()
            except Exception as e:  # never let the thread die
                logger.warning("Sync failed: %s", e)

    def run_once(self, full=False) -> dict:
        with self._lock:
            folder = self._folder
            if folder is None or not self._history.enabled:
                return self.status()
            changed = False
            problems: list[dict] = []   # all of this round, counted together (see _settle)
            try:
                if folder.own_changed():
                    # first run, or someone else wrote our file: keep what is in it
                    kind, code, payload = folder.read_own()
                    if kind == "ok":
                        changed |= self._history.merge_sync(payload.get("history") or {},
                                                            keep_contents=self._keep_contents())
                        writer = payload.get("machine")
                        if writer and folder.machine and writer != folder.machine:
                            self._switch_device(folder, "sync_shared_id")
                    else:
                        # never overwrite what we cannot read (incomplete, damaged, other passphrase)
                        logger.warning("Own sync file unreadable (%s)", code)
                        self._switch_device(folder, "sync_own_unreadable")
                others, problems = folder.read_others(only_new=not full)
                for other in others:
                    self.devices[other["device"]] = {"device": other["device"], "name": other["name"],
                                                     "written": other["written"]}
                    changed |= self._history.merge_sync(other["history"], keep_contents=self._keep_contents())
                if changed or self._history.revision != self._last_revision or full:
                    folder.write(self._history.sync_state(), force=full)
                    self._last_revision = self._history.revision   # a failed write is retried next round
                self.last_sync = datetime.now(timezone.utc).isoformat()
            except SyncError as e:
                problems.append({"file": "", "code": e.code})
            except OSError as e:
                logger.info("Sync folder not usable: %s", e)
                problems.append({"file": "", "code": "sync_folder"})
            self.errors = self._settle(problems)
        if changed:
            self._emit("history_synced", {})
        return self.status()

    def _switch_device(self, folder: SyncFolder, reason: str) -> None:
        old = folder.own_path.name
        new = new_device_id()
        logger.warning("Sync: %s (%s) – this computer now uses %s", old, reason, new)
        folder.change_device(new)
        self._on_new_device(new)
        self._last_revision = None
        self.notice = {"code": reason, "file": old}

    def _settle(self, errors: list[dict]) -> list[dict]:
        """Report a problem only if it persists: a file still arriving through
        the cloud, or a folder that is briefly offline, heals by itself."""
        current = {e["file"] for e in errors}
        self._fails = {k: self._fails.get(k, 0) + 1 for k in current}
        return [e for e in errors if self._fails[e["file"]] >= ERROR_AFTER]

    def status(self) -> dict:
        f = self._folder
        return {"active": f is not None, "folder": str(f.folder) if f else None, "device": f.device if f else None,
                "device_name": platform.node()[:80], "last_sync": self.last_sync,
                "devices": sorted(self.devices.values(), key=lambda d: d["written"], reverse=True),
                "errors": list(self.errors), "notice": self.notice}


def probe_folder(folder: Path, passphrase: str, device: str) -> dict:
    """Before turning sync on: is the folder usable, and does the passphrase
    open the files already there? Returns {"others": n}; raises SyncError."""
    folder = Path(folder)
    if not folder.is_dir():
        raise SyncError("Choose an existing folder.", "sync_folder")
    if len(passphrase) < MIN_PASSPHRASE:
        raise SyncError(f"The passphrase needs at least {MIN_PASSPHRASE} characters.", "sync_passphrase_short")
    probe = SyncFolder(folder, device, passphrase)
    others, errors = probe.read_others(only_new=False)
    if errors and not others and any(e["code"] == "sync_passphrase" for e in errors):
        raise SyncError("The passphrase does not open the files of your other computers.", "sync_passphrase")
    try:
        fd, tmp = tempfile.mkstemp(prefix=".KeyMelier-", dir=folder)
        os.close(fd)
        os.unlink(tmp)
    except OSError:
        raise SyncError("KeyMelier cannot write to this folder.", "sync_folder") from None
    return {"others": len(others)}
