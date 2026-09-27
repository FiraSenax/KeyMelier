"""Create upgrade test data with the code of published releases.

    venv/bin/python tools/make_compat_fixtures.py [v1.5.0 v1.6.1 v1.7.0]

For each tag, the release's own fido2tool_core (from git) writes
history.json and settings.json into a temporary home – exactly the format
that version leaves on a user's computer: named keys, passkeys (list and
search), authenticator accounts, a lost key with a ticked service, a
running key replacement with progress, settings and (from 1.6) a sync id.
The data is fictional. Results go to tests/fixtures/compat/<tag>/ and are
checked by tests/test_upgrade_compat.py against the current code.
"""

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "compat"
TAGS = sys.argv[1:] or ["v1.4.0", "v1.5.0", "v1.6.0", "v1.6.1", "v1.7.0"]

WRITER = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fido2tool_core.scanner import TokenRecord
from fido2tool_core import service as svc

def rec(i, serial):
    return TokenRecord(f"id{i}", "/dev/fixture", f"Fixture Key {i}", serial, "Yubico", f"aaguid-fixture-{i}",
                       ["FIDO_2_0", "FIDO_2_1"], ["credProtect"], {"clientPin": True, "credMgmt": True}, [2, 1],
                       25, 0x050702, "5.7.2", "2026-01-01T00:00:00+00:00", 0x1050, 0x0407, None, False)

class Scanner:          # no hardware: the service only registers callbacks
    def set_callbacks(self, **kw):
        pass

service = svc.KeyService(Scanner(), None)
service.set_settings({"history_enabled": True, "remember_sites": True})
h = service.history
A, B, C, D = rec(1, "11110001"), rec(2, "11110002"), rec(3, "11110003"), rec(4, None)
for r in (A, B, C, D):
    h.update_snapshot(r)
    h.add_event(r, "connected")
a = h.set_sites(A, [
    {"rp_id": "github.com", "name": "GitHub", "count": 1, "users": [{"name": "erika", "display": "Erika"}]},
    {"rp_id": "login.microsoft.com", "name": "Microsoft", "count": 2,
     "users": [{"name": "a@contoso.example", "display": ""}, {"name": "b@contoso.example", "display": ""}]},
])["key_id"]
features = {"probe": hasattr(h, "merge_probe"), "replace": hasattr(h, "set_replace"),
            "sync": hasattr(service, "_write_settings")}
if features["probe"]:                               # 1.5+: keys without a passkey list are searched
    b = h.merge_probe(B, [
        {"rp_id": "github.com", "status": "found", "count": 1, "users": [{"name": "erika", "display": ""}]},
        {"rp_id": "example.com", "status": "none"},
        {"rp_id": "gitlab.com", "status": "error"},
    ], True, 3)["key_id"]
else:
    b = h.set_sites(B, [{"rp_id": "github.com", "name": "GitHub", "count": 1,
                         "users": [{"name": "erika", "display": ""}]}])["key_id"]
c = h.set_sites(C, [{"rp_id": "aws.amazon.com", "name": "AWS", "count": 1, "users": [{"name": "", "display": "Administrator"}]}])["key_id"]
d = h.update_snapshot(D)["key_id"]
h.set_inventory(A, "oath", [{"issuer": "AWS", "name": "root@example.com"}, {"issuer": "GitHub", "name": "erika"}])
h.set_inventory(B, "oath", [{"issuer": "GitHub", "name": "erika"}])
h.set_inventory(A, "openpgp", [{"slot": "sig", "algorithm": "Ed25519", "fingerprint": "AAAA BBBB CCCC DDDD"}])
h.add_event(A, "pin_changed")
h.rename(a, "Everyday key")
h.rename(b, "Backup key")
h.rename(c, "Old office key")
h.set_lost(c, True)
h.set_lost_done(c, "aws.amazon.com", True)
if features["replace"]:                             # 1.5+: guided key replacement
    h.set_replace(a, b)
    h.set_replace_done(a, "pk:github.com|erika", True)
service.set_settings({"lang": "de", "personal_mode": True})
if features["sync"]:                                # 1.6+: sync configuration
    s = service._stored_settings()
    s.update(sync_folder="/Users/fixture/CloudSync/KeyMelier", sync_device="0123456789abcdef")
    service._write_settings(s)
print(json.dumps({"keys": {"A": a, "B": b, "C": c, "D": d}, "features": features}))
'''


def extract(tag: str, dest: Path) -> None:
    data = subprocess.run(["git", "archive", tag, "fido2tool_core"], cwd=ROOT, capture_output=True, check=True).stdout
    with tarfile.open(fileobj=BytesIO(data)) as tar:
        tar.extractall(dest, filter="data")


def main() -> int:
    for tag in TAGS:
        work = Path(tempfile.mkdtemp(prefix=f"km-compat-{tag}-"))
        code, home = work / "code", work / "home"
        code.mkdir()
        home.mkdir()
        extract(tag, code)
        env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
        env.pop("KEYMELIER_STATELESS", None)
        ids = subprocess.run([sys.executable, "-c", WRITER, str(code)], env=env, cwd=work,
                             capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
        target = OUT / tag
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        for name in ("history.json", "settings.json"):
            shutil.copy(home / "keymelier" / name, target / name)
        (target / "keys.json").write_text(json.dumps({"tag": tag, **json.loads(ids)}, indent=1) + "\n")
        shutil.rmtree(work, ignore_errors=True)
        print(f"{tag}: {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
