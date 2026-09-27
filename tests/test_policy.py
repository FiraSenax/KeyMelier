"""Managed advisory sources (company policy): signed, additive only, source visible."""

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fido2tool_core import policy
from fido2tool_core.advisories import AdvisoryChecker
from fido2tool_core.service import KeyService

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OFFICIAL_ID = "CVE-2024-45678"
AAGUID = "cb69481e-8ff7-4039-93ec-0a2729a154a8"      # YubiKey 5 (official EUCLEAK entry)
OTHER_AAGUID = "00000000-1111-2222-3333-444444444444"
FW_5_4 = (5 << 16) | (4 << 8)


def keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, base64.b64encode(pub).decode()


def write_source(folder: Path, priv, advisories, updated="2026-09-27T00:00:00+00:00", name="corp.json"):
    data = json.dumps({"updated": updated, "advisories": advisories}).encode()
    path = folder / name
    path.write_bytes(data)
    (folder / (name + ".sig")).write_text(base64.b64encode(priv.sign(data)).decode(), encoding="ascii")
    return str(path)


def corp(id_="CORP-2026-1", aaguid=OTHER_AAGUID, **extra):
    return {"id": id_, "title": "Internal finding", "severity": "HIGH", "affected_aaguids": [aaguid], **extra}


class TestPolicyParsing(unittest.TestCase):
    def test_validates_entries(self):
        _, pub = keypair()
        raw = {"AdvisorySources": [
            {"Name": "Corp", "Location": "https://example.com/a.json", "PublicKey": pub},
            {"Name": "Corp", "Location": "https://example.com/b.json", "PublicKey": pub},   # duplicate name
            {"Name": "Plain", "Location": "http://example.com/a.json", "PublicKey": pub},   # not https
            {"Name": "Relative", "Location": "a.json", "PublicKey": pub},                   # relative path
            {"Name": "BadKey", "Location": "https://example.com/a.json", "PublicKey": "abc"},
            "not a dict",
        ]}
        sources = policy.advisory_sources(raw)
        self.assertEqual([s["name"] for s in sources], ["Corp"])

    def test_no_policy_means_no_sources(self):
        self.assertEqual(policy.advisory_sources({}), [])
        self.assertEqual(policy.advisory_sources({"AdvisorySources": "x"}), [])

    def test_limit(self):
        _, pub = keypair()
        raw = {"AdvisorySources": [{"Name": f"S{i}", "Location": "https://example.com/a", "PublicKey": pub}
                                   for i in range(policy.MAX_SOURCES + 5)]}
        self.assertEqual(len(policy.advisory_sources(raw)), policy.MAX_SOURCES)

    def test_windows_registry_reader(self):
        """HKLM only; subkeys become sources (fake winreg, runs on every system)."""
        import sys
        import types

        _, pub = keypair()
        tree = {policy.WIN_KEY + r"\AdvisorySources": ["Contoso IT"],
                policy.WIN_KEY + r"\AdvisorySources\Contoso IT": {"Location": "https://intra.example/a.json", "PublicKey": pub}}
        opened = []

        class Handle:
            def __init__(self, path): self.path = path
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def open_key(parent, sub):
            path = sub if isinstance(parent, str) else parent.path + "\\" + sub
            opened.append((parent, path))
            if path not in tree:
                raise OSError("missing")
            return Handle(path)

        def enum_key(h, i):
            names = tree[h.path]
            if i >= len(names):
                raise OSError("done")
            return names[i]

        def query(h, name):
            if name not in tree[h.path]:
                raise OSError("missing")
            return tree[h.path][name], 1

        fake = types.SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", OpenKey=open_key, EnumKey=enum_key, QueryValueEx=query)
        with patch.dict(sys.modules, {"winreg": fake}):
            raw = policy._read_windows()
        self.assertEqual(opened[0][0], "HKLM")
        self.assertEqual([s["name"] for s in policy.advisory_sources(raw)], ["Contoso IT"])

    def test_no_environment_switch_replaces_the_managed_configuration(self):
        """A user-owned JSON file named in KEYMELIER_POLICY_TEST (or similar) is never read:
        the platform reader still decides – with a policy it is kept, without one nothing appears."""
        _, pub = keypair()
        managed = {"AdvisorySources": [{"Name": "Contoso IT", "Location": "https://intra.example/a.json",
                                        "PublicKey": pub}]}
        readers = {"win32": "_read_windows", "darwin": "_read_mac", "linux": "_read_linux"}
        with tempfile.TemporaryDirectory() as d:
            own = Path(d) / "mine.json"
            fake = {"AdvisorySources": [{"Name": "Mine", "Location": "https://evil.example/a.json", "PublicKey": pub}]}
            for content in (json.dumps(fake), json.dumps({}), ""):
                own.write_text(content)
                for platform, reader in readers.items():
                    with self.subTest(platform=platform, content=content[:20]), \
                            patch.dict(os.environ, {"KEYMELIER_POLICY_TEST": str(own), "KEYMELIER_POLICY": str(own)}), \
                            patch.object(sys, "platform", platform), \
                            patch.object(policy, reader, return_value=managed) as platform_reader:
                        self.assertEqual([s["name"] for s in policy.advisory_sources()], ["Contoso IT"])
                        platform_reader.assert_called_once()
            with patch.dict(os.environ, {"KEYMELIER_POLICY_TEST": str(own)}), patch.object(sys, "platform", "linux"), \
                    patch.object(policy, "_read_linux", return_value={}):
                self.assertEqual(policy.advisory_sources(), [], "no policy: the user file adds nothing either")

    def test_policy_module_reads_no_environment(self):
        source = (ROOT / "fido2tool_core" / "policy.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)os\.environ|getenv|^import os\b|^from os\b", "the policy must not depend on the environment")

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_user_writable_policy_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            path.write_text(json.dumps({"AdvisorySources": []}))
            # owned by the test user, not root
            self.assertEqual(policy._read_linux(path), {})


class TestEnterpriseDocs(unittest.TestCase):
    """The examples in ENTERPRISE.md are accepted as written (with a real key)."""

    def setUp(self):
        self.doc = (ROOT / "ENTERPRISE.md").read_text(encoding="utf-8")
        self.pub = keypair()[1]

    def block(self, lang, index=0):
        import re
        return re.findall(rf"```{lang}\n(.*?)```", self.doc, re.S)[index].replace("BASE64-PUBLIC-KEY", self.pub)

    def test_linux_json(self):
        raw = json.loads(self.block("json", 1))
        self.assertEqual([s["name"] for s in policy.advisory_sources(raw)], ["Contoso IT"])

    def test_macos_profile(self):
        import plistlib
        profile = plistlib.loads(self.block("xml").encode())
        payload = profile["PayloadContent"][0]
        self.assertEqual(payload["PayloadType"], "com.keymelier.app")
        self.assertEqual(len(policy.advisory_sources(payload)), 1)

    def test_reg_file_path_and_values(self):
        reg = self.block("reg")
        self.assertIn("[HKEY_LOCAL_MACHINE\\" + policy.WIN_KEY + "\\AdvisorySources\\Contoso IT]", reg)
        self.assertIn('"Location"=', reg)
        self.assertIn('"PublicKey"=', reg)

    def test_document_example_is_a_valid_advisory(self):
        from fido2tool_core.advisories import _clean_entry
        doc = json.loads(self.block("json", 0))
        self.assertIsNotNone(_clean_entry(doc["advisories"][0], "x"))


class TestManagedSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.priv, self.pub = keypair()

    def tearDown(self):
        self.tmp.cleanup()

    def checker(self, location, pub=None):
        return AdvisoryChecker(DATA, [{"name": "Contoso IT", "location": location, "public_key": pub or self.pub}])

    def test_valid_source_adds_finding_with_origin(self):
        c = self.checker(write_source(self.dir, self.priv, [corp()]))
        found = c.check(OTHER_AAGUID, None)
        self.assertEqual([a["id"] for a in found], ["CORP-2026-1"])
        self.assertEqual(found[0]["origin"], "Contoso IT")
        info = c.info()["policy"][0]
        self.assertEqual((info["status"], info["count"]), ("ok", 1))

    def test_bad_signature_is_ignored_and_logged(self):
        location = write_source(self.dir, self.priv, [corp()])
        _, other_pub = keypair()
        with self.assertLogs("fido2tool_core.advisories", "WARNING") as logs:
            c = self.checker(location, other_pub)
        self.assertEqual(c.check(OTHER_AAGUID, None), [])
        self.assertEqual(c.info()["policy"][0]["status"], "invalid")
        self.assertTrue(any("signature invalid" in m for m in logs.output))

    def test_tampered_document_is_ignored(self):
        location = write_source(self.dir, self.priv, [corp()])
        Path(location).write_text(Path(location).read_text().replace("HIGH", "LOW"))
        c = self.checker(location)
        self.assertEqual(c.check(OTHER_AAGUID, None), [])

    def test_missing_source_is_unreachable(self):
        c = self.checker(str(self.dir / "missing.json"))
        self.assertEqual(c.info()["policy"][0]["status"], "unreachable")
        self.assertGreater(c.info()["count"], 0)   # official database unaffected

    def test_official_entry_cannot_be_overridden(self):
        baseline = AdvisoryChecker(DATA, []).check(AAGUID, FW_5_4, "Yubico")
        self.assertIn(OFFICIAL_ID, [a["id"] for a in baseline])
        # Same id, weaker severity, and a firmware range that would exclude the key
        fake = corp(OFFICIAL_ID, AAGUID, severity="LOW", firmware_max_exclusive="1.0.0", note="harmless")
        c = self.checker(write_source(self.dir, self.priv, [fake]))
        found = c.check(AAGUID, FW_5_4, "Yubico")
        self.assertEqual(found, baseline)
        self.assertNotIn("origin", found[0])
        self.assertEqual(c.info()["policy"][0]["count"], 0)

    def test_source_cannot_remove_official_entries(self):
        c = self.checker(write_source(self.dir, self.priv, []))
        self.assertIn(OFFICIAL_ID, [a["id"] for a in c.check(AAGUID, FW_5_4, "Yubico")])
        self.assertEqual(c.info()["count"], AdvisoryChecker(DATA, []).info()["count"])

    def test_managed_entries_are_sanitised(self):
        # Managed entries are reshaped: unknown severity, non-https links dropped
        adv = corp(severity="EXTREME", references=["javascript:alert(1)", "https://intra.example/a"])
        c = self.checker(write_source(self.dir, self.priv, [adv, {"id": 5}, {"id": "X"}]))
        found = c.check(OTHER_AAGUID, None)
        self.assertEqual(found[0]["severity"], "MEDIUM")
        self.assertEqual(found[0]["references"], ["https://intra.example/a"])
        self.assertEqual(c.info()["policy"][0]["count"], 1)

    def test_hostile_entries_are_dropped_or_neutralised(self):
        """Injection attempts through a (validly signed) source: nothing executable reaches the UI."""
        from fido2tool_core.advisories import _clean_entry
        drop = {
            "script in id": corp("<script>alert(1)</script>"),
            "quote in id": corp('X" onmouseover="alert(1)'),
            "id with newline": corp("CORP-1\nFAKE LOG LINE"),
            "aaguid not a uuid": corp(aaguid="<img src=x>"),
            "no aaguid": {**corp(), "affected_aaguids": []},
            "too many aaguids": {**corp(), "affected_aaguids": [OTHER_AAGUID] * 201},
            "unreadable firmware bound": corp(firmware_max_exclusive="abc"),
            "firmware bound as number": corp(firmware_min_inclusive=5),
        }
        for name, adv in drop.items():
            with self.subTest(name):
                self.assertIsNone(_clean_entry(adv, "x"))
        entry = _clean_entry(corp(title="<b>A</b>\u2028next\x1b[31m", note="line1\nline2", cvss="9.8<img src=x>",
                                  references=['https://a.example/"><svg onload=alert(1)>', "javascript:alert(1)",
                                              "https://a.example/x'y", "data:text/html,<script>", "https://a.example/ok?q=1#f"]),
                             "x")
        self.assertNotRegex(entry["title"] + entry["note"], r"[\x00-\x1f\u2028]")
        self.assertEqual(entry["title"], "<b>A</b> next [31m", "markup stays text; the UI escapes it")
        self.assertNotIn("cvss", entry)
        self.assertEqual(entry["references"], ["https://a.example/ok?q=1#f"])
        self.assertEqual(_clean_entry(corp(cvss=9.84), "x")["cvss"], 9.8)
        self.assertNotIn("cvss", _clean_entry(corp(cvss=True), "x"))

    def test_source_name_without_control_characters(self):
        _, pub = keypair()
        raw = {"AdvisorySources": [{"Name": "Contoso\nWARNING fake", "Location": "https://intra.example/a.json",
                                    "PublicKey": pub},
                                   {"Name": "Lab", "Location": "https://intra.example/a.json\nb", "PublicKey": pub}]}
        sources = policy.advisory_sources(raw)
        self.assertEqual([s["name"] for s in sources], ["Contoso WARNING fake"])

    def test_no_rollback_to_older_document(self):
        location = write_source(self.dir, self.priv, [corp()], updated="2026-09-27T00:00:00+00:00")
        c = self.checker(location)
        write_source(self.dir, self.priv, [], updated="2026-01-01T00:00:00+00:00")
        self.assertFalse(c.load_policy_sources(network=False))
        self.assertEqual(len(c.check(OTHER_AAGUID, None)), 1)

    def test_newer_document_replaces(self):
        location = write_source(self.dir, self.priv, [corp()], updated="2026-09-27T00:00:00+00:00")
        c = self.checker(location)
        write_source(self.dir, self.priv, [corp("CORP-2026-2")], updated="2026-09-28T00:00:00+00:00")
        self.assertTrue(c.load_policy_sources(network=False))
        self.assertEqual([a["id"] for a in c.check(OTHER_AAGUID, None)], ["CORP-2026-2"])

    def test_url_sources_wait_for_network_check(self):
        with patch("fido2tool_core.advisories._read_source") as read:
            c = self.checker("https://intra.example/advisories.json")
            read.assert_not_called()
            self.assertEqual(c.info()["policy"][0]["status"], "pending")

    def test_company_links_can_be_opened_exactly(self):
        """References of a signed company source may be opened – only those URLs, nothing else on the host."""
        import app

        link = "https://intra.example/keys/replace?id=1"
        adv = corp(references=[link, "https://intra.example/a b", "https://intra.example/\x1bx"])
        c = self.checker(write_source(self.dir, self.priv, [adv]))
        self.assertEqual(c.policy_links(), {link})
        svc = KeyService.__new__(KeyService)
        svc._advisories = c
        api = app.Api(svc)
        opened = []
        with patch("webbrowser.open", opened.append), patch.object(app, "open_with_system", opened.append):
            api.open_url(link)
            api.open_url("https://intra.example/other")           # same host, not listed
            api.open_url("http://intra.example/keys/replace?id=1")  # not https
            api.open_url("https://github.com/FiraSenax/KeyMelier")  # fixed host still works
        self.assertEqual(opened, [link, "https://github.com/FiraSenax/KeyMelier"])
        # A source with an invalid signature contributes no links
        _, other = keypair()
        bad = self.checker(write_source(self.dir, self.priv, [adv], name="bad.json"), other)
        self.assertEqual(bad.policy_links(), set())

    def test_scanner_passes_origin_to_ui(self):
        from fido2tool_core.scanner import TokenRecord, TokenScanner

        c = self.checker(write_source(self.dir, self.priv, [corp(severity="CRITICAL")]))
        scanner = TokenScanner(advisory_checker=c)
        record = TokenRecord("id", "/dev/test", "Key", "serial", "Unknown", OTHER_AAGUID,
                             [], [], {}, [], None, None, "", "now")
        scanner._enrich_record(record)
        self.assertEqual(record.advisories[0]["origin"], "Contoso IT")
        self.assertEqual(record.security_status, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
