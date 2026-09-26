#!/usr/bin/env python3
"""Look for new security issues affecting FIDO keys and report them for review.

Sources:
  - NVD: CVEs published in the last LOOKBACK_DAYS mentioning a FIDO key vendor
  - FIDO MDS3: status reports (compromise, revocation, UV bypass, update
    available) with an effective date in the last LOOKBACK_DAYS

Findings are printed as Markdown. With --create-issues (in GitHub Actions),
one issue per finding is opened unless an issue with the same ID exists.
Nothing is added to advisories.json automatically: a human verifies the
affected AAGUIDs and firmware range, edits the file and signs it.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LOOKBACK_DAYS = 8
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MDS_URL = "https://mds.fidoalliance.org/"
VENDOR_KEYWORDS = ["yubikey", "yubico", "feitian", "token2", "solokeys", "nitrokey",
                   "titan security key", "fido2 authenticator", "security key firmware"]
ALARMING_STATUS = {"USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE",
                   "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE",
                   "REVOKED", "UPDATE_AVAILABLE"}


def known_ids() -> set[str]:
    doc = json.loads((ROOT / "data" / "advisories.json").read_text(encoding="utf-8"))
    return {a["id"] for a in doc.get("advisories", [])}


def mds_entries() -> list[dict]:
    from fido2tool_core.mds_verify import verify_jwt

    resp = requests.get(MDS_URL, timeout=30)
    resp.raise_for_status()
    return verify_jwt(resp.text).get("entries", [])


def candidate_models(entries: list[dict], text: str) -> list[str]:
    """MDS entries whose description shares a vendor word with the CVE text."""
    words = [w for w in VENDOR_KEYWORDS if w in text.lower()]
    rows = []
    for e in entries:
        ms = e.get("metadataStatement") or {}
        desc = ms.get("description", "")
        if e.get("aaguid") and any(w.split()[0] in desc.lower() for w in words):
            v = ms.get("authenticatorVersion")
            rows.append(f"| `{e['aaguid']}` | {desc} | {v} |")
    return rows[:60]


def nvd_findings(since: datetime, until: datetime) -> list[dict]:
    seen, found = set(), []
    for kw in VENDOR_KEYWORDS:
        params = {
            "keywordSearch": kw,
            # Multi-word terms must appear as a phrase, not as scattered words
            **({"keywordExactMatch": ""} if " " in kw else {}),
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": until.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        try:
            resp = requests.get(NVD_URL, params=params, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"NVD query '{kw}' failed: {e}", file=sys.stderr)
            continue
        for item in resp.json().get("vulnerabilities", []):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            found.append({"id": cve["id"], "source": "NVD", "summary": desc,
                          "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"})
    return found


def mds_findings(entries: list[dict], since: datetime) -> list[dict]:
    found = []
    for e in entries:
        ms = e.get("metadataStatement") or {}
        for report in e.get("statusReports", []):
            status = report.get("status")
            date = report.get("effectiveDate")
            if status not in ALARMING_STATUS or not date:
                continue
            if datetime.fromisoformat(date).replace(tzinfo=timezone.utc) < since:
                continue
            found.append({
                "id": f"MDS-{status}-{e.get('aaguid') or e.get('aaid')}",
                "source": "FIDO MDS3",
                "summary": f"{ms.get('description', 'Unknown authenticator')}: status {status} "
                           f"effective {date}. {report.get('url') or ''}".strip(),
                "url": report.get("url") or MDS_URL,
                "aaguid": e.get("aaguid"),
            })
    return found


def issue_exists(finding_id: str) -> bool:
    out = subprocess.run(["gh", "issue", "list", "--state", "all", "--search", f"{finding_id} in:title",
                          "--json", "number"], capture_output=True, text=True, check=True).stdout
    return bool(json.loads(out or "[]"))


def issue_body(f: dict, entries: list[dict]) -> str:
    rows = [f"| `{f['aaguid']}` | (from status report) | |"] if f.get("aaguid") else candidate_models(entries, f["summary"])
    table = "\n".join(["| AAGUID | Model (MDS3) | authenticatorVersion |", "|---|---|---|", *rows]) if rows else "_No matching models found in MDS3._"
    return f"""**Source:** {f['source']} – {f['url']}

> {f['summary']}

### Candidate models from FIDO MDS3
{table}

### To do
- [ ] Read the vendor advisory; confirm affected products and fixed firmware
- [ ] Pick the affected AAGUIDs (authenticatorVersion ≈ firmware) – do not guess
- [ ] Add an entry to `data/advisories.json` with `references`
- [ ] `python3 tools/advisories_sign.py sign` and commit both files
- [ ] Or close as not relevant

_Opened automatically by the advisory watch workflow._"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--create-issues", action="store_true")
    ap.add_argument("--days", type=int, default=LOOKBACK_DAYS)
    args = ap.parse_args()

    until = datetime.now(timezone.utc)
    since = until - timedelta(days=args.days)
    entries = mds_entries()
    findings = nvd_findings(since, until) + mds_findings(entries, since)
    known = known_ids()
    findings = [f for f in findings if f["id"] not in known]

    print(f"{len(findings)} new finding(s) since {since.date()}")
    for f in findings:
        print(f"- {f['id']} ({f['source']}): {f['summary'][:160]}")
        if args.create_issues and not issue_exists(f["id"]):
            subprocess.run(["gh", "issue", "create", "--title", f"Advisory review: {f['id']}",
                            "--body", issue_body(f, entries), "--label", "advisory"], check=True)


if __name__ == "__main__":
    main()
