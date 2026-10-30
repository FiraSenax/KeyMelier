"""Review baseline for HTML parsing sinks; prevents adding unreviewed sites.

This is a change guard, not a proof that existing templates escape all input.
Update the checked-in baseline only after reviewing the affected data flow.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"(?:\.\s*(?:innerHTML|outerHTML)|\[\s*['\"](?:innerHTML|outerHTML)['\"]\s*\])\s*(?:\+?=)"
                     r"|\b(?:insertAdjacentHTML|createContextualFragment|parseFromString)\s*\("
                     r"|\bdocument\s*\.\s*(?:write|writeln)\s*\(")


def inventory(root=ROOT):
    found = {}
    for file in sorted((root / "static").glob("*.js")):
        for line in file.read_text(encoding="utf-8").splitlines():
            if PATTERN.search(line):
                ident = file.relative_to(root).as_posix() + ":" + hashlib.sha256(line.strip().encode()).hexdigest()
                found[ident] = found.get(ident, 0) + 1
    return found


def main():
    expected = json.loads((ROOT / "tools/html-sinks.json").read_text())
    actual = inventory()
    added = [site for site, count in actual.items() if count > expected.get(site, 0)]
    if added:
        raise SystemExit("Unreviewed HTML sinks: " + ", ".join(added))
    print(f"HTML sink baseline checked ({sum(actual.values())} sites)")


if __name__ == "__main__":
    main()
