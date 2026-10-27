"""Read the shipped legal documents without network access or persistent writes."""
from pathlib import Path


def documents(root: Path, *, bundled: bool) -> dict:
    notices = root / "THIRD_PARTY_LICENSES.txt"
    if not notices.is_file():
        # A frozen application must never silently substitute a source-tree
        # notice list for the actual build's collected components.
        if bundled:
            raise FileNotFoundError("Bundled third-party notices are missing")
        import sys
        sys.path.insert(0, str(root / "tools"))
        import third_party_licenses
        text = third_party_licenses.build()
    else:
        text = notices.read_text(encoding="utf-8")
    result = [{"id": "notices", "filename": "THIRD_PARTY_LICENSES.txt", "text": text},
              {"id": "app", "filename": "LICENSE", "text": (root / "LICENSE").read_text(encoding="utf-8")}]
    sources = root / "THIRD_PARTY_SOURCES.json"
    if sources.is_file():
        result.append({"id": "sources", "filename": sources.name, "text": sources.read_text(encoding="utf-8")})
    elif bundled:
        raise FileNotFoundError("Bundled source manifest is missing")
    return {"bundled": bundled, "documents": result}
