"""Read the shipped legal documents without network access or persistent writes."""
from pathlib import Path
from functools import lru_cache


@lru_cache(maxsize=4)
def _documents(root: Path, *, bundled: bool) -> tuple:
    # Packaged documents are immutable for this process. In development,
    # restart after updating dependencies to regenerate their notice text.
    notices = root / "THIRD_PARTY_LICENSES.txt"
    if not notices.is_file():
        # A frozen application must never silently substitute a source-tree
        # notice list for the actual build's collected components.
        if bundled:
            raise FileNotFoundError("Bundled third-party notices are missing")
        from tools import third_party_licenses
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
    return tuple((doc["id"], doc["filename"], doc["text"]) for doc in result)


def documents(root: Path, *, bundled: bool) -> dict:
    # Return fresh containers so bridge callers cannot mutate the cache.
    return {"bundled": bundled, "documents": [
        {"id": ident, "filename": name, "text": text}
        for ident, name, text in _documents(root, bundled=bundled)]}


def document(root: Path, document_id: str, *, bundled: bool) -> tuple[str, str]:
    if document_id not in ("notices", "app", "sources"):
        raise ValueError("Unknown license document")
    for ident, name, text in _documents(root, bundled=bundled):
        if ident == document_id:
            return name, text
    raise ValueError("License document is unavailable")
