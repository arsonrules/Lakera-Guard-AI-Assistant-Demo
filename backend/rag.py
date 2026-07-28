import pathlib
from functools import lru_cache

FIXTURES_DIR = pathlib.Path(__file__).parent.parent / "tests" / "fixtures"


def _folder(mode: str) -> pathlib.Path:
    return FIXTURES_DIR / f"docs_{mode}"


def _stamp(folder: pathlib.Path) -> tuple:
    """
    A cheap fingerprint of the folder's contents: (name, mtime_ns, size) per file.

    Used as part of the cache key so the cache invalidates itself — no mutation
    site has to remember to clear it. Covers adds, deletes, and in-place
    overwrites (the custom-docs upload endpoint can replace a file by name, which
    would leave the directory's own mtime untouched).
    """
    try:
        return tuple(sorted(
            (p.name, s.st_mtime_ns, s.st_size)
            for p in folder.glob("*.txt") if (s := p.stat())
        ))
    except OSError:
        return ()


@lru_cache(maxsize=8)
def _load(mode: str, _stamp_key: tuple) -> tuple:
    """
    Read every document in a mode once and keep it, pre-lowercased for scoring.

    `retrieve()` runs per scenario — a 30k-row one-shot run would otherwise
    re-read and re-lowercase the same handful of files 30,000 times, allocating a
    full copy of each document every call. `_stamp_key` is unused in the body: it
    exists only to key the cache (see `_stamp`).
    """
    folder = _folder(mode)
    if not folder.exists():
        return ()
    out = []
    for path in sorted(folder.glob("*.txt")):
        try:
            content = path.read_text()
        except OSError:                      # file vanished between glob and read
            continue
        out.append((path.name, content, content.lower()))
    return tuple(out)


def _docs(mode: str) -> tuple:
    folder = _folder(mode)
    return _load(mode, _stamp(folder))


def retrieve(query: str, mode: str = "clean", top_k: int = 2) -> list[dict]:
    """
    Keyword-based retrieval from the fixture document folders.
    Returns up to top_k dicts with keys: filename, content, score.
    """
    if mode == "none":   # explicit "no RAG file" — never retrieve anything
        return []

    query_terms = set(query.lower().split())
    scored = [
        {"filename": name, "content": content,
         "score": sum(1 for term in query_terms if term in lowered)}
        for name, content, lowered in _docs(mode)
    ]

    scored.sort(key=lambda d: d["score"], reverse=True)
    return [d for d in scored[:top_k] if d["score"] > 0]


def list_docs(mode: str) -> list[dict]:
    """All documents in a knowledge-base mode (for reporting what RAG is in use)."""
    if mode == "none":
        return []
    return [{"filename": name, "content": content} for name, content, _ in _docs(mode)]
