import pathlib

FIXTURES_DIR = pathlib.Path(__file__).parent.parent / "tests" / "fixtures"


def retrieve(query: str, mode: str = "clean", top_k: int = 2) -> list[dict]:
    """
    Keyword-based retrieval from the fixture document folders.
    Returns up to top_k dicts with keys: filename, content, score.
    """
    if mode == "none":   # explicit "no RAG file" — never retrieve anything
        return []
    folder = FIXTURES_DIR / f"docs_{mode}"
    if not folder.exists():
        return []

    query_terms = set(query.lower().split())
    scored: list[dict] = []

    for path in folder.glob("*.txt"):
        content = path.read_text()
        score = sum(1 for term in query_terms if term in content.lower())
        scored.append({"filename": path.name, "content": content, "score": score})

    scored.sort(key=lambda d: d["score"], reverse=True)
    return [d for d in scored[:top_k] if d["score"] > 0]


def list_docs(mode: str) -> list[dict]:
    """All documents in a knowledge-base mode (for reporting what RAG is in use)."""
    if mode == "none":
        return []
    folder = FIXTURES_DIR / f"docs_{mode}"
    if not folder.exists():
        return []
    return [{"filename": p.name, "content": p.read_text()}
            for p in sorted(folder.glob("*.txt"))]
