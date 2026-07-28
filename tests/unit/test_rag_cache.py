"""
Offline tests for RAG document caching.

`retrieve()` runs once per scenario, so a 30k-row one-shot run used to re-read
and re-lowercase the same files 30,000 times. The cache is keyed on a per-file
(name, mtime, size) fingerprint so it invalidates itself — these tests pin both
the caching and the invalidation, since a stale knowledge base would silently
change what the guard sees.
"""
import pytest

from backend import rag


@pytest.fixture
def docs_dir():
    """A temporary `docs_<mode>` folder inside the fixtures dir."""
    folder = rag.FIXTURES_DIR / "docs_pytestcache"
    folder.mkdir(exist_ok=True)
    yield folder
    for p in folder.glob("*"):
        p.unlink()
    folder.rmdir()


def test_documents_are_read_once_across_calls(docs_dir, monkeypatch):
    (docs_dir / "a.txt").write_text("refund policy details")
    rag.retrieve("refund", mode="pytestcache")          # prime

    reads: list[str] = []
    real = type(docs_dir).read_text
    monkeypatch.setattr(type(docs_dir), "read_text",
                        lambda self, *a, **k: (reads.append(self.name), real(self, *a, **k))[1])

    for _ in range(50):
        rag.retrieve("refund", mode="pytestcache")
    assert reads == []                                   # served entirely from cache


def test_new_file_is_picked_up(docs_dir):
    assert rag.retrieve("shipping", mode="pytestcache") == []
    (docs_dir / "b.txt").write_text("shipping is free over $50")
    assert rag.retrieve("shipping", mode="pytestcache"), "added file not visible"


def test_in_place_overwrite_invalidates(docs_dir):
    """The upload endpoint can replace a file by name — the directory's own
    mtime may not change, so the fingerprint must cover per-file mtime/size."""
    (docs_dir / "c.txt").write_text("alpha refund policy")
    assert rag.retrieve("refund", mode="pytestcache")
    (docs_dir / "c.txt").write_text("beta shipping terms only")
    assert rag.retrieve("refund", mode="pytestcache") == [], "stale cache after overwrite"
    assert rag.retrieve("shipping", mode="pytestcache"), "new content not visible"


def test_delete_invalidates(docs_dir):
    (docs_dir / "d.txt").write_text("warranty terms")
    assert rag.retrieve("warranty", mode="pytestcache")
    (docs_dir / "d.txt").unlink()
    assert rag.retrieve("warranty", mode="pytestcache") == [], "stale cache after delete"


def test_list_docs_uses_the_same_cache(docs_dir):
    (docs_dir / "e.txt").write_text("hello")
    assert [d["filename"] for d in rag.list_docs("pytestcache")] == ["e.txt"]
    (docs_dir / "e.txt").unlink()
    assert rag.list_docs("pytestcache") == []


# ── Behaviour preserved from the pre-cache implementation ────────────────────

def test_mode_none_never_retrieves():
    assert rag.retrieve("anything", mode="none") == []
    assert rag.list_docs("none") == []


def test_unknown_mode_is_empty():
    assert rag.retrieve("anything", mode="no-such-mode") == []


def test_scores_and_top_k(docs_dir):
    (docs_dir / "hit.txt").write_text("refund refund policy window")
    (docs_dir / "miss.txt").write_text("completely unrelated text")
    out = rag.retrieve("refund policy", mode="pytestcache")
    assert [d["filename"] for d in out] == ["hit.txt"]    # zero-score docs dropped
    assert out[0]["score"] > 0 and "content" in out[0]


def test_top_k_is_respected(docs_dir):
    for i in range(4):
        (docs_dir / f"f{i}.txt").write_text("refund policy")
    assert len(rag.retrieve("refund", mode="pytestcache", top_k=2)) == 2
