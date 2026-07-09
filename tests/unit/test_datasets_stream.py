"""Offline tests for the streaming HuggingFace fetch (datasets.stream_hf), with
the HTTP layer mocked so pages 'arrive' without network."""
from backend import datasets


def _rows_page(prompts, total):
    return {"features": [{"name": "prompt"}, {"name": "category"}],
            "num_rows_total": total,
            "rows": [{"row": {"prompt": p, "category": "harm"}} for p in prompts]}


async def test_stream_hf_yields_meta_batches_and_end(monkeypatch):
    async def fake_list_splits(dataset_id):
        return [{"config": "default", "split": "train"}]

    async def fake_probe(client, dataset_id, cfg, spl):
        return 5

    pages = iter([
        _rows_page(["a1", "a2", "a3"], 5),
        _rows_page(["a4", "a5"], 5),
    ])

    async def fake_get_json(client, url, params, **kw):
        return next(pages)

    monkeypatch.setattr(datasets, "list_splits", fake_list_splits)
    monkeypatch.setattr(datasets, "_probe_total", fake_probe)
    monkeypatch.setattr(datasets, "_get_json", fake_get_json)
    monkeypatch.setattr(datasets.asyncio, "sleep", lambda *_a, **_k: _noop())

    events = [e async for e in datasets.stream_hf("owner/name", limit=5)]
    kinds = [e["type"] for e in events]
    assert kinds[0] == "meta" and kinds[-1] == "end"
    batches = [e for e in events if e["type"] == "batch"]
    all_rows = [r["prompt"] for b in batches for r in b["rows"]]
    assert all_rows == ["a1", "a2", "a3", "a4", "a5"]      # streamed across pages, capped at limit
    assert events[-1]["fetched"] == 5


async def test_stream_hf_respects_limit_across_a_single_page(monkeypatch):
    async def fake_list_splits(dataset_id):
        return [{"config": "default", "split": "train"}]

    async def fake_probe(client, dataset_id, cfg, spl):
        return 100

    async def fake_get_json(client, url, params, **kw):
        return _rows_page([f"p{i}" for i in range(100)], 100)

    monkeypatch.setattr(datasets, "list_splits", fake_list_splits)
    monkeypatch.setattr(datasets, "_probe_total", fake_probe)
    monkeypatch.setattr(datasets, "_get_json", fake_get_json)
    monkeypatch.setattr(datasets.asyncio, "sleep", lambda *_a, **_k: _noop())

    events = [e async for e in datasets.stream_hf("owner/name", limit=3)]
    got = [r["prompt"] for e in events if e["type"] == "batch" for r in e["rows"]]
    assert got == ["p0", "p1", "p2"]        # never exceeds the requested limit


async def _noop():
    return None
