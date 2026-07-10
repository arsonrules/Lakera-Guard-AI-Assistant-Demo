"""Offline tests for the HuggingFace download + strict verification (datasets.py),
with the HTTP layer mocked so no network is touched."""
import json

import pytest

from backend import datasets


def _write(dirpath, name, rows):
    (dirpath / name).write_text(json.dumps(rows), encoding="utf-8")
    return (dirpath / name).stat().st_size


def test_hf_slug_is_filesystem_safe():
    assert datasets.hf_slug("OpenSafetyLab/Salad-Data") == "OpenSafetyLab__Salad-Data"
    assert "/" not in datasets.hf_slug("a/b/c")


def test_count_file_rows_json_list(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([{"q": 1}, {"q": 2}, {"q": 3}]), encoding="utf-8")
    assert datasets._count_file_rows(p) == 3


def test_count_file_rows_json_dict_with_list(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"data": [1, 2]}), encoding="utf-8")
    assert datasets._count_file_rows(p) == 2


def test_count_file_rows_jsonl_and_csv(tmp_path):
    jl = tmp_path / "a.jsonl"
    jl.write_text('{"q":1}\n{"q":2}\n\n', encoding="utf-8")
    assert datasets._count_file_rows(jl) == 2
    cv = tmp_path / "a.csv"
    cv.write_text("prompt\nhi\nbye\n", encoding="utf-8")
    assert datasets._count_file_rows(cv) == 2


def test_verify_dataset_passes_on_exact_match(tmp_path):
    s1 = _write(tmp_path, "a.json", [{"q": 1}, {"q": 2}])
    s2 = _write(tmp_path, "b.json", [{"q": 3}])
    manifest = {"dir": str(tmp_path),
                "files": [{"path": "a.json", "size": s1}, {"path": "b.json", "size": s2}],
                "total_bytes": s1 + s2}
    official = {"files": [{"path": "a.json", "size": s1}, {"path": "b.json", "size": s2}],
                "num_bytes_original_files": s1 + s2, "num_rows": 3}
    rep = datasets.verify_dataset(manifest, official)
    assert rep["ok"] and rep["num_rows"] == 3 and rep["total_bytes"] == s1 + s2
    assert rep["row_check"] == "matched"


def test_verify_dataset_fails_on_size_mismatch(tmp_path):
    s1 = _write(tmp_path, "a.json", [{"q": 1}])
    manifest = {"dir": str(tmp_path), "files": [{"path": "a.json", "size": s1}], "total_bytes": s1}
    official = {"files": [{"path": "a.json", "size": s1 + 99}],
                "num_bytes_original_files": s1 + 99, "num_rows": 1}
    with pytest.raises(datasets.DatasetError, match="size"):
        datasets.verify_dataset(manifest, official)


def test_verify_dataset_fails_on_row_mismatch(tmp_path):
    s1 = _write(tmp_path, "a.json", [{"q": 1}, {"q": 2}])
    manifest = {"dir": str(tmp_path), "files": [{"path": "a.json", "size": s1}], "total_bytes": s1}
    official = {"files": [{"path": "a.json", "size": s1}],
                "num_bytes_original_files": s1, "num_rows": 5}       # claims 5, file has 2
    with pytest.raises(datasets.DatasetError, match="row count"):
        datasets.verify_dataset(manifest, official)


def test_verify_dataset_fails_on_missing_file(tmp_path):
    s1 = _write(tmp_path, "a.json", [{"q": 1}])
    manifest = {"dir": str(tmp_path), "files": [{"path": "a.json", "size": s1}], "total_bytes": s1}
    official = {"files": [{"path": "a.json", "size": s1}, {"path": "b.json", "size": 10}],
                "num_bytes_original_files": s1 + 10, "num_rows": 1}
    with pytest.raises(datasets.DatasetError, match="missing file"):
        datasets.verify_dataset(manifest, official)


async def test_download_reuses_cache(tmp_path, monkeypatch):
    # Pre-create a cached file with the official size; download must NOT refetch it.
    official = {"dataset_id": "own/ds", "files": [{"path": "a.json", "size": 5}],
                "num_bytes_original_files": 5, "num_rows": 1}
    ddir = tmp_path / datasets.hf_slug("own/ds")
    ddir.mkdir(parents=True)
    (ddir / "a.json").write_bytes(b"12345")            # exactly 5 bytes → cache hit

    def _boom(*a, **k):
        raise AssertionError("network fetch attempted for a cached file")
    monkeypatch.setattr(datasets.httpx, "AsyncClient", _boom)

    man = await datasets.download_hf_dataset("own/ds", str(tmp_path), official=official)
    assert man["files"] == [{"path": "a.json", "size": 5, "cached": True}]
    assert man["total_bytes"] == 5
