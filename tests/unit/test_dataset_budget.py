"""
The in-memory dataset store must be bounded by ROWS, not just slot count.

MAX_DATASETS alone allowed 12 x MAX_ROWS (1.2M rows) resident, which is an OOM
waiting to happen on a container with a memory limit.
"""
import pytest
from fastapi import HTTPException

from backend import main


@pytest.fixture(autouse=True)
def _clean_store(monkeypatch):
    monkeypatch.setattr(main, "_datasets", {})
    yield


def _rows(n):
    return [{"prompt": f"p{i}", "category": "c"} for i in range(n)]


def test_import_within_budget_is_stored():
    main._store_dataset("small", "test", None, _rows(1000))
    assert main._total_dataset_rows() == 1000


def test_import_exceeding_row_budget_is_rejected():
    main._store_dataset("a", "test", None, _rows(main.MAX_TOTAL_DATASET_ROWS - 10))
    with pytest.raises(HTTPException) as exc:
        main._store_dataset("b", "test", None, _rows(100))
    assert exc.value.status_code == 400
    assert "Row budget exceeded" in exc.value.detail


def test_rejected_import_does_not_partially_store():
    """The budget check must run before mutation — a rejected import must leave
    the store untouched."""
    main._store_dataset("a", "test", None, _rows(main.MAX_TOTAL_DATASET_ROWS))
    before = dict(main._datasets)
    with pytest.raises(HTTPException):
        main._store_dataset("b", "test", None, _rows(1))
    assert main._datasets.keys() == before.keys()
    assert main._total_dataset_rows() == main.MAX_TOTAL_DATASET_ROWS


def test_budget_counts_across_all_slots():
    half = main.MAX_TOTAL_DATASET_ROWS // 2
    main._store_dataset("a", "test", None, _rows(half))
    main._store_dataset("b", "test", None, _rows(half))
    assert main._total_dataset_rows() == main.MAX_TOTAL_DATASET_ROWS
    with pytest.raises(HTTPException):
        main._store_dataset("c", "test", None, _rows(1))


def test_slot_cap_still_applies():
    for i in range(main.MAX_DATASETS):
        main._store_dataset(f"d{i}", "test", None, _rows(1))
    with pytest.raises(HTTPException, match="slot limit"):
        main._store_dataset("overflow", "test", None, _rows(1))


def test_deleting_frees_budget():
    main._store_dataset("big", "test", None, _rows(main.MAX_TOTAL_DATASET_ROWS))
    with pytest.raises(HTTPException):
        main._store_dataset("next", "test", None, _rows(1))
    main._datasets.clear()                       # what DELETE /api/datasets/{slug} does
    main._store_dataset("next", "test", None, _rows(1))   # now fits


async def test_datasets_endpoint_stays_a_list_and_reports_usage(client):
    """The frontend iterates this response directly, so the body must remain a
    bare array; budget usage rides along in headers."""
    main._store_dataset("a", "test", None, _rows(5))
    resp = await client.get("/api/datasets")
    assert isinstance(resp.json(), list)
    assert resp.headers["X-Dataset-Slots"] == f"1/{main.MAX_DATASETS}"
    assert resp.headers["X-Dataset-Rows"] == f"5/{main.MAX_TOTAL_DATASET_ROWS}"
