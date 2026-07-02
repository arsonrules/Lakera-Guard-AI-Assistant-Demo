"""Offline tests for the one-shot scale guardrails (sampling + hard cap)."""
import pytest
from fastapi import HTTPException

import backend.main as main
from backend.main import OneShotRequest, _prepare_oneshot_rows
from backend.strategies import STRATEGIES


@pytest.fixture(autouse=True)
def _lakera_key(monkeypatch):
    # _prepare_oneshot_rows fails fast without a key; set a dummy (no network).
    monkeypatch.setattr(main, "_lakera_key", "test-key")


def test_sampling_is_deterministic_with_seed():
    rows1, scope1 = _prepare_oneshot_rows(OneShotRequest(max_scenarios=5, seed=42))
    rows2, _ = _prepare_oneshot_rows(OneShotRequest(max_scenarios=5, seed=42))
    assert scope1["sampled"] is True
    assert scope1["base_executed"] == 5
    assert scope1["available"] > 5
    assert [r["id"] for r in rows1] == [r["id"] for r in rows2]


def test_under_cap_is_not_sampled():
    _, scope = _prepare_oneshot_rows(OneShotRequest())   # built-in catalogue < 100
    assert scope["sampled"] is False
    assert scope["base_executed"] == scope["available"]


def test_multiple_datasets_are_concatenated(monkeypatch):
    for slug, n in (("da", 3), ("db", 4)):
        monkeypatch.setitem(main._datasets, slug, {
            "slug": slug, "name": slug, "source": "upload", "count": n, "column": "prompt",
            "rows": [{"prompt": f"{slug} attack {i}", "category": "x"} for i in range(n)]})
    rows, scope = _prepare_oneshot_rows(OneShotRequest(datasets=["da", "db"]))
    assert scope["available"] == 7                       # 3 + 4 rows from both datasets
    assert {r["id"].rsplit("-", 1)[0] for r in rows} == {"da", "db"}


def test_hard_row_cap_raises(monkeypatch):
    strats = list(STRATEGIES.keys())
    # Enough base rows that base × (1 + strategies) exceeds the hard cap. Derive
    # the size from the constant so the test tracks the cap instead of a literal.
    n_base = main.HARD_MAX_ROWS // (1 + len(strats)) + 10
    big = {"slug": "big", "name": "Big", "source": "upload", "count": n_base,
           "column": "prompt",
           "rows": [{"prompt": f"attack {i}", "category": "x"} for i in range(n_base)]}
    monkeypatch.setitem(main._datasets, "big", big)
    req = OneShotRequest(dataset="big", max_scenarios=main.HARD_MAX_SCENARIOS,
                         strategies=strats)
    with pytest.raises(HTTPException) as ei:
        _prepare_oneshot_rows(req)
    assert ei.value.status_code == 400


def test_dataset_sampled_to_default_cap(monkeypatch):
    big = {"slug": "big2", "name": "Big2", "source": "upload", "count": 400,
           "column": "prompt",
           "rows": [{"prompt": f"attack {i}", "category": "x"} for i in range(400)]}
    monkeypatch.setitem(main._datasets, "big2", big)
    strats = list(STRATEGIES.keys())
    rows, scope = _prepare_oneshot_rows(
        OneShotRequest(dataset="big2", strategies=strats, seed=1, max_scenarios=100))
    assert scope["base_executed"] == 100               # default max_scenarios
    assert scope["total_rows"] == 100 * (1 + len(strats))   # base + one variant per strategy
