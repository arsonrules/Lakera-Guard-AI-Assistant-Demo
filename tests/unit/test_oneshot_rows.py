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


def test_hard_row_cap_raises(monkeypatch):
    big = {"slug": "big", "name": "Big", "source": "upload", "count": 400,
           "column": "prompt",
           "rows": [{"prompt": f"attack {i}", "category": "x"} for i in range(400)]}
    monkeypatch.setitem(main._datasets, "big", big)
    req = OneShotRequest(dataset="big", max_scenarios=1000,
                         strategies=list(STRATEGIES.keys()))   # 400 × 7 = 2800 > 2000
    with pytest.raises(HTTPException) as ei:
        _prepare_oneshot_rows(req)
    assert ei.value.status_code == 400


def test_dataset_sampled_to_default_cap(monkeypatch):
    big = {"slug": "big2", "name": "Big2", "source": "upload", "count": 400,
           "column": "prompt",
           "rows": [{"prompt": f"attack {i}", "category": "x"} for i in range(400)]}
    monkeypatch.setitem(main._datasets, "big2", big)
    rows, scope = _prepare_oneshot_rows(
        OneShotRequest(dataset="big2", strategies=list(STRATEGIES.keys()), seed=1))
    assert scope["base_executed"] == 100               # default max_scenarios
    assert scope["total_rows"] == 700                  # 100 × (1 + 6 strategies)
