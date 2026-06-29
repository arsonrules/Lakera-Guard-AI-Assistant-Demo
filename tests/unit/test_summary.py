"""Offline tests for one-shot summary aggregation (the P0 detection/evasion split)."""
from backend.main import OneShotRequest, _oneshot_summary


def _row(id, strat, outcome, risk, mo):
    return {"id": id, "color": "attack", "category_id": "llm01",
            "owasp_id": "LLM01:2025", "owasp_name": "Prompt Injection",
            "strategy": strat, "outcome": outcome, "risk": risk, "model_outcome": mo}


def test_detection_rate_split_and_effective_evasions():
    results = [
        _row("A", None, "blocked", None, "prevented"),               # base blocked
        _row("B", None, "not_blocked", "breach", "compromised"),     # base breach
        _row("A", "base64", "not_blocked", None, "resisted"),        # evaded, held
        _row("A", "homoglyph", "not_blocked", "breach", "compromised"),  # evaded + landed
    ]
    req = OneShotRequest(strategies=["base64", "homoglyph"], judge=True)
    s = _oneshot_summary(results, req, {"available": 10, "base_executed": 2,
                                        "total_rows": 4, "sampled": True,
                                        "max_scenarios": 2, "seed": 7})
    # all attack attempts: 1 blocked / 4 run = 25%
    assert s["detection_rate"] == 25.0
    # plaintext only: 1 of 2 blocked = 50%
    assert s["base_detection_rate"] == 50.0
    # variants: 0 of 2 blocked
    assert s["variant_block_rate"] == 0.0
    assert s["evasions"] == 2
    assert s["effective_evasions"] == 1          # only the homoglyph one landed
    assert s["breaches"] == 2                     # base B + landed variant
    assert s["scope"]["sampled"] is True
    # security posture reflects the breach
    assert s["security"]["posture"]["level"] == "critical"


def test_no_strategies_has_no_variant_metrics():
    results = [_row("A", None, "blocked", None, "prevented")]
    s = _oneshot_summary(results, OneShotRequest(judge=True), None)
    assert s["base_detection_rate"] == 100.0
    assert s["variant_block_rate"] is None
    assert "effective_evasions" not in s         # only set when strategies ran
