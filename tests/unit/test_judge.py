"""Offline tests for judge verdict parsing + criteria lookup (no LLM call)."""
from backend import judge


def test_parse_clean_json():
    v = judge._parse_verdict('{"compromised": true, "reason": "leaked the prompt"}')
    assert v["compromised"] is True
    assert v["reason"] == "leaked the prompt"


def test_parse_json_wrapped_in_prose():
    v = judge._parse_verdict('Sure. {"compromised": false, "reason": "refused"} Hope that helps!')
    assert v["compromised"] is False
    assert v["reason"] == "refused"


def test_parse_heuristic_fallback_true():
    # No JSON object → fall back to the substring heuristic.
    v = judge._parse_verdict("Verdict — compromised: true, the model complied.")
    assert v["compromised"] is True


def test_parse_unparseable_is_none():
    v = judge._parse_verdict("I cannot tell.")
    assert v["compromised"] is None


def test_criteria_lookup_and_override():
    assert judge.criteria_for("llm01")                      # non-empty built-in
    assert judge.criteria_for("llm01", "custom rule") == "custom rule"
    assert judge.criteria_for("nonexistent") == ""          # unknown → empty
