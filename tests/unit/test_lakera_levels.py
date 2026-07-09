"""Tests for the Lakera detector L1–L5 result mapping (req 3)."""
from backend import lakera


def _resp(items):
    return {"flagged": any(i.get("detected") for i in items), "breakdown": items}


def test_simplify_result_maps_levels():
    assert lakera.simplify_result("l1_confident") == "L1"
    assert lakera.simplify_result("l2_very_likely") == "L2"
    assert lakera.simplify_result("l3_likely") == "L3"
    assert lakera.simplify_result("l4_less_likely") == "L4"
    assert lakera.simplify_result("l5_unlikely") == "L5"


def test_simplify_result_no_level_and_unknown():
    assert lakera.simplify_result("no_level") == "-"
    assert lakera.simplify_result("") == "-"
    assert lakera.simplify_result(None) == "-"
    assert lakera.simplify_result("weird_value") == "-"


def test_detector_results_only_detected_by_default():
    resp = _resp([
        {"detector_type": "prompt_attack", "detected": True, "result": "l1_confident"},
        {"detector_type": "pii/address", "detected": False, "result": "l5_unlikely"},
    ])
    dets = lakera.detector_results(resp)
    assert len(dets) == 1
    assert dets[0] == {"type": "prompt_attack", "category": "prompt_attack", "level": "L1"}


def test_detector_results_category_is_prefix():
    resp = _resp([{"detector_type": "moderated_content/hate", "detected": True, "result": "l2_very_likely"}])
    assert lakera.detector_results(resp)[0]["category"] == "moderated_content"


def test_detector_results_all_when_requested():
    resp = _resp([
        {"detector_type": "prompt_attack", "detected": True, "result": "l1_confident"},
        {"detector_type": "pii/ssn", "detected": False, "result": "l5_unlikely"},
    ])
    assert len(lakera.detector_results(resp, only_detected=False)) == 2


def test_results_summary_counts_and_categories():
    resp = _resp([
        {"detector_type": "prompt_attack", "detected": True, "result": "l1_confident"},
        {"detector_type": "pii/address", "detected": True, "result": "l2_very_likely"},
        {"detector_type": "pii/ssn", "detected": True, "result": "l1_confident"},
        {"detector_type": "moderated_content/hate", "detected": False, "result": "l5_unlikely"},
    ])
    s = lakera.results_summary(resp)
    assert s["flagged_count"] == 3                      # three fired
    assert s["categories"] == ["pii", "prompt_attack"]  # sorted unique categories
    assert {d["level"] for d in s["detectors"]} == {"L1", "L2"}


def test_results_summary_empty_breakdown():
    s = lakera.results_summary({"flagged": False})
    assert s == {"detectors": [], "categories": [], "flagged_count": 0}


def test_level_legend_covers_l1_to_l5_and_dash():
    levels = [row["level"] for row in lakera.LEVEL_LEGEND]
    assert levels == ["L1", "L2", "L3", "L4", "L5", "-"]
