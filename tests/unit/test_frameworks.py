"""
Offline tests for the compliance framework mapping (backend/frameworks.py).

The load-bearing rule here is that a control the run never exercised must never
render as a pass. Everything else is presentation; that one is a correctness
property — an auditor reading "evidenced" for something we never tested would be
actively misled.
"""
import pytest

from backend import frameworks as F
from backend.scenarios import CATEGORIES


def _sec(cats):
    return {"categories": cats}


def _cat(cid, owasp, attacks, blocked, breaches=0):
    rate = round(blocked / attacks * 100, 1) if attacks else None
    return {"id": cid, "owasp_id": owasp, "attacks": attacks, "blocked": blocked,
            "breaches": breaches, "detection_rate": rate}


def _control(cov, ref):
    return next(c for b in cov["frameworks"] for c in b["controls"] if c["ref"] == ref)


# ── The core correctness property ────────────────────────────────────────────

def test_unexercised_controls_are_never_a_pass():
    cov = F.coverage(_sec([]))
    verdicts = {c["verdict"] for b in cov["frameworks"] for c in b["controls"]}
    assert verdicts == {"no_evidence"}
    assert cov["totals"]["evidenced"] == 0


def test_no_evidence_is_distinct_from_evidenced():
    """They must be different values so the UI can colour them differently."""
    assert F._verdict(0, None, 0) == "no_evidence"
    assert F._verdict(10, 100.0, 0) == "evidenced"


# ── Grading bands ────────────────────────────────────────────────────────────

def test_full_detection_is_evidenced():
    cov = F.coverage(_sec([_cat("llm01", "LLM01:2025", 10, 10)]))
    assert _control(cov, "AML.T0051")["verdict"] == "evidenced"


def test_a_breach_forces_a_gap_even_at_high_detection():
    """A single landed attack outranks a good detection rate — the control did
    not hold, whatever the average says."""
    cov = F.coverage(_sec([_cat("llm01", "LLM01:2025", 10, 9, breaches=1)]))
    assert _control(cov, "AML.T0051")["verdict"] == "gap"


@pytest.mark.parametrize("blocked,expected", [(10, "evidenced"), (7, "partial"), (2, "gap")])
def test_detection_bands(blocked, expected):
    cov = F.coverage(_sec([_cat("llm01", "LLM01:2025", 10, blocked)]))
    assert _control(cov, "AML.T0051")["verdict"] == expected


# ── Aggregation across categories ────────────────────────────────────────────

def test_one_control_aggregates_every_category_that_maps_to_it():
    """EU AI Act Art. 10 is evidenced by llm02, llm04 and llm08 together."""
    cov = F.coverage(_sec([
        _cat("llm02", "LLM02:2025", 5, 5),
        _cat("llm04", "LLM04:2025", 5, 1),
    ]))
    art10 = _control(cov, "Art. 10")
    assert sorted(art10["evidence"]) == ["LLM02:2025", "LLM04:2025"]
    assert art10["attacks"] == 10 and art10["blocked"] == 6
    assert art10["detection_rate"] == 60.0


def test_categories_with_no_attacks_do_not_count_as_evidence():
    cov = F.coverage(_sec([_cat("llm01", "LLM01:2025", 0, 0)]))
    assert _control(cov, "AML.T0051")["evidence"] == []
    assert _control(cov, "AML.T0051")["verdict"] == "no_evidence"


# ── Presentation contract the UI depends on ──────────────────────────────────

def test_controls_are_sorted_worst_first():
    cov = F.coverage(_sec([
        _cat("llm02", "LLM02:2025", 10, 10),     # evidenced
        _cat("llm04", "LLM04:2025", 10, 1),      # gap
    ]))
    eu = next(b for b in cov["frameworks"] if b["id"] == "eu-ai-act")
    ranks = [F._VERDICT_RANK[c["verdict"]] for c in eu["controls"]]
    assert ranks == sorted(ranks), "gaps must surface above passes"


def test_frameworks_keep_a_stable_curated_order():
    cov = F.coverage(_sec([_cat("llm01", "LLM01:2025", 1, 1)]))
    assert [b["id"] for b in cov["frameworks"]] == [
        f for f in F.FRAMEWORKS if f in {b["id"] for b in cov["frameworks"]}
    ]


def test_disclaimer_and_review_flag_are_always_present():
    """The report must never present these citations as verified fact."""
    cov = F.coverage(_sec([]))
    assert cov["verified"] is False
    assert "not legal advice" in cov["disclaimer"]


# ── Table integrity ──────────────────────────────────────────────────────────

def test_every_mapping_targets_a_known_framework():
    for cat_id, refs in F.MAPPINGS.items():
        for ref in refs:
            assert ref["fw"] in F.FRAMEWORKS, f"{cat_id} -> unknown framework {ref['fw']}"
            assert ref["ref"] and ref["title"]


def test_every_mapped_category_exists_in_the_catalogue():
    known = {c["id"] for c in CATEGORIES}
    assert set(F.MAPPINGS) <= known, f"stale ids: {set(F.MAPPINGS) - known}"


def test_every_owasp_attack_category_has_at_least_one_mapping():
    """A category with no mapping would silently vanish from the report."""
    attack_cats = {
        c["id"] for c in CATEGORIES
        if c["id"] not in ("safe", "multiturn", "dynamic")   # techniques, not OWASP risks
    }
    assert attack_cats <= set(F.MAPPINGS), f"unmapped: {attack_cats - set(F.MAPPINGS)}"


def test_for_category_returns_a_copy():
    a = F.for_category("llm01")
    a.append({"fw": "x"})
    assert len(F.for_category("llm01")) != len(a)


# ── Wiring ───────────────────────────────────────────────────────────────────

async def test_frameworks_endpoint_exposes_the_table(client):
    d = (await client.get("/api/frameworks")).json()
    assert d["verified"] is False
    assert "eu-ai-act" in d["frameworks"] and "llm01" in d["mappings"]


def test_report_build_attaches_compliance():
    from backend import report

    class _Req:
        strategies, compare, judge = [], False, False

    out = report.build([], {"judged": False}, _Req())
    assert "compliance" in out and out["compliance"]["control_count"] > 0
