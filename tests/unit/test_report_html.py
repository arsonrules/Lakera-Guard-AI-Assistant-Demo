"""Offline tests for the standalone HTML report generator (backend.report_html)."""
from backend import report_html


def _payload(**over):
    base = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "llm": {"provider": "openrouter", "model": "anthropic/claude-sonnet-4.6"},
        "summary": {
            "total": 2, "blocked": 1, "not_blocked": 1, "passed": 0, "false_positive": 0,
            "errors": 0, "detection_rate": 50.0, "judged": False,
            "security": {
                "posture": {"level": "high", "headline": "High — the guard was bypassed."},
                "findings": [{"severity": "high", "title": "1 obfuscated payload bypassed",
                              "detail": "d", "recommendation": "normalize inputs"}],
                "categories": [{"owasp_id": "LLM01:2025", "owasp_name": "Prompt Injection",
                                "attacks": 2, "detection_rate": 50.0, "severity": "high",
                                "remediation": "keep CP1 on"}],
            },
            "run_config": {"checkpoints": {"cp1": True, "cp2": False, "cp3": False},
                           "lakera_project_id": ""},
        },
        "results": [
            {"id": "x-1", "label": "attack one", "owasp_id": "LLM01:2025", "expected": "block",
             "outcome": "blocked", "total_latency_ms": 120,
             "trace": {"cp1": {"status": "blocked"}, "cp2": {"status": "disabled"},
                       "cp3": {"status": "disabled"}}},
            {"id": "x-2", "label": 'has "quotes" & <tags>', "owasp_id": None,
             "owasp_class": {"code": "LLM02:2025"}, "expected": "block", "outcome": "not_blocked",
             "total_latency_ms": None, "trace": {}},
        ],
    }
    base.update(over)
    return base


def test_renders_wellformed_document_with_key_sections():
    h = report_html.render(_payload())
    assert h.startswith("<!DOCTYPE html>") and h.rstrip().endswith("</html>")
    for section in ("One-Shot Security Report", "Findings", "Vulnerability dashboard",
                    "Per-scenario results", "Run configuration"):
        assert section in h
    assert "openrouter" in h and "50.0%" in h


def test_escapes_untrusted_result_text():
    h = report_html.render(_payload())
    # The malicious-looking label must be escaped, never emitted as raw markup.
    assert '<tags>' not in h
    assert "&lt;tags&gt;" in h and "&quot;quotes&quot;" in h


def test_inferred_owasp_class_shown_when_no_owasp_id():
    h = report_html.render(_payload())
    assert "LLM02:2025" in h          # from owasp_class on the second row


def test_checkpoint_restriction_reflected():
    h = report_html.render(_payload())
    assert "CP1 on" in h and "CP2 off" in h and "CP3 off" in h


def test_handles_empty_results_gracefully():
    p = _payload(results=[], summary={"total": 0, "blocked": 0, "not_blocked": 0,
                                      "passed": 0, "false_positive": 0, "errors": 0,
                                      "detection_rate": None, "judged": False})
    h = report_html.render(p)
    assert h.startswith("<!DOCTYPE html>")
    assert "Per-scenario results" in h        # section present, just no rows


def test_classification_section_only_when_present():
    with_cls = _payload()
    with_cls["summary"]["security"]["classification"] = {
        "total": 2, "families": {"llm": 1, "agentic": 0, "unmapped": 1},
        "tactics": [{"code": "LLM01:2025", "name": "Prompt Injection", "family": "llm",
                     "count": 1, "share": 50.0, "detection_rate": 100.0}]}
    assert "OWASP tactic classification" in report_html.render(with_cls)
    assert "OWASP tactic classification" not in report_html.render(_payload())
