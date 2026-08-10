"""Offline tests for the CLI HTML report (backend.report_html) — a mirror of the
web UI's one-shot report. Assertions use `class="…"` attributes (present only in
the rendered body) to avoid matching the embedded CSS/comments."""
import pytest

from backend import report_html


def _payload(**over):
    base = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "llm": {"provider": "openrouter", "model": "anthropic/claude-sonnet-4.6"},
        "judge": {"enabled": True, "provider": "openrouter", "model": "anthropic/claude-opus-4"},
        "summary": {
            "total": 2, "blocked": 1, "not_blocked": 1, "passed": 0, "false_positive": 0,
            "errors": 0, "detection_rate": 50.0, "judged": True, "breaches": 0,
            "resisted": 1, "prevented": 1, "compared": False,
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
             "trace": {"cp1": {"status": "blocked",
                               "detectors": [{"type": "prompt_attack", "category": "prompt_attack", "level": "L1"}]},
                       "cp2": {"status": "disabled"}, "cp3": {"status": "disabled"}}},
            {"id": "x-2", "label": 'has "quotes" & <tags>', "owasp_id": None,
             "owasp_class": {"code": "LLM02:2025", "family": "llm"}, "expected": "block",
             "outcome": "not_blocked", "total_latency_ms": None, "trace": {}},
        ],
    }
    base.update(over)
    return base


def test_renders_wellformed_document_with_web_ui_sections():
    h = report_html.render(_payload())
    assert h.startswith("<!DOCTYPE html>") and h.rstrip().endswith("</html>")
    assert 'id="os-body"' in h
    for cls in ('class="os-hero"', 'class="os-legend"', 'class="os-lakera-summary"',
                'class="os-table"', 'class="os-summary os-summary-secondary"'):
        assert cls in h, cls
    assert "openrouter" in h and "50%" in h          # provider in meta + detection hero (JS-parity: 50.0 → 50%)


def test_embeds_app_stylesheet_and_sprite():
    # Parity with the web UI comes from reusing the app's live CSS + icon sprite.
    h = report_html.render(_payload())
    assert "<symbol" in h and "<style>" in h


def test_stylesheet_excludes_js_report_exporter():
    # Regression: the frontend's own client-side report exporter builds a string
    # with '<style>' + styles + … '</style>' LITERALS. A naive <style> scrape used
    # to capture that JS as CSS, corrupting the cascade and dropping the report's
    # body-scroll fix (report became unscrollable). The <style> block must contain
    # only real CSS — no JS concatenation tokens — and keep exactly one body rule
    # that enables vertical scrolling (height:auto + overflow-y:auto).
    styles, _sprite, _i18n = report_html._app_assets()
    assert "+ '" not in styles and "=> " not in styles          # no JS leaked in as CSS
    assert ".os-report-head" not in styles                       # that leak marker is gone
    h = report_html.render(_payload())
    style_block = h[h.index("<style>"):h.index("</style>")]
    assert style_block.count("body{display:block") == 1          # exactly the real scroll-fix rule
    assert "overflow-y:auto" in style_block and "height:auto" in style_block


def test_judge_model_shown_when_judged():
    h = report_html.render(_payload())
    assert 'class="os-judge-info"' in h
    assert "anthropic/claude-opus-4" in h            # the dedicated judge model


def test_judge_hidden_when_not_judged():
    p = _payload(judge={"enabled": False, "provider": "x", "model": "y"})
    p["summary"]["judged"] = False
    assert 'class="os-judge-info"' not in report_html.render(p)


def test_lakera_detections_summary_counts_from_traces():
    h = report_html.render(_payload())
    assert 'class="os-lakera-summary"' in h
    assert "prompt_attack" in h                       # the fired detector category
    assert 'class="lk-badge lk-l1"' in h              # L1 badge from the trace


def test_vulnerability_dashboard_collapsed_by_default():
    h = report_html.render(_payload())
    # <details> without an `open` attribute = collapsed.
    assert 'class="os-dash-collapsible"' in h
    assert 'class="os-dash-collapsible" open' not in h


def test_escapes_untrusted_result_text():
    h = report_html.render(_payload())
    assert "<tags>" not in h
    assert "&lt;tags&gt;" in h and "&quot;quotes&quot;" in h


def test_inferred_owasp_class_shown():
    h = report_html.render(_payload())
    assert "LLM02:2025" in h                          # from owasp_class on row 2


def test_checkpoint_restriction_reflected():
    h = report_html.render(_payload())
    assert 'class="os-runcfg"' in h
    # CP1 active vs CP2/CP3 disabled render as used/none tags.
    assert 'class="os-runcfg-tag used"' in h and 'class="os-runcfg-tag none"' in h


def test_handles_empty_results_gracefully():
    p = _payload(results=[], summary={"total": 0, "blocked": 0, "not_blocked": 0, "passed": 0,
                                      "false_positive": 0, "errors": 0, "detection_rate": None,
                                      "judged": False})
    h = report_html.render(p)
    assert h.startswith("<!DOCTYPE html>")
    assert 'class="os-table"' in h                    # table present, just no rows


def test_classification_section_only_when_present():
    with_cls = _payload()
    with_cls["summary"]["security"]["classification"] = {
        "total": 2, "families": {"llm": 1, "agentic": 0, "unmapped": 1},
        "tactics": [{"code": "LLM01:2025", "name": "Prompt Injection", "family": "llm",
                     "count": 1, "share": 50.0, "detection_rate": 100.0}]}
    assert 'class="os-classify"' in report_html.render(with_cls)
    assert 'class="os-classify"' not in report_html.render(_payload())


def test_per_scenario_lakera_detectors_present():
    h = report_html.render(_payload())
    # Each scenario reveal carries its checkpoint detector results.
    assert 'class="lk-cp"' in h and 'class="lk-cp-tag"' in h


# ── Guard-supplied level reaches a class attribute ───────────────────────────

def test_lk_badge_level_cannot_escape_the_class_attribute():
    """
    The detector level comes from the Guard response, and it lands in a class
    ATTRIBUTE — a context where escaping the badge TEXT (which was already done)
    gives no protection. Levels are the fixed l1..l5 enum, so clamping to a
    CSS-identifier charset is lossless.
    """
    html = report_html._lk_badge('x" onmouseover=alert(1) y="')
    cls = html.split('class="')[1].split('"')[0]
    token = cls.replace("lk-badge ", "", 1)

    # What matters is that the level survives as ONE inert CSS identifier: no
    # quote to close the attribute, no space to start a new class, no `=` to
    # form an attribute. A substring like "onmouseover" inside the token is
    # harmless — it is a class name, not markup.
    assert not set(token) & set('"\'= <>/'), f"level can break out of the attribute: {token!r}"
    assert html.count('class="') == 1, "level injected a second attribute"
    # The opening tag carries the class and nothing else.
    assert html.split(">")[0] == f'<span class="{cls}"'
    # The same value in TEXT position stays escaped (this part already worked).
    assert '<' not in html.split(">", 1)[1] or "&quot;" in html


@pytest.mark.parametrize("level,expected", [
    ("l1", "lk-l1"), ("l2", "lk-l2"), ("l3", "lk-l3"), ("l4", "lk-l4"), ("l5", "lk-l5"),
    ("-", "lk-none"), (None, "lk-none"), ("", "lk-none"),
])
def test_lk_badge_renders_real_levels_unchanged(level, expected):
    """The clamp must not alter any level the app actually receives."""
    assert f'class="lk-badge {expected}"' in report_html._lk_badge(level)
