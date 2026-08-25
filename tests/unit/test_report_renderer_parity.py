"""
The compliance section has TWO renderers: backend/report_html.py (CLI export)
and complianceSectionHtml() in frontend/index.html (in-app modal + browser
export). DEPLOYMENT_REVIEW.md §1.2 logs the duplication; drift between the two
has already caused one real bug.

Consolidating them means either shipping a JS runtime in the backend or making
the modal fetch server-rendered HTML — both worse than this. So instead: pin
the contract the two share. These are string-level checks on purpose. They
cannot prove the renderers agree (that was verified byte-for-byte by hand
against a payload covering all four verdicts) — they catch the specific way
this drifts, which is someone changing one side's class names or thresholds.
"""
import re
from pathlib import Path

from backend import report_html

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
JS = FRONTEND.read_text(encoding="utf-8")


def test_the_frontend_has_a_compliance_renderer_at_all():
    """Without this the modal silently omits the section — the original bug."""
    assert "function complianceSectionHtml(sec)" in JS
    assert "html += complianceSectionHtml(s.security);" in JS


def test_verdict_styling_matches_the_backend():
    """A verdict rendered green on one side and grey on the other is the worst
    possible failure here — `no_evidence` must never read as a pass."""
    block = re.search(r"const VERDICT_META = \{(.*?)\n  \};", JS, re.S)
    assert block, "VERDICT_META not found"
    js = {m[0]: m[1:] for m in re.findall(
        r"(\w+):\s*\['([\w-]+)', '([\w-]+)', '([^']+)'\]", block.group(1))}
    assert js == report_html._VERDICT_META


def test_no_evidence_is_never_styled_as_a_pass():
    cls = report_html._VERDICT_META["no_evidence"][0]
    assert cls == "oc-skipped" and cls != report_html._VERDICT_META["evidenced"][0]


def test_the_unverified_disclaimer_is_rendered_by_both():
    """Shipping the mapping as fact before a compliance owner signs it off is a
    real-world liability, not a cosmetic issue."""
    assert "if (!c.verified)" in JS and "os-clsnote" in JS
    src = Path(report_html.__file__).read_text(encoding="utf-8")
    assert 'if not compliance.get("verified")' in src


def test_both_sides_use_the_same_i18n_keys():
    for key in ("os.complianceTitle", "os.complianceEvidenced"):
        assert f"t('{key}')" in JS, f"frontend missing {key}"
        assert f'T("{key}")' in Path(report_html.__file__).read_text(encoding="utf-8")


# ── Target Test: both renderers must drop the guard readouts together ─────────

def test_both_renderers_detect_a_target_run_the_same_way():
    """One renderer showing a 0% detection rate for an unguarded run — while the
    other omits it — is exactly the drift this file exists to catch."""
    assert "const tgt = (d.llm || {}).provider === 'http';" in JS
    src = Path(report_html.__file__).read_text(encoding="utf-8")
    assert 'tgt = llm.get("provider") == "http"' in src


def test_both_renderers_style_the_risk_bands_identically():
    """A Critical run rendered green on one side is a reporting failure."""
    src = Path(report_html.__file__).read_text(encoding="utf-8")
    js = dict(re.findall(r"(\w+): '(\w+)'", re.search(
        r"const RISK_CLS = \{(.*?)\};", JS, re.S).group(1)))
    assert set(js) == {"low", "medium", "high", "critical"}
    assert set(report_html._RISK_SEV) == set(js)
    assert 'sv-critical' in JS and '"critical": "critical"' in src
