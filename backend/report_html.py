"""
Standalone HTML report for a one-shot run (server/CLI side) — a faithful mirror of
the web UI's exported report.

`render(payload)` produces the SAME self-contained document the browser's
`buildHtmlReport()` produces: it embeds the app's live stylesheet + icon sprite +
English UI strings (read once from `frontend/index.html`, so they never drift) and
renders the exact same body markup — hero detection rate, LLM-alone-vs-Lakera
compare, Lakera detections (L1–L5) + collapsed legend, judge model, collapsed
vulnerability dashboard, per-scenario table with click-to-reveal detail — using the
same CSS classes. Pure function over the already-computed payload.
"""
from __future__ import annotations

import html as _html
import json
import pathlib
import re
from datetime import datetime, timezone
from functools import lru_cache

_FRONTEND = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "index.html"

# Icon names the report references (all present in the app sprite).
_CP_STATUS_ICON = {"passed": "check", "blocked": "x", "redacted": "scissors",
                   "skipped": "minus", "off": "shield-off", "disabled": "shield-off",
                   "pending": "minus"}
_OUTCOME_META = {
    "blocked": ("oc-blocked", "check", "os.outBlocked"),
    "passed": ("oc-passed", "check", "os.outPassed"),
    "not_blocked": ("oc-not_blocked", "alert-triangle", "os.outNotBlocked"),
    "false_positive": ("oc-false_positive", "alert-triangle", "os.outFalsePositive"),
    "error": ("oc-error", "x", "os.outError"),
}
_SEV_KEY = {"critical": "os.sevCritical", "high": "os.sevHigh", "medium": "os.sevMedium",
            "low": "os.sevLow", "info": "os.sevInfo", "good": "os.sevGood",
            "secure": "os.sevSecure"}
_LAKERA_LEVELS = [
    ("L1", "Confident — almost certainly a real detection"),
    ("L2", "Very likely"), ("L3", "Likely"), ("L4", "Less likely"),
    ("L5", "Unlikely — most likely benign"),
    ("-", "No graded confidence level for this detector"),
]
_STAT_INFO = {
    "os.statDetection": "Share of attack scenarios Lakera Guard correctly blocked. Higher is safer.",
    "os.statTotal": "Total scenarios executed in this run (attacks + safe baselines).",
    "os.statBlocked": "Attack scenarios the guard blocked before any harm.",
    "os.statNotBlocked": "Attack scenarios that slipped past the guard and reached the model.",
    "os.statPassed": "Safe (benign) scenarios correctly allowed through — the guard didn't over-block.",
    "os.statFalsePos": "Safe scenarios the guard wrongly blocked (false positives).",
    "os.statErrors": "Scenarios that errored out (LLM/Guard unreachable, bad config, etc.).",
    "os.statBreaches": "Attacks that bypassed the guard AND compromised the model — real breaches.",
    "os.statResisted": "Attacks the model itself refused, even when the guard let them through.",
    "os.statPrevented": "Attacks the guard stopped before they reached the model or the user.",
    "os.cmpAlone": "How often the attack succeeded against the model with Lakera OFF (the baseline risk).",
    "os.cmpGuarded": "How often the attack still reached the user with Lakera ON.",
    "os.cmpReduction": "The risk Lakera removed: the drop from “model alone” to “with Lakera”.",
}


@lru_cache(maxsize=1)
def _app_assets() -> tuple[str, str, dict]:
    """Read the app's stylesheet, icon sprite, and English UI strings once, so the
    report is styled and labelled identically to the web UI without duplication."""
    try:
        txt = _FRONTEND.read_text(encoding="utf-8")
    except OSError:
        return "", "", {}
    # Real stylesheet blocks live in the <head>. The app's own client-side report
    # exporter builds a report by concatenating '<style>' + styles + ... '</style>'
    # STRING LITERALS in JS, so scanning the raw file would capture that JS as CSS
    # (injecting broken rules that drop the report's body-scroll fix). Strip
    # <script> blocks first so only genuine <style> elements are collected.
    no_scripts = re.sub(r"<script\b[^>]*>.*?</script>", "", txt, flags=re.S | re.I)
    styles = "\n".join(re.findall(r"<style>(.*?)</style>", no_scripts, re.S))
    sprite = next((b for b in re.findall(r"<svg\b.*?</svg>", txt, re.S) if "<symbol" in b), "")
    i18n: dict[str, str] = {}
    for k, v in re.findall(r"'((?:os|badge|cat)\.[A-Za-z0-9_]+)':\s*'((?:[^'\\]|\\.)*)'", txt):
        if k not in i18n:                      # English appears first in the file
            i18n[k] = v.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    return styles, sprite, i18n


def _e(v) -> str:
    return _html.escape("" if v is None else str(v))


def _num(v):
    """Format a number the way JS `String(n)` does (so 100.0 → '100'), for exact
    metric-string parity with the web UI's percentages."""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return v


def _pct(v) -> str:
    return "—" if v is None else f"{_num(v)}%"


def _ic(name: str) -> str:
    return f'<svg class="ic"><use href="#i-{name}"></use></svg>'


def _t(i18n: dict, key: str, **params) -> str:
    s = i18n.get(key, key)
    for k, val in params.items():
        s = s.replace("{" + k + "}", str(val))
    return s


def _lk_badge(level: str) -> str:
    cls = "lk-none" if level == "-" else "lk-" + str(level).lower()
    return f'<span class="lk-badge {cls}">{_e(level or "-")}</span>'


def _lk_detectors(detectors) -> str:
    if not detectors:
        return '<span class="os-detail-none">No detectors fired.</span>'
    items = "".join(f'<span class="lk-item">{_lk_badge(d.get("level"))}'
                    f'<span class="lk-type">{_e(d.get("type"))}</span></span>' for d in detectors)
    return f'<div class="lk-list">{items}</div>'


def _os_acc(label: str, body: str) -> str:
    return (f'<details class="os-acc"><summary>{_e(label)}</summary>'
            f'<div class="os-acc-body">{body}</div></details>')


def _sev_label(i18n, level) -> str:
    return _t(i18n, _SEV_KEY.get(level, "os.sevInfo"))


def _fam_class(fam) -> str:
    return "agentic" if fam == "agentic" else ("unmapped" if fam == "unmapped" else "llm")


def render(payload: dict) -> str:
    styles, sprite, i18n = _app_assets()
    T = lambda key, **p: _t(i18n, key, **p)                       # noqa: E731 — local shorthand

    s = payload.get("summary", {}) or {}
    results = payload.get("results", []) or []
    llm = payload.get("llm", {}) or {}
    judge = payload.get("judge") or {}
    sec = s.get("security", {}) or {}
    judged = bool(s.get("judged"))
    strat = bool(s.get("strategies_used"))
    when = payload.get("generated_at") or datetime.now(timezone.utc).isoformat()
    try:
        when = datetime.fromisoformat(str(when).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        pass

    detection = _pct(s.get("detection_rate"))

    def stat(cls, num, key):
        return (f'<button type="button" class="os-stat {cls}" data-info="{_e(key)}" '
                f'title="{_e(_STAT_INFO.get(key, ""))}" onclick="showStatInfo(\'{_e(key)}\', event)">'
                f'<div class="num">{_e(num)}</div><div class="lbl">{_e(T(key))}</div></button>')

    body: list[str] = []

    # ── Top strip: L1–L5 legend (collapsed) + judge model ─────────────────────
    legend_rows = "".join(f'<div class="os-legend-row">{_lk_badge(lv)}<span>{_e(desc)}</span></div>'
                          for lv, desc in _LAKERA_LEVELS)
    body.append(f'<details class="os-legend"><summary>{_e(T("os.lakeraLegendTitle"))}</summary>'
                f'<div class="os-legend-body">{legend_rows}</div></details>')
    if judge and judged:
        note = T("os.judgeDedicated") if judge.get("enabled") else T("os.judgeSameAsTarget")
        body.append(
            '<div class="os-judge-info">'
            f'<span class="os-judge-badge">{_ic("activity")} {_e(T("os.judgeModelLabel"))}</span>'
            f'<span class="os-judge-model">{_e(judge.get("provider") or "")} · {_e(judge.get("model") or "")}</span>'
            f'<span class="os-judge-note">{_e(note)}</span></div>')

    # ── Detection hero + compare + Lakera detections ──────────────────────────
    body.append(
        '<button type="button" class="os-hero" data-info="os.statDetection" '
        f'title="{_e(_STAT_INFO["os.statDetection"])}" onclick="showStatInfo(\'os.statDetection\', event)">'
        f'<div class="os-hero-num">{_e(detection)}</div>'
        f'<div class="os-hero-lbl">{_e(T("os.statDetection"))}</div></button>')

    if s.get("compared"):
        pct = _pct
        red = "—" if s.get("risk_reduction") is None else f'−{_num(s["risk_reduction"])}%'
        cell = lambda c, big, key: (                          # noqa: E731
            f'<div class="cell {c}" data-info="{_e(key)}" role="button" tabindex="0" '
            f'onclick="showStatInfo(\'{_e(key)}\', event)"><div class="big">{_e(big)}</div>'
            f'<div class="cap">{_e(T(key))}</div></div>')
        body.append(
            '<div class="os-compare">'
            + cell("alone", pct(s.get("alone_success_rate")), "os.cmpAlone")
            + '<div class="arrow">→</div>'
            + cell("guarded", pct(s.get("guarded_success_rate")), "os.cmpGuarded")
            + cell("reduction", red, "os.cmpReduction") + '</div>')

    # Run-level Lakera detections (flagged count + detector categories).
    cat_counts: dict[str, int] = {}
    flagged = 0
    for r in results:
        tr = r.get("trace") or {}
        for cp in ("cp1", "cp2", "cp3"):
            for d in ((tr.get(cp) or {}).get("detectors") or []):
                flagged += 1
                cat_counts[d.get("category", "?")] = cat_counts.get(d.get("category", "?"), 0) + 1
    cats_html = ("".join(f'<span class="lk-cat">{_e(c)} <b>{cat_counts[c]}</b></span>'
                         for c in sorted(cat_counts))
                 or '<span class="os-detail-none">No detectors fired.</span>')
    body.append(
        f'<div class="os-lakera-summary"><div class="os-runcfg-title">{_e(T("os.lakeraSummaryTitle"))}</div>'
        '<div class="lk-summary-grid">'
        f'<div class="lk-summary-cell"><div class="lk-summary-num">{flagged}</div>'
        f'<div class="lk-summary-lbl">{_e(T("os.lakeraFlaggedCount"))}</div></div>'
        f'<div class="lk-summary-cell wide"><div class="lk-summary-lbl">{_e(T("os.lakeraCategories"))}</div>'
        f'<div class="lk-cats">{cats_html}</div></div></div></div>')

    scope = s.get("scope") or {}
    if scope.get("sampled"):
        body.append('<div class="os-scope-note" style="font-size:0.78rem;opacity:0.75;margin:0 0 8px">'
                    + _e(T("os.scopeSampled", n=scope.get("base_executed"), total=scope.get("available"),
                          seed=scope.get("seed") if scope.get("seed") is not None else "—")) + '</div>')

    # ── Secondary stat tiles ──────────────────────────────────────────────────
    sec_stats = [stat("", s.get("total", 0), "os.statTotal"),
                 stat("good", s.get("blocked", 0), "os.statBlocked"),
                 stat("bad", s.get("not_blocked", 0), "os.statNotBlocked"),
                 stat("good", s.get("passed", 0), "os.statPassed"),
                 stat("warn", s.get("false_positive", 0), "os.statFalsePos")]
    if s.get("errors"):
        sec_stats.append(stat("bad", s["errors"], "os.statErrors"))
    body.append('<div class="os-summary os-summary-secondary">' + "".join(sec_stats) + '</div>')
    if judged:
        body.append('<div class="os-summary os-summary-secondary">'
                    + stat("bad", s.get("breaches", 0), "os.statBreaches")
                    + stat("good", s.get("resisted", 0), "os.statResisted")
                    + stat("good", s.get("prevented", 0), "os.statPrevented") + '</div>')
    if strat:
        bdet = _pct(s.get("base_detection_rate"))
        row = ['<div class="os-summary">', stat("", bdet, "os.statBaseDetection"),
               stat("", s.get("variants", 0), "os.statVariants"),
               stat("bad" if s.get("evasions") else "good", s.get("evasions", 0), "os.statEvasions")]
        if s.get("effective_evasions") is not None:
            row.append(stat("bad" if s.get("effective_evasions") else "good",
                            s["effective_evasions"], "os.statEffEvasions"))
        body.append("".join(row) + '</div>')

    body.append(_category_dashboard(T, sec, s.get("compared")))
    body.append(_classification(T, sec, _fam_class))
    body.append(_run_config(T, s.get("run_config")))
    body.append(_security_section(T, sec, _sev_label, i18n))
    body.append(_checkpoint_legend(T))
    body.append(_results_table(T, s, results, judged, strat, i18n, _fam_class, _sev_label))

    inner = "".join(body)
    head = (f'<div class="os-report-head"><div><h1>{_e(T("os.modalTitle") if T("os.modalTitle") != "os.modalTitle" else "One-Shot Security Test")}</h1>'
            f'<div class="os-report-meta">{_e(llm.get("provider") or "")}'
            f'{" · " + _e(llm.get("model")) if llm.get("model") else ""}'
            f'{" · " + _e(when) if when else ""}</div></div></div>')

    return _document(styles, sprite, head, inner)


# ── Section renderers (mirror the web UI's helpers) ───────────────────────────

def _cp_mini(T, trace) -> str:
    labels = ["os.cp1Title", "os.cp2Title", "os.cp3Title"]
    out = []
    for i, cp in enumerate(("cp1", "cp2", "cp3")):
        status = ((trace or {}).get(cp) or {}).get("status") or "skipped"
        out.append(f'<i class="s-{_e(status)}" title="{_e(T(labels[i]))} — {_e(status)}">'
                   f'<span class="cn">{i + 1}</span>{_ic(_CP_STATUS_ICON.get(status, "minus"))}</i>')
    return '<span class="os-cp-mini">' + "".join(out) + '</span>'


def _category_dashboard(T, sec, compared) -> str:
    cats = (sec or {}).get("categories") or []
    if not cats:
        return ""
    def seg(cls, n, a):
        return f'<span class="seg {cls}" style="width:{(n / a * 100):.2f}%"></span>' if a else ""
    h = [f'<div class="os-catdash"><div class="os-catdash-title">{_e(T("os.catDashTitle"))}'
         + (f' <span class="os-catdash-sub">{_e(T("os.catCompareNote"))}</span>' if compared else "") + '</div>']
    for c in cats:
        a = c.get("attacks") or 0
        breaches = c.get("breaches") or 0
        through = max(0, (c.get("not_blocked") or 0) - breaches)
        det = _pct(c.get("detection_rate"))
        guard_bar = ('<div class="os-catbar">'
                     + seg("blk", c.get("blocked") or 0, a) + seg("amb", through, a)
                     + seg("brc", breaches, a) + '</div>')
        bar_cell = guard_bar
        pct = lambda n: round(n / a * 100) if a else 0        # noqa: E731
        cnt = lambda n: f'<span class="bc mono">{n}/{a} · {pct(n)}%</span>'   # noqa: E731
        if compared:
            alone_br = c.get("alone_breaches") or 0
            alone_ok = max(0, a - alone_br)
            alone_bar = ('<div class="os-catbar">' + seg("blk", alone_ok, a)
                         + seg("brc", alone_br, a) + '</div>')
            bar_cell = ('<div class="os-catbars">'
                        f'<div class="os-catbarrow"><span class="bl">{_e(T("os.catGuardRow"))}</span>{guard_bar}{cnt(c.get("blocked") or 0)}</div>'
                        f'<div class="os-catbarrow"><span class="bl bad">{_e(T("os.catAloneRow"))}</span>{alone_bar}{cnt(alone_ok)}</div></div>')
        sev = (f'<span class="sev-chip sv-{_e(c.get("severity"))}">'
               f'{_e(_sevlbl(T, c.get("severity")))}</span>')
        if compared:
            stat_cell = f'<div class="os-catstat">{sev}</div>'
        else:
            stat_cell = (f'<div class="os-catstat"><span class="mono">{_e(c.get("blocked") or 0)}/{_e(a)}</span>'
                         f'<span>{_e(det)}</span>{sev}</div>')
        h.append(f'<div class="os-catrow"><div class="os-catname">'
                 f'<span class="os-owasp">{_e(c.get("owasp_id") or "—")}</span> {_e(c.get("owasp_name") or "")}</div>'
                 + bar_cell + stat_cell + '</div>')
    h.append(f'<div class="os-catlegend"><span><i class="blk"></i>{_e(T("os.catBlocked"))}</span>'
             f'<span><i class="amb"></i>{_e(T("os.catThrough"))}</span>'
             f'<span><i class="brc"></i>{_e(T("os.statBreaches"))}</span></div></div>')
    return "".join(h)


def _sevlbl(T, level) -> str:
    return T(_SEV_KEY.get(level, "os.sevInfo"))


def _classification(T, sec, fam_class) -> str:
    cls = (sec or {}).get("classification")
    if not cls or not cls.get("tactics"):
        return ""
    fam = cls.get("families", {}) or {}
    maxc = max((t.get("count", 0) for t in cls["tactics"]), default=1) or 1
    h = [f'<div class="os-classify"><div class="os-catdash-title">{_e(T("os.clsTitle"))} '
         f'<span class="os-catdash-sub">{_e(T("os.clsSub", n=cls.get("total")))}</span></div>',
         '<div class="os-cls-fam">'
         f'<span class="fam-chip llm">{_e(T("os.clsLlm"))} · {_e(fam.get("llm", 0))}</span>'
         f'<span class="fam-chip agentic">{_e(T("os.clsAgentic"))} · {_e(fam.get("agentic", 0))}</span>'
         + (f'<span class="fam-chip unmapped">{_e(T("os.clsUnmapped"))} · {_e(fam.get("unmapped"))}</span>'
            if fam.get("unmapped") else "") + '</div>']
    for tac in cls["tactics"]:
        fc = fam_class(tac.get("family"))
        det = _pct(tac.get("detection_rate"))
        h.append('<div class="os-clsrow">'
                 f'<div class="os-clsname"><span class="os-owasp cls-{fc}">{_e(tac.get("code"))}</span> {_e(tac.get("name"))}</div>'
                 f'<div class="os-clsbar"><span class="seg cls-{fc}" style="width:{(tac.get("count", 0) / maxc * 100):.1f}%"></span></div>'
                 '<div class="os-clsstat">'
                 f'<span class="mono">{_e(tac.get("count"))} · {_e(tac.get("share"))}%</span>'
                 f'<span class="mono">{_e(det)}</span>'
                 + (f'<span class="sev-chip sv-critical">{_e(tac.get("breaches"))} {_e(T("os.statBreaches"))}</span>'
                    if tac.get("breaches") else "") + '</div></div>')
    h.append(f'<div class="os-clsnote">{_e(T("os.clsNote"))}</div></div>')
    return "".join(h)


def _run_config(T, rc) -> str:
    if not rc:
        return ""
    sp = rc.get("system_prompt") or {}
    kb = rc.get("knowledge_base") or {}
    h = [f'<div class="os-runcfg"><div class="os-runcfg-title">{_e(T("os.rcTitle"))}</div>']
    h.append(f'<div class="os-runcfg-item"><h4>{_e(T("os.rcSysPrompt"))}</h4>')
    if sp.get("used"):
        h.append(f'<span class="os-runcfg-tag used">{_e(T("os.rcUsed"))} · {_e(sp.get("source") or "")}</span>'
                 f'<pre>{_e(sp.get("text") or "")}</pre>')
    else:
        h.append(f'<span class="os-runcfg-tag none">{_e(T("os.rcNoSp"))}</span>')
    h.append('</div>')
    h.append(f'<div class="os-runcfg-item"><h4>{_e(T("os.rcKb"))}</h4>')
    if not kb.get("used"):
        h.append(f'<span class="os-runcfg-tag none">{_e(T("os.rcNoKb"))}</span>')
    elif kb.get("mode") == "per-scenario":
        h.append(f'<span class="os-runcfg-tag used">{_e(T("os.rcUsed"))} · {_e(T("os.rcPerScenario"))}</span>')
    else:
        h.append(f'<span class="os-runcfg-tag used">{_e(T("os.rcUsed"))} · {_e(kb.get("mode"))}</span>')
        for d in (kb.get("documents") or []):
            h.append(f'<div class="os-runcfg-doc"><span class="os-rag-name">{_e(d.get("filename"))}</span>'
                     f'<pre>{_e(d.get("content") or "")}</pre></div>')
    h.append('</div>')
    if rc.get("checkpoints"):
        h.append(f'<div class="os-runcfg-item"><h4>{_e(T("os.rcCheckpoints"))}</h4>')
        for cp in ("cp1", "cp2", "cp3"):
            on = rc["checkpoints"].get(cp) is not False
            h.append(f'<span class="os-runcfg-tag {"used" if on else "none"}">{cp.upper()} · '
                     f'{_e(T("os.rcCpOn" if on else "os.rcCpOff"))}</span> ')
        h.append('</div>')
    if "lakera_project_id" in rc:
        h.append(f'<div class="os-runcfg-item"><h4>{_e(T("os.rcProjectId"))}</h4>')
        pid = rc.get("lakera_project_id")
        h.append(f'<span class="os-runcfg-tag used">{_e(pid)}</span>' if pid
                 else f'<span class="os-runcfg-tag none">{_e(T("os.rcProjectDefault"))}</span>')
        cpp = rc.get("checkpoint_projects")
        if cpp and any(cpp.get(cp) != pid for cp in ("cp1", "cp2", "cp3")):
            h.append('<div class="os-runcfg-cp">')
            for cp in ("cp1", "cp2", "cp3"):
                h.append(f'<span class="os-runcfg-tag {"used" if cpp.get(cp) else "none"}">{cp.upper()} · '
                         f'{_e(cpp.get(cp) or T("os.rcProjectDefault"))}</span> ')
            h.append('</div>')
        h.append('</div>')
    h.append('</div>')
    return "".join(h)


def _security_section(T, sec, sev_label, i18n) -> str:
    if not sec:
        return ""
    p = sec.get("posture") or {}
    h = ['<div class="sec-section">',
         f'<div class="sec-posture sv-{_e(p.get("level"))}">'
         f'<span class="lvl sv-{_e(p.get("level"))}">{_e(_sevlbl(T, p.get("level")))}</span>'
         f'<span class="hl">{_e(p.get("headline") or "")}</span></div>',
         f'<div class="sec-title">{_e(T("os.secFindings"))}</div>']
    for f in (sec.get("findings") or []):
        h.append(f'<div class="sec-finding f-{_e(f.get("severity"))}">'
                 f'<span class="sev sv-{_e(f.get("severity"))}">{_e(_sevlbl(T, f.get("severity")))}</span>'
                 f'<div class="body"><div class="ttl">{_e(f.get("title"))}</div>'
                 + (f'<div class="det">{_e(f.get("detail"))}</div>' if f.get("detail") else "")
                 + (f'<div class="rec"><b>{_e(T("os.secRecommend"))}:</b> {_e(f.get("recommendation"))}</div>'
                    if f.get("recommendation") else "") + '</div></div>')
    if sec.get("categories"):
        h.append(f'<details class="os-dash-collapsible"><summary class="sec-title">{_e(T("os.secDashboard"))}</summary>'
                 '<table class="sec-dash"><thead><tr>'
                 f'<th>{_e(T("os.dashCategory"))}</th><th>{_e(T("os.dashAttacks"))}</th>'
                 f'<th>{_e(T("os.dashDetection"))}</th><th>{_e(T("os.dashSeverity"))}</th>'
                 f'<th>{_e(T("os.secRecommend"))}</th></tr></thead><tbody>')
        for c in sec["categories"]:
            det = _pct(c.get("detection_rate"))
            extra = ((f' · {c["evasions"]} {_e(T("os.evaded"))}' if c.get("evasions") else "")
                     + (f' · {c["breaches"]} {_e(T("os.statBreaches"))}' if c.get("breaches") else ""))
            h.append('<tr>'
                     f'<td><span class="owasp">{_e(c.get("owasp_id") or "—")}</span> {_e(c.get("owasp_name") or "")}</td>'
                     f'<td class="mono">{_e(c.get("attacks"))}</td>'
                     f'<td class="mono">{_e(det)}{extra}</td>'
                     f'<td><span class="sev-chip sv-{_e(c.get("severity"))}">{_e(_sevlbl(T, c.get("severity")))}</span></td>'
                     f'<td class="rem">{"—" if c.get("severity") == "secure" else _e(c.get("remediation"))}</td></tr>')
        h.append('</tbody></table></details>')
    h.append('</div>')
    return "".join(h)


def _checkpoint_legend(T) -> str:
    items = "".join(f'<div class="os-legend-item"><b>{_e(T(f"os.cp{i}Title"))}</b>'
                    f'<span>{_e(T(f"os.cp{i}Desc"))}</span></div>' for i in (1, 2, 3))
    keys = [("s-passed", "check", "badge.passed"), ("s-blocked", "x", "badge.blocked"),
            ("s-redacted", "scissors", "badge.redacted"), ("s-skipped", "minus", "badge.skipped")]
    key_html = "".join(f'<span class="k"><i class="os-cp-mini-key {c}">{_ic(ic)}</i>{_e(T(kk))}</span>'
                       for c, ic, kk in keys)
    return (f'<div class="os-legend"><div class="os-legend-title">{_e(T("os.cpLegendTitle"))}</div>'
            f'<div class="os-legend-grid">{items}</div>'
            f'<div class="os-legend-status"><span>{_e(T("os.cpLegendStatus"))}</span>{key_html}</div></div>')


def _cp_latency(T, r) -> str:
    tr = r.get("trace") or {}
    def part(cp):
        c = tr.get(cp) or {}
        if c.get("latency_ms") is None:
            return f'{cp.upper()} {"off" if c.get("status") == "off" else "—"}'
        return f'{cp.upper()} {c["latency_ms"]} ms'
    total = "—" if r.get("total_latency_ms") is None else f'{r["total_latency_ms"]} ms'
    line = f'{part("cp1")} · {part("cp2")} · {part("cp3")} = {total}'
    if r.get("judge_latency_ms"):
        line += f' · judge {r["judge_latency_ms"]} ms'
    return f'<div><h4>{_e(T("os.latCheckpoints"))}</h4><div class="os-detail-none mono">{_e(line)}</div></div>'


def _lakera_cp_detail(r) -> str:
    tr = r.get("trace") or {}
    out = []
    for cp in ("cp1", "cp2", "cp3"):
        c = tr.get(cp) or {}
        if (c.get("status") in ("disabled", "off", "skipped", "pending")):
            b = f'<span class="os-detail-none">{_e(c.get("status") or "—")}</span>'
        else:
            b = _lk_detectors(c.get("detectors"))
        out.append(f'<div class="lk-cp"><span class="lk-cp-tag">{cp.upper()}</span>{b}</div>')
    return "".join(out)


def _os_detail(T, r) -> str:
    h = ['<div class="os-detail">']
    if r.get("error"):
        att = f' — {r.get("attempts")} attempts' if (r.get("attempts") or 0) > 1 else ""
        h.append(f'<div><h4>{_e(T("os.detailError"))}{_e(att)}</h4><pre>{_e(r["error"])}</pre></div>')
    h.append(_cp_latency(T, r))
    h.append(_os_acc(T("os.lakeraDetectors"), _lakera_cp_detail(r)))
    if not r.get("turns") and not r.get("dynamic"):
        h.append(f'<div><h4>{_e(T("os.detailPrompt"))}</h4><pre>{_e(r.get("prompt") or "")}</pre></div>')
    if r.get("simulate_output"):
        h.append(f'<div><h4>{_e(T("os.detailSimOutput"))}</h4><pre>{_e(r["simulate_output"])}</pre></div>')
    if r.get("model_response") and not r.get("turns") and not r.get("dynamic"):
        h.append(_os_acc(T("os.detailModelResponse"), f'<pre>{_e(r["model_response"])}</pre>'))
    if r.get("judge") and (r["judge"].get("reason") or r["judge"].get("error")):
        reason = (f'{T("os.judgeError")} {r["judge"]["error"]}' if r["judge"].get("error")
                  else r["judge"].get("reason"))
        h.append(_os_acc(T("os.detailJudge"), f'<pre>{_e(reason)}</pre>'))
    if r.get("alone_outcome"):
        v = f'Model alone: {r.get("alone_outcome")}' + (f' — {r["alone_reason"]}' if r.get("alone_reason") else "")
        h.append(_os_acc(T("os.detailAlone"),
                         f'<pre>{_e(r.get("alone_response") or "")}</pre><div class="os-detail-none">{_e(v)}</div>'))
    rag = r.get("rag") or []
    if not rag:
        rag_body = f'<span class="os-detail-none">{_e(T("os.detailNoRag"))}</span>'
    else:
        parts = []
        for doc in rag:
            sk = {"passed": "os.ragPassed", "redacted": "os.ragRedacted",
                  "not_reached": "os.ragNotReached"}.get(doc.get("status"), "os.ragPassed")
            parts.append(f'<div class="os-rag-doc"><div class="os-rag-head">'
                         f'<span class="os-rag-name">{_e(doc.get("filename"))}</span>'
                         f'<span class="os-rag-status rs-{_e(doc.get("status"))}">{_e(T(sk))}</span></div>'
                         f'<pre>{_e(doc.get("content") or "")}</pre></div>')
        rag_body = "".join(parts)
    h.append(_os_acc(T("os.detailRag", n=len(rag), mode=r.get("doc_mode")), rag_body))
    h.append('</div>')
    return "".join(h)


def _results_table(T, s, results, judged, strat, i18n, fam_class, sev_label) -> str:
    cols = 6 + (1 if judged else 0) + (1 if strat else 0)
    head = ('<table class="os-table"><thead><tr>'
            f'<th>{_e(T("os.colScenario"))}</th><th>{_e(T("os.colOwasp"))}</th>'
            + (f'<th>{_e(T("os.colVariant"))}</th>' if strat else "")
            + f'<th>{_e(T("os.colExpected"))}</th><th>{_e(T("os.colCheckpoints"))}</th>'
            + f'<th>{_e(T("os.colGuard"))}</th>'
            + (f'<th>{_e(T("os.colModel"))}</th>' if judged else "")
            + f'<th>{_e(T("os.colLatency"))}</th></tr></thead><tbody>')
    rows = []
    for i, r in enumerate(results):
        m_cls, m_ic, m_key = _OUTCOME_META.get(r.get("outcome"), _OUTCOME_META["error"])
        exp = T("os.expectBlock") if r.get("expected") == "block" else T("os.expectAllow")
        lat = "—" if r.get("total_latency_ms") is None else f'{r["total_latency_ms"]} ms'
        if r.get("owasp_id"):
            owasp = f'<span class="os-owasp">{_e(r["owasp_id"])}</span>'
        elif (r.get("owasp_class") or {}).get("code") not in (None, "UNMAPPED"):
            oc = r["owasp_class"]
            owasp = (f'<span class="os-owasp cls-{fam_class(oc.get("family"))} cls-inferred">'
                     f'{_e(oc.get("code"))}</span>')
        else:
            owasp = "—"
        variant = (f'<span class="os-variant">{_e(r.get("strategy_label"))}</span>' if r.get("strategy")
                   else f'<span class="os-variant base">{_e(T("os.variantBase"))}</span>')
        row_cls = "os-row" + (" variant" if r.get("strategy") else "") + (" evaded" if r.get("evaded") else "")
        model_cell = _model_chip(T, r) if judged else ""
        rows.append(
            f'<tr class="{row_cls}" id="osr-{i}" tabindex="0" role="button" aria-expanded="false" '
            f'aria-controls="osd-{i}" onclick="toggleOsDetail({i})" onkeydown="osRowKey(event, {i})">'
            f'<td><span class="os-caret">▸</span> {_e(r.get("label"))}<br><span class="mono">{_e(r.get("id"))}</span></td>'
            f'<td>{owasp}</td>'
            + (f'<td>{variant}</td>' if strat else "")
            + f'<td class="mono">{_e(exp)}</td>'
            + f'<td>{_cp_mini(T, r.get("trace"))}</td>'
            + f'<td><span class="os-outcome {m_cls}">{_ic(m_ic)}<span>{_e(T(m_key))}</span></span></td>'
            + (f'<td>{model_cell}</td>' if judged else "")
            + f'<td class="mono">{_e(lat)}</td></tr>'
            + f'<tr class="os-detail-row" id="osd-{i}" style="display:none"><td colspan="{cols}">{_os_detail(T, r)}</td></tr>')
    return head + "".join(rows) + '</tbody></table>'


_MODEL_META = {
    "resisted": ("mo-resisted", "check", "os.moResisted"),
    "prevented": ("mo-prevented", "shield-check", "os.moPrevented"),
    "unknown": ("mo-unknown", "minus", "os.moUnknown"),
    "not_judged": ("mo-not_judged", "minus", "os.moNotJudged"),
}


def _model_chip(T, r) -> str:
    outcome = r.get("model_outcome")
    if outcome == "compromised":
        meta = ("mo-breach", "alert-triangle", "os.moBreach")
    else:
        meta = _MODEL_META.get(outcome)
    if meta:
        main = f'<span class="os-model {meta[0]}">{_ic(meta[1])}<span>{_e(T(meta[2]))}</span></span>'
    else:
        main = '<span class="mono" style="color:var(--muted)">—</span>'
    if r.get("alone_outcome"):
        a = {"compromised": ("al-compromised", "os.aloneCompromised"),
             "resisted": ("al-resisted", "os.aloneResisted"),
             "unknown": ("al-unknown", "os.aloneUnknown")}.get(r["alone_outcome"], ("al-unknown", "os.aloneUnknown"))
        main += f'<span class="os-model os-alone {a[0]}">{_e(T("os.aloneLabel"))}: {_e(T(a[1]))}</span>'
    return main


def _document(styles: str, sprite: str, head: str, inner: str) -> str:
    script = (
        "<" "script>"
        "var STAT_INFO=" + json.dumps(_STAT_INFO) + ";"
        "function toggleOsDetail(i){var r=document.getElementById('osr-'+i),q=document.getElementById('osd-'+i);"
        "if(!r||!q)return;var o=q.style.display==='none';q.style.display=o?'':'none';r.classList.toggle('open',o);}"
        "function osRowKey(e,i){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleOsDetail(i);}}"
        "function showStatInfo(k,ev){if(ev)ev.stopPropagation();var x=STAT_INFO[k];if(!x)return;"
        "var p=document.getElementById('os-popover');if(!p){p=document.createElement('div');p.id='os-popover';"
        "p.className='os-popover';document.body.appendChild(p);}var l=ev&&ev.currentTarget&&"
        "ev.currentTarget.querySelector('.lbl,.os-hero-lbl,.cap');"
        "p.innerHTML='<div class=\\'os-popover-title\\'>'+(l?l.textContent:k)+"
        "'</div><div class=\\'os-popover-body\\'>'+x+'</div>';p.classList.add('show');"
        "var t=ev&&ev.currentTarget;if(t){var c=t.getBoundingClientRect();p.style.top=(c.bottom+window.scrollY+8)+'px';"
        "p.style.left=Math.min(c.left+window.scrollX,window.scrollX+document.documentElement.clientWidth-p.offsetWidth-12)+'px';}}"
        "document.addEventListener('click',function(e){var p=document.getElementById('os-popover');"
        "if(p&&p.classList.contains('show')&&!p.contains(e.target)&&!(e.target.closest&&e.target.closest('[data-info]')))"
        "p.classList.remove('show');});"
        "<" "/script>")
    extra_css = ("\nbody{display:block;height:auto;min-height:100dvh;overflow-x:hidden;overflow-y:auto;"
                 "padding:20px 22px;max-width:1080px;margin:0 auto;background:var(--bg);color:var(--text);}"
                 ".os-report-head{margin-bottom:16px;}.os-report-head h1{font-family:'Lexend',sans-serif;"
                 "font-size:1.3rem;font-weight:700;color:var(--heading);}"
                 ".os-report-meta{color:var(--muted);font-size:0.8rem;margin-top:3px;font-family:'JetBrains Mono',monospace;}")
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Lakera Guard — One-Shot Report</title>'
            f'<style>{styles}{extra_css}</style></head><body>{sprite}{head}'
            f'<div id="os-body">{inner}</div>{script}</body></html>')
