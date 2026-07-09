"""
Standalone HTML report for a one-shot run (server/CLI side).

`render(payload)` turns the run payload (`{summary, results, llm, generated_at}`)
into a single self-contained, dark-themed HTML document — no external assets, no
JavaScript — suitable for archiving or emailing alongside the JSON. Pure function
over the already-computed summary/results, so it mirrors the web report's data
without depending on the browser.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

_SEV_COLORS = {
    "critical": "#F87171", "high": "#F87171", "medium": "#FBBF24",
    "low": "#818CF8", "info": "#818CF8", "good": "#34D399", "secure": "#34D399",
}
_OUTCOME = {
    "blocked": ("#34D399", "BLOCKED"), "passed": ("#34D399", "PASSED"),
    "not_blocked": ("#F87171", "NOT BLOCKED"), "false_positive": ("#FBBF24", "FALSE POSITIVE"),
    "error": ("#94A3B8", "ERROR"),
}
_CP_GLYPH = {"passed": "✓", "blocked": "✗", "redacted": "✂", "skipped": "–",
             "disabled": "⊘", "off": "–", "pending": "–"}
_CP_COLOR = {"passed": "#34D399", "blocked": "#F87171", "redacted": "#FBBF24",
             "skipped": "#94A3B8", "disabled": "#94A3B8", "off": "#94A3B8", "pending": "#94A3B8"}


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _card(num, label, color=None) -> str:
    style = f'style="color:{color}"' if color else ""
    return (f'<div class="card"><div class="n" {style}>{_e(num)}</div>'
            f'<div class="l">{_e(label)}</div></div>')


def _chip(text, color) -> str:
    return (f'<span class="chip" style="color:{color};border-color:{color}">{_e(text)}</span>')


def render(payload: dict) -> str:
    s = payload.get("summary", {}) or {}
    results = payload.get("results", []) or []
    llm = payload.get("llm", {}) or {}
    sec = s.get("security", {}) or {}
    rc = s.get("run_config", {}) or {}
    judged = bool(s.get("judged"))
    when = payload.get("generated_at") or datetime.now(timezone.utc).isoformat()
    try:
        when = datetime.fromisoformat(when.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        pass

    det = "—" if s.get("detection_rate") is None else f'{s["detection_rate"]}%'

    # ── summary cards ──────────────────────────────────────────────────────────
    cards = [
        _card(s.get("total", 0), "Total"),
        _card(s.get("blocked", 0), "Blocked", "#34D399"),
        _card(s.get("not_blocked", 0), "Not blocked", "#F87171"),
        _card(s.get("passed", 0), "Passed", "#34D399"),
        _card(s.get("false_positive", 0), "False positive", "#FBBF24"),
    ]
    if s.get("errors"):
        cards.append(_card(s["errors"], "Errors", "#F87171"))
    cards.append(_card(det, "Detection"))
    if judged:
        cards += [_card(s.get("breaches", 0), "Breaches", "#F87171"),
                  _card(s.get("resisted", 0), "Resisted", "#34D399"),
                  _card(s.get("prevented", 0), "Prevented", "#34D399")]
    cards_html = f'<div class="cards">{"".join(cards)}</div>'

    # ── posture + findings ─────────────────────────────────────────────────────
    posture_html = ""
    posture = sec.get("posture") or {}
    if posture:
        col = _SEV_COLORS.get(posture.get("level"), "#818CF8")
        findings = "".join(
            f'<div class="finding" style="border-left-color:{_SEV_COLORS.get(f.get("severity"), "#818CF8")}">'
            f'{_chip((f.get("severity") or "").upper(), _SEV_COLORS.get(f.get("severity"), "#818CF8"))}'
            f'<div><div class="ft">{_e(f.get("title"))}</div>'
            + (f'<div class="fd">{_e(f.get("detail"))}</div>' if f.get("detail") else "")
            + (f'<div class="fr"><b>Recommendation:</b> {_e(f.get("recommendation"))}</div>'
               if f.get("recommendation") else "")
            + "</div></div>"
            for f in sec.get("findings", [])
        )
        posture_html = (
            f'<div class="sec"><div class="posture" style="border-color:{col}">'
            f'{_chip((posture.get("level") or "").upper(), col)} '
            f'<span class="hl">{_e(posture.get("headline"))}</span></div>'
            f'<h2>Findings &amp; recommendations</h2>{findings}</div>'
        )

    # ── per-OWASP dashboard ────────────────────────────────────────────────────
    dash_html = ""
    cats = sec.get("categories") or []
    if cats:
        rows = "".join(
            f"<tr><td><code>{_e(c.get('owasp_id') or '—')}</code> {_e(c.get('owasp_name'))}</td>"
            f"<td>{_e(c.get('attacks'))}</td>"
            f"<td>{'—' if c.get('detection_rate') is None else str(c['detection_rate']) + '%'}</td>"
            f"<td>{_chip((c.get('severity') or '').upper(), _SEV_COLORS.get(c.get('severity'), '#818CF8'))}</td>"
            f"<td class=\"rem\">{'—' if c.get('severity') == 'secure' else _e(c.get('remediation'))}</td></tr>"
            for c in cats
        )
        dash_html = (
            '<div class="sec"><h2>Vulnerability dashboard (by OWASP category)</h2>'
            '<table class="dash"><thead><tr><th>Category</th><th>Attacks</th>'
            '<th>Detection</th><th>Severity</th><th>Remediation</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )

    # ── OWASP tactic classification (imported datasets) ────────────────────────
    cls_html = ""
    cls = sec.get("classification")
    if cls and cls.get("tactics"):
        fam = cls.get("families", {})
        maxc = max((t.get("count", 0) for t in cls["tactics"]), default=1) or 1
        bars = ""
        for t in cls["tactics"]:
            fcol = {"agentic": "#FBBF24", "unmapped": "#94A3B8"}.get(t.get("family"), "#818CF8")
            width = round(t.get("count", 0) / maxc * 100, 1)
            det_t = "—" if t.get("detection_rate") is None else f'{t["detection_rate"]}%'
            bars += (
                f'<div class="clsrow"><div class="clsname"><code style="color:{fcol}">{_e(t.get("code"))}</code> '
                f'{_e(t.get("name"))}</div>'
                f'<div class="clsbar"><span style="width:{width}%;background:{fcol}"></span></div>'
                f'<div class="clsstat">{_e(t.get("count"))} · {_e(t.get("share"))}% · det {det_t}</div></div>'
            )
        cls_html = (
            f'<div class="sec"><h2>OWASP tactic classification '
            f'<span class="sub">{_e(cls.get("total"))} imported prompts</span></h2>'
            f'<div class="clsfam">LLM Top 10: {_e(fam.get("llm", 0))} · '
            f'Agentic: {_e(fam.get("agentic", 0))} · Unmapped: {_e(fam.get("unmapped", 0))}</div>'
            f"{bars}</div>"
        )

    # ── run configuration (checkpoints + project ids) ──────────────────────────
    cfg_html = ""
    if rc:
        parts = []
        cps = rc.get("checkpoints")
        if cps:
            parts.append("Checkpoints: " + " · ".join(
                f"{cp.upper()} {'on' if cps.get(cp, True) else 'off'}" for cp in ("cp1", "cp2", "cp3")))
        if "lakera_project_id" in rc:
            parts.append("Lakera Project ID: " + (_e(rc["lakera_project_id"]) or "None (key default policy)"))
        cpp = rc.get("checkpoint_projects")
        if cpp and any(cpp.get(cp) != rc.get("lakera_project_id") for cp in ("cp1", "cp2", "cp3")):
            parts.append("Per-checkpoint: " + " · ".join(
                f"{cp.upper()} {_e(cpp.get(cp)) or 'default'}" for cp in ("cp1", "cp2", "cp3")))
        if parts:
            cfg_html = ('<div class="sec"><h2>Run configuration</h2>'
                        + "".join(f'<div class="cfg">{p}</div>' for p in parts) + "</div>")

    # ── results table ──────────────────────────────────────────────────────────
    def cp_cell(trace) -> str:
        out = ""
        for i, cp in enumerate(("cp1", "cp2", "cp3"), 1):
            st_ = (trace.get(cp, {}) or {}).get("status", "skipped") if trace else "skipped"
            out += (f'<span class="cpb" style="color:{_CP_COLOR.get(st_, "#94A3B8")};'
                    f'border-color:{_CP_COLOR.get(st_, "#94A3B8")}">{i} {_CP_GLYPH.get(st_, "–")}</span>')
        return out

    res_rows = ""
    for r in results:
        col, lbl = _OUTCOME.get(r.get("outcome"), _OUTCOME["error"])
        owasp = r.get("owasp_id") or ((r.get("owasp_class") or {}).get("code")
                                      if (r.get("owasp_class") or {}).get("code") not in (None, "UNMAPPED") else "—")
        lat = "—" if r.get("total_latency_ms") is None else f'{r["total_latency_ms"]} ms'
        res_rows += (
            f'<tr><td>{_e(r.get("label"))}<br><code class="id">{_e(r.get("id"))}</code></td>'
            f'<td><code>{_e(owasp)}</code></td>'
            f'<td>{_e("block" if r.get("expected") == "block" else "allow")}</td>'
            f'<td class="mono">{cp_cell(r.get("trace"))}</td>'
            f'<td><b style="color:{col}">{_e(lbl)}</b></td>'
            f'<td class="mono">{_e(lat)}</td></tr>'
        )
    results_html = (
        '<div class="sec"><h2>Per-scenario results</h2><table class="res"><thead><tr>'
        '<th>Scenario</th><th>OWASP</th><th>Expected</th><th>Checkpoints (CP1·CP2·CP3)</th>'
        '<th>Guard verdict</th><th>Latency</th></tr></thead>'
        f"<tbody>{res_rows}</tbody></table></div>"
    )

    scope = s.get("scope") or {}
    scope_note = ""
    if scope.get("sampled"):
        scope_note = (f'<div class="meta">Sampled {_e(scope.get("base_executed"))} of '
                      f'{_e(scope.get("available"))} scenarios (seed '
                      f'{_e(scope.get("seed") if scope.get("seed") is not None else "—")}).</div>')

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lakera Guard — One-Shot Report</title>
<style>
  :root{{--bg:#0B1120;--panel:#131C2E;--border:#243049;--text:#E6EDF7;--muted:#93A1B8;--brand:#818CF8;}}
  *{{box-sizing:border-box;}} body{{margin:0;padding:32px;background:var(--bg);color:var(--text);
    font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.55;}}
  h1{{font-size:1.35rem;margin:0 0 4px;}} h2{{font-size:0.72rem;text-transform:uppercase;
    letter-spacing:0.06em;color:var(--muted);margin:18px 0 10px;}}
  .meta{{color:var(--muted);font-size:0.82rem;margin-bottom:16px;}} .meta code{{color:var(--brand);}}
  code{{font-family:ui-monospace,Menlo,monospace;}} .id{{color:var(--muted);font-size:0.72rem;}}
  .sub{{font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted);font-size:0.72rem;}}
  .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;}}
  .card{{flex:1;min-width:120px;border:1px solid var(--border);border-radius:10px;background:var(--panel);padding:14px 16px;}}
  .card .n{{font-size:1.7rem;font-weight:700;}} .card .l{{color:var(--muted);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.05em;}}
  .sec{{margin-bottom:22px;}} .chip{{font-size:0.6rem;font-weight:700;letter-spacing:0.04em;padding:2px 8px;border:1px solid;border-radius:999px;}}
  .posture{{display:flex;align-items:center;gap:12px;padding:13px 16px;border:1px solid;border-radius:10px;font-weight:600;}}
  .posture .hl{{font-size:0.95rem;}}
  .finding{{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--border);border-left:3px solid var(--border);border-radius:8px;background:var(--panel);padding:11px 13px;margin-bottom:8px;}}
  .finding .ft{{font-weight:600;}} .finding .fd{{color:var(--muted);font-size:0.85rem;margin-top:2px;}}
  .finding .fr{{font-size:0.85rem;margin-top:5px;}} .finding .fr b{{color:var(--brand);}}
  table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:0.82rem;}}
  th,td{{text-align:left;padding:8px 11px;border-bottom:1px solid #1B2740;vertical-align:top;}}
  th{{font-size:0.64rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--muted);}}
  td code{{color:var(--brand);}} .rem{{color:var(--muted);font-size:0.78rem;}} .mono{{font-family:ui-monospace,Menlo,monospace;}}
  .cpb{{display:inline-block;padding:1px 5px;margin-right:3px;border:1px solid;border-radius:4px;font-size:0.64rem;font-family:ui-monospace,Menlo,monospace;}}
  .clsfam{{color:var(--muted);font-size:0.8rem;margin-bottom:10px;}}
  .clsrow{{display:grid;grid-template-columns:1.6fr 3fr auto;gap:12px;align-items:center;margin-bottom:6px;}}
  .clsname{{font-size:0.82rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
  .clsbar{{height:13px;border-radius:7px;overflow:hidden;background:#1B2740;}} .clsbar span{{display:block;height:100%;}}
  .clsstat{{font-size:0.76rem;color:var(--muted);white-space:nowrap;font-family:ui-monospace,Menlo,monospace;}}
  .cfg{{font-family:ui-monospace,Menlo,monospace;font-size:0.8rem;color:var(--muted);margin-bottom:4px;}}
  footer{{margin-top:22px;color:var(--muted);font-size:0.74rem;}}
</style></head><body>
<h1>Lakera Guard — One-Shot Security Report</h1>
<div class="meta">Generated {_e(when)} · Provider <code>{_e(llm.get('provider') or '—')}</code>
  · Model <code>{_e(llm.get('model') or '—')}</code></div>
{scope_note}
{cards_html}
{posture_html}
{dash_html}
{cls_html}
{cfg_html}
{results_html}
<footer>Lakera Guard AI Assistant Security Demo — checkpoint trace (CP1 user input · CP2 RAG docs · CP3 LLM output).
"Not blocked" attack rows are expected for categories that rely on defence-in-depth beyond prompt scanning.</footer>
</body></html>"""
