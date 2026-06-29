"""
Headless one-shot runner — config-as-code + CI gate for the Lakera Guard demo.

    python -m backend.oneshot --suite suite.yaml --min-detection 0.9
    python -m backend.oneshot --all-categories --strategies base64,homoglyph
    python -m backend.oneshot --suite suite.yaml --dry-run    # validate, no API calls

Reuses the same prepare → run → summarize pipeline as the web UI (backend.main.
run_oneshot). Secrets come from the environment only (LAKERA_GUARD_API_KEY,
LLM_API_KEY / OPENROUTER_API_KEY); the suite file never holds keys.

Exit codes (for CI):
    0  run completed and every gate threshold passed
    1  a gate threshold was violated  (the "fail the build" signal)
    2  configuration / usage error    (bad suite, missing key, bad provider)
    3  execution error                (LLM/Lakera unreachable; nothing evaluated)
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import pathlib
import sys

from fastapi import HTTPException
from pydantic import ValidationError

from backend import datasets, history, llm
from backend import main as core
from backend.main import OneShotRequest

EXIT_OK, EXIT_GATE, EXIT_CONFIG, EXIT_RUN = 0, 1, 2, 3


class ConfigError(Exception):
    """A user-facing configuration problem → exit code 2."""


# ── Effective configuration (defaults ← suite ← CLI flags) ────────────────────

DEFAULTS: dict = {
    "scope": {"category": None, "include_safe": True, "dataset": None,
              "max_scenarios": 100, "seed": None},
    "options": {"judge": True, "compare": False, "strategies": [], "doc_mode": None,
                "system_prompt": None, "no_system_prompt": False, "concurrency": None},
    "llm": {"provider": "openrouter", "base_url": None, "model": None},
    # Optional independent judge model. All-null → judge with the target model.
    "judge_llm": {"provider": None, "base_url": None, "model": None},
    "gate": {"min_detection": None, "max_breaches": None, "max_evasions": None,
             "max_effective_evasions": None, "max_false_positives": None},
}


def load_suite(path: str) -> dict:
    """Load a .yaml/.yml/.json suite file into a dict."""
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(f"suite file not found: {path}")
    text = p.read_text(encoding="utf-8")
    ext = p.suffix.lower()
    try:
        if ext in (".yaml", ".yml"):
            import yaml  # lazy: only needed for YAML suites
            data = yaml.safe_load(text)
        elif ext == ".json":
            data = json.loads(text)
        else:
            raise ConfigError(f"unsupported suite format '{ext}' (use .yaml or .json)")
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 — surface parse errors as config errors
        raise ConfigError(f"could not parse suite {path}: {exc}")
    if not isinstance(data, dict):
        raise ConfigError("suite must be a mapping at the top level")
    return data


def _deep_merge(base: dict, override: dict | None) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def build_effective_config(args: argparse.Namespace) -> dict:
    """Merge DEFAULTS ← suite ← explicitly-provided CLI flags."""
    cfg = _deep_merge(DEFAULTS, load_suite(args.suite) if args.suite else {})

    # Only flags the user actually set (argparse default None) override the suite.
    s, o, g, m = cfg["scope"], cfg["options"], cfg["gate"], cfg["llm"]
    if args.all_categories:
        s["category"] = None
    elif args.category is not None:
        s["category"] = args.category
    for key, val in (("dataset", args.dataset), ("max_scenarios", args.max_scenarios),
                     ("seed", args.seed)):
        if val is not None:
            s[key] = val
    if args.judge is not None:
        o["judge"] = args.judge
    if args.compare:
        o["compare"] = True
    if args.strategies is not None:
        o["strategies"] = [x.strip() for x in args.strategies.split(",") if x.strip()]
    if args.doc_mode is not None:
        o["doc_mode"] = args.doc_mode
    if args.concurrency is not None:
        o["concurrency"] = args.concurrency
    for key, val in (("provider", args.provider), ("base_url", args.base_url),
                     ("model", args.model)):
        if val is not None:
            m[key] = val
    jl = cfg["judge_llm"]
    for key, val in (("provider", args.judge_provider), ("base_url", args.judge_base_url),
                     ("model", args.judge_model)):
        if val is not None:
            jl[key] = val
    for key, val in (("min_detection", args.min_detection), ("max_breaches", args.max_breaches),
                     ("max_evasions", args.max_evasions),
                     ("max_effective_evasions", args.max_effective_evasions),
                     ("max_false_positives", args.max_false_positives)):
        if val is not None:
            g[key] = val
    cfg["_dataset_file"] = args.dataset_file
    return cfg


# ── Resolution → provider config, key, request ────────────────────────────────

def resolve_llm_config(llm_cfg: dict, *, dry_run: bool = False) -> dict:
    provider = llm_cfg.get("provider") or llm.DEFAULT_PROVIDER
    if provider not in llm.PROVIDER_PRESETS:
        raise ConfigError(f"unknown provider '{provider}'")
    p = llm.preset(provider)
    base_url = llm_cfg.get("base_url") or p["base_url"]
    model = llm_cfg.get("model") or p["default_model"]
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENROUTER_API_KEY") or ""
    # A dry-run validates the suite/scope without calling APIs, so don't require secrets.
    if not dry_run:
        if p["requires_key"] and not api_key:
            raise ConfigError(f"{p['label']} requires an API key — set LLM_API_KEY or OPENROUTER_API_KEY.")
        if not model:
            raise ConfigError(f"a model id is required for {p['label']} — set llm.model or --model.")
    return {"provider": provider, "base_url": base_url, "api_key": api_key,
            "model": model or "(unset)"}


def resolve_judge_config(judge_cfg: dict, *, dry_run: bool = False) -> dict | None:
    """
    Build the dedicated judge config, or None when nothing is configured (the
    judge then falls back to the target model). Key comes from JUDGE_API_KEY.
    """
    provider = judge_cfg.get("provider")
    base_url = judge_cfg.get("base_url")
    model = judge_cfg.get("model")
    api_key = os.environ.get("JUDGE_API_KEY", "")
    if not (provider or base_url or model or api_key):
        return None
    provider = provider or llm.DEFAULT_PROVIDER
    if provider not in llm.PROVIDER_PRESETS:
        raise ConfigError(f"unknown judge provider '{provider}'")
    p = llm.preset(provider)
    base_url = base_url or p["base_url"]
    model = model or p["default_model"]
    if not dry_run:
        if p["requires_key"] and not api_key:
            raise ConfigError(f"judge provider {p['label']} requires an API key — set JUDGE_API_KEY.")
        if not model:
            raise ConfigError(f"a judge model id is required for {p['label']} — set judge_llm.model or --judge-model.")
    return {"provider": provider, "base_url": base_url, "api_key": api_key,
            "model": model or "(unset)"}


def resolve_lakera_key(*, dry_run: bool) -> str:
    key = os.environ.get("LAKERA_GUARD_API_KEY", "").strip()
    if not key and not dry_run:
        raise ConfigError("LAKERA_GUARD_API_KEY is not set.")
    return key or "(dry-run-placeholder)"


def build_request(cfg: dict) -> OneShotRequest:
    s, o = cfg["scope"], cfg["options"]
    try:
        return OneShotRequest(
            category_id=s["category"], include_safe=s["include_safe"], dataset=s["dataset"],
            max_scenarios=s["max_scenarios"], seed=s["seed"],
            judge=o["judge"], compare=o["compare"], strategies=o["strategies"] or [],
            doc_mode=o["doc_mode"], system_prompt=o["system_prompt"],
            no_system_prompt=o["no_system_prompt"], concurrency=o["concurrency"],
        )
    except ValidationError as exc:
        raise ConfigError(f"invalid run configuration: {exc.errors()[0].get('msg', exc)}")


def load_dataset_file(path: str) -> str:
    """Parse a local CSV/JSON/JSONL/TXT into an in-memory dataset; return its slug."""
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(f"dataset file not found: {path}")
    try:
        parsed = datasets.parse_upload(p.name, p.read_bytes())
    except datasets.DatasetError as exc:
        raise ConfigError(f"dataset file: {exc}")
    slug = core._slugify(p.stem)
    core._datasets[slug] = {"slug": slug, "name": p.name, "source": "cli-file",
                            "count": len(parsed["rows"]), "column": parsed["column"],
                            "rows": parsed["rows"]}
    return slug


# ── Gate evaluation (pure) ────────────────────────────────────────────────────

def evaluate_gate(summary: dict, gate: dict) -> tuple[bool, list[str]]:
    """Return (passed, [failure messages]). Thresholds left as None aren't enforced."""
    fails: list[str] = []
    md = gate.get("min_detection")
    if md is not None:
        base = summary.get("base_detection_rate")
        if base is None:
            fails.append(f"min detection {md:.0%}: no attack scenarios were evaluated")
        elif base / 100.0 < md - 1e-9:
            fails.append(f"base detection {base:.1f}% < required {md:.0%}")
    for key, label, skey in (
        ("max_breaches", "real breaches", "breaches"),
        ("max_evasions", "guard evasions", "evasions"),
        ("max_effective_evasions", "landed evasions", "effective_evasions"),
        ("max_false_positives", "false positives", "false_positive"),
    ):
        lim = gate.get(key)
        if lim is not None:
            val = summary.get(skey, 0) or 0
            if val > lim:
                fails.append(f"{label} {val} > allowed {lim}")
    return (not fails, fails)


# ── Rendering ─────────────────────────────────────────────────────────────────

def _fmt_rate(v) -> str:
    return "—" if v is None else f"{v:.1f}%"


def render_plan(scope: dict, req: OneShotRequest, llm_config: dict,
                judge_config: dict | None = None) -> str:
    judge = (f"{judge_config['provider']} · {judge_config['model']}"
             if judge_config else "same as target")
    return "\n".join([
        "Run plan (dry-run — no API calls):",
        f"  provider     : {llm_config['provider']} · {llm_config['model']}",
        f"  judge model  : {judge}",
        f"  scope        : {'dataset ' + req.dataset if req.dataset else (req.category_id or 'all categories')}",
        f"  scenarios    : {scope['base_executed']} of {scope['available']}"
        + (" (sampled)" if scope['sampled'] else ""),
        f"  strategies   : {', '.join(req.strategies) or 'none'}",
        f"  total rows   : {scope['total_rows']} (incl. variants)",
        f"  judge/compare: {req.judge} / {req.compare}",
    ])


def render_text(out: dict) -> str:
    s = out["summary"]
    sec = s.get("security", {})
    lines = [
        f"Posture: {sec.get('posture', {}).get('level', '?').upper()} — "
        f"{sec.get('posture', {}).get('headline', '')}",
        f"  scenarios    : {s['total']}  (blocked {s['blocked']} · not-blocked {s['not_blocked']} "
        f"· passed {s['passed']} · false-pos {s['false_positive']} · errors {s['errors']})",
        f"  detection    : base {_fmt_rate(s.get('base_detection_rate'))} · "
        f"all {_fmt_rate(s.get('detection_rate'))}",
    ]
    if s.get("judged"):
        lines.append(f"  judged       : breaches {s.get('breaches', 0)} · "
                     f"resisted {s.get('resisted', 0)} · prevented {s.get('prevented', 0)}")
    if s.get("strategies_used"):
        lines.append(f"  obfuscation  : variants {s.get('variants', 0)} · "
                     f"evasions {s.get('evasions', 0)} · landed {s.get('effective_evasions', 0)}")
    for c in sec.get("categories", []):
        lines.append(f"    {c['owasp_id'] or c['id']:<12} {c['severity']:<9} "
                     f"det {_fmt_rate(c.get('detection_rate'))}")
    return "\n".join(lines)


def load_baseline(path: str) -> dict:
    """Load a saved run JSON and return its summary (for diffing)."""
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(f"baseline not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"could not parse baseline {path}: {exc}")
    summary = data.get("summary", data)   # accept a full run record or a bare summary
    if not isinstance(summary, dict):
        raise ConfigError("baseline has no summary")
    return summary


def render_diff(diff: dict) -> str:
    lines = ["Regression diff vs baseline:"]
    for r in diff["metrics"]:
        if r["delta"] in (None, 0):
            continue
        flag = "  ⚠ regressed" if r["regressed"] else ""
        lines.append(f"  {r['metric']:<20} {r['base']} → {r['head']} ({r['delta']:+}){flag}")
    if len(lines) == 1:
        lines.append("  (no metric changes)")
    lines.append("  → REGRESSION" if diff["regressed"] else "  → no regression")
    return "\n".join(lines)


def render_md(out: dict) -> str:
    s = out["summary"]
    sec = s.get("security", {})
    p = sec.get("posture", {})
    md = [f"### Red-team gate — {p.get('level', '?').upper()}", "", p.get("headline", ""), "",
          "| Metric | Value |", "|---|---|",
          f"| Scenarios | {s['total']} |",
          f"| Base detection | {_fmt_rate(s.get('base_detection_rate'))} |",
          f"| Real breaches | {s.get('breaches', 0)} |"]
    if s.get("strategies_used"):
        md.append(f"| Guard evasions / landed | {s.get('evasions', 0)} / {s.get('effective_evasions', 0)} |")
    if sec.get("categories"):
        md += ["", "| OWASP | Severity | Detection |", "|---|---|---|"]
        md += [f"| {c['owasp_id'] or c['id']} | {c['severity']} | {_fmt_rate(c.get('detection_rate'))} |"
               for c in sec["categories"]]
    return "\n".join(md)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m backend.oneshot",
                                 description="Headless Lakera Guard red-team runner + CI gate.")
    ap.add_argument("--suite", help="path to a .yaml/.json suite file")
    g = ap.add_argument_group("scope")
    g.add_argument("--category", help="run a single OWASP category id (e.g. llm01)")
    g.add_argument("--all-categories", action="store_true", help="run the whole catalogue")
    g.add_argument("--dataset", help="run an imported dataset slug")
    g.add_argument("--dataset-file", help="load a local CSV/JSON/JSONL/TXT dataset and run it")
    g.add_argument("--max-scenarios", type=int)
    g.add_argument("--seed", type=int)
    o = ap.add_argument_group("options")
    o.add_argument("--judge", action=argparse.BooleanOptionalAction, default=None,
                   help="grade model responses with the LLM judge (default on)")
    o.add_argument("--compare", action="store_true", help="also run each attack with Lakera OFF")
    o.add_argument("--strategies", help="comma-separated obfuscation strategies")
    o.add_argument("--doc-mode", choices=["clean", "poisoned", "custom", "none"])
    o.add_argument("--concurrency", type=int)
    p = ap.add_argument_group("provider")
    p.add_argument("--provider")
    p.add_argument("--base-url")
    p.add_argument("--model")
    j = ap.add_argument_group("judge provider (optional; defaults to the target model)")
    j.add_argument("--judge-provider")
    j.add_argument("--judge-base-url")
    j.add_argument("--judge-model")
    gate = ap.add_argument_group("gate")
    gate.add_argument("--min-detection", type=float, help="min base detection rate, 0..1")
    gate.add_argument("--max-breaches", type=int)
    gate.add_argument("--max-evasions", type=int)
    gate.add_argument("--max-effective-evasions", type=int)
    gate.add_argument("--max-false-positives", type=int)
    out = ap.add_argument_group("output")
    out.add_argument("--out", help="write the full JSON report to this path")
    out.add_argument("--format", choices=["text", "md"], default="text", help="stdout summary format")
    out.add_argument("--dry-run", action="store_true", help="validate + print the plan, no API calls")
    out.add_argument("--quiet", action="store_true", help="suppress the stdout summary")
    hist = ap.add_argument_group("history")
    hist.add_argument("--save-history", action="store_true", help="append this run to the history dir")
    hist.add_argument("--history-dir", default="runs", help="history directory (default: runs)")
    hist.add_argument("--baseline", help="a saved run JSON to diff this run against")
    hist.add_argument("--fail-on-regression", action="store_true",
                      help="exit 1 if a metric regressed vs --baseline")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = build_effective_config(args)
        llm_config = resolve_llm_config(cfg["llm"], dry_run=args.dry_run)
        judge_config = resolve_judge_config(cfg["judge_llm"], dry_run=args.dry_run)
        lakera_key = resolve_lakera_key(dry_run=args.dry_run)
        if cfg.get("_dataset_file"):
            cfg["scope"]["dataset"] = load_dataset_file(cfg["_dataset_file"])
        req = build_request(cfg)
        # Load the baseline up front so a bad path fails before any API spend.
        baseline = load_baseline(args.baseline) if args.baseline else None
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # The prepare/run helpers read these module globals for fail-fast + RAG/dataset lookups.
    core._llm_config = llm_config
    core._lakera_key = lakera_key

    try:
        if args.dry_run:
            rows, scope = core._prepare_oneshot_rows(req)
            print(render_plan(scope, req, llm_config, judge_config))
            return EXIT_OK
        out = asyncio.run(core.run_oneshot(req, llm_config=llm_config, lakera_key=lakera_key,
                                           judge_config=judge_config))
    except HTTPException as exc:
        print(f"config error: {exc.detail}", file=sys.stderr)
        return EXIT_CONFIG

    summary = out["summary"]
    out_payload = {**out, "llm": {k: v for k, v in llm_config.items() if k != "api_key"}}
    if not args.quiet:
        print(render_md(out) if args.format == "md" else render_text(out))
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(out_payload, indent=2), encoding="utf-8")

    # Nothing actually got evaluated → execution error, not a gate verdict.
    if summary["errors"] and (summary["blocked"] + summary["not_blocked"]) == 0:
        print("execution error: every scenario failed (LLM/Lakera unreachable?)", file=sys.stderr)
        return EXIT_RUN

    # Regression diff vs a baseline run.
    regressed = False
    if baseline is not None:
        diff = history.diff_summaries(baseline, summary)
        if not args.quiet:
            print("\n" + render_diff(diff))
        regressed = diff["regressed"]

    if args.save_history:
        rec = history.save(out_payload, args.history_dir, label=(args.suite or None))
        if not args.quiet:
            print(f"saved run {rec['id']} → {rec['path']}")

    ok, fails = evaluate_gate(summary, cfg["gate"])
    if not args.quiet:
        if ok:
            print("\nGATE PASS")
        else:
            print("\nGATE FAIL:", file=sys.stderr)
            for f in fails:
                print(f"  - {f}", file=sys.stderr)
    fail = (not ok) or (args.fail_on_regression and regressed)
    return EXIT_OK if not fail else EXIT_GATE


if __name__ == "__main__":
    raise SystemExit(main())
