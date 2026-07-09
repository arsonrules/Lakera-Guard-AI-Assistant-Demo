"""
Headless one-shot runner — config-as-code + CI gate for the Lakera Guard demo.

    python -m backend.oneshot --suite suite.yaml --min-detection 0.9
    python -m backend.oneshot --all-categories --strategies base64,homoglyph
    python -m backend.oneshot --suite suite.yaml --dry-run    # validate, no API calls

    # Stream a HuggingFace dataset (download + scan overlap), scan CP1 only,
    # 32 parallel workers, and write JSON + HTML reports:
    python -m backend.oneshot --hf-dataset OpenSafetyLab/Salad-Data \
        --project-id CP1 --burst-size 32 --output-dir reports/

Reuses the same prepare → run → summarize pipeline as the web UI (backend.main.
run_oneshot). Secrets come from the environment only (LAKERA_GUARD_API_KEY,
LLM_API_KEY / OPENROUTER_API_KEY); the suite file never holds keys.

Highlights:
  • Concurrent HuggingFace download + scan (streaming pipeline; --stream).
  • --project-id {CP1,CP2,CP3} restricts the run to one checkpoint.
  • --burst-size adjusts the parallel scan pool (companion of --concurrency).
  • --output-dir writes BOTH a machine-readable .json and a styled .html report.
  • --lakera-endpoint URL / --lakera-region point the Guard at a custom region.
  • Provider routing: --provider / --base-url / --model / --api-key (target),
    plus a separate LLM judge (--judge / --judge-* / --judge-api-key).
  • --compare runs each attack Guard-ON vs Guard-OFF for a risk-reduction score.
  • Modern terminal UX via `rich` (progress bar + colored status), with a plain
    fallback when rich is unavailable.

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
import csv
import io
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError

from backend import datasets, history, lakera, llm, ratelimit, report_html
from backend import main as core
from backend.main import OneShotRequest

EXIT_OK, EXIT_GATE, EXIT_CONFIG, EXIT_RUN = 0, 1, 2, 3

# ── Terminal UX (rich if available; graceful plain-text fallback) ─────────────
try:
    from rich.console import Console
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
                               TextColumn, TimeElapsedColumn)
    _console: "Console | None" = Console(stderr=True)
    _RICH = True
except Exception:   # noqa: BLE001 — rich is optional; never let its absence break a run
    _console = None
    _RICH = False


def _status(msg: str, style: str = "cyan") -> None:
    """Print a status line to stderr (stdout stays clean for --format piping)."""
    if _RICH and _console is not None:
        _console.print(f"[{style}]•[/] {msg}")
    else:
        print(msg, file=sys.stderr)


def _make_progress():
    """A rich progress bar for the scan phase, or a no-op fallback."""
    if _RICH and _console is not None:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=_console, transient=True,
        )

    class _NullProgress:   # minimal drop-in when rich isn't installed
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def add_task(self, *a, **k):
            return 0

        def update(self, *a, **k):
            pass

    return _NullProgress()


class ConfigError(Exception):
    """A user-facing configuration problem → exit code 2."""


class PreflightError(Exception):
    """The target LLM failed its pre-run reachability check → exit code 3."""


# ── Effective configuration (defaults ← suite ← CLI flags) ────────────────────

DEFAULTS: dict = {
    "scope": {"category": None, "include_safe": True, "dataset": None, "datasets": [],
              "max_scenarios": 100, "seed": None},
    "options": {"judge": True, "compare": False, "strategies": [], "doc_mode": None,
                "system_prompt": None, "no_system_prompt": False, "concurrency": None,
                "max_rounds": 4, "project_id": None, "rate_limit": 8.0},
    "llm": {"provider": "openrouter", "base_url": None, "model": None, "api_key": None},
    # Optional independent judge model. All-null → judge with the target model.
    "judge_llm": {"provider": None, "base_url": None, "model": None, "api_key": None},
    # Optional custom Lakera Guard region: a full endpoint URL or a known region id.
    "lakera": {"endpoint": None, "region": None},
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
    # Scan concurrency: --concurrency wins; otherwise the --burst-size knob (default 8).
    if args.concurrency is not None:
        o["concurrency"] = args.concurrency
    elif args.burst_size is not None:
        o["concurrency"] = args.burst_size
    if args.max_rounds is not None:
        o["max_rounds"] = args.max_rounds
    if args.project_id is not None:
        o["project_id"] = args.project_id
    if args.rate_limit is not None:
        o["rate_limit"] = args.rate_limit
    for key, val in (("provider", args.provider), ("base_url", args.base_url),
                     ("model", args.model), ("api_key", args.api_key)):
        if val is not None:
            m[key] = val
    jl = cfg["judge_llm"]
    for key, val in (("provider", args.judge_provider), ("base_url", args.judge_base_url),
                     ("model", args.judge_model), ("api_key", args.judge_api_key)):
        if val is not None:
            jl[key] = val
    lk = cfg["lakera"]
    if args.lakera_endpoint is not None:
        lk["endpoint"] = args.lakera_endpoint
    if args.lakera_region is not None:
        lk["region"] = args.lakera_region
    for key, val in (("min_detection", args.min_detection), ("max_breaches", args.max_breaches),
                     ("max_evasions", args.max_evasions),
                     ("max_effective_evasions", args.max_effective_evasions),
                     ("max_false_positives", args.max_false_positives)):
        if val is not None:
            g[key] = val
    # Dataset sources resolved to slugs in main(): local files/dir (offline) and
    # HuggingFace imports (network). Multiple run together as req.datasets.
    cfg["_dataset_files"] = list(args.dataset_file or [])   # --dataset-file is repeatable
    cfg["_dataset_dir"] = args.dataset_dir
    cfg["_hf_datasets"] = list(args.hf_dataset or [])       # --hf-dataset is repeatable
    cfg["_hf_limit"] = args.hf_limit
    cfg["_hf_column"] = args.hf_column
    cfg["_hf_all"] = args.hf_all
    cfg["_stream"] = args.stream          # concurrent HF download + scan (default on)
    cfg["_output_dir"] = args.output_dir  # write both report.json + report.html here
    return cfg


# ── Resolution → provider config, key, request ────────────────────────────────

def resolve_llm_config(llm_cfg: dict, *, dry_run: bool = False) -> dict:
    provider = llm_cfg.get("provider") or llm.DEFAULT_PROVIDER
    if provider not in llm.PROVIDER_PRESETS:
        raise ConfigError(
            f"unknown provider '{provider}' — choose one of: {', '.join(sorted(llm.PROVIDER_PRESETS))}.")
    p = llm.preset(provider)
    base_url = llm_cfg.get("base_url") or p["base_url"]
    model = llm_cfg.get("model") or p["default_model"]
    # Precedence: explicit --api-key → LLM_API_KEY → OPENROUTER_API_KEY (back-compat).
    api_key = (llm_cfg.get("api_key") or os.environ.get("LLM_API_KEY")
               or os.environ.get("OPENROUTER_API_KEY") or "")
    # A dry-run validates the suite/scope without calling APIs, so don't require secrets.
    if not dry_run:
        if p["requires_key"] and not api_key:
            raise ConfigError(
                f"{p['label']} requires an API key — pass --api-key, or set "
                f"$LLM_API_KEY / $OPENROUTER_API_KEY. (Or use a local provider that needs no key: "
                f"--provider lmstudio|ollama|omlx.)")
        if not model:
            raise ConfigError(f"a model id is required for {p['label']} — set --model (or llm.model in the suite).")
    return {"provider": provider, "base_url": base_url, "api_key": api_key,
            "model": model or "(unset)"}


def resolve_judge_config(judge_cfg: dict, *, dry_run: bool = False) -> dict | None:
    """
    Build the dedicated LLM-judge config, or None when nothing is configured (the
    judge then falls back to the target model). Key precedence: --judge-api-key →
    $JUDGE_API_KEY.
    """
    provider = judge_cfg.get("provider")
    base_url = judge_cfg.get("base_url")
    model = judge_cfg.get("model")
    api_key = judge_cfg.get("api_key") or os.environ.get("JUDGE_API_KEY", "")
    if not (provider or base_url or model or api_key):
        return None
    provider = provider or llm.DEFAULT_PROVIDER
    if provider not in llm.PROVIDER_PRESETS:
        raise ConfigError(
            f"unknown judge provider '{provider}' — choose one of: {', '.join(sorted(llm.PROVIDER_PRESETS))}.")
    p = llm.preset(provider)
    base_url = base_url or p["base_url"]
    model = model or p["default_model"]
    if not dry_run:
        if p["requires_key"] and not api_key:
            raise ConfigError(
                f"judge provider {p['label']} requires an API key — pass --judge-api-key or set $JUDGE_API_KEY.")
        if not model:
            raise ConfigError(
                f"a judge model id is required for {p['label']} — set --judge-model (or judge_llm.model).")
    return {"provider": provider, "base_url": base_url, "api_key": api_key,
            "model": model or "(unset)"}


def resolve_lakera_endpoint(lakera_cfg: dict) -> str | None:
    """
    Resolve a custom Lakera Guard endpoint from `--lakera-endpoint URL` (a full
    URL or bare region host) or `--lakera-region <id>`. Returns the normalized
    endpoint URL, or None to keep the default (Community / $LAKERA_ENDPOINT).
    """
    endpoint = lakera_cfg.get("endpoint")
    region = lakera_cfg.get("region")
    if endpoint:
        try:
            return lakera.normalize_endpoint(endpoint)
        except ValueError as exc:
            raise ConfigError(f"invalid --lakera-endpoint: {exc}")
    if region:
        match = next((r for r in lakera.REGIONS if r["id"] == region), None)
        if not match:
            known = ", ".join(r["id"] for r in lakera.REGIONS)
            raise ConfigError(f"unknown --lakera-region '{region}' — choose one of: {known}.")
        return match["url"]
    return None


async def _preflight_target_llm(llm_config: dict) -> str | None:
    """
    Ping the target LLM's /models endpoint before a real run. Turns the most common
    failure mode — a wrong base-url/port/host (e.g. `host.docker.internal` from the
    host shell) or an unserved model — into ONE clear message up front, instead of
    the same httpx connection error repeating (with retries) across every scenario.
    Returns an error string to abort on, or None when the LLM is reachable.
    """
    res = await llm.test_connection(
        provider=llm_config["provider"], base_url=llm_config["base_url"],
        api_key=llm_config["api_key"], model=llm_config["model"])
    if not res.get("ok"):
        return (f"target LLM at {llm_config['base_url']} is unreachable — {res.get('error')} "
                f"Fix --provider/--base-url/--model (or pass --no-preflight to skip this check).")
    if res.get("model_present") is False:
        avail = ", ".join(res.get("models", [])[:5]) or "none advertised"
        return (f"model '{llm_config['model']}' isn't served by {llm_config['base_url']} "
                f"(available: {avail}). Pass a served --model, or --no-preflight to skip.")
    return None


def _representative_error(results: list[dict]) -> str | None:
    """The most common error among failed scenarios — appended to the run-failed
    message so the user sees WHY even when they skipped the pre-flight check."""
    from collections import Counter
    errs = [r.get("error") for r in results if r.get("outcome") == "error" and r.get("error")]
    if not errs:
        return None
    msg, n = Counter(errs).most_common(1)[0]
    return msg + (f"   ({n}× of {len(errs)} failures)" if n > 1 else "")


def resolve_lakera_key(*, dry_run: bool) -> str:
    key = os.environ.get("LAKERA_GUARD_API_KEY", "").strip()
    if not key and not dry_run:
        raise ConfigError("LAKERA_GUARD_API_KEY is not set.")
    return key or "(dry-run-placeholder)"


def _checkpoints_for(project_id: str | None) -> dict:
    """--project-id CPn restricts the run to that single checkpoint (others off).
    None → all three checkpoints active (the default pipeline)."""
    if not project_id:
        return {"cp1": True, "cp2": True, "cp3": True}
    pid = project_id.upper()
    return {"cp1": pid == "CP1", "cp2": pid == "CP2", "cp3": pid == "CP3"}


def build_request(cfg: dict) -> OneShotRequest:
    s, o = cfg["scope"], cfg["options"]
    try:
        return OneShotRequest(
            category_id=s["category"], include_safe=s["include_safe"], dataset=s["dataset"],
            datasets=s.get("datasets") or [],
            max_scenarios=s["max_scenarios"], seed=s["seed"],
            judge=o["judge"], compare=o["compare"], strategies=o["strategies"] or [],
            doc_mode=o["doc_mode"], system_prompt=o["system_prompt"],
            no_system_prompt=o["no_system_prompt"], concurrency=o["concurrency"],
            max_rounds=o["max_rounds"],
            checkpoints=_checkpoints_for(o.get("project_id")),
        )
    except ValidationError as exc:
        raise ConfigError(f"invalid run configuration: {exc.errors()[0].get('msg', exc)}")


DATASET_EXTS = {".csv", ".json", ".jsonl", ".txt"}


def _store_cli_dataset(name: str, source: str, column: str | None, rows: list[dict]) -> str:
    """Register an in-memory dataset for the run (no MAX_DATASETS cap for the CLI)."""
    slug = core._slugify(name)
    core._datasets[slug] = {"slug": slug, "name": name, "source": source,
                            "count": len(rows), "column": column, "rows": rows}
    return slug


def load_dataset_file(path: str) -> str:
    """Parse a local CSV/JSON/JSONL/TXT into an in-memory dataset; return its slug."""
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(f"dataset file not found: {path}")
    try:
        parsed = datasets.parse_upload(p.name, p.read_bytes())
    except datasets.DatasetError as exc:
        raise ConfigError(f"dataset file '{path}': {exc}")
    return _store_cli_dataset(p.name, "cli-file", parsed["column"], parsed["rows"])


def load_dataset_dir(path: str) -> list[str]:
    """Load every .csv/.json/.jsonl/.txt in a directory; return their slugs (sorted)."""
    p = pathlib.Path(path)
    if not p.is_dir():
        raise ConfigError(f"dataset dir not found: {path}")
    files = sorted(f for f in p.iterdir() if f.is_file() and f.suffix.lower() in DATASET_EXTS)
    if not files:
        raise ConfigError(f"no .csv/.json/.jsonl/.txt files in {path}")
    return [load_dataset_file(str(f)) for f in files]


async def import_hf_dataset(dataset_id: str, *, limit: int, column: str | None,
                            all_configs: bool) -> str:
    """Fetch a HuggingFace dataset (network) into an in-memory dataset; return its slug."""
    try:
        result = await datasets.fetch_hf(dataset_id, column=column, limit=limit,
                                         all_configs=all_configs)
    except datasets.DatasetError as exc:
        raise ConfigError(f"HuggingFace '{dataset_id}': {exc}")
    return _store_cli_dataset(dataset_id, "cli-hf", result["column"], result["rows"])


def _local_scope_slugs(cfg: dict) -> list[str]:
    """Resolve the offline dataset sources (single --dataset slug, --dataset-file(s),
    --dataset-dir) into slugs. HuggingFace imports are resolved separately (network)."""
    slugs: list[str] = []
    if cfg["scope"].get("dataset"):          # legacy single imported slug / suite value
        slugs.append(cfg["scope"]["dataset"])
    for f in cfg.get("_dataset_files", []):
        slugs.append(load_dataset_file(f))
    if cfg.get("_dataset_dir"):
        slugs.extend(load_dataset_dir(cfg["_dataset_dir"]))
    return slugs


# ── Streaming HuggingFace download + concurrent scan ──────────────────────────

async def run_streaming(req: OneShotRequest, hf_specs: list[dict], *, llm_config: dict,
                        lakera_key: str, judge_config: dict | None, burst: int) -> dict:
    """
    Concurrent HuggingFace **download + scan** pipeline. A producer pages rows in
    from HuggingFace and, as each page arrives, feeds scenario rows into a bounded
    queue; `burst` consumer workers scan them in parallel — so downloading and
    scanning overlap instead of the run stalling on a full download first.

    Returns the run payload `{summary, results}` (same shape as `run_oneshot`).
    """
    sem = asyncio.Semaphore(max(1, burst))
    queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, burst) * 4)   # backpressure
    results: list[dict] = []
    do_judge = req.judge or req.compare
    sp = core._oneshot_system_prompt(req)
    proj = core._oneshot_project_id(req)
    cp_proj = core._oneshot_cp_projects(req)
    checkpoints = req.checkpoints.model_dump()
    strat_mult = 1 + len([s for s in req.strategies if core.strategies.is_valid(s)])
    counters = {"base": 0, "produced": 0, "expected": 0, "partial": False}

    with _make_progress() as progress:
        task = progress.add_task("Scanning as it downloads", total=None)

        async def producer() -> None:
            order = 0
            for spec in hf_specs:
                async for evt in datasets.stream_hf(
                        spec["id"], column=spec["column"], limit=spec["limit"],
                        all_configs=spec["all"]):
                    if evt["type"] == "meta":
                        counters["expected"] += evt["total"] * strat_mult
                        progress.update(task, total=counters["expected"])
                    elif evt["type"] == "batch":
                        for item in evt["rows"]:
                            counters["base"] += 1
                            base = core.dataset_row(spec["slug"], counters["base"], item, spec["name"])
                            for row in core._expand_with_strategies([base], req.strategies):
                                row["order"] = order
                                order += 1
                                counters["produced"] += 1
                                await queue.put(row)
                    elif evt["type"] == "end":
                        counters["partial"] = counters["partial"] or evt.get("partial", False)

        async def consumer() -> None:
            while True:
                row = await queue.get()
                try:
                    if row is None:                 # shutdown sentinel
                        return
                    res = await core._run_one_resilient(
                        row, sem, do_judge, req.compare, sp,
                        llm_config=llm_config, lakera_key=lakera_key, lakera_project_id=proj,
                        judge_config=judge_config or llm_config, max_rounds=req.max_rounds,
                        checkpoints=checkpoints, checkpoint_projects=cp_proj)
                    results.append(res)
                    progress.update(task, advance=1)
                finally:
                    queue.task_done()

        consumers = [asyncio.create_task(consumer()) for _ in range(max(1, burst))]
        producer_exc: Exception | None = None
        try:
            await producer()
        except datasets.DatasetError as exc:
            producer_exc = exc
        finally:
            for _ in consumers:                      # always release the workers
                await queue.put(None)
            await asyncio.gather(*consumers)

    if producer_exc is not None and not results:     # nothing salvageable → surface it
        raise ConfigError(str(producer_exc))
    if producer_exc is not None:
        _status(f"streaming stopped early ({producer_exc}); keeping {len(results)} scanned", "yellow")
        counters["partial"] = True

    results.sort(key=lambda r: r.get("order", 0))
    scope = {
        "available": counters["base"], "base_executed": counters["base"],
        "total_rows": counters["produced"], "sampled": False, "streamed": True,
        "partial": counters["partial"], "max_scenarios": req.max_scenarios, "seed": req.seed,
    }
    return {"summary": core._oneshot_summary(results, req, scope), "results": results}


# ── Dual-format reporting (JSON + styled HTML) ────────────────────────────────

def write_reports(payload: dict, *, output_dir: str | None, out_json: str | None,
                  out_csv: str | None) -> list[str]:
    """Write the requested report artifacts; return the paths written.
    `--output-dir` produces BOTH a timestamped report.json and report.html."""
    written: list[str] = []
    if output_dir:
        d = pathlib.Path(output_dir)
        d.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        jpath = d / f"oneshot-{stamp}.json"
        hpath = d / f"oneshot-{stamp}.html"
        jpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        hpath.write_text(report_html.render(payload), encoding="utf-8")
        written += [str(jpath), str(hpath)]
    if out_json:
        pathlib.Path(out_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(out_json)
    if out_csv:
        pathlib.Path(out_csv).write_text(results_to_csv(payload["results"]), encoding="utf-8")
        written.append(out_csv)
    return written


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
                judge_config: dict | None = None, lakera_endpoint: str | None = None,
                rate_limit: float | None = None) -> str:
    judge = (f"{judge_config['provider']} · {judge_config['model']}"
             if judge_config else "same as target")
    if req.datasets:
        scope_str = f"datasets [{', '.join(req.datasets)}]"
    elif req.dataset:
        scope_str = f"dataset {req.dataset}"
    else:
        scope_str = req.category_id or "all categories"
    cps = req.checkpoints.model_dump()
    active = [cp.upper() for cp in ("cp1", "cp2", "cp3") if cps[cp]]
    checkpoints_str = "CP1+CP2+CP3 (all)" if len(active) == 3 else " ".join(active)
    rate_str = f"{rate_limit:g} req/s" if rate_limit and rate_limit > 0 else "unlimited"
    return "\n".join([
        "Run plan (dry-run — no API calls):",
        f"  provider     : {llm_config['provider']} · {llm_config['model']}",
        f"  judge model  : {judge}",
        f"  lakera guard : {lakera_endpoint or lakera.current_endpoint()}",
        f"  rate limit   : {rate_str}",
        f"  scope        : {scope_str}",
        f"  checkpoints  : {checkpoints_str}",
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
    cls = sec.get("classification")
    if cls:
        fam = cls.get("families", {})
        lines.append(f"  owasp classify: {cls.get('total', 0)} prompts · "
                     f"LLM {fam.get('llm', 0)} · agentic {fam.get('agentic', 0)} · "
                     f"unmapped {fam.get('unmapped', 0)}")
        for tac in cls.get("tactics", []):
            lines.append(f"    {tac['code']:<12} {tac['count']:>5} ({tac['share']}%) "
                         f"det {_fmt_rate(tac.get('detection_rate'))}")
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


CSV_COLUMNS = ["id", "label", "owasp_id", "owasp_class", "category_id", "expected", "outcome",
               "blocked", "model_outcome", "risk", "strategy", "total_latency_ms",
               "judge_reason", "assertions_matched"]


def results_to_csv(results: list[dict]) -> str:
    """Flatten per-scenario results to CSV (one row per result) for spreadsheets/CI."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in results:
        checks = r.get("assertions") or []
        cls = r.get("owasp_class") or {}
        cls_code = cls.get("code") if cls.get("code") not in (None, "UNMAPPED") else ""
        w.writerow({
            "id": r.get("id"), "label": r.get("label"), "owasp_id": r.get("owasp_id"),
            "owasp_class": cls_code,
            "category_id": r.get("category_id"), "expected": r.get("expected"),
            "outcome": r.get("outcome"), "blocked": r.get("blocked"),
            "model_outcome": r.get("model_outcome"), "risk": r.get("risk"),
            "strategy": r.get("strategy") or "", "total_latency_ms": r.get("total_latency_ms"),
            "judge_reason": (r.get("judge") or {}).get("reason", "") if r.get("judge") else "",
            "assertions_matched": sum(1 for c in checks if c.get("matched")),
        })
    return buf.getvalue()


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
    cls = sec.get("classification")
    if cls:
        md += ["", f"#### OWASP tactic classification ({cls.get('total', 0)} imported prompts)",
               "", "| Tactic | Prompts | Share | Detection |", "|---|---|---|---|"]
        md += [f"| {tac['code']} {tac['name']} | {tac['count']} | {tac['share']}% "
               f"| {_fmt_rate(tac.get('detection_rate'))} |"
               for tac in cls.get("tactics", [])]
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
    g.add_argument("--dataset-file", action="append", metavar="PATH",
                   help="load a local CSV/JSON/JSONL/TXT dataset and run it; repeatable "
                        "to run several datasets together")
    g.add_argument("--dataset-dir", metavar="DIR",
                   help="load every .csv/.json/.jsonl/.txt file in a directory and run them together")
    g.add_argument("--hf-dataset", action="append", metavar="OWNER/NAME",
                   help="import a public HuggingFace dataset and run it; repeatable")
    g.add_argument("--hf-limit", type=int, default=100,
                   help="rows to import per --hf-dataset (default 100; ignored with --hf-all)")
    g.add_argument("--hf-column", help="prompt column override for --hf-dataset (default: auto-detect)")
    g.add_argument("--hf-all", action="store_true",
                   help="import every row of each --hf-dataset (up to 100,000)")
    g.add_argument("--stream", action=argparse.BooleanOptionalAction, default=True,
                   help="for --hf-dataset: scan chunks concurrently AS they download "
                        "(streaming pipeline) instead of downloading everything first "
                        "(default: on; --no-stream to import fully first)")
    g.add_argument("--max-scenarios", type=int)
    g.add_argument("--seed", type=int)
    o = ap.add_argument_group("options")
    o.add_argument("--project-id", choices=["CP1", "CP2", "CP3"], metavar="{CP1,CP2,CP3}",
                   help="restrict the run to a single checkpoint: CP1 (user input), "
                        "CP2 (RAG documents), or CP3 (LLM output). Default: all three.")
    o.add_argument("--burst-size", type=int, default=8, metavar="N",
                   help="scan concurrency — number of scenarios tested in parallel "
                        "(1–100, default 8). Alias/companion of --concurrency, which wins if both are set.")
    o.add_argument("--judge", action=argparse.BooleanOptionalAction, default=None,
                   help="LLM judge: grade each attack's model output for compromise / policy "
                        "violation (default on; --no-judge to skip). See the 'judge provider' group "
                        "to score with a separate, stronger model.")
    o.add_argument("--compare", action="store_true",
                   help="Guard ON vs OFF: also run each attack with Lakera disabled to measure the "
                        "guard's risk reduction (implies --judge; doubles model calls).")
    o.add_argument("--strategies", help="comma-separated obfuscation strategies")
    o.add_argument("--doc-mode", choices=["clean", "poisoned", "custom", "none"])
    o.add_argument("--concurrency", type=int)
    o.add_argument("--rate-limit", type=float, metavar="RPS",
                   help="max outbound requests/second across ALL workers (Guard scans + LLM "
                        "calls share one token-bucket limiter; default 8). Use 0 to disable "
                        "throttling. Independent of --concurrency (how many run at once).")
    o.add_argument("--max-rounds", type=int, help="round budget for dynamic scenarios (1–10)")
    lg = ap.add_argument_group("lakera guard")
    lg.add_argument("--lakera-endpoint", metavar="URL",
                    help="custom Lakera Guard endpoint/region URL, e.g. "
                         "https://eu-west-1.api.lakera.ai (a bare region host gets /v2/guard "
                         "appended). Default: Community, or $LAKERA_ENDPOINT.")
    lg.add_argument("--lakera-region", choices=[r["id"] for r in lakera.REGIONS],
                    help="pick a known Guard region by id instead of a full URL "
                         "(e.g. eu-west-1, us, ap-southeast-1).")
    p = ap.add_argument_group("provider (target LLM)")
    p.add_argument("--provider", help="openrouter | lmstudio | ollama | omlx | custom")
    p.add_argument("--base-url", help="OpenAI-compatible base URL (overrides the provider preset)")
    p.add_argument("--model", help="model id to test against")
    p.add_argument("--api-key", metavar="KEY",
                   help="target provider API key (overrides $LLM_API_KEY / $OPENROUTER_API_KEY). "
                        "Prefer the env var — a CLI key is visible in the process list & shell history.")
    p.add_argument("--preflight", action=argparse.BooleanOptionalAction, default=True,
                   help="before a real run, ping the target LLM once and abort with a clear "
                        "message if the base-url/host/port/model is wrong (default: on; "
                        "--no-preflight to skip and let each scenario fail individually).")
    j = ap.add_argument_group("judge provider (optional; defaults to the target model)")
    j.add_argument("--judge-provider")
    j.add_argument("--judge-base-url")
    j.add_argument("--judge-model")
    j.add_argument("--judge-api-key", metavar="KEY",
                   help="judge provider API key (overrides $JUDGE_API_KEY).")
    gate = ap.add_argument_group("gate")
    gate.add_argument("--min-detection", type=float, help="min base detection rate, 0..1")
    gate.add_argument("--max-breaches", type=int)
    gate.add_argument("--max-evasions", type=int)
    gate.add_argument("--max-effective-evasions", type=int)
    gate.add_argument("--max-false-positives", type=int)
    out = ap.add_argument_group("output")
    out.add_argument("--output-dir", metavar="DIR",
                     help="write BOTH a structured report.json and a styled report.html into DIR "
                          "(created if needed; filenames are timestamped)")
    out.add_argument("--out", help="write the full JSON report to this exact path")
    out.add_argument("--csv", help="write per-scenario results as CSV to this path")
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
        lakera_endpoint = resolve_lakera_endpoint(cfg["lakera"])   # custom region URL (or None)
        # Offline dataset sources (files/dir); HuggingFace imports happen at run time.
        local_slugs = _local_scope_slugs(cfg)
        hf_ids = cfg["_hf_datasets"]
        # Load the baseline up front so a bad path fails before any API spend.
        baseline = load_baseline(args.baseline) if args.baseline else None
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # The prepare/run helpers read these module globals for fail-fast + RAG/dataset lookups.
    core._llm_config = llm_config
    core._lakera_key = lakera_key
    # Point every CP1/CP2/CP3 Guard scan at the chosen region for this process.
    # (Skipped for a dry-run, which stays side-effect-free; the plan still shows it.)
    if lakera_endpoint and not args.dry_run:
        lakera.set_endpoint(lakera_endpoint)
        _status(f"Lakera Guard endpoint: {lakera.current_endpoint()}")
    # Throttle every outbound request (Guard + LLM) through one shared token bucket
    # so N parallel workers can't collectively exceed the cap. 0/negative disables it.
    rate_limit = cfg["options"]["rate_limit"]
    if not args.dry_run:
        ratelimit.configure(rate_limit if rate_limit and rate_limit > 0 else ratelimit.UNLIMITED)
        if ratelimit.current_rate() > 0:
            _status(f"Rate limit: {ratelimit.current_rate():g} req/s (all workers share it)")

    # HuggingFace datasets can either stream (download + scan concurrently) or be
    # imported fully first. Stream only when the run is cleanly HF-only.
    hf_specs = [{"id": hid, "slug": core._slugify(hid), "name": hid,
                 "limit": cfg["_hf_limit"], "column": cfg["_hf_column"], "all": cfg["_hf_all"]}
                for hid in hf_ids]
    explicit_scope = bool(local_slugs or args.category or args.all_categories or cfg["scope"]["dataset"])
    use_stream = bool(cfg["_stream"] and hf_specs and not explicit_scope)

    try:
        if args.dry_run:
            cfg["scope"]["datasets"] = local_slugs
            req = build_request(cfg)
            rows, scope = core._prepare_oneshot_rows(req)
            plan = render_plan(scope, req, llm_config, judge_config, lakera_endpoint,
                               cfg["options"]["rate_limit"])
            if hf_ids:   # not fetched during a dry-run (that's a network call)
                plan += f"\n  hf ({'streamed' if use_stream else 'imported'} at run) : " + ", ".join(hf_ids)
            print(plan)
            return EXIT_OK

        async def _run_and_close():
            try:
                # Fail fast on a misconfigured target LLM (wrong host/port/model) so a
                # 50k-row run doesn't hammer a dead endpoint scenario-by-scenario.
                if args.preflight:
                    problem = await _preflight_target_llm(llm_config)
                    if problem:
                        raise PreflightError(problem)
                    _status("target LLM reachable ✓", "green")
                if use_stream:
                    req = build_request(cfg)   # datasets empty; streaming feeds rows directly
                    burst = req.concurrency or core.ONESHOT_CONCURRENCY
                    _status(f"streaming {len(hf_specs)} HuggingFace dataset(s) · {burst} parallel workers")
                    return await run_streaming(req, hf_specs, llm_config=llm_config,
                                               lakera_key=lakera_key, judge_config=judge_config,
                                               burst=burst)
                # Batch: import HuggingFace fully, then run everything together.
                hf_slugs = []
                for hid in hf_ids:
                    _status(f"importing HuggingFace dataset {hid} …")
                    hf_slugs.append(await import_hf_dataset(
                        hid, limit=cfg["_hf_limit"], column=cfg["_hf_column"], all_configs=cfg["_hf_all"]))
                cfg["scope"]["datasets"] = local_slugs + hf_slugs
                req = build_request(cfg)
                return await core.run_oneshot(req, llm_config=llm_config, lakera_key=lakera_key,
                                              judge_config=judge_config)
            finally:
                await lakera.aclose()   # release the shared Guard connection pool
                ratelimit.reset()       # clear the process-wide throttle for later in-process runs

        if _RICH and use_stream:
            out = asyncio.run(_run_and_close())               # streaming shows its own progress bar
        elif _RICH and _console is not None:
            with _console.status("[cyan]Running one-shot scenarios…[/]"):
                out = asyncio.run(_run_and_close())
        else:
            out = asyncio.run(_run_and_close())
    except PreflightError as exc:       # target LLM unreachable — fail fast, one message
        print(f"execution error: {exc}", file=sys.stderr)
        return EXIT_RUN
    except ConfigError as exc:          # HuggingFace import / dataset errors
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except HTTPException as exc:
        print(f"config error: {exc.detail}", file=sys.stderr)
        return EXIT_CONFIG

    summary = out["summary"]
    out_payload = {**out, "llm": {k: v for k, v in llm_config.items() if k != "api_key"},
                   "generated_at": datetime.now(timezone.utc).isoformat()}
    if not args.quiet:
        print(render_md(out) if args.format == "md" else render_text(out))
    # Dual-format reporting: --output-dir → both JSON + HTML; --out / --csv as before.
    try:
        for pth in write_reports(out_payload, output_dir=args.output_dir,
                                 out_json=args.out, out_csv=args.csv):
            _status(f"wrote {pth}", "green")
    except OSError as exc:
        print(f"config error: could not write report: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # Nothing actually got evaluated → execution error, not a gate verdict.
    if summary["errors"] and (summary["blocked"] + summary["not_blocked"]) == 0:
        msg = "execution error: every scenario failed (LLM/Lakera unreachable?)"
        rep = _representative_error(out.get("results", []))
        if rep:
            msg += f"\n  → {rep}"
        print(msg, file=sys.stderr)
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
