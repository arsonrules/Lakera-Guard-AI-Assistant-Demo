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
    # Optional independent judge model. Any field left null inherits the matching
    # value from the main model (the CRITICAL judge fallback rule).
    "judge_llm": {"provider": None, "base_url": None, "model": None, "api_key": None},
    # Optional custom Lakera Guard region: a full endpoint URL or a known region id
    # (--lakera-url / --lakera-endpoint / --lakera-region), an override API key
    # (--lakera-api-key), and per-checkpoint Project IDs (--lakera-projects).
    "lakera": {"endpoint": None, "region": None, "api_key": None,
               "projects": {"cp1": None, "cp2": None, "cp3": None}},
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


# ── CLI value parsers (comma-lists & key=value maps) ──────────────────────────

def _parse_kv(spec: str, *, flag: str) -> dict:
    """Parse a `key=value,key2=value2` string into a dict. Whitespace-tolerant;
    later duplicate keys win. Raises ConfigError on a token missing its `=`."""
    out: dict = {}
    for tok in (spec or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "=" not in tok:
            raise ConfigError(f"{flag}: '{tok}' must be key=value "
                              f"(e.g. {flag} input=id1,output=id2).")
        k, v = tok.split("=", 1)
        k = k.strip()
        if not k:
            raise ConfigError(f"{flag}: empty key in '{tok}'.")
        out[k] = v.strip()
    return out


# --lakera-projects keys map to the three checkpoints (friendly names + CPn aliases).
_LAKERA_PROJECT_KEYS = {
    "input": "cp1", "cp1": "cp1",
    "rag": "cp2", "cp2": "cp2",
    "output": "cp3", "cp3": "cp3",
}


def _parse_lakera_projects(spec: str) -> dict:
    """`input=id1,rag=id2,output=id3` → {cp1,cp2,cp3} Project IDs (unset → None)."""
    projects: dict = {"cp1": None, "cp2": None, "cp3": None}
    for key, val in _parse_kv(spec, flag="--lakera-projects").items():
        cp = _LAKERA_PROJECT_KEYS.get(key.lower())
        if not cp:
            raise ConfigError(
                f"--lakera-projects: unknown checkpoint '{key}' — use "
                f"input/rag/output (or cp1/cp2/cp3).")
        projects[cp] = val
    return projects


# --mapping keys → the dataset fields we understand.
_MAPPING_KEYS = {"prompt", "category", "tactics"}


def _parse_mapping(spec: str) -> dict:
    """`prompt=text,category=owasp_category,tactics=attack_tactics` → field map."""
    mapping = _parse_kv(spec, flag="--mapping")
    unknown = set(mapping) - _MAPPING_KEYS
    if unknown:
        raise ConfigError(
            f"--mapping: unknown field(s) {', '.join(sorted(unknown))} — "
            f"supported: {', '.join(sorted(_MAPPING_KEYS))}.")
    return mapping


def _load_system_prompt_file(path: str) -> str:
    """Read a `--system-prompt <file>.txt` into a system-prompt string. Requires a
    `.txt` file that exists and holds non-empty text; raises ConfigError otherwise."""
    p = pathlib.Path(path)
    if p.suffix.lower() != ".txt":
        raise ConfigError(f"--system-prompt must be a .txt file (got '{p.suffix or path}').")
    if not p.is_file():
        raise ConfigError(f"--system-prompt file not found: {path}")
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not read --system-prompt file '{path}': {exc}")
    text = text.strip()
    if not text:
        raise ConfigError(f"--system-prompt file '{path}' is empty.")
    return text


def _load_knowledge_base_file(path: str) -> str:
    """Read a `--knowledge-base <file>.txt` into a RAG context string. Validates the
    file exists and is a readable, non-empty `.txt` before reading; any failure is
    surfaced as a ConfigError (a clean, user-friendly message + exit 2) rather than
    an uncaught crash."""
    p = pathlib.Path(path)
    if p.suffix.lower() != ".txt":
        raise ConfigError(f"--knowledge-base must be a .txt file (got '{p.suffix or path}').")
    if not p.is_file():
        raise ConfigError(f"--knowledge-base file not found: {path}")
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not read --knowledge-base file '{path}': {exc}")
    text = text.strip()
    if not text:
        raise ConfigError(f"--knowledge-base file '{path}' is empty.")
    return text


def _looks_like_hf_id(token: str) -> bool:
    """A HuggingFace id is `owner/name` with no filesystem extension."""
    return bool(datasets._DATASET_ID_RE.match(token)) and pathlib.Path(token).suffix == ""


def _split_dataset_arg(spec: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Split a comma-separated --dataset value into (files, dirs, hf_ids, slugs).

    Each token is routed by what it looks like: an existing local directory → dir
    (every supported file in it is loaded); an existing path or a token with a
    dataset file extension → local file; an `owner/name` id → HuggingFace; anything
    else → a previously-imported dataset slug (suite/back-compat). An EXISTING local
    directory is checked before the HuggingFace-id pattern so a local path like
    `datasets/OpenSafetyLab__Salad-Data` isn't mistaken for a remote id."""
    files, dirs, hf_ids, slugs = [], [], [], []
    for tok in (spec or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        p = pathlib.Path(tok)
        if p.is_dir():                              # existing local directory of datasets
            dirs.append(tok)
        elif p.is_file():
            files.append(tok)
        elif p.suffix.lower() in DATASET_EXTS:      # a file path (even if not yet present)
            files.append(tok)
        elif _looks_like_hf_id(tok):
            hf_ids.append(tok)
        else:
            slugs.append(tok)
    return files, dirs, hf_ids, slugs


def build_effective_config(args: argparse.Namespace) -> dict:
    """Merge DEFAULTS ← suite ← explicitly-provided CLI flags."""
    cfg = _deep_merge(DEFAULTS, load_suite(args.suite) if args.suite else {})

    # Only flags the user actually set (argparse default None) override the suite.
    s, o, g, m = cfg["scope"], cfg["options"], cfg["gate"], cfg["llm"]
    if args.all_categories:
        s["category"] = None
    elif args.category is not None:
        s["category"] = args.category
    for key, val in (("max_scenarios", args.max_scenarios), ("seed", args.seed)):
        if val is not None:
            s[key] = val
    # --dataset is a comma-separated one-shot convenience: each token is routed to
    # a local dir/file, a HuggingFace id, or a pre-imported slug (see _split_dataset_arg).
    ds_files, ds_dirs, ds_hf, ds_slugs = _split_dataset_arg(args.dataset or "")
    if len(ds_slugs) == 1 and not ds_files and not ds_dirs and not ds_hf:
        s["dataset"] = ds_slugs[0]          # single legacy slug → scope.dataset
    elif ds_slugs:
        s["datasets"] = (s.get("datasets") or []) + ds_slugs
    if args.judge is not None:
        o["judge"] = args.judge
    if args.compare:
        o["compare"] = True
    if args.strategies is not None:
        o["strategies"] = [x.strip() for x in args.strategies.split(",") if x.strip()]
    if args.doc_mode is not None:
        o["doc_mode"] = args.doc_mode
    # System prompt: --system-prompt <file>.txt applies that file's content;
    # otherwise (and unless a suite set one) the CLI defaults to CLEAN mode — no
    # system prompt at all — independent of any Web UI / global setting.
    if args.system_prompt is not None:
        o["system_prompt"] = _load_system_prompt_file(args.system_prompt)
        o["no_system_prompt"] = False
    elif not o.get("system_prompt") and not o.get("no_system_prompt"):
        o["no_system_prompt"] = True
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
    # --lakera-url is the unified endpoint knob (full URL or a known region id);
    # --lakera-endpoint / --lakera-region remain as explicit back-compat aliases.
    if args.lakera_url is not None:
        if any(r["id"] == args.lakera_url for r in lakera.REGIONS):
            lk["region"] = args.lakera_url
        else:
            lk["endpoint"] = args.lakera_url
    if args.lakera_endpoint is not None:
        lk["endpoint"] = args.lakera_endpoint
    if args.lakera_region is not None:
        lk["region"] = args.lakera_region
    if args.lakera_api_key is not None:
        lk["api_key"] = args.lakera_api_key
    if args.lakera_projects is not None:
        lk["projects"] = _parse_lakera_projects(args.lakera_projects)
    for key, val in (("min_detection", args.min_detection), ("max_breaches", args.max_breaches),
                     ("max_evasions", args.max_evasions),
                     ("max_effective_evasions", args.max_effective_evasions),
                     ("max_false_positives", args.max_false_positives)):
        if val is not None:
            g[key] = val
    # Optional field mapping (dataset JSON field → prompt/category/tactics input).
    mapping = _parse_mapping(args.mapping or "")
    cfg["_mapping"] = mapping
    # Prompt column: --mapping prompt=… wins, else --hf-column, else auto-detect.
    cfg["_prompt_column"] = mapping.get("prompt") or args.hf_column
    cfg["_category_column"] = mapping.get("category")
    cfg["_tactics_column"] = mapping.get("tactics")
    # Dataset sources resolved to slugs in main(): local files/dir (offline) and
    # HuggingFace imports (network). Multiple run together as req.datasets.
    # --dataset tokens routed to files/HF are merged with the explicit flags.
    cfg["_dataset_files"] = ds_files + list(args.dataset_file or [])   # --dataset-file is repeatable
    cfg["_dataset_dir"] = args.dataset_dir
    cfg["_dataset_dirs"] = ds_dirs           # local directories routed from --dataset
    cfg["_hf_datasets"] = ds_hf + list(args.hf_dataset or [])          # --hf-dataset is repeatable
    cfg["_hf_limit"] = args.hf_limit
    cfg["_hf_column"] = cfg["_prompt_column"]
    cfg["_hf_all"] = args.hf_all
    cfg["_hf_download"] = args.hf_download   # download + verify original files, then scan locally
    cfg["_datasets_dir"] = args.datasets_dir
    cfg["_stream"] = args.stream          # concurrent HF download + scan (default on)
    cfg["_output_dir"] = args.output_dir  # write both report.json + report.html here
    # Optional RAG knowledge base:
    #   omitted            → None      → clean mode (default clean RAG file retrieved)
    #   the literal "none" → bypass    → force doc_mode="none": NO file ops at all
    #                                     (not even the clean file) and no injection
    #   a .txt path        → contents  → injected as extra RAG context
    cfg["_knowledge_base_none"] = False
    if args.knowledge_base and args.knowledge_base.strip().lower() == "none":
        cfg["_knowledge_base"] = None
        cfg["_knowledge_base_none"] = True
        o["doc_mode"] = "none"            # existing no-RAG mode → rag.retrieve returns []
    elif args.knowledge_base:
        cfg["_knowledge_base"] = _load_knowledge_base_file(args.knowledge_base)
    else:
        cfg["_knowledge_base"] = None
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


def resolve_judge_config(judge_cfg: dict, main_cfg: dict, *, dry_run: bool = False) -> dict | None:
    """
    Build the dedicated LLM-judge config, or None when NOTHING judge-specific is
    configured (the judge then simply reuses the target model).

    CRITICAL FALLBACK RULE: when at least one judge field is given, every OMITTED
    judge field inherits the corresponding value from the already-resolved main
    model config (`main_cfg`) — provider, base_url, model, and api_key each fall
    back independently. Key precedence for the judge: --judge-api-key →
    $JUDGE_API_KEY → the main model's key.
    """
    provider = judge_cfg.get("provider")
    base_url = judge_cfg.get("base_url")
    model = judge_cfg.get("model")
    api_key = judge_cfg.get("api_key") or os.environ.get("JUDGE_API_KEY", "")
    # Nothing judge-specific at all → judge with the target model (return None).
    if not (provider or base_url or model or api_key):
        return None
    # Per-field fallback to the resolved main model configuration.
    provider = provider or main_cfg["provider"]
    if provider not in llm.PROVIDER_PRESETS:
        raise ConfigError(
            f"unknown judge provider '{provider}' — choose one of: {', '.join(sorted(llm.PROVIDER_PRESETS))}.")
    p = llm.preset(provider)
    # If the judge provider matches the main one, inherit the main base_url/model;
    # a different provider falls back to that provider's preset defaults.
    same_provider = provider == main_cfg["provider"]
    base_url = base_url or (main_cfg["base_url"] if same_provider else p["base_url"])
    model = model or (main_cfg["model"] if same_provider else p["default_model"])
    api_key = api_key or main_cfg.get("api_key") or ""
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


def resolve_lakera_key(cli_key: str | None = None, *, dry_run: bool) -> str:
    """Lakera Guard key precedence: --lakera-api-key → $LAKERA_GUARD_API_KEY."""
    key = (cli_key or os.environ.get("LAKERA_GUARD_API_KEY", "")).strip()
    if not key and not dry_run:
        raise ConfigError(
            "no Lakera Guard key — pass --lakera-api-key or set $LAKERA_GUARD_API_KEY.")
    return key or "(dry-run-placeholder)"


def resolve_lakera_projects(projects: dict | None) -> dict:
    """Normalize the parsed --lakera-projects map to a {cp1,cp2,cp3} dict of
    Project IDs (a checkpoint left unset stays None → inherits the default)."""
    projects = projects or {}
    return {cp: projects.get(cp) for cp in ("cp1", "cp2", "cp3")}


def _checkpoints_for(project_id: str | None) -> dict:
    """--project-id CPn restricts the run to that single checkpoint (others off).
    None → all three checkpoints active (the default pipeline)."""
    if not project_id:
        return {"cp1": True, "cp2": True, "cp3": True}
    pid = project_id.upper()
    return {"cp1": pid == "CP1", "cp2": pid == "CP2", "cp3": pid == "CP3"}


def build_request(cfg: dict) -> OneShotRequest:
    s, o = cfg["scope"], cfg["options"]
    cp_projects = resolve_lakera_projects(cfg.get("lakera", {}).get("projects"))
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
            # Per-checkpoint Lakera Project IDs from --lakera-projects (input=CP1,
            # rag=CP2, output=CP3); each None → inherits the run-level project.
            checkpoint_projects=cp_projects,
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


def load_dataset_file(path: str, *, column: str | None = None,
                      category_column: str | None = None,
                      tactics_column: str | None = None) -> str:
    """Parse a local CSV/JSON/JSONL/TXT into an in-memory dataset; return its slug.
    Optional column names come from the CLI --mapping (else auto-detected)."""
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(f"dataset file not found: {path}")
    try:
        parsed = datasets.parse_upload(p.name, p.read_bytes(), column=column,
                                       category_column=category_column,
                                       tactics_column=tactics_column)
    except datasets.DatasetError as exc:
        raise ConfigError(f"dataset file '{path}': {exc}")
    return _store_cli_dataset(p.name, "cli-file", parsed["column"], parsed["rows"])


def load_dataset_dir(path: str, **cols) -> list[str]:
    """Load every .csv/.json/.jsonl/.txt in a directory; return their slugs (sorted)."""
    p = pathlib.Path(path)
    if not p.is_dir():
        raise ConfigError(f"dataset dir not found: {path}")
    files = sorted(f for f in p.iterdir() if f.is_file() and f.suffix.lower() in DATASET_EXTS)
    if not files:
        raise ConfigError(f"no .csv/.json/.jsonl/.txt files in {path}")
    return [load_dataset_file(str(f), **cols) for f in files]


async def import_hf_dataset(dataset_id: str, *, limit: int, column: str | None,
                            all_configs: bool, category_column: str | None = None,
                            tactics_column: str | None = None) -> str:
    """Fetch a HuggingFace dataset (network) into an in-memory dataset; return its slug."""
    try:
        result = await datasets.fetch_hf(dataset_id, column=column, limit=limit,
                                         all_configs=all_configs,
                                         category_column=category_column,
                                         tactics_column=tactics_column)
    except datasets.DatasetError as exc:
        raise ConfigError(f"HuggingFace '{dataset_id}': {exc}")
    return _store_cli_dataset(dataset_id, "cli-hf", result["column"], result["rows"])


async def download_and_verify_hf(hf_ids: list[str], dest_dir: str, *,
                                 column: str | None = None,
                                 category_column: str | None = None,
                                 tactics_column: str | None = None) -> list[str]:
    """
    Steps 1–2 of the CLI workflow: download each dataset's original files to
    `dest_dir/<slug>/` (reusing the cache), then STRICTLY verify the row count and
    total file size against the official HuggingFace metadata. Returns the slugs of
    the loaded local datasets, ready to scan. Raises ConfigError on any mismatch.
    """
    slugs: list[str] = []
    for hid in hf_ids:
        try:
            _status(f"HuggingFace {hid}: fetching official metadata …")
            meta = await datasets.hf_official_metadata(hid)
            _status(f"  official: {meta['num_data_files']} data file(s) · "
                    f"{meta['num_rows']} rows · {meta['num_bytes_original_files']:,} bytes")
            man = await datasets.download_hf_dataset(
                hid, dest_dir, official=meta,
                on_file=lambda p, sz, cached: _status(
                    f"  {'cached ' if cached else 'downloaded'} {p} ({sz:,} bytes)",
                    "green" if cached else "cyan"))
            report = datasets.verify_dataset(man, meta)
        except datasets.DatasetError as exc:
            raise ConfigError(str(exc))
        _status(f"  ✓ verified: {report['total_bytes']:,} bytes == official; "
                f"rows {report['num_rows']} == official ({report['row_check']})", "green")
        # Load each verified file for scanning (parse into prompt rows).
        for f in man["files"]:
            slugs.append(load_dataset_file(str(pathlib.Path(man["dir"]) / f["path"]),
                                           column=column, category_column=category_column,
                                           tactics_column=tactics_column))
    return slugs


def _mapping_cols(cfg: dict) -> dict:
    """The --mapping column kwargs shared by every local/HF dataset loader."""
    return {"column": cfg.get("_prompt_column"),
            "category_column": cfg.get("_category_column"),
            "tactics_column": cfg.get("_tactics_column")}


def _local_scope_slugs(cfg: dict) -> list[str]:
    """Resolve the offline dataset sources (single --dataset slug, --dataset-file(s),
    --dataset-dir) into slugs. HuggingFace imports are resolved separately (network)."""
    cols = _mapping_cols(cfg)
    slugs: list[str] = []
    if cfg["scope"].get("dataset"):          # legacy single imported slug / suite value
        slugs.append(cfg["scope"]["dataset"])
    for f in cfg.get("_dataset_files", []):
        slugs.append(load_dataset_file(f, **cols))
    for d in ([cfg["_dataset_dir"]] if cfg.get("_dataset_dir") else []) + cfg.get("_dataset_dirs", []):
        slugs.extend(load_dataset_dir(d, **cols))
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
                        all_configs=spec["all"],
                        category_column=spec.get("category_column"),
                        tactics_column=spec.get("tactics_column")):
                    if evt["type"] == "meta":
                        counters["expected"] += evt["total"] * strat_mult
                        progress.update(task, total=counters["expected"])
                    elif evt["type"] == "batch":
                        for item in evt["rows"]:
                            counters["base"] += 1
                            base = core.dataset_row(spec["slug"], counters["base"], item, spec["name"])
                            # Honor the run's doc_mode override on streamed rows too (the
                            # batch path does this in _prepare_oneshot_rows). Without it,
                            # dataset_row's hardcoded "clean" would make --knowledge-base
                            # none / --doc-mode none still read the clean RAG file.
                            if req.doc_mode:
                                base["doc_mode"] = req.doc_mode
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
                rate_limit: float | None = None, knowledge_base: str | None = None,
                knowledge_base_none: bool = False) -> str:
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
    cpp = req.checkpoint_projects.model_dump()
    proj_bits = [f"{cp.upper()}={cpp[cp]}" for cp in ("cp1", "cp2", "cp3") if cpp[cp]]
    lines = [
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
    ]
    if req.no_system_prompt:
        sp_str = "clean mode (none)"
    elif req.system_prompt:
        sp_str = f"from file ({len(req.system_prompt)} chars)"
    else:
        sp_str = "built-in default"
    lines.append(f"  system prompt: {sp_str}")
    if knowledge_base_none:
        kb_str = "none (all RAG bypassed — no files)"
    else:
        kb_str = f"from file ({len(knowledge_base)} chars)" if knowledge_base else "clean mode (none)"
    lines.append(f"  knowledge base: {kb_str}")
    if proj_bits:
        lines.append(f"  cp projects  : {' '.join(proj_bits)}")
    return "\n".join(lines)


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
    g.add_argument("--dataset", metavar="SPEC",
                   help="dataset source(s) for a one-shot run: a HuggingFace id "
                        "(owner/name), a local directory, one or more local file paths, "
                        "or a previously-imported slug — comma-separate several "
                        "(e.g. file1.json,file2.csv or OpenSafetyLab/Salad-Data or "
                        "datasets/OpenSafetyLab__Salad-Data). Each token is auto-routed "
                        "to the right loader (an existing local dir is never mistaken for "
                        "a remote id).")
    g.add_argument("--mapping", metavar="K=V,…",
                   help="map dataset fields to run inputs as key=value pairs: "
                        "prompt=<field>,category=<field>,tactics=<field> "
                        "(e.g. prompt=text_field,category=owasp_category,"
                        "tactics=attack_tactics). Applies to --dataset/--dataset-file/"
                        "--dataset-dir/--hf-dataset; omitted fields are auto-detected.")
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
    g.add_argument("--hf-download", action="store_true",
                   help="download each --hf-dataset's ORIGINAL files to --datasets-dir and "
                        "VERIFY their row count + total size against the official HuggingFace "
                        "metadata, then scan the cached files (re-runs reuse the cache).")
    g.add_argument("--datasets-dir", metavar="DIR", default="datasets",
                   help="local cache directory for --hf-download (default: datasets/)")
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
    o.add_argument("--system-prompt", metavar="FILE.txt",
                   help="apply the contents of a .txt file as the run's system prompt. "
                        "When omitted, the run defaults to CLEAN mode — no system prompt "
                        "at all (independent of any Web UI / global setting).")
    o.add_argument("--knowledge-base", metavar="FILE.txt|none",
                   help="inject a .txt file's contents as extra RAG context appended to "
                        "each scenario's LLM prompt. Pass the literal 'none' to strictly "
                        "bypass ALL RAG file operations — not even the default clean file "
                        "is loaded. When omitted, the run stays in CLEAN mode (the default "
                        "clean file is used; current execution path unchanged).")
    o.add_argument("--doc-mode", choices=["clean", "poisoned", "custom", "none"])
    o.add_argument("--concurrency", type=int)
    o.add_argument("--rate-limit", type=float, metavar="RPS",
                   help="max outbound requests/second across ALL workers (Guard scans + LLM "
                        "calls share one token-bucket limiter; default 8). Use 0 to disable "
                        "throttling. Independent of --concurrency (how many run at once).")
    o.add_argument("--max-rounds", type=int, help="round budget for dynamic scenarios (1–10)")
    lg = ap.add_argument_group("lakera guard")
    lg.add_argument("--lakera-url", metavar="URL|REGION",
                    help="Lakera Guard endpoint: a full URL / bare region host "
                         "(https://eu-west-1.api.lakera.ai — /v2/guard is appended) OR a "
                         "known region id (" + ", ".join(r["id"] for r in lakera.REGIONS) +
                         "). Default: Community, or $LAKERA_ENDPOINT.")
    lg.add_argument("--lakera-api-key", metavar="KEY",
                    help="Lakera Guard API key (overrides $LAKERA_GUARD_API_KEY). Prefer "
                         "the env var — a CLI key is visible in the process list & shell history.")
    lg.add_argument("--lakera-projects", metavar="K=V,…",
                    help="per-checkpoint Lakera Project IDs as key=value pairs: "
                         "input=<id> (CP1 user input), rag=<id> (CP2 RAG docs), "
                         "output=<id> (CP3 LLM output) — e.g. "
                         "input=id1,rag=id2,output=id3. Unset checkpoints use the key's "
                         "default policy. cp1/cp2/cp3 accepted as aliases.")
    lg.add_argument("--lakera-endpoint", metavar="URL",
                    help="alias for --lakera-url that only accepts a full URL / bare "
                         "region host (kept for back-compat).")
    lg.add_argument("--lakera-region", choices=[r["id"] for r in lakera.REGIONS],
                    help="alias for --lakera-url that only accepts a known region id "
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
    j = ap.add_argument_group(
        "judge provider (optional; each omitted flag falls back to the matching "
        "main-model value; ALL omitted → judge with the target model)")
    j.add_argument("--judge-provider", help="judge provider (fallback: --provider)")
    j.add_argument("--judge-base-url", help="judge base URL (fallback: --base-url when same provider)")
    j.add_argument("--judge-model", help="judge model id (fallback: --model when same provider)")
    j.add_argument("--judge-api-key", metavar="KEY",
                   help="judge provider API key (precedence: this → $JUDGE_API_KEY → --api-key).")
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
        # Judge inherits any omitted field from the resolved main model (fallback rule).
        judge_config = resolve_judge_config(cfg["judge_llm"], llm_config, dry_run=args.dry_run)
        lakera_key = resolve_lakera_key(cfg["lakera"].get("api_key"), dry_run=args.dry_run)
        lakera_endpoint = resolve_lakera_endpoint(cfg["lakera"])   # custom region URL (or None)
        # Offline dataset sources (files/dir); HuggingFace imports happen at run time.
        local_slugs = _local_scope_slugs(cfg)
        hf_ids = cfg["_hf_datasets"]
        # --hf-download: fetch + verify the ORIGINAL files to /datasets now, then scan
        # them as local datasets (so they're excluded from the streaming/import path).
        if cfg["_hf_download"] and hf_ids and not args.dry_run:
            local_slugs += asyncio.run(
                download_and_verify_hf(hf_ids, cfg["_datasets_dir"], column=cfg["_hf_column"],
                                       category_column=cfg["_category_column"],
                                       tactics_column=cfg["_tactics_column"]))
            hf_ids = []
        # Load the baseline up front so a bad path fails before any API spend.
        baseline = load_baseline(args.baseline) if args.baseline else None
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # The prepare/run helpers read these module globals for fail-fast + RAG/dataset lookups.
    core._llm_config = llm_config
    core._lakera_key = lakera_key
    # Inject the optional CLI knowledge base as run-wide extra RAG context. None (no
    # --knowledge-base) leaves it unset, so scenarios run the existing clean path.
    core._cli_knowledge_base = [cfg["_knowledge_base"]] if cfg.get("_knowledge_base") else None
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
                 "limit": cfg["_hf_limit"], "column": cfg["_hf_column"], "all": cfg["_hf_all"],
                 "category_column": cfg["_category_column"], "tactics_column": cfg["_tactics_column"]}
                for hid in hf_ids]
    explicit_scope = bool(local_slugs or args.category or args.all_categories or cfg["scope"]["dataset"])
    use_stream = bool(cfg["_stream"] and hf_specs and not explicit_scope)

    try:
        if args.dry_run:
            cfg["scope"]["datasets"] = local_slugs
            req = build_request(cfg)
            rows, scope = core._prepare_oneshot_rows(req)
            plan = render_plan(scope, req, llm_config, judge_config, lakera_endpoint,
                               cfg["options"]["rate_limit"], cfg.get("_knowledge_base"),
                               cfg.get("_knowledge_base_none", False))
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
                        hid, limit=cfg["_hf_limit"], column=cfg["_hf_column"], all_configs=cfg["_hf_all"],
                        category_column=cfg["_category_column"], tactics_column=cfg["_tactics_column"]))
                cfg["scope"]["datasets"] = local_slugs + hf_slugs
                req = build_request(cfg)
                return await core.run_oneshot(req, llm_config=llm_config, lakera_key=lakera_key,
                                              judge_config=judge_config)
            finally:
                await lakera.aclose()   # release the shared Guard connection pool
                await llm.aclose()      # …and the shared LLM/judge pool
                ratelimit.reset()       # clear the process-wide throttle for later in-process runs
                core._cli_knowledge_base = None   # clear the run-wide knowledge base

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
    # Public judge config for the report (same shape as the web UI's `d.judge`):
    # `enabled` = a dedicated judge model; otherwise it mirrors the target model.
    _jc = judge_config or llm_config
    judge_public = {"enabled": judge_config is not None,
                    "provider": _jc.get("provider"), "model": _jc.get("model"),
                    "base_url": _jc.get("base_url")}
    out_payload = {**out, "llm": {k: v for k, v in llm_config.items() if k != "api_key"},
                   "judge": judge_public,
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
