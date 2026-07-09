"""
External attack-dataset import for one-shot testing.

Two sources:
  • HuggingFace — fetched through the public datasets-server HTTP API (paginated
    rows, no full download, no auth for public datasets). The host is fixed, so
    only the dataset id is user-supplied (validated) — no SSRF.
  • Manual upload — CSV / JSON / JSONL / TXT.

Each import is normalized to a list of {prompt, category} rows that the one-shot
runner treats as attack scenarios.
"""
import asyncio
import csv
import io
import json
import random
import re
import time

import httpx

HF_BASE = "https://datasets-server.huggingface.co"
HF_PAGE = 100            # datasets-server max rows per request (API limit)
MAX_ROWS = 100_000       # hard cap we keep per imported dataset
UPLOAD_MAX_BYTES = 16 * 1024 * 1024  # 16 MB (larger to fit big uploaded datasets)

# Column auto-detection (case-insensitive), most specific first.
# `baseq`/`augq` are SALAD-Data's base / attack-augmented question columns;
# `jailbreak`/`forbidden_prompt`/`turns` cover other common safety datasets.
PROMPT_COLS = [
    "prompt", "attack", "jailbreak", "forbidden_prompt", "question",
    "baseq", "augq", "instruction", "text", "input", "query",
    "goal", "behavior", "sentence", "content", "message", "turns",
]
CATEGORY_COLS = [
    "category", "harm_category", "1-category", "2-category", "3-category",
    "categories", "type", "topic", "subcategory",
]

_DATASET_ID_RE = re.compile(r"^[A-Za-z0-9][\w.\-]*/[\w.\-]+$")


class DatasetError(ValueError):
    """User-facing dataset import problem."""


class RateLimited(DatasetError):
    """HuggingFace kept rate-limiting after all retries (used for partial fallback)."""


def _pick(columns: list[str], candidates: list[str]) -> str | None:
    low = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand in low:
            return low[cand]
    return None


def _coerce(value) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        # Some datasets nest the text (e.g. {"text": "..."}).
        for k in PROMPT_COLS:
            if k in value and isinstance(value[k], str):
                return value[k].strip()
    return str(value).strip() if value is not None else ""


HF_MAX_RETRIES = 8       # patient backoff so large imports ride out rate limits
HF_BACKOFF_CAP = 30.0    # max seconds between retries


async def _get_json(client: httpx.AsyncClient, url: str, params: dict, *, timeout: float = 30.0) -> dict:
    """
    GET JSON with patient, jittered backoff. The datasets-server rate-limits
    bursts, so large imports otherwise die on HTTP 429. On a persistent rate
    limit we raise RateLimited so the caller can keep what it already fetched
    (partial import) instead of failing the whole run.
    """
    delay = 1.0
    for attempt in range(HF_MAX_RETRIES):
        try:
            resp = await client.get(url, params=params, timeout=timeout)
        except httpx.RequestError:
            if attempt == HF_MAX_RETRIES - 1:
                raise
            await asyncio.sleep(min(delay, HF_BACKOFF_CAP))
            delay = min(delay * 2, HF_BACKOFF_CAP)
            continue
        if resp.status_code in (429, 500, 502, 503, 504):
            if attempt == HF_MAX_RETRIES - 1:
                raise RateLimited(f"HuggingFace kept returning HTTP {resp.status_code} after retries.")
            retry_after = resp.headers.get("Retry-After")
            base = float(retry_after) if (retry_after or "").replace(".", "", 1).isdigit() else delay
            await asyncio.sleep(min(base, HF_BACKOFF_CAP) + random.uniform(0, 0.5))  # jitter
            delay = min(delay * 2, HF_BACKOFF_CAP)
            continue
        if resp.status_code >= 400:
            raise DatasetError(f"HuggingFace returned HTTP {resp.status_code}.")
        return resp.json()
    raise RateLimited("HuggingFace request failed after retries.")


async def list_splits(dataset_id: str) -> list[dict]:
    if not _DATASET_ID_RE.match(dataset_id):
        raise DatasetError("Dataset id must look like 'owner/name'.")
    async with httpx.AsyncClient() as client:
        data = await _get_json(client, f"{HF_BASE}/splits", {"dataset": dataset_id}, timeout=20.0)
    return data.get("splits", [])


class _Deadline:
    """Shared cross-split state: row budget, time budget, progress, combined total."""
    def __init__(self, limit, combined_total, on_progress, time_budget, start):
        self.limit = limit
        self.combined_total = combined_total
        self.on_progress = on_progress
        self.time_budget = time_budget
        self.start = start
        self.rows: list[dict] = []
        self.partial = False

    def over_budget(self) -> bool:
        return bool(self.time_budget and (time.monotonic() - self.start) > self.time_budget and self.rows)


async def _probe_total(client, dataset_id, cfg, spl) -> int:
    try:
        d = await _get_json(client, f"{HF_BASE}/rows",
                            {"dataset": dataset_id, "config": cfg, "split": spl, "offset": 0, "length": 1})
        return d.get("num_rows_total", 0)
    except DatasetError:
        return 0


async def _fetch_split(client, dataset_id, cfg, spl, *, column, category_column, st: _Deadline) -> None:
    """Page through one config/split, appending to st.rows up to st.limit. Skips a
    split whose prompt column can't be detected (returns without raising)."""
    detected_col, detected_cat, seen = column, category_column, False
    pace, offset, first = 0.2, 0, True
    while len(st.rows) < st.limit:
        page = min(HF_PAGE, st.limit - len(st.rows))
        if not first:
            await asyncio.sleep(pace)
        first = False
        try:
            data = await _get_json(
                client, f"{HF_BASE}/rows",
                {"dataset": dataset_id, "config": cfg, "split": spl, "offset": offset, "length": page},
            )
        except RateLimited:
            if st.rows:
                st.partial = True
                return
            raise
        if not seen:
            seen = True
            feats = [f["name"] for f in data.get("features", [])]
            detected_col = detected_col or _pick(feats, PROMPT_COLS)
            detected_cat = detected_cat or _pick(feats, CATEGORY_COLS)
            if not detected_col:
                return  # this split has no usable prompt column — skip it
        sub_total = data.get("num_rows_total", 0)
        page_rows = data.get("rows", [])
        if not page_rows:
            break
        for item in page_rows:
            prompt = _coerce(item.get("row", {}).get(detected_col))
            if not prompt:
                continue
            cat = _coerce(item.get("row", {}).get(detected_cat)) if detected_cat else cfg
            st.rows.append({"prompt": prompt, "category": cat})
            if len(st.rows) >= st.limit:
                break
        offset += len(page_rows)
        if st.on_progress:
            await st.on_progress(len(st.rows), st.combined_total)
        if offset >= sub_total:
            break
        if st.over_budget():
            st.partial = True
            return


async def fetch_hf(
    dataset_id: str,
    *,
    config: str | None = None,
    split: str | None = None,
    column: str | None = None,
    category_column: str | None = None,
    limit: int = 25,
    all_configs: bool = False,
    on_progress=None,
    time_budget: float | None = None,
) -> dict:
    """
    Fetch up to `limit` prompts from a HuggingFace dataset.

    Datasets are split into configs (e.g. SALAD-Data: base_set, attack_enhanced_set…).
      • all_configs=True  → import across EVERY config+split (the whole dataset).
      • config/split given → just that one.
      • neither           → default to the LARGEST config (not the arbitrary first).
    `on_progress(fetched, total)` streams progress; `time_budget` bounds the worst case.
    """
    if not _DATASET_ID_RE.match(dataset_id):
        raise DatasetError("Dataset id must look like 'owner/name'.")
    limit = max(1, min(int(limit or 25), MAX_ROWS))
    start = time.monotonic()

    splits = await list_splits(dataset_id)
    if not splits:
        raise DatasetError(f"No splits found for '{dataset_id}'. Is it a public dataset?")
    available = [{"config": s["config"], "split": s["split"]} for s in splits]

    async with httpx.AsyncClient() as client:
        if all_configs:
            targets = splits
        elif config or split:
            targets = [next(
                (s for s in splits
                 if (not config or s["config"] == config) and (not split or s["split"] == split)),
                splits[0],
            )]
        elif len(splits) == 1:
            targets = splits
        else:
            # Pick the largest config so a default import grabs the meaningful bulk.
            counts = [(s, await _probe_total(client, dataset_id, s["config"], s["split"])) for s in splits]
            targets = [max(counts, key=lambda x: x[1])[0]]

        # Combined total across the splits we'll actually read (for the progress bar).
        combined_total = 0
        for s in targets:
            combined_total += await _probe_total(client, dataset_id, s["config"], s["split"])

        st = _Deadline(limit, combined_total, on_progress, time_budget, start)
        used: list[str] = []
        for s in targets:
            if len(st.rows) >= st.limit or st.over_budget():
                st.partial = True
                break
            before = len(st.rows)
            await _fetch_split(client, dataset_id, s["config"], s["split"],
                               column=column, category_column=category_column, st=st)
            if len(st.rows) > before:
                used.append(s["config"])

    if not st.rows:
        raise DatasetError("No usable prompt rows were returned (no prompt column found in any config).")
    return {
        "rows": st.rows, "column": column or "(auto)", "category_column": category_column,
        "config": "+".join(dict.fromkeys(used)) if all_configs else targets[0]["config"],
        "split": "*" if all_configs else targets[0]["split"],
        "features": [], "available": available,
        "partial": st.partial, "requested": limit, "total": combined_total,
    }


async def stream_hf(
    dataset_id: str,
    *,
    config: str | None = None,
    split: str | None = None,
    column: str | None = None,
    category_column: str | None = None,
    limit: int = 25,
    all_configs: bool = False,
    time_budget: float | None = None,
):
    """
    Async generator that yields batches (pages) of {prompt, category} rows **as
    they download** from HuggingFace, so a caller can scan chunks concurrently
    instead of waiting for the whole dataset. Same source/selection logic as
    `fetch_hf`, but streamed.

    Yields dicts:
      {"type": "meta",  "total": <combined rows across the splits we'll read>}   (first)
      {"type": "batch", "rows": [{prompt, category}, …], "fetched": <cumulative>} (per page)
      {"type": "end",   "fetched": <total kept>, "partial": <bool>}              (last)
    """
    if not _DATASET_ID_RE.match(dataset_id):
        raise DatasetError("Dataset id must look like 'owner/name'.")
    limit = max(1, min(int(limit or 25), MAX_ROWS))
    start = time.monotonic()

    splits = await list_splits(dataset_id)
    if not splits:
        raise DatasetError(f"No splits found for '{dataset_id}'. Is it a public dataset?")

    async with httpx.AsyncClient() as client:
        if all_configs:
            targets = splits
        elif config or split:
            targets = [next(
                (s for s in splits
                 if (not config or s["config"] == config) and (not split or s["split"] == split)),
                splits[0],
            )]
        elif len(splits) == 1:
            targets = splits
        else:
            counts = [(s, await _probe_total(client, dataset_id, s["config"], s["split"])) for s in splits]
            targets = [max(counts, key=lambda x: x[1])[0]]

        combined_total = 0
        for s in targets:
            combined_total += await _probe_total(client, dataset_id, s["config"], s["split"])
        yield {"type": "meta", "total": min(combined_total, limit) or limit}

        fetched, partial, produced_any = 0, False, False
        for s in targets:
            if fetched >= limit:
                break
            cfg, spl = s["config"], s["split"]
            detected_col, detected_cat, seen = column, category_column, False
            pace, offset, first = 0.2, 0, True
            while fetched < limit:
                page = min(HF_PAGE, limit - fetched)
                if not first:
                    await asyncio.sleep(pace)
                first = False
                try:
                    data = await _get_json(
                        client, f"{HF_BASE}/rows",
                        {"dataset": dataset_id, "config": cfg, "split": spl, "offset": offset, "length": page},
                    )
                except RateLimited:
                    if produced_any:
                        partial = True
                        break
                    raise
                if not seen:
                    seen = True
                    feats = [f["name"] for f in data.get("features", [])]
                    detected_col = detected_col or _pick(feats, PROMPT_COLS)
                    detected_cat = detected_cat or _pick(feats, CATEGORY_COLS)
                    if not detected_col:
                        break  # this split has no usable prompt column — skip it
                sub_total = data.get("num_rows_total", 0)
                page_rows = data.get("rows", [])
                if not page_rows:
                    break
                batch: list[dict] = []
                for it in page_rows:
                    prompt = _coerce(it.get("row", {}).get(detected_col))
                    if not prompt:
                        continue
                    cat = _coerce(it.get("row", {}).get(detected_cat)) if detected_cat else cfg
                    batch.append({"prompt": prompt, "category": cat})
                    if fetched + len(batch) >= limit:
                        break
                if batch:
                    fetched += len(batch)
                    produced_any = True
                    yield {"type": "batch", "rows": batch, "fetched": fetched}
                offset += len(page_rows)
                if offset >= sub_total:
                    break
                if time_budget and (time.monotonic() - start) > time_budget and produced_any:
                    partial = True
                    break
            if partial:
                break

        if not produced_any:
            raise DatasetError("No usable prompt rows were returned (no prompt column found in any config).")
        yield {"type": "end", "fetched": fetched, "partial": partial}


def parse_upload(filename: str, content: bytes, column: str | None = None) -> dict:
    """Parse an uploaded CSV/JSON/JSONL/TXT file into prompt rows."""
    if len(content) > UPLOAD_MAX_BYTES:
        raise DatasetError(f"File exceeds {UPLOAD_MAX_BYTES // (1024*1024)} MB limit.")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise DatasetError("File must be valid UTF-8 text.")

    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    rows: list[dict] = []
    detected_col = column

    def add(prompt, cat=""):
        p = _coerce(prompt)
        if p:
            rows.append({"prompt": p, "category": _coerce(cat)})

    if ext == "csv":
        reader = csv.DictReader(io.StringIO(text))
        cols = reader.fieldnames or []
        detected_col = detected_col or _pick(cols, PROMPT_COLS) or (cols[0] if cols else None)
        cat_col = _pick(cols, CATEGORY_COLS)
        if not detected_col:
            raise DatasetError("CSV has no columns.")
        for r in reader:
            add(r.get(detected_col), r.get(cat_col) if cat_col else "")
    elif ext == "jsonl":
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                add(obj)
            elif isinstance(obj, dict):
                col = detected_col or _pick(list(obj), PROMPT_COLS)
                detected_col = detected_col or col
                cat_col = _pick(list(obj), CATEGORY_COLS)
                add(obj.get(col), obj.get(cat_col) if cat_col else "")
    elif ext == "json":
        data = json.loads(text)
        items = data if isinstance(data, list) else data.get("data") or data.get("rows") or []
        for obj in items:
            if isinstance(obj, str):
                add(obj)
            elif isinstance(obj, dict):
                col = detected_col or _pick(list(obj), PROMPT_COLS)
                detected_col = detected_col or col
                cat_col = _pick(list(obj), CATEGORY_COLS)
                add(obj.get(col), obj.get(cat_col) if cat_col else "")
    else:  # txt or unknown → one prompt per non-empty line
        detected_col = "line"
        for line in text.splitlines():
            add(line)

    if not rows:
        raise DatasetError("No usable prompt rows found in the file.")
    return {"rows": rows[:MAX_ROWS], "column": detected_col}
