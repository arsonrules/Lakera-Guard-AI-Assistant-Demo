"""
Run-history persistence + regression diff.

A one-shot run can be saved to a directory of JSON reports so runs can be compared
over time — "did detection drop / did breaches appear since the last run?". Pure
file + dict operations (no app state) so the web UI, the CLI, and CI all share it.
"""
import datetime as _dt
import json
import pathlib
import re

# Metrics compared across runs, with the direction that counts as a REGRESSION.
# rate metrics: a drop is bad; count metrics: a rise is bad.
LOWER_IS_WORSE = ("base_detection_rate", "detection_rate")
HIGHER_IS_WORSE = ("breaches", "effective_evasions", "evasions",
                   "not_blocked", "false_positive", "errors")
NEUTRAL = ("total",)
METRIC_KEYS = LOWER_IS_WORSE + HIGHER_IS_WORSE + NEUTRAL

_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}(?:-[0-9]+)?$")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def metrics(summary: dict) -> dict:
    """Pull the comparable scalar metrics out of a run summary."""
    return {k: summary.get(k) for k in METRIC_KEYS}


def save(payload: dict, directory: str | pathlib.Path, *, label: str | None = None) -> dict:
    """Persist a run ({summary, results, ...}) as a timestamped JSON file."""
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    rid = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = d / f"{rid}.json"
    n = 2
    while path.exists():           # avoid collisions within the same second
        rid = f"{rid.split('-')[0]}-{rid.split('-')[1]}-{n}"
        path = d / f"{rid}.json"
        n += 1
    record = {"id": rid, "saved_at": _now_iso(), "label": label, **payload}
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return {"id": rid, "saved_at": record["saved_at"], "label": label, "path": str(path)}


def list_runs(directory: str | pathlib.Path) -> list[dict]:
    """Metadata for saved runs, newest first (no heavy results payload)."""
    d = pathlib.Path(directory)
    if not d.exists():
        return []
    out: list[dict] = []
    for p in d.glob("*.json"):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        s = rec.get("summary", {})
        out.append({"id": rec.get("id", p.stem), "saved_at": rec.get("saved_at"),
                    "label": rec.get("label"), "metrics": metrics(s),
                    "posture": (s.get("security") or {}).get("posture", {}).get("level")})
    out.sort(key=lambda r: r["id"], reverse=True)
    return out


def load(directory: str | pathlib.Path, run_id: str) -> dict | None:
    if not _ID_RE.match(run_id):       # guard against path traversal
        return None
    p = pathlib.Path(directory) / f"{run_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def delete(directory: str | pathlib.Path, run_id: str) -> bool:
    if not _ID_RE.match(run_id):
        return False
    p = pathlib.Path(directory) / f"{run_id}.json"
    if p.exists():
        p.unlink()
        return True
    return False


def diff_summaries(base: dict, head: dict) -> dict:
    """
    Compare two run summaries. Returns per-metric deltas and an overall
    `regressed` flag (any worse-direction metric moved the wrong way).
    """
    bm, hm = metrics(base), metrics(head)
    rows: list[dict] = []
    regressed = False
    for k in METRIC_KEYS:
        b, h = bm.get(k), hm.get(k)
        delta = None
        if isinstance(b, (int, float)) and isinstance(h, (int, float)):
            delta = round(h - b, 3)
        worse = False
        if delta is not None and delta != 0:
            if k in LOWER_IS_WORSE and delta < 0:
                worse = True
            elif k in HIGHER_IS_WORSE and delta > 0:
                worse = True
        regressed = regressed or worse
        rows.append({"metric": k, "base": b, "head": h, "delta": delta, "regressed": worse})
    return {"metrics": rows, "regressed": regressed}
