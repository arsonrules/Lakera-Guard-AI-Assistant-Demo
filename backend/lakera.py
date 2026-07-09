import asyncio
import time
from urllib.parse import urlsplit

import httpx

from backend import ratelimit

# Default "Community" Guard endpoint (full path). Regional clusters share the
# same /v2/guard path on a region-specific host.
COMMUNITY_ENDPOINT = "https://api.lakera.ai/v2/guard"

# Selectable Lakera Guard regions shown in the Settings panel. `url` is the full
# Guard endpoint; the first entry is the default. Keep ids stable — the UI and
# .env reference them.
REGIONS = [
    {"id": "community",     "label": "Community",             "url": "https://api.lakera.ai/v2/guard"},
    {"id": "us",            "label": "US (multi-region)",     "url": "https://us.api.lakera.ai/v2/guard"},
    {"id": "us-east-1",     "label": "US East (N. Virginia)", "url": "https://us-east-1.api.lakera.ai/v2/guard"},
    {"id": "us-west-2",     "label": "US West (Oregon)",      "url": "https://us-west-2.api.lakera.ai/v2/guard"},
    {"id": "eu-west-1",     "label": "EU (Ireland)",          "url": "https://eu-west-1.api.lakera.ai/v2/guard"},
    {"id": "ap-southeast-1","label": "Asia (Singapore)",      "url": "https://ap-southeast-1.api.lakera.ai/v2/guard"},
]

# Back-compat alias for the module default.
LAKERA_ENDPOINT = COMMUNITY_ENDPOINT


class LakeraAPIError(RuntimeError):
    """
    Lakera Guard returned an HTTP error (e.g. 400 invalid region, 401 bad key).

    Distinct from an LLM-provider error so callers can attribute the failure to
    the *guard* (and point the user at the Guard settings) instead of blaming the
    model config. Carries `status_code` so retry logic can still treat 429/5xx as
    transient.
    """

    def __init__(self, status_code: int, message: str, *, endpoint: str = "", body: str = ""):
        self.status_code = status_code
        self.endpoint = endpoint
        self.body = body
        super().__init__(message)

# Current runtime endpoint. Mutable; seeded from .env and updated from the UI
# via main.py (a single deployment targets one Guard region at a time).
_endpoint = COMMUNITY_ENDPOINT


def normalize_endpoint(url: str) -> str:
    """Accept a region base host (e.g. https://us.api.lakera.ai) or a full Guard
    URL and return the full /v2/guard endpoint. Blank → the Community default."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return COMMUNITY_ENDPOINT
    if not url.startswith(("http://", "https://")):
        raise ValueError("Lakera endpoint must start with http:// or https://")
    # A bare host with no path → append the Guard path so a region host works.
    if not urlsplit(url).path.strip("/"):
        url += "/v2/guard"
    return url


def set_endpoint(url: str) -> str:
    """Update the runtime Guard endpoint. Returns the normalized value."""
    global _endpoint
    _endpoint = normalize_endpoint(url)
    return _endpoint


def current_endpoint() -> str:
    return _endpoint


def _build_body(text: str, project_id: str = "") -> dict:
    """Lakera Guard v2 request body. `project_id` (when set) selects that
    project's configured Guard policy."""
    body = {"messages": [{"role": "user", "content": text}], "breakdown": True}
    if project_id:
        body["project_id"] = project_id
    return body


# Shared, connection-pooled HTTP client. One Guard scan happens per checkpoint,
# so a high-concurrency one-shot run fires hundreds of scans; reusing keep-alive
# connections (instead of a fresh TLS handshake per `httpx.AsyncClient()`) is
# what makes 100-way parallelism fast. The client isn't bound to a host — every
# call passes the full URL — so switching Guard regions just pools new
# connections for the new host. Sized comfortably above MAX_CONCURRENCY.
_LIMITS = httpx.Limits(max_connections=128, max_keepalive_connections=64)
_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        async with _client_lock:            # guard against a concurrent first-use race
            if _client is None or _client.is_closed:
                _client = httpx.AsyncClient(limits=_LIMITS, timeout=10.0)
    return _client


async def aclose() -> None:
    """Close the shared client (call on app shutdown / after a CLI run)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


async def check(text: str, api_key: str, project_id: str = "", endpoint: str = "") -> dict:
    """Run Lakera Guard v2 on a text string. Returns response dict + latency_ms.

    `endpoint` overrides the configured regional endpoint when given (mainly for
    tests); otherwise the current runtime endpoint is used."""
    await ratelimit.acquire()          # global outbound-request rate cap (no-op unless configured)
    start = time.monotonic()
    client = await _get_client()
    used_endpoint = endpoint or _endpoint
    resp = await client.post(
        used_endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
        json=_build_body(text, project_id),
        timeout=10.0,
    )
    if resp.status_code >= 400:
        raise _api_error(resp, used_endpoint)
    data = resp.json()
    data["latency_ms"] = int((time.monotonic() - start) * 1000)
    return data


def _api_error(resp: httpx.Response, endpoint: str) -> "LakeraAPIError":
    """Turn a Lakera Guard HTTP error response into a clear, actionable message.

    Lakera's error body is `{"error": "ErrX", "message": "...", ...}`; we surface
    the human message and add a fix-it hint for the common misconfigurations
    (wrong region for the key, bad/missing key)."""
    code = resp.status_code
    detail = ""
    try:
        j = resp.json()
        msg = (j.get("message") or "").strip()
        err = (j.get("error") or "").strip()
        detail = msg or err
        if err and msg and err.lower() not in msg.lower():
            detail = f"{msg} ({err})"
    except Exception:   # noqa: BLE001 — non-JSON body: fall back to raw text
        detail = (resp.text or "").strip()[:200]
    low = detail.lower()
    if "region" in low:
        hint = (f" — the configured Guard region ({endpoint}) doesn't match this API key. "
                f"Pick the correct region in Settings (Community is https://api.lakera.ai).")
    elif code in (401, 403):
        hint = " — check your Lakera Guard API key in Settings."
    else:
        hint = " — check your Lakera Guard configuration in Settings."
    return LakeraAPIError(code, f"Lakera Guard error ({code}): {detail}{hint}",
                          endpoint=endpoint, body=(resp.text or "")[:300])


def is_flagged(result: dict) -> bool:
    return result.get("flagged", False)


def flagged_categories(result: dict) -> list[str]:
    """Return detector_type strings for every detector that fired."""
    return [
        item["detector_type"]
        for item in result.get("breakdown", [])
        if item.get("detected")
    ]


# ── Confidence-level mapping (Lakera Guard results → compact L1–L5 badges) ─────
# Each detector in a guard response carries a `result` like "l1_confident" …
# "l5_unlikely" (or "no_level"). We collapse it to a compact L1–L5 badge, or "-"
# when there is no graded level, so the UI/report can show it at a glance.
_LEVELS = {"l1": "L1", "l2": "L2", "l3": "L3", "l4": "L4", "l5": "L5"}

# Human-readable legend, shown (collapsed) at the top of the result/report.
LEVEL_LEGEND = [
    {"level": "L1", "desc": "Confident — almost certainly a real detection"},
    {"level": "L2", "desc": "Very likely"},
    {"level": "L3", "desc": "Likely"},
    {"level": "L4", "desc": "Less likely"},
    {"level": "L5", "desc": "Unlikely — most likely benign"},
    {"level": "-",  "desc": "No graded confidence level for this detector"},
]


def simplify_result(result: str | None) -> str:
    """Map a Lakera detector `result` (e.g. 'l1_confident', 'no_level') to a
    compact L1–L5 badge, or '-' when there is no graded level."""
    key = (result or "").strip().lower()[:2]
    return _LEVELS.get(key, "-")


def _detector_category(detector_type: str) -> str:
    """High-level category of a detector_type, e.g. 'pii/address' -> 'pii'."""
    return (detector_type or "").split("/", 1)[0] or "unknown"


def detector_results(result: dict, *, only_detected: bool = True) -> list[dict]:
    """Per-detector L1–L5 mapping from a guard-response breakdown. By default keeps
    only the detectors that fired (the useful signal); each item is
    {type, category, level}."""
    out: list[dict] = []
    for item in result.get("breakdown", []) or []:
        if only_detected and not item.get("detected"):
            continue
        dt = item.get("detector_type", "")
        out.append({
            "type": dt,
            "category": _detector_category(dt),
            "level": simplify_result(item.get("result")),
        })
    return out


def results_summary(result: dict) -> dict:
    """Compact per-scan Lakera summary shared by the chat trace and the one-shot
    report: the fired detectors (type + L1–L5), their categories, and a count."""
    dets = detector_results(result, only_detected=True)
    return {
        "detectors": dets,
        "categories": sorted({d["category"] for d in dets}),
        "flagged_count": len(dets),
    }
