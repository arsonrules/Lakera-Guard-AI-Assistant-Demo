import time
from urllib.parse import urlsplit

import httpx

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


async def check(text: str, api_key: str, project_id: str = "", endpoint: str = "") -> dict:
    """Run Lakera Guard v2 on a text string. Returns response dict + latency_ms.

    `endpoint` overrides the configured regional endpoint when given (mainly for
    tests); otherwise the current runtime endpoint is used."""
    start = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            endpoint or _endpoint,
            headers={"Authorization": f"Bearer {api_key}"},
            json=_build_body(text, project_id),
            timeout=10.0,
        )
        resp.raise_for_status()
    data = resp.json()
    data["latency_ms"] = int((time.monotonic() - start) * 1000)
    return data


def is_flagged(result: dict) -> bool:
    return result.get("flagged", False)


def flagged_categories(result: dict) -> list[str]:
    """Return detector_type strings for every detector that fired."""
    return [
        item["detector_type"]
        for item in result.get("breakdown", [])
        if item.get("detected")
    ]
