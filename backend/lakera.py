import time
import httpx

LAKERA_ENDPOINT = "https://api.lakera.ai/v2/guard"


def _build_body(text: str, project_id: str = "") -> dict:
    """Lakera Guard v2 request body. `project_id` (when set) selects that
    project's configured Guard policy."""
    body = {"messages": [{"role": "user", "content": text}], "breakdown": True}
    if project_id:
        body["project_id"] = project_id
    return body


async def check(text: str, api_key: str, project_id: str = "") -> dict:
    """Run Lakera Guard v2 on a text string. Returns response dict + latency_ms."""
    start = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            LAKERA_ENDPOINT,
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
